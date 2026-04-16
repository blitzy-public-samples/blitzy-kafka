/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.common.security.oauthbearer.internals.secured;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.oauthbearer.JwtValidatorException;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerIllegalTokenException;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerUnsecuredJws;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * {@code CachedFile} goes a little beyond the basic file caching mechanism by allowing the file to be "transformed"
 * into an in-memory representation of the file contents for easier use by the caller.
 *
 * @param <T> Type of the "transformed" file contents
 */
// SECURITY: SEC-OAUTH-077 (LOW) Generic file caching utility with transformer and refresh policy.
// Why: Reads file contents into memory and caches the result. The file's integrity is
// assumed — no checksum, signature, or permission verification is performed.
// Exploit: TOCTOU (Time-of-check-time-of-use) race — snapshot() checks file.lastModified()
// then reads file.toPath() in separate operations (lines 129-133). An attacker with write
// access could replace the file between the stat and read calls. Additionally, file.length()
// (line 129) may not match the actual read size if the file changes concurrently.
// Improvement: (1) Read file atomically (e.g., to temp then rename), (2) Verify file
// permissions reject world-writable files, (3) Consider file locking during read.
//
// CROSS-CUTTING: Used by JwksFileVerificationKeyResolver (JWKS file caching with
// VerificationKeyResolverTransformer), FileJwtRetriever (JWT file caching with STRING_NOOP
// or STRING_JSON_VALIDATING_TRANSFORMER), and assertion/FileAssertionCreator and
// assertion/FileAssertionJwtTemplate (assertion file caching).
// Depends on: SerializedJwt (JWT structure validation), OAuthBearerUnsecuredJws (JSON parsing).
// Contract: Constructor loads file synchronously. Subsequent access via transformed() may
// trigger refresh based on RefreshPolicy. KafkaException thrown on I/O errors.
public class CachedFile<T> {

    /**
     * Function object that provides as arguments the file and its contents and returns the in-memory representation
     * of the file contents.
     */
    public interface Transformer<T> {

        /**
         * Transforms the raw contents into a (possibly) different representation.
         *
         * @param file     File containing the source data
         * @param contents Data from file; could be zero length but not {@code null}
         */
        T transform(File file, String contents);
    }

    /**
     * Function object that provides as arguments the file and its metadata and returns a flag to determine if the
     * file should be reloaded from disk.
     */
    // DECISION: RefreshPolicy is a pluggable strategy interface with two built-in implementations:
    // staticPolicy() — load once, never refresh. lastModifiedPolicy() — refresh when mtime changes.
    // Alternative: Timer-based refresh with fixed interval. Rationale: File modification timestamp
    // is cheap to check (single stat() call) and provides precise change detection.
    public interface RefreshPolicy<T> {

        /**
         * Given the {@link File} and its snapshot, determine if the file should be reloaded from disk.
         */
        boolean shouldRefresh(File file, Snapshot<T> snapshot);

        /**
         * This cache refresh policy only loads the file once.
         */
        static <T> RefreshPolicy<T> staticPolicy() {
            return (file, snapshot) -> snapshot == null;
        }

        /**
         * This policy will refresh the cached file if the snapshot's time is older than the current timestamp.
         */
        static <T> RefreshPolicy<T> lastModifiedPolicy() {
            return (file, snapshot) -> {
                if (snapshot == null)
                    return true;

                return file.lastModified() != snapshot.lastModified();
            };
        }
    }

    /**
     * No-op transformer that retains the exact file contents as a string.
     */
    public static final Transformer<String> STRING_NOOP_TRANSFORMER = (file, contents) -> contents;

    /**
     * This transformer really only validates that the given file contents represent a properly-formed JWT.
     * If not, a {@link OAuthBearerIllegalTokenException} or {@link JwtValidatorException} is thrown.
     */
    // SECURITY: SEC-OAUTH-078 (MEDIUM) Validates that file contents are a properly-formed JWT (3 dot-separated
    // Why: Cached file access depends on filesystem integrity to
    // protect token material between reads.
    // segments with valid Base64 header and payload). Uses SerializedJwt for structural validation
    // and OAuthBearerUnsecuredJws.toMap() for JSON parsing validation. Does NOT verify signature —
    // this is a structural check only. A malformed file triggers OAuthBearerIllegalTokenException
    // or JwtValidatorException, preventing downstream processing of garbage data.
    // Exploit: An attacker with filesystem access could modify the cached
    // token file between reads, injecting a forged token.
    // Improvement: Add file integrity verification (e.g., checksum)
    // before reading cached token data to detect tampering.
    public static final Transformer<String> STRING_JSON_VALIDATING_TRANSFORMER = (file, contents) -> {
        contents = contents.trim();
        SerializedJwt serializedJwt = new SerializedJwt(contents);
        OAuthBearerUnsecuredJws.toMap(serializedJwt.getHeader());
        OAuthBearerUnsecuredJws.toMap(serializedJwt.getPayload());
        return contents;
    };

    private final File file;
    private final Transformer<T> transformer;
    private final RefreshPolicy<T> cacheRefreshPolicy;
    // DECISION: Uses atomic snapshot replacement pattern — the snapshot field is a single
    // reference that is replaced atomically. No synchronization (volatile, lock) is used.
    // Alternatives: (1) volatile field for guaranteed visibility, (2) ReadWriteLock for
    // consistency. Rationale: In practice, CachedFile is used from a single thread per
    // resolver instance. The snapshot() method is called on every access, so staleness is
    // naturally bounded by the refresh policy. Risk: Without volatile, a stale snapshot may
    // be visible to other threads for an indeterminate period (Java Memory Model visibility
    // guarantee requires happens-before).
    private Snapshot<T> snapshot;

    // DECISION: Constructor calls snapshot() immediately, eagerly loading the file.
    // Alternative: Lazy load on first access. Rationale: Fail-fast — if the file is missing or
    // unreadable, the constructor throws KafkaException immediately during configure(), rather
    // than deferring failure to the first resolveKey() call. This makes configuration errors
    // visible at startup time.
    public CachedFile(File file, Transformer<T> transformer, RefreshPolicy<T> cacheRefreshPolicy) {
        this.file = file;
        this.transformer = transformer;
        this.cacheRefreshPolicy = cacheRefreshPolicy;
        this.snapshot = snapshot();
    }

    public long size() {
        return snapshot().size();
    }

    public long lastModified() {
        return snapshot().lastModified();
    }

    public String contents() {
        return snapshot().contents();
    }

    public T transformed() {
        return snapshot().transformed();
    }

    // SECURITY: SEC-OAUTH-079 (LOW) Snapshot replacement — when refresh is needed, a new Snapshot is created
    // Why: Cached file access depends on filesystem integrity to
    // protect token material between reads.
    // with current file metadata and contents. The old snapshot is replaced atomically (single
    // reference assignment, line 140). Concurrent readers may see either the old or new snapshot.
    // This is acceptable because snapshot replacement is monotonic (always moves forward).
    // Exploit: Improper handling could be exploited to bypass security controls or leak sensitive information.
    // Improvement: Add comprehensive logging for security-relevant operations and enforce fail-closed semantics.
    private Snapshot<T> snapshot() {
        if (cacheRefreshPolicy.shouldRefresh(file, snapshot)) {
            long size = file.length();
            long lastModified = file.lastModified();
            String contents;

            try {
                contents = Files.readString(file.toPath());
            } catch (IOException e) {
                throw new KafkaException("Error reading the file contents of OAuth resource " + file.getPath() + " for caching");
            }

            T transformed = transformer.transform(file, contents);
            snapshot = new Snapshot<>(size, lastModified, contents, transformed);
        }

        return snapshot;
    }

    public static class Snapshot<T> {

        private final long size;

        private final long lastModified;

        private final String contents;

        private final T transformed;

        public Snapshot(long size, long lastModified, String contents, T transformed) {
            this.size = size;
            this.lastModified = lastModified;
            this.contents = contents;
            this.transformed = transformed;
        }

        public long size() {
            return size;
        }

        public long lastModified() {
            return lastModified;
        }

        public String contents() {
            return contents;
        }

        public T transformed() {
            return transformed;
        }
    }
}
