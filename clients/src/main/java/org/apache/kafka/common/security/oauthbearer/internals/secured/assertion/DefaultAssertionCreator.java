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
package org.apache.kafka.common.security.oauthbearer.internals.secured.assertion;

import org.apache.kafka.common.security.oauthbearer.JwtRetrieverException;
import org.apache.kafka.common.security.oauthbearer.internals.secured.CachedFile;
import org.apache.kafka.common.utils.Utils;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Optional;

import static org.apache.kafka.common.security.oauthbearer.internals.secured.CachedFile.RefreshPolicy.lastModifiedPolicy;
import static org.apache.kafka.common.security.oauthbearer.internals.secured.assertion.AssertionUtils.privateKey;
import static org.apache.kafka.common.security.oauthbearer.internals.secured.assertion.AssertionUtils.sign;

/**
 * This is the "default" {@link AssertionCreator} in that it is the common case of using a configured signing
 * algorithm, private key file, and optional passphrase to sign a JWT to dynamically create an assertion.
 *
 * <p/>
 *
 * The provided private key file will be cached in memory but will be refreshed when the file changes.
 * <em>Note</em>: there is not yet a facility to reload the configured passphrase. If using a private key
 * passphrase, either use the same passphrase for each private key or else restart the client/application
 * so that the new private key and passphrase will be used.
 */
// SECURITY: (HIGH) Private key material held in memory as java.security.PrivateKey — the JVM garbage
// collector cannot zero memory, so private key bytes persist in heap until overwritten by new allocations.
// Exploit: A heap dump (e.g., via jmap, JDWP debug attachment, or /proc/pid/mem on Linux) reveals the
// private key, enabling unlimited token generation against the OAuth provider.
// Improvement: Consider HSM-backed keys via PKCS#11 provider, or use a separate key management service
// that never exports private keys. At minimum, restrict JMX/debug ports in production.
//
// CROSS-CUTTING: Depends on AssertionUtils.privateKey() (PKCS#8 key parsing),
// AssertionUtils.sign() (JCA signature), CachedFile<PrivateKey> (file caching with lastModified
// refresh policy), and Jackson ObjectMapper (JSON serialization of template claims).
// Used by JwtBearerJwtRetriever when assertionCreatorClass config points to this class.
// Implements AssertionCreator interface — consumed via factory pattern in AssertionUtils.
// Impact: Changes to signing algorithm mapping in AssertionUtils.getSignature() directly affect
// all assertions created by this class.
public class DefaultAssertionCreator implements AssertionCreator {

    // DECISION: Base64 URL-safe encoding without padding per RFC 7515 (JWS Compact Serialization).
    // Alternative: Standard Base64 with padding. Rationale: JWT/JWS spec requires URL-safe Base64
    // without padding for compact serialization.
    private static final Base64.Encoder BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private final String algorithm;
    // SECURITY: (HIGH) CachedFile stores the parsed PrivateKey object in memory indefinitely. The key is
    // refreshed only when the file's lastModified timestamp changes, but old keys are not explicitly
    // cleared from memory — they remain in heap until GC collects them.
    // Exploit: An attacker could exhaust server resources by sending oversized or excessive requests.
    // Improvement: Enforce strict per-connection resource limits and implement connection rate limiting.
    private final CachedFile<PrivateKey> privateKeyFile;

    // DECISION: Passphrase is captured once at construction time and NOT dynamically reloaded — the
    // CachedFile reloads the private key file on modification, but uses the original passphrase.
    // If the passphrase changes, a client restart is required. See Javadoc note at lines 44-46.
    public DefaultAssertionCreator(String algorithm, File privateKeyFile, Optional<String> passphrase) {
        this.algorithm = algorithm;

        this.privateKeyFile = new CachedFile<>(
            privateKeyFile,
            new PrivateKeyTransformer(passphrase),
            lastModifiedPolicy()
        );
    }

    // DECISION: Uses jose4j-independent manual JWT construction: JSON serialize → Base64URL encode →
    // concatenate → sign. Alternative: Use jose4j JsonWebSignature which handles header/payload/signature
    // construction. Rationale: Manual construction avoids jose4j dependency for signing (jose4j is used
    // only for verification), giving full control over the JWT structure and avoiding potential jose4j
    // header injection from template values.
    @Override
    public String create(AssertionJwtTemplate template) throws GeneralSecurityException, IOException {
        // DECISION: Template claims are serialized first (header/payload to JSON), then signed. The
        // template provides the raw claims; the creator adds only the signature layer. This separation
        // ensures the AssertionCreator does not modify claim content — it is a pure signing operation.
        ObjectMapper mapper = new ObjectMapper();
        String header = BASE64_ENCODER.encodeToString(Utils.utf8(mapper.writeValueAsString(template.header())));
        String payload = BASE64_ENCODER.encodeToString(Utils.utf8(mapper.writeValueAsString(template.payload())));
        String content = header + "." + payload;
        PrivateKey privateKey = privateKeyFile.transformed();
        String signedContent = sign(algorithm, privateKey, content);
        return content + "." + signedContent;
    }

    // SECURITY: (MEDIUM) PEM file parsing — strips BEGIN/END delimiters and newlines, then delegates to
    // AssertionUtils.privateKey(). The raw PEM content (String) passes through multiple intermediate
    // String objects during .replace() calls — each is a separate heap allocation containing key material.
    // Exploit: Memory forensics on a running JVM can recover multiple copies of the PEM-encoded key from
    // the young generation heap. Improvement: Use byte[] with explicit zeroing instead of String operations.
    private static class PrivateKeyTransformer implements CachedFile.Transformer<PrivateKey> {

        private final Optional<String> passphrase;

        public PrivateKeyTransformer(Optional<String> passphrase) {
            this.passphrase = passphrase;
        }

        @Override
        public PrivateKey transform(File file, String contents) {
            try {
                contents = contents.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("\n", "");

                return privateKey(contents.getBytes(StandardCharsets.UTF_8), passphrase);
            } catch (GeneralSecurityException | IOException e) {
                throw new JwtRetrieverException("An error occurred generating the OAuth assertion private key from " + file.getPath(), e);
            }
        }
    }
}
