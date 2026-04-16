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
package org.apache.kafka.common.security.scram.internals;

import org.apache.kafka.common.security.authenticator.CredentialCache;
import org.apache.kafka.common.security.scram.ScramCredential;

import java.util.Base64;
import java.util.Collection;
import java.util.Properties;

/**
 * SCRAM Credential persistence utility functions. Implements format conversion used
 * for the credential store implemented in Kafka. Credentials are persisted as a comma-separated
 * String of key-value pairs:
 * <pre>
 *   salt=<i>salt</i>,stored_key=<i>stored_key</i>,server_key=<i>server_key</i>,iterations=<i>iterations</i>
 * </pre>
 *
 */
// SECURITY: SEC-SCRAM-018 (MEDIUM) Credential serialization/deserialization for SCRAM credential persistence.
// Why: This utility serializes ScramCredential (salt, storedKey, serverKey, iterations) to a
// comma-delimited string format for storage in ZooKeeper or KRaft metadata records. The
// serialized format contains security-sensitive derived cryptographic material.
// Exploit: If credential data is not properly validated during deserialization, crafted
// credential records could cause authentication bypass (e.g., zero-length storedKey causing
// MessageDigest.isEqual() to trivially pass) or denial of service (e.g., extremely large
// iteration count causing CPU exhaustion during PBKDF2, or negative iteration count causing
// arithmetic errors). A malicious admin with ZooKeeper write access could inject crafted
// credential records to compromise any user's authentication.
// Improvement: (1) Validate all deserialized fields: non-null, non-empty byte arrays,
// positive iteration count within mechanism bounds (4096-16384), correct key lengths for
// the hash algorithm. (2) Add HMAC integrity protection to serialized credential format.
//
// DECISION: Properties-based serialization with Base64 encoding for byte arrays.
// Format: "salt=<base64>,stored_key=<base64>,server_key=<base64>,iterations=<int>"
// Alternatives: (1) JSON with Jackson, (2) Protobuf binary format, (3) Custom binary encoding.
// Rationale: (1) Properties format is human-readable for debugging ZooKeeper/metadata content.
// (2) Compatible with ZooKeeper's string-based storage without additional serialization libraries.
// (3) No external dependency needed -- uses only java.util.Properties and java.util.Base64.
// Risk: The comma-delimited format is fragile -- if Base64 values ever contain commas (they don't
// in standard Base64), parsing would break. The format is stable and must not change without
// a migration path, as it is used for persisted credentials.
//
// CROSS-CUTTING: Used by the metadata layer for credential persistence and by broker startup
// for credential loading:
// - metadata/ScramCredentialData uses this for credential-to-record conversion
// - Broker credential initialization calls createCache() to set up per-mechanism caches
// - tools/ CLI (kafka-storage, kafka-configs) uses this for credential string formatting
// Depends on: ScramMechanism for mechanism name enumeration, CredentialCache for cache creation,
// ScramCredential for the credential data model.
// Contract: Serialization format MUST remain stable across Kafka versions for backward
// compatibility with persisted credentials in ZooKeeper and KRaft metadata logs.
// Impact: Changing the serialized format breaks credential restore on broker restart.
public final class ScramCredentialUtils {
    private static final String SALT = "salt";
    private static final String STORED_KEY = "stored_key";
    private static final String SERVER_KEY = "server_key";
    private static final String ITERATIONS = "iterations";

    private ScramCredentialUtils() {}

    // SECURITY: SEC-SCRAM-019 (HIGH) Serializes raw credential bytes as Base64. The output string contains storedKey
    // Why: SCRAM credentials contain derived key material that
    // enables offline attacks if exposed.
    // and serverKey which are security-sensitive -- serverKey enables server impersonation.
    // This string should be stored in access-controlled storage (ZooKeeper ACLs or KRaft metadata).
    // Exploit: External mutation of the returned byte[] reference could
    // corrupt the stored credential, causing authentication failures.
    // Improvement: Encrypt SCRAM credential bytes during storage and
    // add integrity verification on deserialization.
    public static String credentialToString(ScramCredential credential) {
        return String.format("%s=%s,%s=%s,%s=%s,%s=%d",
               SALT,
               Base64.getEncoder().encodeToString(credential.salt()),
               STORED_KEY,
               Base64.getEncoder().encodeToString(credential.storedKey()),
               SERVER_KEY,
               Base64.getEncoder().encodeToString(credential.serverKey()),
               ITERATIONS,
               credential.iterations());
    }

    // SECURITY: SEC-SCRAM-020 (MEDIUM) Deserialization performs
    // size check (exactly 4 properties) and key presence check,
    // Why: SCRAM credentials contain derived key material that
    // enables offline attacks if exposed.
    // but does NOT validate: (1) byte array lengths (salt, storedKey, serverKey could be empty),
    // (2) iteration count bounds (could be 0, negative, or extremely large), (3) Base64 validity
    // (invalid Base64 throws IllegalArgumentException from Base64.getDecoder().decode()).
    // Exploit: External mutation of the returned byte[] reference could
    // corrupt the stored credential, causing authentication failures.
    // Improvement: Return Arrays.copyOf() for salt, storedKey, and
    // serverKey accessors to prevent external credential mutation.
    public static ScramCredential credentialFromString(String str) {
        Properties props = toProps(str);
        if (props.size() != 4 || !props.containsKey(SALT) || !props.containsKey(STORED_KEY) ||
                !props.containsKey(SERVER_KEY) || !props.containsKey(ITERATIONS)) {
            throw new IllegalArgumentException("Credentials not valid: " + str);
        }
        byte[] salt = Base64.getDecoder().decode(props.getProperty(SALT));
        byte[] storedKey = Base64.getDecoder().decode(props.getProperty(STORED_KEY));
        byte[] serverKey = Base64.getDecoder().decode(props.getProperty(SERVER_KEY));
        int iterations = Integer.parseInt(props.getProperty(ITERATIONS));
        return new ScramCredential(salt, storedKey, serverKey, iterations);
    }

    // DECISION: Custom comma-split parser rather than Properties.load() because the format uses
    // commas as delimiters (not newlines). Properties.load() expects newline-separated entries.
    private static Properties toProps(String str) {
        Properties props = new Properties();
        String[] tokens = str.split(",");
        for (String token : tokens) {
            int index = token.indexOf('=');
            if (index <= 0)
                throw new IllegalArgumentException("Credentials not valid: " + str);
            props.put(token.substring(0, index), token.substring(index + 1));
        }
        return props;
    }

    public static void createCache(CredentialCache cache, Collection<String> mechanisms) {
        for (String mechanism : ScramMechanism.mechanismNames()) {
            if (mechanisms.contains(mechanism))
                cache.createCache(mechanism, ScramCredential.class);
        }
    }
}
