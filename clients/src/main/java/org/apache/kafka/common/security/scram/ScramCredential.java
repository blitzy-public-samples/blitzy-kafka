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
package org.apache.kafka.common.security.scram;

/**
 * SCRAM credential class that encapsulates the credential data persisted for each user that is
 * accessible to the server. See <a href="https://tools.ietf.org/html/rfc5802#section-5">RFC rfc5802</a>
 * for details.
 */
// SECURITY: (MEDIUM) Immutable data carrier for server-side SCRAM credential parameters.
// Why: This class holds the derived SCRAM credential components (salt, storedKey, serverKey,
// iterations) that are persisted on the server. The original password is NOT stored -- only
// derived values per RFC 5802. However, these derived values are security-sensitive:
//   - serverKey: Enables computation of ServerSignature, allowing server impersonation
//   - storedKey: H(ClientKey) -- recovering ClientKey requires hash inversion (computationally hard)
//   - salt: Public parameter, but combined with low iteration count enables offline brute-force
// Exploit: If an attacker obtains the serialized credential (e.g., from ZooKeeper/KRaft metadata
// or a heap dump), they can mount an offline dictionary attack. With the salt and iteration count,
// they compute SaltedPassword = PBKDF2(password, salt, iterations) for candidate passwords and
// compare derived StoredKey against the stored value. At 4096 iterations (minimum per RFC 5802),
// a single GPU can test ~100K passwords/second with SHA-256.
// Improvement: (1) Increase default iteration count to 16384+ for stronger brute-force resistance.
// (2) Implement credential zeroization -- add a close()/destroy() method that zeros byte arrays
// after authentication completes. (3) Use constant-time comparison for serverKey/storedKey.
//
// DECISION: Immutable class with no equals()/hashCode()/toString() implementation.
// Alternatives: (1) Record type (Java 16+), (2) Class with defensive copies in accessors.
// Rationale: This is a simple data carrier for the authentication hot path. Omitting
// defensive copies in accessors avoids byte array allocation during every SCRAM exchange.
// No toString() prevents accidental credential logging. No equals()/hashCode() because
// credentials are not used as map keys or in collections requiring value equality.
//
// CROSS-CUTTING: Core credential type consumed across the SCRAM authentication stack:
// - scram/internals/ScramSaslServer: Verifies client proof against storedKey/serverKey
// - scram/internals/ScramFormatter: Creates credentials from password via PBKDF2
// - scram/internals/ScramCredentialUtils: Serializes/deserializes for persistence
// - scram/ScramCredentialCallback: Transfers credentials through JAAS callbacks
// - authenticator/CredentialCache: Stores credentials in-memory per mechanism
// - metadata/ScramCredentialData: Converts to/from KRaft metadata records
// Contract: Immutable after construction. Thread-safe for concurrent reads.
// Impact: Changing field types, constructor signature, or accessor semantics breaks
// all SCRAM authentication paths and credential persistence/migration.
public class ScramCredential {

    // SECURITY: (HIGH) Salt is a random value generated per-user by ScramFormatter.secureRandomBytes().
    // Must be at least 16 bytes (128 bits) per NIST SP 800-132 recommendations.
    // Exploit: Predictable nonce or salt values would allow precomputation attacks against the challenge-response.
    // Improvement: Verify SecureRandom is seeded from a strong entropy source on the deployment platform.
    private final byte[] salt;
    // SECURITY: (HIGH) ServerKey = HMAC(SaltedPassword, "Server Key"). Direct exposure enables
    // server impersonation -- an attacker with ServerKey can compute valid ServerSignatures.
    // Exploit: Stolen delegation tokens could be used for unauthorized access until expiry or revocation.
    // Improvement: Implement token usage auditing and consider shorter default token lifetimes.
    private final byte[] serverKey;
    // SECURITY: (HIGH) StoredKey = H(ClientKey) where ClientKey = HMAC(SaltedPassword, "Client Key").
    // Stored instead of ClientKey so the server cannot impersonate the client.
    // Exploit: Stolen delegation tokens could be used for unauthorized access until expiry or revocation.
    // Improvement: Implement token usage auditing and consider shorter default token lifetimes.
    private final byte[] storedKey;
    // SECURITY: (MEDIUM) Iteration count for PBKDF2 key derivation. Minimum 4096 per RFC 5802
    // Section 5.1. Lower values dramatically reduce brute-force resistance.
    // Exploit: An attacker could brute-force weak passwords if the iteration count is set below the recommended
    // minimum.
    // Improvement: Enforce a minimum iteration count floor and consider periodic increases as hardware improves.
    private final int iterations;

    /**
     * Constructs a new credential.
     */
    // DECISION: Constructor stores direct references to byte arrays (no defensive copies).
    // This is a conscious performance trade-off -- the caller (ScramFormatter) creates fresh
    // arrays for each credential, so aliasing is safe in practice. Documented contract:
    // callers MUST NOT modify arrays after passing them to this constructor.
    public ScramCredential(byte[] salt, byte[] storedKey, byte[] serverKey, int iterations) {
        this.salt = salt;
        this.serverKey = serverKey;
        this.storedKey = storedKey;
        this.iterations = iterations;
    }

    /**
     * Returns the salt used to process this credential using the SCRAM algorithm.
     */
    // SECURITY: (MEDIUM) Returns direct reference to internal byte array (no defensive copy).
    // Callers MUST NOT modify the returned array. A defensive copy would be safer but
    // was omitted for performance -- SCRAM authentication is on the hot path.
    // Exploit: A caller retaining a reference could modify credential bytes in-place, corrupting shared state.
    // Improvement: Return defensive copies of sensitive byte arrays via Arrays.copyOf().
    public byte[] salt() {
        return salt;
    }

    /**
     * Server key computed from the client password using the SCRAM algorithm.
     */
    // SECURITY: (MEDIUM) Returns direct reference to internal byte array (no defensive copy).
    // Callers MUST NOT modify the returned array. A defensive copy would be safer but
    // was omitted for performance -- SCRAM authentication is on the hot path.
    // Exploit: A caller retaining a reference could modify credential bytes in-place, corrupting shared state.
    // Improvement: Return defensive copies of sensitive byte arrays via Arrays.copyOf().
    public byte[] serverKey() {
        return serverKey;
    }

    /**
     * Stored key computed from the client password using the SCRAM algorithm.
     */
    // SECURITY: (MEDIUM) Returns direct reference to internal byte array (no defensive copy).
    // Callers MUST NOT modify the returned array. A defensive copy would be safer but
    // was omitted for performance -- SCRAM authentication is on the hot path.
    // Exploit: A caller retaining a reference could modify credential bytes in-place, corrupting shared state.
    // Improvement: Return defensive copies of sensitive byte arrays via Arrays.copyOf().
    public byte[] storedKey() {
        return storedKey;
    }

    /**
     * Number of iterations used to process this credential using the SCRAM algorithm.
     */
    public int iterations() {
        return iterations;
    }
}