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

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/*
 * This code is duplicated in org.apache.kafka.clients.admin.ScramMechanism.
 * The type field in both files must match and must not change. The type field
 * is used both for passing ScramCredentialUpsertion and for the internal 
 * UserScramCredentialRecord. Do not change the type field.
 */
// SECURITY: (MEDIUM) SCRAM mechanism variant definitions -- SHA-256 and SHA-512.
// Why: Defines the cryptographic algorithm parameters and iteration count bounds for all SCRAM
// authentication in Kafka. The minimum iteration count (4096) directly controls brute-force
// resistance of SCRAM credentials.
// Exploit: If only SCRAM-SHA-256 is offered and a future cryptanalytic breakthrough weakens
// SHA-256, the mechanism becomes vulnerable to offline credential attacks. Additionally,
// if the minIterations bound (4096) is reduced through code modification, existing credentials
// would lose their brute-force resistance. An attacker who compromises the config to lower
// max.iterations could create credentials with weak key derivation.
// Improvement: (1) Default to SCRAM-SHA-512 when both variants are available for higher
// security margin. (2) Consider increasing minIterations to 8192 or higher to reflect modern
// GPU capabilities. (3) Add a mechanism version field to support future algorithm agility.
//
// DECISION: Enum-based mechanism definition with associated crypto algorithm names and
// iteration bounds, supporting both SHA-256 and SHA-512 for algorithm agility per RFC 7677.
// Alternatives: (1) Configuration-driven mechanism list, (2) Plugin-based mechanism registry.
// Rationale: Enum provides compile-time type safety and exhaustive switch coverage. The fixed
// set of mechanisms matches the Kafka protocol specification -- adding new mechanisms requires
// a KIP and protocol version bump.
// Risk: Enum values cannot be extended without code changes, unlike a plugin-based approach.
//
// CROSS-CUTTING: Foundational enum referenced by nearly all SCRAM-related classes:
// - ScramSaslServer, ScramSaslClient: Algorithm selection and iteration validation
// - ScramFormatter: Hash and MAC algorithm names for JCA initialization
// - ScramSaslClientProvider, ScramSaslServerProvider: Mechanism name iteration for registration
// - ScramCredentialUtils: Mechanism name enumeration for cache creation
// - ScramServerCallbackHandler: Mechanism-specific credential lookup
// - External: admin/ScramMechanism duplicates type codes for public API
// - External: broker configuration (BrokerSecurityConfigs.SASL_ENABLED_MECHANISMS_CONFIG)
// Contract: Type byte codes and mechanismName values MUST remain stable across Kafka versions.
// Impact: Changing type codes breaks persisted UserScramCredentialRecord in KRaft metadata.
// Impact: Changing mechanism names breaks JAAS configuration and SASL negotiation.
public enum ScramMechanism {

    // SECURITY: (MEDIUM) SHA-256 variant -- 256-bit hash output. Currently secure against known cryptanalysis.
    // min=4096, max=16384 iterations. Type byte 1 -- persisted in metadata records, must not change.
    // DECISION: Iteration bounds [4096, 16384]. The minimum (4096) follows RFC 5802 Section 5.1.
    // The maximum (16384) balances security with authentication latency -- at 16384 iterations,
    // PBKDF2 with SHA-256 takes ~20ms on modern hardware per authentication attempt.
    // Exploit: An attacker could brute-force weak passwords if the iteration count is set below the recommended
    // minimum.
    // Improvement: Enforce a minimum iteration count floor and consider periodic increases as hardware improves.
    SCRAM_SHA_256((byte) 1, "SHA-256", "HmacSHA256", 4096, 16384),
    // SECURITY: (MEDIUM) SHA-512 variant -- 512-bit hash output. Higher security margin than SHA-256.
    // min=4096, max=16384 iterations. Type byte 2 -- persisted in metadata records, must not change.
    // SHA-512 has slightly higher computational cost but provides stronger collision resistance.
    // Exploit: A weakness in the hash algorithm could enable preimage or collision attacks.
    // Improvement: Monitor NIST guidance on hash algorithm deprecation and plan migration paths.
    SCRAM_SHA_512((byte) 2, "SHA-512", "HmacSHA512", 4096, 16384);

    // DECISION: Byte type codes (1=SHA-256, 2=SHA-512) are duplicated in admin/ScramMechanism
    // (as noted in the comment block above). These codes are used in UserScramCredentialRecord
    // and ScramCredentialUpsertion API messages. The duplication exists because admin/ is a
    // public API package while this is an internal implementation class -- merging would expose
    // internal details in the public API surface.
    private final byte type;
    private final String mechanismName;
    private final String hashAlgorithm;
    private final String macAlgorithm;
    // SECURITY: (HIGH) Minimum iteration count for PBKDF2 key derivation. Set to 4096 per RFC 5802
    // Section 5.1. Enforced in ScramSaslServer.evaluateResponse() and ScramSaslClient.evaluateChallenge().
    // Lowering this value would reduce brute-force resistance of all SCRAM credentials.
    // Exploit: An attacker could brute-force weak passwords if the iteration count is set below the recommended
    // minimum.
    // Improvement: Enforce a minimum iteration count floor and consider periodic increases as hardware improves.
    private final int minIterations;
    private final int maxIterations;

    // DECISION: Unmodifiable map for mechanism name lookups, built once at class load.
    // Using Collections.unmodifiableMap() instead of Map.of() for compatibility and explicit
    // immutability signaling. The map is keyed by mechanism name (e.g., "SCRAM-SHA-256").
    private static final Map<String, ScramMechanism> MECHANISMS_MAP;

    static {
        Map<String, ScramMechanism> map = new HashMap<>();
        for (ScramMechanism mech : values())
            map.put(mech.mechanismName, mech);
        MECHANISMS_MAP = Collections.unmodifiableMap(map);
    }

    ScramMechanism(
        byte type,
        String hashAlgorithm,
        String macAlgorithm,
        int minIterations,
        int maxIterations
    ) {
        this.type = type;
        this.mechanismName = "SCRAM-" + hashAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.macAlgorithm = macAlgorithm;
        this.minIterations = minIterations;
        this.maxIterations = maxIterations;
    }

    public final String mechanismName() {
        return mechanismName;
    }

    public String hashAlgorithm() {
        return hashAlgorithm;
    }

    public String macAlgorithm() {
        return macAlgorithm;
    }

    public int minIterations() {
        return minIterations;
    }

    public int maxIterations() {
        return maxIterations;
    }

    public static ScramMechanism forMechanismName(String mechanismName) {
        return MECHANISMS_MAP.get(mechanismName);
    }

    public static Collection<String> mechanismNames() {
        return MECHANISMS_MAP.keySet();
    }

    public static boolean isScram(String mechanismName) {
        return MECHANISMS_MAP.containsKey(mechanismName);
    }

    /**
     *
     * @return the type indicator for this SASL SCRAM mechanism
     */
    public byte type() {
        return this.type;
    }
}
