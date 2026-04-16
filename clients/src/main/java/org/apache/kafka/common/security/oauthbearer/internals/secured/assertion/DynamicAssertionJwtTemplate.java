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

import org.apache.kafka.common.utils.Time;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * A "dynamic" {@link AssertionJwtTemplate} is that which will dynamically add the following values
 * at runtime:
 *
 * <ul>
 *     <li>{@code alg} (Algorithm) header</li>
 *     <li>{@code typ} (Type) header</li>
 *     <li>{@code iat} (Issued at) timestamp claim (in seconds)</li>
 *     <li>{@code exp} (Expiration) timestamp claim (in seconds)</li>
 *     <li>{@code nbf} (Not before) timestamp claim (in seconds)</li>
 *     <li>(Optionally) {@code jti} (JWT ID) claim</li>
 * </ul>
 */
// CROSS-CUTTING: Used in LayeredAssertionJwtTemplate composition as the highest-priority layer
// (added last by AssertionUtils.layeredAssertionJwtTemplate()). Dynamic claims (iat, exp, jti)
// override any same-named claims from static or file-based templates.
// Depends on: Time (clock abstraction from org.apache.kafka.common.utils — enables test injection).
// Created by AssertionUtils.dynamicAssertionJwtTemplate() using config values for algorithm,
// expSeconds, nbfSeconds, and includeJti from SaslConfigs.
// Impact: Changes to time computation or claim names affect all jwt-bearer assertion flows.
public class DynamicAssertionJwtTemplate implements AssertionJwtTemplate {

    private final Time time;
    private final String algorithm;
    private final int expSeconds;
    private final int nbfSeconds;
    private final boolean includeJti;

    public DynamicAssertionJwtTemplate(Time time,
                                       String algorithm,
                                       int expSeconds,
                                       int nbfSeconds,
                                       boolean includeJti) {
        this.time = time;
        this.algorithm = algorithm;
        this.expSeconds = expSeconds;
        this.nbfSeconds = nbfSeconds;
        this.includeJti = includeJti;
    }

    // DECISION: Header always includes alg and typ:"JWT" per RFC 7519 Section 5. No kid (key ID)
    // is added here — kid is not required for single-key scenarios. Alternative: Include kid from
    // config. Rationale: kid is identity-provider-specific; when needed, it can be supplied via
    // StaticAssertionJwtTemplate or FileAssertionJwtTemplate and merged in LayeredAssertionJwtTemplate.
    @Override
    public Map<String, Object> header() {
        // DECISION: Allocates fresh HashMap on every header()/payload() call. Alternative: Cache results.
        // Rationale: payload() includes time-sensitive claims (iat, exp) that must reflect current time.
        // Returns Collections.unmodifiableMap() to prevent caller mutation. Thread-safe for concurrent
        // access since no shared mutable state is read or written.
        Map<String, Object> values = new HashMap<>();
        values.put("alg", algorithm);
        values.put("typ", "JWT");
        return Collections.unmodifiableMap(values);
    }

    @Override
    public Map<String, Object> payload() {
        // DECISION: Time-based claims (iat/exp/nbf) calculated from Time abstraction rather than
        // System.currentTimeMillis(). Alternative: Direct system clock. Rationale: Time abstraction
        // enables deterministic testing — test code can inject MockTime to verify expiry calculations
        // without real clock delays. Production code uses SystemTime which delegates to system clock.

        // SECURITY: (MEDIUM) Time-based claims (iat, exp, nbf) use seconds precision. Clock skew between
        // the Kafka client and the OAuth provider can cause premature expiry or delayed activation.
        // The nbf (not before) is set to currentTime - nbfSeconds to account for clock skew backward.
        // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
        // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
        long currentTimeSecs = time.milliseconds() / 1000L;

        Map<String, Object> values = new HashMap<>();
        values.put("iat", currentTimeSecs);
        values.put("exp", currentTimeSecs + expSeconds);
        values.put("nbf", currentTimeSecs - nbfSeconds);

        // SECURITY: (HIGH) jti (JWT ID) claim generated using UUID.randomUUID() for replay prevention.
        // Why: The jti claim provides a unique identifier per assertion to prevent replay attacks at the
        // token endpoint. Each assertion should have a unique jti so the provider can reject duplicates.
        // Exploit: If UUID generation is predictable (e.g., using a weak PRNG), an attacker could predict
        // future jti values and pre-generate assertions. Java's UUID.randomUUID() uses SecureRandom
        // internally (cryptographically strong), but this is JVM-implementation-dependent.
        // Improvement: Consider explicit SecureRandom-based generation for defense in depth, or verify
        // the JVM implementation uses a cryptographic PRNG for UUID v4 generation.
        if (includeJti)
            values.put("jti", UUID.randomUUID().toString());

        return Collections.unmodifiableMap(values);
    }
}
