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

import org.apache.kafka.common.security.scram.internals.ScramSaslClient.ScramSaslClientFactory;

import java.security.Provider;
import java.security.Security;

// SECURITY: (LOW) JCA security provider registration for client-side SCRAM SASL mechanisms.
// Why: Provider registration is global JVM state via java.security.Security.addProvider().
// This registers SaslClientFactory entries for SCRAM-SHA-256 and SCRAM-SHA-512 mechanisms.
// Exploit: A malicious provider registered earlier with the same mechanism name
// ("SaslClientFactory.SCRAM-SHA-256") would take precedence over this provider, intercepting
// all SCRAM client authentication. The attacker's factory could return a SaslClient that
// leaks credentials or accepts any server challenge, enabling MITM attacks.
// Improvement: (1) Check for existing providers with conflicting mechanism names before
// registration. (2) Use Security.insertProviderAt() with a specific position instead of
// addProvider() to control precedence. (3) Log the registered provider list for audit.

// CROSS-CUTTING: Called by ScramLoginModule static initializer (scram/ScramLoginModule.java).
// Registers ScramSaslClient.ScramSaslClientFactory for all ScramMechanism variants.
// Consumed by Java SASL framework during Sasl.createSaslClient() in
// authenticator/SaslClientAuthenticator. Must be registered before any SASL negotiation begins.
// Impact: If initialize() is not called, SCRAM-SHA-256/512 client mechanisms are unavailable.
public final class ScramSaslClientProvider extends Provider {

    private static final long serialVersionUID = 1L;

    // DECISION: Private constructor -- provider instantiation only via static initialize() method.
    // Provider info string "SASL/SCRAM Client Provider" version "1.0" is fixed and not versioned
    // with Kafka releases. Registration iterates over all ScramMechanism enum values to register
    // SaslClientFactory entries for each supported mechanism.
    private ScramSaslClientProvider() {
        super("SASL/SCRAM Client Provider", "1.0", "SASL/SCRAM Client Provider for Kafka");
        for (ScramMechanism mechanism : ScramMechanism.values())
            put("SaslClientFactory." + mechanism.mechanismName(), ScramSaslClientFactory.class.getName());
    }

    // DECISION: Static initialize() called from ScramLoginModule class initializer (static block).
    // Uses Security.addProvider() rather than insertProviderAt() -- appends to provider list.
    // Rationale: Append order is sufficient for SCRAM mechanisms which are Kafka-specific and
    // unlikely to conflict with other JCA providers. Multiple calls are idempotent -- addProvider()
    // ignores duplicate provider names.
    public static void initialize() {
        Security.addProvider(new ScramSaslClientProvider());
    }
}
