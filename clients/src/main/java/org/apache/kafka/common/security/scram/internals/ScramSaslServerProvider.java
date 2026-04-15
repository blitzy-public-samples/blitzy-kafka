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

import org.apache.kafka.common.security.scram.internals.ScramSaslServer.ScramSaslServerFactory;

import java.security.Provider;
import java.security.Security;

// SECURITY: (LOW) JCA security provider registration for server-side SCRAM SASL mechanisms.
// Why: Registers SaslServerFactory entries for SCRAM-SHA-256 and SCRAM-SHA-512 into the
// global JVM security provider list via Security.addProvider(). Same security considerations
// as ScramSaslClientProvider apply — provider registration is global JVM state.
// Exploit: A malicious provider registered with the same "SaslServerFactory.SCRAM-SHA-256"
// key before this provider would intercept all server-side SCRAM authentication, potentially
// accepting invalid client proofs or leaking server credentials.
// Improvement: Same as ScramSaslClientProvider — check for conflicting providers before
// registration and use Security.insertProviderAt() for explicit precedence control.

// CROSS-CUTTING: Called by ScramLoginModule static initializer (scram/ScramLoginModule.java).
// Registers ScramSaslServer.ScramSaslServerFactory for all ScramMechanism variants.
// Consumed by Java SASL framework during Sasl.createSaslServer() in
// authenticator/SaslServerAuthenticator. Must be registered before any SASL negotiation begins.
// Impact: If initialize() is not called, SCRAM-SHA-256/512 server mechanisms are unavailable,
// and brokers will reject SCRAM authentication requests from clients.
public final class ScramSaslServerProvider extends Provider {

    private static final long serialVersionUID = 1L;

    // DECISION: Mirrors ScramSaslClientProvider structure for server-side registration.
    // Registers ScramSaslServer.ScramSaslServerFactory for each ScramMechanism variant.
    // Private constructor enforces singleton-via-initialize() pattern.
    private ScramSaslServerProvider() {
        super("SASL/SCRAM Server Provider", "1.0", "SASL/SCRAM Server Provider for Kafka");
        for (ScramMechanism mechanism : ScramMechanism.values())
            put("SaslServerFactory." + mechanism.mechanismName(), ScramSaslServerFactory.class.getName());
    }

    // DECISION: Static initialize() called from ScramLoginModule class initializer alongside
    // ScramSaslClientProvider.initialize(). Both client and server providers are registered
    // simultaneously on class load, regardless of whether the JVM is acting as client or server.
    // Rationale: Kafka brokers act as both SASL clients (inter-broker) and servers (client-facing).
    public static void initialize() {
        Security.addProvider(new ScramSaslServerProvider());
    }
}
