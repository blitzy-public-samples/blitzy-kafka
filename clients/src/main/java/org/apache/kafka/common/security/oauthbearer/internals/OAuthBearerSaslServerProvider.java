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
package org.apache.kafka.common.security.oauthbearer.internals;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerSaslServer.OAuthBearerSaslServerFactory;

import java.security.Provider;
import java.security.Security;

// SECURITY: (LOW) Global JVM-wide SASL provider registration for OAUTHBEARER server factory.
// Why: Security.addProvider() registers the OAUTHBEARER SaslServerFactory globally in the JVM's
// security provider list. Once registered, any SASL server context can use OAUTHBEARER.
// Exploit: In a shared JVM environment, a malicious component could register a replacement
// OAUTHBEARER server provider that accepts ALL tokens without validation, effectively
// disabling authentication for all Kafka brokers in the same JVM.
// Improvement: Verify no pre-existing OAUTHBEARER server provider is registered before
// adding this one. Log a WARNING if a duplicate provider is detected.

// CROSS-CUTTING: Registered by OAuthBearerLoginModule's static initializer alongside
// OAuthBearerSaslClientProvider. Provides OAuthBearerSaslServerFactory to the JVM's
// SASL framework, enabling javax.security.sasl.Sasl.createSaslServer() to discover and
// create OAuthBearerSaslServer instances on the broker side.
// Depends on: OAuthBearerSaslServer.OAuthBearerSaslServerFactory.
// Impact: Must be registered before any broker-side OAUTHBEARER authentication.
public final class OAuthBearerSaslServerProvider extends Provider {
    private static final long serialVersionUID = 1L;

    // DECISION: Mirrors OAuthBearerSaslClientProvider's registration pattern for the server side.
    // Maps "SaslServerFactory.OAUTHBEARER" to OAuthBearerSaslServerFactory class name.
    // Same rationale as client provider — SASL specification requires Provider-based registration.
    private OAuthBearerSaslServerProvider() {
        super("SASL/OAUTHBEARER Server Provider", "1.0", "SASL/OAUTHBEARER Server Provider for Kafka");
        put("SaslServerFactory." + OAuthBearerLoginModule.OAUTHBEARER_MECHANISM,
                OAuthBearerSaslServerFactory.class.getName());
    }

    // SECURITY: (LOW) Same idempotency concern as OAuthBearerSaslClientProvider — multiple
    // calls add duplicate providers. The SASL framework uses the first matching provider.
    public static void initialize() {
        Security.addProvider(new OAuthBearerSaslServerProvider());
    }
}
