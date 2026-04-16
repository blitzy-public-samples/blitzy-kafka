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
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerSaslClient.OAuthBearerSaslClientFactory;

import java.security.Provider;
import java.security.Security;

// SECURITY: (LOW) Global JVM-wide SASL provider registration for OAUTHBEARER client factory.
// Why: Security.addProvider() modifies the JVM-global security provider list. Once registered,
// the OAUTHBEARER mechanism is available to ALL SASL contexts in the JVM.
// Exploit: In a shared JVM environment (e.g., application server hosting multiple Kafka clients),
// a malicious application could register a replacement OAUTHBEARER provider BEFORE this one,
// intercepting SASL authentication and capturing bearer tokens.
// Improvement: Use Security.insertProviderAt(provider, 1) to register at a specific position,
// or check for pre-existing OAUTHBEARER providers before registration.
//
// CROSS-CUTTING: Registered by OAuthBearerLoginModule's static initializer (lines 269-272
// of OAuthBearerLoginModule.java). Provides OAuthBearerSaslClientFactory to the JVM's
// SASL framework, enabling javax.security.sasl.Sasl.createSaslClient() to discover and
// create OAuthBearerSaslClient instances. Depends on OAuthBearerSaslClient.OAuthBearerSaslClientFactory.
// Impact: Must be registered before any OAUTHBEARER client authentication attempt.
public final class OAuthBearerSaslClientProvider extends Provider {
    private static final long serialVersionUID = 1L;

    // DECISION: Uses java.security.Provider API for SASL factory registration rather than
    // META-INF/services ServiceLoader. Alternative: ServiceLoader-based SPI discovery.
    // Rationale: The SASL specification (JSR 28) requires providers to be registered via
    // Security.addProvider(). ServiceLoader is not supported by javax.security.sasl.Sasl.
    // The provider maps "SaslClientFactory.OAUTHBEARER" to OAuthBearerSaslClientFactory class.
    private OAuthBearerSaslClientProvider() {
        super("SASL/OAUTHBEARER Client Provider", "1.0", "SASL/OAUTHBEARER Client Provider for Kafka");
        put("SaslClientFactory." + OAuthBearerLoginModule.OAUTHBEARER_MECHANISM,
                OAuthBearerSaslClientFactory.class.getName());
    }

    // SECURITY: (LOW) No idempotency check — calling initialize() multiple times adds duplicate
    // providers. While harmless (SASL framework uses the first match), it wastes memory and
    // could confuse provider enumeration tools.
    // Exploit: An attacker could exhaust server resources by sending oversized or excessive requests.
    // Improvement: Enforce strict per-connection resource limits and implement connection rate limiting.
    public static void initialize() {
        Security.addProvider(new OAuthBearerSaslClientProvider());
    }
}
