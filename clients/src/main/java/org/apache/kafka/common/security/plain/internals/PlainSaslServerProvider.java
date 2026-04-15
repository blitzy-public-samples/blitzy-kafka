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
package org.apache.kafka.common.security.plain.internals;

import org.apache.kafka.common.security.plain.internals.PlainSaslServer.PlainSaslServerFactory;

import java.security.Provider;
import java.security.Security;

// SECURITY: (LOW) Registers PLAIN SASL mechanism with JCA Security framework.
// Why: This provider enables discovery of PlainSaslServerFactory via java.security.Security.
// Once registered, any code in the JVM can create a PLAIN SaslServer.
// Exploit: A malicious library in the same JVM could invoke Security.removeProvider() to
// deregister PLAIN, causing authentication failures (DoS). Alternatively, it could register
// a rogue provider with higher priority to intercept PLAIN auth.
// Improvement: Consider checking if the provider is already registered before adding
// (idempotency) and logging a warning if another PLAIN provider exists with different priority.
//
// CROSS-CUTTING: Called by plain/PlainLoginModule static initializer (class-load time).
// Depends on PlainSaslServer.PlainSaslServerFactory (registered as SaslServerFactory impl).
// Contract: initialize() must be called before any PLAIN SASL authentication attempt.
// Impact: If not initialized, Sasl.createSaslServer("PLAIN", ...) returns null, causing
// NullPointerException in authenticator/SaslServerAuthenticator.
public final class PlainSaslServerProvider extends Provider {

    private static final long serialVersionUID = 1L;

    // DECISION: Uses JCA Provider registration pattern for SASL mechanism discovery.
    // Alternatives: (1) Direct factory instantiation without JCA, (2) ServiceLoader-based discovery.
    // Rationale: JCA Provider is the standard Java mechanism for pluggable security services.
    // Allows the SaslServer factory to be discovered via Sasl.createSaslServer() without direct
    // class coupling.
    private PlainSaslServerProvider() {
        super("Simple SASL/PLAIN Server Provider", "1.0", "Simple SASL/PLAIN Server Provider for Kafka");
        put("SaslServerFactory." + PlainSaslServer.PLAIN_MECHANISM, PlainSaslServerFactory.class.getName());
    }

    public static void initialize() {
        Security.addProvider(new PlainSaslServerProvider());
    }
}
