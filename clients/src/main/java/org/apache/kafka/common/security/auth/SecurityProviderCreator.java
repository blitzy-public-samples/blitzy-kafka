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
package org.apache.kafka.common.security.auth;

import org.apache.kafka.common.Configurable;

import java.security.Provider;
import java.util.Map;

/**
 * An interface for generating security providers.
 */
// SECURITY: SEC-AUTH-010 (LOW) Plugin interface for registering custom JCA security providers.
// Why: Implementations are loaded via reflection from SecurityConfig and registered
// with java.security.Security.addProvider(). A malicious or misconfigured provider
// could replace standard cryptographic algorithms (e.g., substitute a weak PRNG,
// install a backdoored TLS implementation, or override certificate validation).
// Exploit: An attacker who can modify the security.providers configuration could
// register a provider that returns compromised key material or weakens cipher suites.
// Improvement: Consider verifying that the returned Provider does not override
// security-critical algorithms already registered by the JVM's built-in providers.
public interface SecurityProviderCreator extends Configurable {

    // CROSS-CUTTING: Loaded via reflection by SecurityConfig (common/config package).
    // The returned Provider is registered globally via java.security.Security.addProvider(),
    // affecting ALL cryptographic operations in the JVM (SSL, SASL, signature verification).
    // Depends on: common/Configurable for lifecycle. Impact: Provider registration is
    // JVM-global; changes affect all Kafka clients/brokers in the same JVM process.

    // DECISION: Default no-op configure() method. Alternative: Make configure() abstract
    // to force implementors to handle configuration. Rationale: Most security providers
    // are self-contained and don't need Kafka-specific configuration; the default empty
    // implementation avoids unnecessary boilerplate in simple provider creators.
    /**
     * Configure method is used to configure the generator to create the Security Provider
     * @param config configuration parameters for initialising security provider
     */
    default void configure(Map<String, ?> config) {

    }

    /**
     * Generate the security provider configured
     */
    Provider getProvider();
}
