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

import java.io.Closeable;
import java.security.KeyStore;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLEngine;

/**
 * Plugin interface for allowing creation of <code>SSLEngine</code> object in a custom way.
 * For example, you can use this to customize loading your key material and trust material needed for <code>SSLContext</code>.
 * This is complementary to the existing Java Security Provider mechanism which allows the entire provider
 * to be replaced with a custom provider. In scenarios where only the configuration mechanism for SSL engines
 * need to be updated, this interface provides a convenient method for overriding the default implementation.
 */
// SECURITY: SEC-AUTH-012 (MEDIUM) Plugin interface for SSL engine creation — custom implementations
// handle private keys and control cipher selection for ALL Kafka TLS connections.
// Why: Implementations have full control over SSLContext, KeyManager, and TrustManager
// configuration. A compromised or misconfigured factory can silently weaken TLS security.
// Exploit: A malicious SslEngineFactory implementation could: (1) disable certificate
// verification by using a TrustManager that accepts all certificates, (2) enable weak
// cipher suites (e.g., RC4, NULL ciphers), (3) downgrade TLS protocol version to
// TLSv1.0, or (4) leak private key material through the keystore() accessor.
// Improvement: Consider adding a post-creation verification step that validates the
// SSLEngine's enabled protocols and cipher suites against a minimum security baseline
// (e.g., TLSv1.2+, no NULL/RC4/DES ciphers) before the engine is used for connections.
//
// CROSS-CUTTING: Implemented by ssl/DefaultSslEngineFactory (default) and
// ssl/CommonNameLoggingSslEngineFactory (CN logging wrapper). Consumed by
// ssl/SslFactory which manages dynamic SSL reconfiguration (certificate rotation).
// Extends Configurable (receives ssl.* config properties) and Closeable (resource cleanup).
// Contract: configure() is called once with SSL configs. shouldBeRebuilt() is called on
// config changes to determine if a new factory instance is needed. keystore()/truststore()
// expose key material for validation during reconfiguration — handle with care.
public interface SslEngineFactory extends Configurable, Closeable {

    /**
     * Creates a new <code>SSLEngine</code> object to be used by the client.
     *
     * @param peerHost               The peer host to use. This is used in client mode if endpoint validation is enabled.
     * @param peerPort               The peer port to use. This is a hint and not used for validation.
     * @param endpointIdentification Endpoint identification algorithm for client mode.
     * @return The new <code>SSLEngine</code>.
     */
    SSLEngine createClientSslEngine(String peerHost, int peerPort, String endpointIdentification);

    /**
     * Creates a new <code>SSLEngine</code> object to be used by the server.
     *
     * @param peerHost               The peer host to use. This is a hint and not used for validation.
     * @param peerPort               The peer port to use. This is a hint and not used for validation.
     * @return The new <code>SSLEngine</code>.
     */
    SSLEngine createServerSslEngine(String peerHost, int peerPort);

    // DECISION: shouldBeRebuilt() enables lazy SSL reconfiguration — the factory decides
    // whether new configs require rebuilding rather than always rebuilding on any change.
    // Alternative: Always rebuild on config change. Rationale: SSL engine creation is expensive
    // (involves KeyStore loading, SSLContext initialization); lazy rebuild avoids unnecessary
    // overhead when only non-SSL configs change. This supports the dynamic certificate rotation
    // use case (KIP-226) where only keystore/truststore changes trigger rebuilds.
    /**
     * Returns true if <code>SSLEngine</code> needs to be rebuilt. This method will be called when reconfiguration is triggered on
     * the <code>SslFactory</code> used to create SSL engines. Based on the new configs provided in <i>nextConfigs</i>, this method
     * will decide whether underlying <code>SSLEngine</code> object needs to be rebuilt. If this method returns true, the
     * <code>SslFactory</code> will create a new instance of this object with <i>nextConfigs</i> and run other
     * checks before deciding to use the new object for <i>new incoming connection</i> requests. Existing connections
     * are not impacted by this and will not see any changes done as part of reconfiguration.
     * <p>
     * For example, if the implementation depends on file-based key material, it can check if the file was updated
     * compared to the previous/last-loaded timestamp and return true.
     * </p>
     *
     * @param nextConfigs       The new configuration we want to use.
     * @return                  True only if the underlying <code>SSLEngine</code> object should be rebuilt.
     */
    boolean shouldBeRebuilt(Map<String, Object> nextConfigs);

    /**
     * Returns the names of configs that may be reconfigured.
     * @return Names of configuration options that are dynamically reconfigurable.
     */
    Set<String> reconfigurableConfigs();

    // DECISION: Exposing keystore()/truststore() as part of the interface rather than keeping
    // them internal. Rationale: SslFactory uses these during reconfiguration to validate that
    // new key material is compatible with existing connections before switching.
    /**
     * Returns keystore configured for this factory.
     * @return The keystore for this factory or null if a keystore is not configured.
     */
    KeyStore keystore();

    /**
     * Returns truststore configured for this factory.
     * @return The truststore for this factory or null if a truststore is not configured.
     */
    KeyStore truststore();
}