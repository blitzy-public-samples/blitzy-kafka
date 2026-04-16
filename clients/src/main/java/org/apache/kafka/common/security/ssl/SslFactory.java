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
package org.apache.kafka.common.security.ssl;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.Reconfigurable;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.config.internals.BrokerSecurityConfigs;
import org.apache.kafka.common.network.ConnectionMode;
import org.apache.kafka.common.security.auth.SslEngineFactory;
import org.apache.kafka.common.utils.ConfigUtils;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

// SECURITY: SEC-SSL-012 (HIGH) Dynamic certificate rotation with atomic swap window (KIP-226).
// Why: SslFactory supports runtime SSL reconfiguration — when certificates are
// rotated, a new SslEngineFactory is created and atomically swapped for the old
// one via reconfigure(). During the brief swap window, old and new factories coexist.
// Exploit: During the atomic swap window, a client presenting a certificate valid
// under the old CA but not the new CA could still authenticate if a connection was
// initiated just before the swap completes. The old SslEngineFactory reference
// remains in use for in-progress handshakes. Conversely, legitimate clients
// presenting new certs could be rejected if their handshake started before the
// swap but completed after.
// Improvement: Consider a dual-validation approach during rotation that accepts
// certificates valid under either old or new CA during a configurable transition
// period. Also consider adding a metric for connections using the old factory.

// DECISION: Implements Reconfigurable for hot-reload without broker restart.
// Alternative: Require broker restart for certificate rotation. Rationale: In
// production, certificate rotation is frequent (e.g., 90-day cert lifetimes) and
// requiring restarts would cause availability impact. The volatile reference swap
// pattern (reconfigure() replaces this.sslEngineFactory) provides thread-safe
// factory replacement.
public class SslFactory implements Reconfigurable, Closeable {
    // CROSS-CUTTING: Central SSL lifecycle manager consumed by
    // common/network/SslChannelBuilder for creating SSL channels on every new
    // connection. Also consumed by core/DynamicBrokerConfig for runtime
    // reconfiguration of SSL certificates. Depends on: auth/SslEngineFactory
    // (plugin interface), common/Reconfigurable (reconfiguration lifecycle),
    // common/config/SslConfigs (SSL configuration keys). The sslEngineFactory
    // field is read by SslChannelBuilder on every new connection — the
    // volatile-like semantics of the reconfigure() swap ensure visibility.

    private static final Logger log = LoggerFactory.getLogger(SslFactory.class);

    private final ConnectionMode connectionMode;
    private final String clientAuthConfigOverride;
    private final boolean keystoreVerifiableUsingTruststore;
    private String endpointIdentification;
    private SslEngineFactory sslEngineFactory;
    private Map<String, Object> sslEngineFactoryConfig;

    public SslFactory(ConnectionMode connectionMode) {
        this(connectionMode, null, false);
    }

    /**
     * Create an SslFactory.
     *
     * @param connectionMode                        Whether to use client or server mode.
     * @param clientAuthConfigOverride              The value to override ssl.client.auth with, or null
     *                                              if we don't want to override it.
     * @param keystoreVerifiableUsingTruststore     True if we should require the keystore to be verifiable
     *                                              using the truststore.
     */
    public SslFactory(ConnectionMode connectionMode,
                      String clientAuthConfigOverride,
                      boolean keystoreVerifiableUsingTruststore) {
        this.connectionMode = connectionMode;
        this.clientAuthConfigOverride = clientAuthConfigOverride;
        this.keystoreVerifiableUsingTruststore = keystoreVerifiableUsingTruststore;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void configure(Map<String, ?> configs) throws KafkaException {
        if (sslEngineFactory != null) {
            throw new IllegalStateException("SslFactory was already configured.");
        }
        this.endpointIdentification = (String) configs.get(SslConfigs.SSL_ENDPOINT_IDENTIFICATION_ALGORITHM_CONFIG);

        // The input map must be a mutable RecordingMap in production.
        Map<String, Object> nextConfigs = (Map<String, Object>) configs;
        if (clientAuthConfigOverride != null) {
            nextConfigs.put(BrokerSecurityConfigs.SSL_CLIENT_AUTH_CONFIG, clientAuthConfigOverride);
        }
        SslEngineFactory builder = instantiateSslEngineFactory(nextConfigs);
        if (keystoreVerifiableUsingTruststore) {
            try {
                SslEngineValidator.validate(builder, builder);
            } catch (Exception e) {
                throw new ConfigException("A client SSLEngine created with the provided settings " +
                        "can't connect to a server SSLEngine created with those settings.", e);
            }
        }
        this.sslEngineFactory = builder;
    }

    @Override
    public Set<String> reconfigurableConfigs() {
        return sslEngineFactory.reconfigurableConfigs();
    }

    @Override
    public void validateReconfiguration(Map<String, ?> newConfigs) throws ConfigException {
        try {
            createNewSslEngineFactory(newConfigs);
        } catch (IllegalStateException e) {
            throw new ConfigException("SSL reconfiguration failed due to " + e);
        }
    }

    // DECISION: Atomic swap of SslEngineFactory reference — new connections use
    // new factory, existing connections continue with the SSLEngine they already
    // created. Alternative: Close all existing connections and force reconnection.
    // Rationale: Closing existing connections would cause a brief outage during
    // rotation; the swap approach is zero-downtime. The old factory is closed only
    // after the swap (Utils.closeQuietly).
    @Override
    public void reconfigure(Map<String, ?> newConfigs) throws KafkaException {
        SslEngineFactory newSslEngineFactory = createNewSslEngineFactory(newConfigs);
        if (newSslEngineFactory != this.sslEngineFactory) {
            Utils.closeQuietly(this.sslEngineFactory, "close stale ssl engine factory");
            this.sslEngineFactory = newSslEngineFactory;
            log.info("Created new {} SSL engine builder with keystore {} truststore {}", connectionMode,
                    newSslEngineFactory.keystore(), newSslEngineFactory.truststore());
        }
    }

    // SECURITY: SEC-SSL-013 (MEDIUM) Reflective instantiation of SslEngineFactory
    // Why: SSL factory controls certificate management and TLS
    // configuration that determines transport security.
    // implementations. The factory class is configured via
    // SSL_ENGINE_FACTORY_CLASS_CONFIG. If this config is writable by untrusted
    // users, a malicious class could be loaded that weakens TLS. The default
    // fallback to DefaultSslEngineFactory is safe; custom factories require trust.
    // Exploit: An attacker with config write access could specify a
    // malicious SslEngineFactory class that weakens TLS or logs key material.
    // Improvement: Validate configured cipher suites against a known-good
    // allowlist and reject deprecated or weak algorithms.
    private SslEngineFactory instantiateSslEngineFactory(Map<String, Object> configs) {
        @SuppressWarnings("unchecked")
        Class<? extends SslEngineFactory> sslEngineFactoryClass =
                (Class<? extends SslEngineFactory>) configs.get(SslConfigs.SSL_ENGINE_FACTORY_CLASS_CONFIG);
        SslEngineFactory sslEngineFactory;
        if (sslEngineFactoryClass == null) {
            sslEngineFactory = new DefaultSslEngineFactory();
        } else {
            sslEngineFactory = Utils.newInstance(sslEngineFactoryClass);
        }
        sslEngineFactory.configure(configs);
        this.sslEngineFactoryConfig = configs;
        return sslEngineFactory;
    }

    /* COMPLEXITY: 44 lines — Multi-phase SSL factory reconfiguration with
     * validation. Control flow:
     * 1. Check factory is initialized (throw IllegalStateException if not)
     * 2. Merge new configs with existing configs (only reconfigurable keys)
     * 3. Apply clientAuth override if configured
     * 4. Check if factory needs rebuilding (shouldBeRebuilt) — early return
     * 5. Instantiate new factory with merged configs
     * 6. Validate keystore presence invariants (can't add/remove keystore)
     * 7. Validate DN and SAN compatibility (unless explicitly allowed)
     * 8. Validate truststore presence invariants
     * 9. Optionally perform bidirectional handshake via SslEngineValidator
     * Exit paths: (1) not initialized → IllegalStateException, (2) no rebuild
     * needed → return current factory, (3) validation passes → return new
     * factory, (4) any validation failure → throw ConfigException
     */
    private SslEngineFactory createNewSslEngineFactory(Map<String, ?> newConfigs) {
        if (sslEngineFactory == null) {
            throw new IllegalStateException("SslFactory has not been configured.");
        }
        Map<String, Object> nextConfigs = new HashMap<>(sslEngineFactoryConfig);
        copyMapEntries(nextConfigs, newConfigs, reconfigurableConfigs());
        if (clientAuthConfigOverride != null) {
            nextConfigs.put(BrokerSecurityConfigs.SSL_CLIENT_AUTH_CONFIG, clientAuthConfigOverride);
        }
        if (!sslEngineFactory.shouldBeRebuilt(nextConfigs)) {
            return sslEngineFactory;
        }
        try {
            SslEngineFactory newSslEngineFactory = instantiateSslEngineFactory(nextConfigs);
            if (sslEngineFactory.keystore() == null) {
                if (newSslEngineFactory.keystore() != null) {
                    throw new ConfigException("Cannot add SSL keystore to an existing listener for " +
                            "which no keystore was configured.");
                }
            } else {
                if (newSslEngineFactory.keystore() == null) {
                    throw new ConfigException("Cannot remove the SSL keystore from an existing listener for " +
                            "which a keystore was configured.");
                }

                // SECURITY: SEC-SSL-014 (MEDIUM) Certificate compatibility validation during
                // Why: SSL factory controls certificate management and TLS
                // configuration that determines transport security.
                // reconfiguration. By default (ssl.allow.dn.changes=false,
                // ssl.allow.san.changes=false), the new certificate must have
                // the same DN and SANs as the old one. This prevents an
                // operator from accidentally (or maliciously) rotating to a
                // cert with a different identity, which could break
                // inter-broker authentication or change the broker's identity
                // in ACL checks.
                // Exploit: During certificate reconfiguration, the validation window
                // could be exploited to inject a cert with a different identity.
                // attacks.
                // Improvement: Validate configured cipher suites against a known-good
                // allowlist and reject deprecated or weak algorithms.
                boolean allowDnChanges = ConfigUtils.getBoolean(nextConfigs, BrokerSecurityConfigs.SSL_ALLOW_DN_CHANGES_CONFIG, BrokerSecurityConfigs.DEFAULT_SSL_ALLOW_DN_CHANGES_VALUE);
                boolean allowSanChanges = ConfigUtils.getBoolean(nextConfigs, BrokerSecurityConfigs.SSL_ALLOW_SAN_CHANGES_CONFIG, BrokerSecurityConfigs.DEFAULT_SSL_ALLOW_SAN_CHANGES_VALUE);

                CertificateEntries.ensureCompatible(newSslEngineFactory.keystore(), sslEngineFactory.keystore(), allowDnChanges, allowSanChanges);
            }
            if (sslEngineFactory.truststore() == null && newSslEngineFactory.truststore() != null) {
                throw new ConfigException("Cannot add SSL truststore to an existing listener for which no " +
                        "truststore was configured.");
            }
            if (keystoreVerifiableUsingTruststore) {
                if (sslEngineFactory.truststore() != null || sslEngineFactory.keystore() != null) {
                    SslEngineValidator.validate(sslEngineFactory, newSslEngineFactory);
                }
            }
            return newSslEngineFactory;
        } catch (Exception e) {
            log.debug("Validation of dynamic config update of SSLFactory failed.", e);
            throw new ConfigException("Validation of dynamic config update of SSLFactory failed: " + e);
        }
    }

    public SSLEngine createSslEngine(Socket socket) {
        return createSslEngine(peerHost(socket), socket.getPort());
    }

    /**
     * Prefer `createSslEngine(Socket)` if a `Socket` instance is available. If using this overload,
     * avoid reverse DNS resolution in the computation of `peerHost`.
     */
    public SSLEngine createSslEngine(String peerHost, int peerPort) {
        if (sslEngineFactory == null) {
            throw new IllegalStateException("SslFactory has not been configured.");
        }
        if (connectionMode == ConnectionMode.SERVER) {
            return sslEngineFactory.createServerSslEngine(peerHost, peerPort);
        } else {
            return sslEngineFactory.createClientSslEngine(peerHost, peerPort, endpointIdentification);
        }
    }

    /**
     * Returns host/IP address of remote host without reverse DNS lookup to be used as the host
     * for creating SSL engine. This is used as a hint for session reuse strategy and also for
     * hostname verification of server hostnames.
     * <p>
     * Scenarios:
     * <ul>
     *   <li>Server-side
     *   <ul>
     *     <li>Server accepts connection from a client. Server knows only client IP
     *     address. We want to avoid reverse DNS lookup of the client IP address since the server
     *     does not verify or use client hostname. The IP address can be used directly.</li>
     *   </ul>
     *   </li>
     *   <li>Client-side
     *   <ul>
     *     <li>Client connects to server using hostname. No lookup is necessary
     *     and the hostname should be used to create the SSL engine. This hostname is validated
     *     against the hostname in SubjectAltName (dns) or CommonName in the certificate if
     *     hostname verification is enabled. Authentication fails if hostname does not match.</li>
     *     <li>Client connects to server using IP address, but certificate contains only
     *     SubjectAltName (dns). Use of reverse DNS lookup to determine hostname introduces
     *     a security vulnerability since authentication would be reliant on a secure DNS.
     *     Hence hostname verification should fail in this case.</li>
     *     <li>Client connects to server using IP address and certificate contains
     *     SubjectAltName (ipaddress). This could be used when Kafka is on a private network.
     *     If reverse DNS lookup is used, authentication would succeed using IP address if lookup
     *     fails and IP address is used, but authentication would fail if lookup succeeds and
     *     dns name is used. For consistency and to avoid dependency on a potentially insecure
     *     DNS, reverse DNS lookup should be avoided and the IP address specified by the client for
     *     connection should be used to create the SSL engine.</li>
     *   </ul></li>
     * </ul>
     */
    private String peerHost(Socket socket) {
        return new InetSocketAddress(socket.getInetAddress(), 0).getHostString();
    }

    public SslEngineFactory sslEngineFactory() {
        return sslEngineFactory;
    }

    /**
     * Copy entries from one map into another.
     *
     * @param destMap   The map to copy entries into.
     * @param srcMap    The map to copy entries from.
     * @param keySet    Only entries with these keys will be copied.
     * @param <K>       The map key type.
     * @param <V>       The map value type.
     */
    private static <K, V> void copyMapEntries(Map<K, V> destMap,
                                              Map<K, ? extends V> srcMap,
                                              Set<K> keySet) {
        for (K k : keySet) {
            copyMapEntry(destMap, srcMap, k);
        }
    }

    /**
     * Copy entry from one map into another.
     *
     * @param destMap   The map to copy entries into.
     * @param srcMap    The map to copy entries from.
     * @param key       The entry with this key will be copied
     * @param <K>       The map key type.
     * @param <V>       The map value type.
     */
    private static <K, V> void copyMapEntry(Map<K, V> destMap,
                                            Map<K, ? extends V> srcMap,
                                            K key) {
        if (srcMap.containsKey(key)) {
            destMap.put(key, srcMap.get(key));
        }
    }

    @Override
    public void close() {
        Utils.closeQuietly(sslEngineFactory, "close engine factory");
    }

    // DECISION: CertificateEntries validates DN/SAN compatibility between old
    // and new keystores. Uses canonical Principal comparison (Objects.equals)
    // with fallback to RFC2253 name comparison (getName().equalsIgnoreCase) to
    // handle encoding differences between certificate providers. This dual
    // comparison prevents false positives from tag encoding differences
    // (printable string vs UTF-8 representations of the same DN).
    static class CertificateEntries {
        private final String alias;
        private final Principal subjectPrincipal;
        private final Set<List<?>> subjectAltNames;

        static List<CertificateEntries> create(KeyStore keystore) throws GeneralSecurityException {
            Enumeration<String> aliases = keystore.aliases();
            List<CertificateEntries> entries = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert  = keystore.getCertificate(alias);
                if (cert instanceof X509Certificate)
                    entries.add(new CertificateEntries(alias, (X509Certificate) cert));
            }
            return entries;
        }

        static void ensureCompatible(KeyStore newKeystore, KeyStore oldKeystore, boolean allowDnChanges, boolean allowSanChanges) throws GeneralSecurityException {
            List<CertificateEntries> newEntries = CertificateEntries.create(newKeystore);
            List<CertificateEntries> oldEntries = CertificateEntries.create(oldKeystore);

            if (!allowDnChanges) {
                ensureCompatibleDNs(newEntries, oldEntries);
            }

            if (!allowSanChanges) {
                ensureCompatibleSANs(newEntries, oldEntries);
            }
        }

        private static void ensureCompatibleDNs(List<CertificateEntries> newEntries, List<CertificateEntries> oldEntries) {
            if (newEntries.size() != oldEntries.size()) {
                throw new ConfigException(String.format("Keystore entries do not match, existing store contains %d entries, new store contains %d entries",
                    oldEntries.size(), newEntries.size()));
            }

            for (int i = 0; i < newEntries.size(); i++) {
                CertificateEntries newEntry = newEntries.get(i);
                CertificateEntries oldEntry = oldEntries.get(i);
                Principal newPrincipal = newEntry.subjectPrincipal;
                Principal oldPrincipal = oldEntry.subjectPrincipal;

                // Compare principal objects to compare canonical names (e.g. to ignore leading/trailing whitespaces).
                // Canonical names may differ if the tags of a field changes from one with a printable string representation
                // to one without or vice-versa due to optional conversion to hex representation based on the tag. So we
                // also compare Principal.getName which compares the RFC2253 name. If either matches, allow dynamic update.
                if (!Objects.equals(newPrincipal, oldPrincipal) && !newPrincipal.getName().equalsIgnoreCase(oldPrincipal.getName())) {
                    throw new ConfigException(String.format("Keystore DistinguishedName does not match: " +
                        " existing={alias=%s, DN=%s}, new={alias=%s, DN=%s}",
                        oldEntry.alias, oldEntry.subjectPrincipal, newEntry.alias, newEntry.subjectPrincipal));
                }
            }
        }

        private static void ensureCompatibleSANs(List<CertificateEntries> newEntries, List<CertificateEntries> oldEntries) {
            if (newEntries.size() != oldEntries.size()) {
                throw new ConfigException(String.format("Keystore entries do not match, existing store contains %d entries, new store contains %d entries",
                    oldEntries.size(), newEntries.size()));
            }

            for (int i = 0; i < newEntries.size(); i++) {
                CertificateEntries newEntry = newEntries.get(i);
                CertificateEntries oldEntry = oldEntries.get(i);

                if (!newEntry.subjectAltNames.containsAll(oldEntry.subjectAltNames)) {
                    throw new ConfigException(String.format("Keystore SubjectAltNames do not match: " +
                            " existing={alias=%s, SAN=%s}, new={alias=%s, SAN=%s}",
                        oldEntry.alias, oldEntry.subjectAltNames, newEntry.alias, newEntry.subjectAltNames));
                }
            }
        }

        CertificateEntries(String alias, X509Certificate cert) throws GeneralSecurityException {
            this.alias = alias;
            this.subjectPrincipal = cert.getSubjectX500Principal();
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            // use a set for comparison
            this.subjectAltNames = altNames != null ? new HashSet<>(altNames) : Collections.emptySet();
        }

        @Override
        public int hashCode() {
            return Objects.hash(subjectPrincipal, subjectAltNames);
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof CertificateEntries))
                return false;
            CertificateEntries other = (CertificateEntries) obj;
            return Objects.equals(subjectPrincipal, other.subjectPrincipal) &&
                    Objects.equals(subjectAltNames, other.subjectAltNames);
        }

        @Override
        public String toString() {
            return "subjectPrincipal=" + subjectPrincipal +
                    ", subjectAltNames=" + subjectAltNames;
        }
    }

    // SECURITY: SEC-SSL-015 (MEDIUM) Simulates a full TLS handshake between old and new
    // Why: SSL factory controls certificate management and TLS
    // configuration that determines transport security.
    // SSL engine factories to validate compatibility before committing the
    // swap. This prevents deploying a new cert/key combination that would
    // break inter-broker communication. The validation creates both
    // client→server and server→client handshake pairs to verify bidirectional
    // compatibility (old-server↔new-client and new-server↔old-client).
    // Exploit: During certificate reconfiguration, the validation window
    // could be exploited to inject a cert with a different identity.
    // Improvement: Add synchronization guards during certificate
    // reconfiguration to prevent concurrent modification.
    /**
     * Validator used to verify dynamic update of keystore used in inter-broker communication.
     * The validator checks that a successful handshake can be performed using the keystore and
     * truststore configured on this SslFactory.
     */
    private static class SslEngineValidator {
        private static final ByteBuffer EMPTY_BUF = ByteBuffer.allocate(0);
        private final SSLEngine sslEngine;
        private SSLEngineResult handshakeResult;
        private ByteBuffer appBuffer;
        private ByteBuffer netBuffer;

        // CROSS-CUTTING: Bidirectional handshake validation — tests both
        // old-server↔new-client and new-server↔old-client to ensure rolling
        // certificate updates work in a mixed-version cluster where some
        // brokers have the old cert and others have the new cert.
        static void validate(SslEngineFactory oldEngineBuilder,
                             SslEngineFactory newEngineBuilder) throws SSLException {
            validate(createSslEngineForValidation(oldEngineBuilder, ConnectionMode.SERVER),
                    createSslEngineForValidation(newEngineBuilder, ConnectionMode.CLIENT));
            validate(createSslEngineForValidation(newEngineBuilder, ConnectionMode.SERVER),
                    createSslEngineForValidation(oldEngineBuilder, ConnectionMode.CLIENT));
        }

        private static SSLEngine createSslEngineForValidation(SslEngineFactory sslEngineFactory, ConnectionMode connectionMode) {
            // Use empty hostname, disable hostname verification
            if (connectionMode == ConnectionMode.SERVER) {
                return sslEngineFactory.createServerSslEngine("", 0);
            } else {
                return sslEngineFactory.createClientSslEngine("", 0, "");
            }
        }

        static void validate(SSLEngine clientEngine, SSLEngine serverEngine) throws SSLException {
            SslEngineValidator clientValidator = new SslEngineValidator(clientEngine);
            SslEngineValidator serverValidator = new SslEngineValidator(serverEngine);
            try {
                clientValidator.beginHandshake();
                serverValidator.beginHandshake();
                while (!serverValidator.complete() || !clientValidator.complete()) {
                    clientValidator.handshake(serverValidator);
                    serverValidator.handshake(clientValidator);
                }
            } finally {
                clientValidator.close();
                serverValidator.close();
            }
        }

        private SslEngineValidator(SSLEngine engine) {
            this.sslEngine = engine;
            appBuffer = ByteBuffer.allocate(sslEngine.getSession().getApplicationBufferSize());
            netBuffer = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
        }

        void beginHandshake() throws SSLException {
            sslEngine.beginHandshake();
        }
        /* COMPLEXITY: 42 lines — SSLEngine handshake state machine simulation.
         * Control flow: Infinite loop driven by SSLEngineResult.HandshakeStatus:
         * - NEED_WRAP: Wrap application data to network buffer; handle
         *   BUFFER_OVERFLOW by waiting for peer consumption or growing buffer.
         *   Return after wrap to let peer unwrap.
         * - NEED_UNWRAP: Delegate to unwrap() with peer's network buffer.
         *   Return null from unwrap means BUFFER_UNDERFLOW (need more data).
         * - NEED_TASK: Execute delegated task synchronously, then continue.
         * - FINISHED: Return — handshake complete.
         * - NOT_HANDSHAKING: Verify handshake was actually finished. If peer
         *   has remaining data, unwrap it (e.g., NewSessionTicket in TLS 1.3).
         *   Throw if not finished.
         * Key invariant: Buffer growth uses Utils.ensureCapacity to prevent
         * unbounded allocation.
         */
        void handshake(SslEngineValidator peerValidator) throws SSLException {
            SSLEngineResult.HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
            while (true) {
                switch (handshakeStatus) {
                    case NEED_WRAP:
                        handshakeResult = sslEngine.wrap(EMPTY_BUF, netBuffer);
                        switch (handshakeResult.getStatus()) {
                            case OK: break;
                            case BUFFER_OVERFLOW:
                                if (netBuffer.position() != 0) // Wait for peer to consume previously wrapped data
                                    return;
                                netBuffer.compact();
                                netBuffer = Utils.ensureCapacity(netBuffer, sslEngine.getSession().getPacketBufferSize());
                                netBuffer.flip();
                                break;
                            case BUFFER_UNDERFLOW:
                            case CLOSED:
                            default:
                                throw new SSLException("Unexpected handshake status: " + handshakeResult.getStatus());
                        }
                        return;
                    case NEED_UNWRAP:
                        handshakeStatus = unwrap(peerValidator, true);
                        if (handshakeStatus == null) return;
                        break;
                    case NEED_TASK:
                        sslEngine.getDelegatedTask().run();
                        handshakeStatus = sslEngine.getHandshakeStatus();
                        break;
                    case FINISHED:
                        return;
                    case NOT_HANDSHAKING:
                        if (handshakeResult.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.FINISHED)
                            throw new SSLException("Did not finish handshake, handshake status: " + handshakeResult.getHandshakeStatus());
                        else if (peerValidator.netBuffer.position() != 0) {
                            unwrap(peerValidator, false);
                        }
                        return;
                    default:
                        throw new IllegalStateException("Unexpected handshake status: " + handshakeStatus);
                }
            }
        }

        private SSLEngineResult.HandshakeStatus unwrap(SslEngineValidator peerValidator, boolean updateHandshakeResult) throws SSLException {
            // Unwrap regardless of whether there is data in the buffer to ensure that
            // handshake status is updated if required.
            peerValidator.netBuffer.flip(); // unwrap the data from peer
            SSLEngineResult sslEngineResult = sslEngine.unwrap(peerValidator.netBuffer, appBuffer);
            if (updateHandshakeResult) {
                handshakeResult = sslEngineResult;
            }
            peerValidator.netBuffer.compact();
            SSLEngineResult.HandshakeStatus handshakeStatus = sslEngineResult.getHandshakeStatus();
            switch (sslEngineResult.getStatus()) {
                case OK: break;
                case BUFFER_OVERFLOW:
                    appBuffer = Utils.ensureCapacity(appBuffer, sslEngine.getSession().getApplicationBufferSize());
                    break;
                case BUFFER_UNDERFLOW:
                    netBuffer = Utils.ensureCapacity(netBuffer, sslEngine.getSession().getPacketBufferSize());
                    // BUFFER_UNDERFLOW typically indicates that we need more data from peer,
                    // so return to process peer.
                    return null;
                case CLOSED:
                default:
                    throw new SSLException("Unexpected handshake status: " + sslEngineResult.getStatus());
            }
            return handshakeStatus;
        }

        boolean complete() {
            return sslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ||
                    sslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }

        void close() {
            sslEngine.closeOutbound();
            try {
                sslEngine.closeInbound();
            } catch (Exception e) {
                // ignore
            }
        }
    }
}