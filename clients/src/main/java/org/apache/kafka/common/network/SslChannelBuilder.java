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
package org.apache.kafka.common.network;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.config.internals.BrokerSecurityConfigs;
import org.apache.kafka.common.memory.MemoryPool;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.KafkaPrincipalSerde;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.apache.kafka.common.security.ssl.SslFactory;
import org.apache.kafka.common.security.ssl.SslPrincipalMapper;
import org.apache.kafka.common.utils.Utils;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

// SECURITY: (MEDIUM) SslChannelBuilder constructs SSL/TLS channels using SslFactory
// for SSLEngine configuration. Implements ListenerReconfigurable to support dynamic
// SSL certificate rotation without broker restart. The SslFactory is replaced atomically
// during reconfiguration.
// Risk: During dynamic reconfiguration, there is a brief window where new connections
// may use the old or new certificate depending on timing. SslFactory's createSslEngine()
// is not synchronized -- new connections created during reconfigure() may use either the
// old or new factory depending on the JVM's memory model visibility guarantees.
// Improvement: Consider using a volatile or AtomicReference for the SslFactory field to
// ensure immediate visibility of the new factory across threads.
//
// CROSS-CUTTING: Depends on security/ssl/SslFactory for SSLEngine creation and
// configuration. SslFactory in turn depends on the JDK's JSSE provider for TLS
// implementation. Changes to SslFactory's createSslEngine() or
// SslTransportLayer.create() affect all SSL connections.
// Contract: SslFactory must be configured before buildChannel() is called.
// Impact: If SslFactory changes its SSLEngine initialization (e.g., different cipher
// suites), all connections created by this builder are affected.
// Exploit: An attacker could exploit weak cipher suites or certificate validation gaps for MITM attacks.
public class SslChannelBuilder implements ChannelBuilder, ListenerReconfigurable {
    private final ListenerName listenerName;
    private final boolean isInterBrokerListener;
    private final ConnectionMode connectionMode;
    private SslFactory sslFactory;
    private Map<String, ?> configs;
    private SslPrincipalMapper sslPrincipalMapper;

    /**
     * Constructs an SSL channel builder. ListenerName is provided only
     * for server channel builder and will be null for client channel builder.
     */
    public SslChannelBuilder(ConnectionMode connectionMode,
                             ListenerName listenerName,
                             boolean isInterBrokerListener) {
        this.connectionMode = connectionMode;
        this.listenerName = listenerName;
        this.isInterBrokerListener = isInterBrokerListener;
    }

    public void configure(Map<String, ?> configs) throws KafkaException {
        try {
            this.configs = configs;
            String sslPrincipalMappingRules = (String) configs.get(BrokerSecurityConfigs.SSL_PRINCIPAL_MAPPING_RULES_CONFIG);
            if (sslPrincipalMappingRules != null)
                sslPrincipalMapper = SslPrincipalMapper.fromRules(sslPrincipalMappingRules);
            this.sslFactory = new SslFactory(connectionMode, null, isInterBrokerListener);
            this.sslFactory.configure(this.configs);
        } catch (KafkaException e) {
            throw e;
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    @Override
    public Set<String> reconfigurableConfigs() {
        return SslConfigs.RECONFIGURABLE_CONFIGS;
    }

    @Override
    public void validateReconfiguration(Map<String, ?> configs) {
        sslFactory.validateReconfiguration(configs);
    }

    // DECISION: Implements ListenerReconfigurable for dynamic SSL certificate rotation.
    // When new SSL configuration is applied, a new SslFactory is created and validated
    // before replacing the old one. This avoids broker restarts for certificate rotation.
    // Alternative: Require broker restart for cert changes -- rejected for operational
    // agility. The isInterBrokerListener flag is used to determine if this builder is
    // for inter-broker communication, which may have different reconfiguration
    // requirements.
    @Override
    public void reconfigure(Map<String, ?> configs) {
        sslFactory.reconfigure(configs);
    }

    @Override
    public ListenerName listenerName() {
        return listenerName;
    }

    // DECISION: Each connection gets its own SSLEngine and SslTransportLayer. SSLEngine
    // instances are not reusable across connections -- they maintain per-connection TLS
    // state (session keys, sequence numbers). The SslFactory is shared across all
    // connections for the same listener. The SslAuthenticator (created by SslFactory)
    // performs certificate validation and principal extraction. The sslPrincipalMapper
    // translates X.509 DNs to Kafka principal names.
    @Override
    public KafkaChannel buildChannel(String id, SelectionKey key, int maxReceiveSize,
                                     MemoryPool memoryPool, ChannelMetadataRegistry metadataRegistry) throws KafkaException {
        SslTransportLayer transportLayer = null;
        try {
            transportLayer = buildTransportLayer(sslFactory, id, key, metadataRegistry);
            final SslTransportLayer finalTransportLayer = transportLayer;
            Supplier<Authenticator> authenticatorCreator = () ->
                new SslAuthenticator(configs, finalTransportLayer, listenerName, sslPrincipalMapper);
            return new KafkaChannel(id, transportLayer, authenticatorCreator, maxReceiveSize,
                    memoryPool != null ? memoryPool : MemoryPool.NONE, metadataRegistry);
        } catch (Exception e) {
            // Ideally these resources are closed by the KafkaChannel but this builder should close the resources instead
            // if an error occurs due to which KafkaChannel is not created.
            Utils.closeQuietly(transportLayer, "transport layer for channel Id: " + id);
            throw new KafkaException(e);
        }
    }

    @Override
    public void close() {
        if (sslFactory != null) sslFactory.close();
    }

    protected SslTransportLayer buildTransportLayer(SslFactory sslFactory, String id, SelectionKey key, ChannelMetadataRegistry metadataRegistry) throws IOException {
        SocketChannel socketChannel = (SocketChannel) key.channel();
        return SslTransportLayer.create(id, key, sslFactory.createSslEngine(socketChannel.socket()),
            metadataRegistry);
    }

    /**
     * Note that client SSL authentication is handled in {@link SslTransportLayer}. This class is only used
     * to transform the derived principal using a {@link KafkaPrincipalBuilder} configured by the user.
     */
    private static class SslAuthenticator implements Authenticator {
        private final SslTransportLayer transportLayer;
        private final KafkaPrincipalBuilder principalBuilder;
        private final ListenerName listenerName;

        private SslAuthenticator(Map<String, ?> configs, SslTransportLayer transportLayer, ListenerName listenerName, SslPrincipalMapper sslPrincipalMapper) {
            this.transportLayer = transportLayer;
            this.principalBuilder = ChannelBuilders.createPrincipalBuilder(configs, null, sslPrincipalMapper);
            this.listenerName = listenerName;
        }
        /**
         * No-Op for plaintext authenticator
         */
        @Override
        public void authenticate() {}

        /**
         * Constructs Principal using configured principalBuilder.
         * @return the built principal
         */
        @Override
        public KafkaPrincipal principal() {
            InetAddress clientAddress = transportLayer.socketChannel().socket().getInetAddress();
            // listenerName should only be null in Client mode where principal() should not be called
            if (listenerName == null)
                throw new IllegalStateException("Unexpected call to principal() when listenerName is null");
            SslAuthenticationContext context = new SslAuthenticationContext(
                    transportLayer.sslSession(),
                    clientAddress,
                    listenerName.value());
            return principalBuilder.build(context);
        }

        @Override
        public Optional<KafkaPrincipalSerde> principalSerde() {
            return Optional.of(principalBuilder);
        }

        @Override
        public void close() {
            if (principalBuilder instanceof Closeable)
                Utils.closeQuietly((Closeable) principalBuilder, "principal builder");
        }

        /**
         * SslAuthenticator doesn't implement any additional authentication mechanism.
         * @return true
         */
        @Override
        public boolean complete() {
            return true;
        }
    }
}
