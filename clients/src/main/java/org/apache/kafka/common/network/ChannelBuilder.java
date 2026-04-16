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

import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.memory.MemoryPool;

import java.nio.channels.SelectionKey;


// DECISION: Factory interface for constructing KafkaChannel instances. The separation of
// ChannelBuilder (factory) from KafkaChannel (instance) enables per-listener configuration:
// each listener can have its own ChannelBuilder with distinct security settings.
// The configure() → buildChannel() lifecycle allows deferred initialization after the
// builder receives its configuration.
// Implementations: PlaintextChannelBuilder, SslChannelBuilder, SaslChannelBuilder.
// Alternative: Direct KafkaChannel construction — rejected because channel construction
// requires security protocol-specific configuration (SSL keys, SASL mechanisms, Kerberos
// principals) that varies per listener.

// CROSS-CUTTING: This interface is the extension point for custom transport layers. Third-party
// ChannelBuilder implementations can provide custom encryption, authentication, or channel
// behavior. Consumed by Selector via ChannelBuilders factory class.
// Contract: configure() must be called before buildChannel(). close() must release all
// resources (e.g., SslFactory, LoginManager). buildChannel() must return a fully-initialized
// KafkaChannel that is ready for the handshake/authentication lifecycle.

/**
 * A ChannelBuilder interface to build Channel based on configs
 */
public interface ChannelBuilder extends AutoCloseable, Configurable {

    /**
     * returns a Channel with TransportLayer and Authenticator configured.
     * @param  id  channel id
     * @param  key SelectionKey
     * @param  maxReceiveSize max size of a single receive buffer to allocate
     * @param  memoryPool memory pool from which to allocate buffers, or null for none
     * @param  metadataRegistry registry which stores the metadata about the channels
     * @return KafkaChannel
     */
    KafkaChannel buildChannel(String id, SelectionKey key, int maxReceiveSize,
                              MemoryPool memoryPool, ChannelMetadataRegistry metadataRegistry) throws KafkaException;

    /**
     * Closes ChannelBuilder
     */
    @Override
    void close();

}
