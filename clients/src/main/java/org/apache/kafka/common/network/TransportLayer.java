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

/*
 * Transport layer for underlying communication.
 * At very basic level it is wrapper around SocketChannel and can be used as substitute for SocketChannel
 * and other network Channel implementations.
 * As NetworkClient replaces BlockingChannel and other implementations we will be using KafkaChannel as
 * a network I/O channel.
 */

import org.apache.kafka.common.errors.AuthenticationException;

import java.io.IOException;
import java.nio.channels.ScatteringByteChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.security.Principal;

// DECISION: Transport abstraction that adds handshake(), ready(), hasBytesBuffered(), and
// principal extraction to the standard ScatteringByteChannel/TransferableChannel contracts.
// This enables KafkaChannel to work uniformly with both plaintext (PlaintextTransportLayer)
// and TLS-encrypted (SslTransportLayer) connections. The handshake() method is the key
// extension — it drives TLS negotiation for SSL channels and is a no-op for plaintext.
// Alternative: No abstraction — have KafkaChannel use SocketChannel directly and conditionally
// wrap with SSLEngine. Rejected because the conditional logic would be scattered throughout
// the read/write paths, making the code fragile and hard to test.
//
// CROSS-CUTTING: Core abstraction consumed by KafkaChannel. Implementations in this package:
// PlaintextTransportLayer, SslTransportLayer. Created by ChannelBuilder implementations
// (PlaintextChannelBuilder, SslChannelBuilder, SaslChannelBuilder).
// Impact: Adding a new method to TransportLayer requires updates to both implementations
// and potentially to tests that mock this interface.
public interface TransportLayer extends ScatteringByteChannel, TransferableChannel {

    // DECISION: ready() = true means the transport is capable of application data transfer.
    // For PlaintextTransportLayer, always true. For SslTransportLayer, true only after TLS
    // handshake completes. hasBytesBuffered() indicates data is available in intermediate
    // buffers (SSL decryption buffer) that won't trigger a SelectionKey readable event.
    // hasPendingWrites() (inherited from TransferableChannel) indicates data in the write
    // buffer that hasn't been flushed to the socket, which prevents the channel from being
    // marked as send-complete prematurely.

    /**
     * Returns true if the channel has handshake and authentication done.
     */
    boolean ready();

    /**
     * Finishes the process of connecting a socket channel.
     */
    boolean finishConnect() throws IOException;

    /**
     * disconnect socketChannel
     */
    void disconnect();

    /**
     * Tells whether or not this channel's network socket is connected.
     */
    boolean isConnected();

    /**
     * returns underlying socketChannel
     */
    SocketChannel socketChannel();

    /**
     * Get the underlying selection key
     */
    SelectionKey selectionKey();

    /**
     * This a no-op for the non-secure PLAINTEXT implementation. For SSL, this performs
     * SSL handshake. The SSL handshake includes client authentication if configured using
     * {@link org.apache.kafka.common.config.internals.BrokerSecurityConfigs#SSL_CLIENT_AUTH_CONFIG}.
     * @throws AuthenticationException if handshake fails due to an {@link javax.net.ssl.SSLException}.
     * @throws IOException if read or write fails with an I/O error.
    */
    void handshake() throws AuthenticationException, IOException;

    /**
     * Returns `SSLSession.getPeerPrincipal()` if this is an SslTransportLayer and there is an authenticated peer,
     * `KafkaPrincipal.ANONYMOUS` is returned otherwise.
     */
    Principal peerPrincipal() throws IOException;

    void addInterestOps(int ops);

    void removeInterestOps(int ops);

    boolean isMute();

    /**
     * @return true if channel has bytes to be read in any intermediate buffers
     * which may be processed without reading additional data from the network.
     */
    boolean hasBytesBuffered();
}
