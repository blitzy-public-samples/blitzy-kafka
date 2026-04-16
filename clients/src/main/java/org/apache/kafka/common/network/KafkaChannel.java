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

import org.apache.kafka.common.errors.AuthenticationException;
import org.apache.kafka.common.errors.SslAuthenticationException;
import org.apache.kafka.common.memory.MemoryPool;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalSerde;
import org.apache.kafka.common.utils.Utils;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * A Kafka connection either existing on a client (which could be a broker in an
 * inter-broker scenario) and representing the channel to a remote broker or the
 * reverse (existing on a broker and representing the channel to a remote
 * client, which could be a broker in an inter-broker scenario).
 * <p>
 * Each instance has the following:
 * <ul>
 * <li>a unique ID identifying it in the {@code KafkaClient} instance via which
 * the connection was made on the client-side or in the instance where it was
 * accepted on the server-side</li>
 * <li>a reference to the underlying {@link TransportLayer} to allow reading and
 * writing</li>
 * <li>an {@link Authenticator} that performs the authentication (or
 * re-authentication, if that feature is enabled and it applies to this
 * connection) by reading and writing directly from/to the same
 * {@link TransportLayer}.</li>
 * <li>a {@link MemoryPool} into which responses are read (typically the JVM
 * heap for clients, though smaller pools can be used for brokers and for
 * testing out-of-memory scenarios)</li>
 * <li>a {@link NetworkReceive} representing the current incomplete/in-progress
 * request (from the server-side perspective) or response (from the client-side
 * perspective) being read, if applicable; or a non-null value that has had no
 * data read into it yet or a null value if there is no in-progress
 * request/response (either could be the case)</li>
 * <li>a {@link Send} representing the current request (from the client-side
 * perspective) or response (from the server-side perspective) that is either
 * waiting to be sent or partially sent, if applicable, or null</li>
 * <li>a {@link ChannelMuteState} to document if the channel has been muted due
 * to memory pressure or other reasons</li>
 * </ul>
 */
// SECURITY: (MEDIUM) KafkaChannel wraps TransportLayer + Authenticator, serving as the per-
// connection security boundary. The channel enforces that no application-level reads/writes
// occur until both the transport handshake (TLS) and application-level authentication (SASL)
// are complete. The mute state machine prevents processing of unauthenticated requests.
// Risk: If the ready() check is bypassed or the prepare() sequence is interrupted,
// unauthenticated data could be processed. The muting mechanism (mute/unmute/muteState) gates
// request processing on the server side — a bug in the mute state machine could allow request
// processing on unauthenticated channels.
// Improvement: Consider adding an explicit assertion in read()/write() that the channel is
// authenticated, rather than relying solely on the caller (Selector.pollSelectionKeys) to
// enforce the ready() check before invoking read operations.
//
// CROSS-CUTTING: KafkaChannel is the per-connection abstraction used by Selector (this package),
// NetworkClient (clients/), and SocketServer (core/src/main/scala/kafka/network/). Any change
// to KafkaChannel's mute state machine, authentication lifecycle, or read/write contract
// affects all three consumers. The SocketServer in particular depends on the mute state machine
// for request ordering and throttling.
// Contract: Callers must call prepare() until ready() returns true before reading/writing data.
// Impact: If prepare() semantics change, both client-side and server-side connection handling
// break.
public class KafkaChannel implements AutoCloseable {
    private static final long MIN_REAUTH_INTERVAL_ONE_SECOND_NANOS = 1000 * 1000 * 1000;

    /**
     * Mute States for KafkaChannel:
     * <ul>
     *   <li> NOT_MUTED: Channel is not muted. This is the default state. </li>
     *   <li> MUTED: Channel is muted. Channel must be in this state to be unmuted. </li>
     *   <li> MUTED_AND_RESPONSE_PENDING: (SocketServer only) Channel is muted and SocketServer has not sent a response
     *                                    back to the client yet (acks != 0) or is currently waiting to receive a
     *                                    response from the API layer (acks == 0). </li>
     *   <li> MUTED_AND_THROTTLED: (SocketServer only) Channel is muted and throttling is in progress due to quota
     *                             violation. </li>
     *   <li> MUTED_AND_THROTTLED_AND_RESPONSE_PENDING: (SocketServer only) Channel is muted, throttling is in progress,
     *                                                  and a response is currently pending. </li>
     * </ul>
     */
    // DECISION: Five-state mute state machine rather than a simple boolean mute flag. The server
    // (SocketServer) needs fine-grained mute control to enforce request ordering (one request at
    // a time per channel) and throttling (quota violations). A boolean mute would conflate
    // backpressure muting (memory pressure) with server-side request-ordering muting.
    // Alternatives: (1) Simple boolean — rejected because it cannot distinguish between memory-
    // pressure muting and server-initiated muting. (2) Multiple boolean flags — rejected because
    // state transitions become error-prone without a single state variable.
    // Risk: The state machine transitions are guarded by IllegalStateException in
    // handleChannelMuteEvent() — an invalid transition indicates a programming error in the
    // SocketServer's mute management.
    public enum ChannelMuteState {
        NOT_MUTED,
        MUTED,
        MUTED_AND_RESPONSE_PENDING,
        MUTED_AND_THROTTLED,
        MUTED_AND_THROTTLED_AND_RESPONSE_PENDING
    }

    /** Socket server events that will change the mute state:
     * <ul>
     *   <li> REQUEST_RECEIVED: A request has been received from the client. </li>
     *   <li> RESPONSE_SENT: A response has been sent out to the client (ack != 0) or SocketServer has heard back from
     *                       the API layer (acks = 0) </li>
     *   <li> THROTTLE_STARTED: Throttling started due to quota violation. </li>
     *   <li> THROTTLE_ENDED: Throttling ended. </li>
     * </ul>
     *
     * Valid transitions on each event are:
     * <ul>
     *   <li> REQUEST_RECEIVED: MUTED => MUTED_AND_RESPONSE_PENDING </li>
     *   <li> RESPONSE_SENT:    MUTED_AND_RESPONSE_PENDING => MUTED, MUTED_AND_THROTTLED_AND_RESPONSE_PENDING => MUTED_AND_THROTTLED </li>
     *   <li> THROTTLE_STARTED: MUTED_AND_RESPONSE_PENDING => MUTED_AND_THROTTLED_AND_RESPONSE_PENDING </li>
     *   <li> THROTTLE_ENDED:   MUTED_AND_THROTTLED => MUTED, MUTED_AND_THROTTLED_AND_RESPONSE_PENDING => MUTED_AND_RESPONSE_PENDING </li>
     * </ul>
     */
    public enum ChannelMuteEvent {
        REQUEST_RECEIVED,
        RESPONSE_SENT,
        THROTTLE_STARTED,
        THROTTLE_ENDED
    }

    private final String id;
    private final TransportLayer transportLayer;
    private final Supplier<Authenticator> authenticatorCreator;
    // CROSS-CUTTING: Depends on Authenticator interface (this package) with implementations in
    // security/authenticator/ (SaslServerAuthenticator, SaslClientAuthenticator) and
    // PlaintextChannelBuilder.DefaultAuthenticator (no-op for PLAINTEXT).
    // Contract: authenticate() must be idempotent until complete() returns true.
    private Authenticator authenticator;
    // Tracks accumulated network thread time. This is updated on the network thread.
    // The values are read and reset after each response is sent.
    private long networkThreadTimeNanos;
    private final int maxReceiveSize;
    private final MemoryPool memoryPool;
    private final ChannelMetadataRegistry metadataRegistry;
    private NetworkReceive receive;
    private NetworkSend send;
    // Track connection and mute state of channels to enable outstanding requests on channels to be
    // processed after the channel is disconnected.
    private boolean disconnected;
    private ChannelMuteState muteState;
    private ChannelState state;
    private SocketAddress remoteAddress;
    private int successfulAuthentications;
    private boolean midWrite;
    private long lastReauthenticationStartNanos;

    public KafkaChannel(String id, TransportLayer transportLayer, Supplier<Authenticator> authenticatorCreator,
                        int maxReceiveSize, MemoryPool memoryPool, ChannelMetadataRegistry metadataRegistry) {
        this.id = id;
        this.transportLayer = transportLayer;
        this.authenticatorCreator = authenticatorCreator;
        this.authenticator = authenticatorCreator.get();
        this.networkThreadTimeNanos = 0L;
        this.maxReceiveSize = maxReceiveSize;
        this.memoryPool = memoryPool;
        this.metadataRegistry = metadataRegistry;
        this.disconnected = false;
        this.muteState = ChannelMuteState.NOT_MUTED;
        this.state = ChannelState.NOT_CONNECTED;
    }

    public void close() throws IOException {
        this.disconnected = true;
        Utils.closeAll(transportLayer, authenticator, receive, metadataRegistry);
    }

    /**
     * Returns the principal returned by `authenticator.principal()`.
     */
    public KafkaPrincipal principal() {
        return authenticator.principal();
    }

    public Optional<KafkaPrincipalSerde> principalSerde() {
        return authenticator.principalSerde();
    }

    /**
     * Does handshake of transportLayer and authentication using configured authenticator.
     * For SSL with client authentication enabled, {@link TransportLayer#handshake()} performs
     * authentication. For SASL, authentication is performed by {@link Authenticator#authenticate()}.
     */
    // SECURITY: (HIGH) Two-phase authentication: first transportLayer.handshake() (TLS handshake),
    // then authenticator.authenticate() (SASL). This ordering is critical — SASL credentials must
    // only be transmitted after the TLS tunnel is established. If the order were reversed, SASL
    // credentials would be sent in cleartext on SASL_SSL connections.
    // Risk: An implementation bug that calls authenticator.authenticate() before
    // transportLayer.ready() could leak credentials on the wire. The current code guards this
    // with the conditional check.
    // Improvement: Consider adding an explicit precondition check in Authenticator.authenticate()
    // that verifies the transport layer is ready, as defense-in-depth.
    public void prepare() throws AuthenticationException, IOException {
        boolean authenticating = false;
        try {
            if (!transportLayer.ready())
                transportLayer.handshake();
            if (transportLayer.ready() && !authenticator.complete()) {
                authenticating = true;
                authenticator.authenticate();
            }
        } catch (AuthenticationException e) {
            // Clients are notified of authentication exceptions to enable operations to be terminated
            // without retries. Other errors are handled as network exceptions in Selector.
            String remoteDesc = remoteAddress != null ? remoteAddress.toString() : null;
            state = new ChannelState(ChannelState.State.AUTHENTICATION_FAILED, e, remoteDesc);
            if (authenticating) {
                delayCloseOnAuthenticationFailure();
                throw new DelayedResponseAuthenticationException(e);
            }
            throw e;
        }
        if (ready()) {
            ++successfulAuthentications;
            state = ChannelState.READY;
        }
    }

    public void disconnect() {
        disconnected = true;
        if (state == ChannelState.NOT_CONNECTED && remoteAddress != null) {
            //if we captured the remote address we can provide more information
            state = new ChannelState(ChannelState.State.NOT_CONNECTED, remoteAddress.toString());
        }
        transportLayer.disconnect();
    }

    public void state(ChannelState state) {
        this.state = state;
    }

    public ChannelState state() {
        return this.state;
    }

    public boolean finishConnect() throws IOException {
        //we need to grab remoteAddr before finishConnect() is called otherwise
        //it becomes inaccessible if the connection was refused.
        SocketChannel socketChannel = transportLayer.socketChannel();
        if (socketChannel != null) {
            remoteAddress = socketChannel.getRemoteAddress();
        }
        boolean connected = transportLayer.finishConnect();
        if (connected) {
            if (ready()) {
                state = ChannelState.READY;
            } else if (remoteAddress != null) {
                state = new ChannelState(ChannelState.State.AUTHENTICATE, remoteAddress.toString());
            } else {
                state = ChannelState.AUTHENTICATE;
            }
        }
        return connected;
    }

    public boolean isConnected() {
        return transportLayer.isConnected();
    }

    public String id() {
        return id;
    }

    public SelectionKey selectionKey() {
        return transportLayer.selectionKey();
    }

    /**
     * externally muting a channel should be done via selector to ensure proper state handling
     */
    void mute() {
        if (muteState == ChannelMuteState.NOT_MUTED) {
            if (!disconnected) transportLayer.removeInterestOps(SelectionKey.OP_READ);
            muteState = ChannelMuteState.MUTED;
        }
    }

    /**
     * Unmute the channel. The channel can be unmuted only if it is in the MUTED state. For other muted states
     * (MUTED_AND_*), this is a no-op.
     *
     * @return Whether or not the channel is in the NOT_MUTED state after the call
     */
    boolean maybeUnmute() {
        if (muteState == ChannelMuteState.MUTED) {
            if (!disconnected) transportLayer.addInterestOps(SelectionKey.OP_READ);
            muteState = ChannelMuteState.NOT_MUTED;
        }
        return muteState == ChannelMuteState.NOT_MUTED;
    }

    // COMPLEXITY: 38 lines — Mute state machine transition handler.
    // Structure: Switch on ChannelMuteEvent type, each case validates the current muteState and
    // transitions to the next state. If no valid transition exists, throws IllegalStateException.
    // Key paths: REQUEST_RECEIVED (MUTED → MUTED_AND_RESPONSE_PENDING),
    //   RESPONSE_SENT (MUTED_AND_RESPONSE_PENDING → MUTED),
    //   THROTTLE_STARTED (MUTED_AND_RESPONSE_PENDING → MUTED_AND_THROTTLED_AND_RESPONSE_PENDING),
    //   THROTTLE_ENDED (MUTED_AND_THROTTLED → MUTED).
    // Exit: Always returns void; throws if transition is invalid.
    // Handle the specified channel mute-related event and transition the mute state according to the state machine.
    public void handleChannelMuteEvent(ChannelMuteEvent event) {
        boolean stateChanged = false;
        switch (event) {
            case REQUEST_RECEIVED:
                if (muteState == ChannelMuteState.MUTED) {
                    muteState = ChannelMuteState.MUTED_AND_RESPONSE_PENDING;
                    stateChanged = true;
                }
                break;
            case RESPONSE_SENT:
                if (muteState == ChannelMuteState.MUTED_AND_RESPONSE_PENDING) {
                    muteState = ChannelMuteState.MUTED;
                    stateChanged = true;
                }
                if (muteState == ChannelMuteState.MUTED_AND_THROTTLED_AND_RESPONSE_PENDING) {
                    muteState = ChannelMuteState.MUTED_AND_THROTTLED;
                    stateChanged = true;
                }
                break;
            case THROTTLE_STARTED:
                if (muteState == ChannelMuteState.MUTED_AND_RESPONSE_PENDING) {
                    muteState = ChannelMuteState.MUTED_AND_THROTTLED_AND_RESPONSE_PENDING;
                    stateChanged = true;
                }
                break;
            case THROTTLE_ENDED:
                if (muteState == ChannelMuteState.MUTED_AND_THROTTLED) {
                    muteState = ChannelMuteState.MUTED;
                    stateChanged = true;
                }
                if (muteState == ChannelMuteState.MUTED_AND_THROTTLED_AND_RESPONSE_PENDING) {
                    muteState = ChannelMuteState.MUTED_AND_RESPONSE_PENDING;
                    stateChanged = true;
                }
        }
        if (!stateChanged) {
            throw new IllegalStateException("Cannot transition from " + muteState.name() + " for " + event.name());
        }
    }

    public ChannelMuteState muteState() {
        return muteState;
    }

    /**
     * Delay channel close on authentication failure. This will remove all read/write operations from the channel until
     * {@link #completeCloseOnAuthenticationFailure()} is called to finish up the channel close.
     */
    // SECURITY: (MEDIUM) Removes OP_WRITE interest to prevent further writes on the channel
    // after authentication failure. This is the server-side half of the timing-attack mitigation
    // — the channel remains open (holding the TCP connection) for a configurable delay before
    // the error response is sent and the connection is closed. See Selector.
    // DelayedAuthenticationFailureClose for the delay mechanism.
    private void delayCloseOnAuthenticationFailure() {
        transportLayer.removeInterestOps(SelectionKey.OP_WRITE);
    }

    /**
     * Finish up any processing on {@link #prepare()} failure.
     * @throws IOException
     */
    void completeCloseOnAuthenticationFailure() throws IOException {
        transportLayer.addInterestOps(SelectionKey.OP_WRITE);
        // Invoke the underlying handler to finish up any processing on authentication failure
        authenticator.handleAuthenticationFailure();
    }

    /**
     * Returns true if this channel has been explicitly muted using {@link KafkaChannel#mute()}
     */
    public boolean isMuted() {
        return muteState != ChannelMuteState.NOT_MUTED;
    }

    // DECISION: Channel is considered "in mutable state" only when: (a) a receive is in progress,
    // (b) memory for that receive has NOT yet been allocated, and (c) the transport layer is
    // ready. This prevents muting channels that have already allocated their buffers (no point
    // in muting) or channels not yet authenticated (transport not ready). This is the signal to
    // Selector that the channel should be muted due to memory pressure.
    public boolean isInMutableState() {
        // Some requests do not require memory, so if we do not know what the current (or future) request is
        // (receive == null) we don't mute. We also don't mute if whatever memory required has already been
        // successfully allocated (if none is required for the currently-being-read request
        // receive.memoryAllocated() is expected to return true)
        if (receive == null || receive.memoryAllocated())
            return false;
        // also cannot mute if underlying transport is not in the ready state
        return transportLayer.ready();
    }

    public boolean ready() {
        return transportLayer.ready() && authenticator.complete();
    }

    public boolean hasSend() {
        return send != null;
    }

    /**
     * Returns the address to which this channel's socket is connected or `null` if the socket has never been connected.
     *
     * If the socket was connected prior to being closed, then this method will continue to return the
     * connected address after the socket is closed.
     */
    public InetAddress socketAddress() {
        return transportLayer.socketChannel().socket().getInetAddress();
    }

    /**
     * Returns the port to which this channel's socket is connected or 0 if the socket has never been connected.
     *
     * If the socket was connected prior to being closed, then this method will continue to return the
     * connected port number after the socket is closed.
     */
    public int socketPort() {
        return transportLayer.socketChannel().socket().getPort();
    }

    public String socketDescription() {
        Socket socket = transportLayer.socketChannel().socket();
        if (socket.getInetAddress() == null)
            return socket.getLocalAddress().toString();
        return socket.getInetAddress().toString();
    }

    public void setSend(NetworkSend send) {
        if (this.send != null)
            throw new IllegalStateException("Attempt to begin a send operation with prior send operation still in progress, connection id is " + id);
        this.send = send;
        this.transportLayer.addInterestOps(SelectionKey.OP_WRITE);
    }

    public NetworkSend maybeCompleteSend() {
        if (send != null && send.completed()) {
            midWrite = false;
            transportLayer.removeInterestOps(SelectionKey.OP_WRITE);
            NetworkSend result = send;
            send = null;
            return result;
        }
        return null;
    }

    // DECISION: Auto-muting on memory exhaustion — if the receive requires memory but allocation
    // failed (MemoryPool returned null), the channel mutes itself. This creates a backpressure
    // signal that propagates from the MemoryPool through the channel to the Selector, which
    // stops reading from this channel until memory is available. This prevents OOM in the broker.
    public long read() throws IOException {
        if (receive == null) {
            receive = new NetworkReceive(maxReceiveSize, id, memoryPool);
        }

        long bytesReceived = receive(this.receive);

        if (this.receive.requiredMemoryAmountKnown() && !this.receive.memoryAllocated() && isInMutableState()) {
            //pool must be out of memory, mute ourselves.
            mute();
        }
        return bytesReceived;
    }

    public NetworkReceive currentReceive() {
        return receive;
    }

    public NetworkReceive maybeCompleteReceive() {
        if (receive != null && receive.complete()) {
            receive.payload().rewind();
            NetworkReceive result = receive;
            receive = null;
            return result;
        }
        return null;
    }

    public long write() throws IOException {
        if (send == null)
            return 0;

        midWrite = true;
        return send.writeTo(transportLayer);
    }

    /**
     * Accumulates network thread time for this channel.
     */
    public void addNetworkThreadTimeNanos(long nanos) {
        networkThreadTimeNanos += nanos;
    }

    /**
     * Returns accumulated network thread time for this channel and resets
     * the value to zero.
     */
    public long getAndResetNetworkThreadTimeNanos() {
        long current = networkThreadTimeNanos;
        networkThreadTimeNanos = 0;
        return current;
    }

    private long receive(NetworkReceive receive) throws IOException {
        try {
            return receive.readFrom(transportLayer);
        } catch (SslAuthenticationException e) {
            // With TLSv1.3, post-handshake messages may throw SSLExceptions, which are
            // handled as authentication failures
            String remoteDesc = remoteAddress != null ? remoteAddress.toString() : null;
            state = new ChannelState(ChannelState.State.AUTHENTICATION_FAILED, e, remoteDesc);
            throw e;
        }
    }

    /**
     * @return true if underlying transport has bytes remaining to be read from any underlying intermediate buffers.
     */
    public boolean hasBytesBuffered() {
        return transportLayer.hasBytesBuffered();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        KafkaChannel that = (KafkaChannel) o;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return super.toString() + " id=" + id;
    }
    
    /**
     * Return the number of times this instance has successfully authenticated. This
     * value can only exceed 1 when re-authentication is enabled and it has
     * succeeded at least once.
     * 
     * @return the number of times this instance has successfully authenticated
     */
    public int successfulAuthentications() {
        return successfulAuthentications;
    }

    /**
     * If this is a server-side connection that has an expiration time and at least
     * 1 second has passed since the prior re-authentication (if any) started then
     * begin the process of re-authenticating the connection and return true,
     * otherwise return false
     * 
     * @param saslHandshakeNetworkReceive
     *            the mandatory {@link NetworkReceive} containing the
     *            {@code SaslHandshakeRequest} that has been received on the server
     *            and that initiates re-authentication.
     * @param nowNanosSupplier
     *            {@code Supplier} of the current time. The value must be in
     *            nanoseconds as per {@code System.nanoTime()} and is therefore only
     *            useful when compared to such a value -- it's absolute value is
     *            meaningless.
     * 
     * @return true if this is a server-side connection that has an expiration time
     *         and at least 1 second has passed since the prior re-authentication
     *         (if any) started to indicate that the re-authentication process has
     *         begun, otherwise false
     * @throws AuthenticationException
     *             if re-authentication fails due to invalid credentials or other
     *             security configuration errors
     * @throws IOException
     *             if read/write fails due to an I/O error
     * @throws IllegalStateException
     *             if this channel is not "ready"
     */
    // SECURITY: (MEDIUM) Re-authentication rate limiting — enforces a minimum 1-second interval
    // between re-authentication attempts (MIN_REAUTH_INTERVAL_ONE_SECOND_NANOS). Without this
    // guard, a malicious client could repeatedly trigger re-authentication to cause CPU-intensive
    // SASL/SCRAM operations, creating a computational DoS.
    // Risk: Attacker sends SaslHandshakeRequest at high frequency to exhaust broker CPU with
    // PBKDF2/SCRAM computations. The 1-second floor limits the rate.
    // Improvement: Consider making the re-auth interval configurable and/or using exponential
    // backoff for repeated re-authentication attempts from the same connection.
    public boolean maybeBeginServerReauthentication(NetworkReceive saslHandshakeNetworkReceive,
            Supplier<Long> nowNanosSupplier) throws AuthenticationException, IOException {
        if (!ready())
            throw new IllegalStateException(
                    "KafkaChannel should be \"ready\" when processing SASL Handshake for potential re-authentication");
        /*
         * Re-authentication is disabled if there is no session expiration time, in
         * which case the SASL handshake network receive will be processed normally,
         * which results in a failure result being sent to the client. Also, no need to
         * check if we are muted since we are processing a received packet when we invoke
         * this.
         */
        if (authenticator.serverSessionExpirationTimeNanos() == null)
            return false;
        /*
         * We've delayed getting the time as long as possible in case we don't need it,
         * but at this point we need it -- so get it now.
         */
        long nowNanos = nowNanosSupplier.get();
        /*
         * Cannot re-authenticate more than once every second; an attempt to do so will
         * result in the SASL handshake network receive being processed normally, which
         * results in a failure result being sent to the client.
         */
        if (lastReauthenticationStartNanos != 0
                && nowNanos - lastReauthenticationStartNanos < MIN_REAUTH_INTERVAL_ONE_SECOND_NANOS)
            return false;
        lastReauthenticationStartNanos = nowNanos;
        swapAuthenticatorsAndBeginReauthentication(
                new ReauthenticationContext(authenticator, saslHandshakeNetworkReceive, nowNanos));
        return true;
    }

    /**
     * If this is a client-side connection that is not muted, there is no
     * in-progress write, and there is a session expiration time defined that has
     * past then begin the process of re-authenticating the connection and return
     * true, otherwise return false
     * 
     * @param nowNanosSupplier
     *            {@code Supplier} of the current time. The value must be in
     *            nanoseconds as per {@code System.nanoTime()} and is therefore only
     *            useful when compared to such a value -- it's absolute value is
     *            meaningless.
     * 
     * @return true if this is a client-side connection that is not muted, there is
     *         no in-progress write, and there is a session expiration time defined
     *         that has past to indicate that the re-authentication process has
     *         begun, otherwise false
     * @throws AuthenticationException
     *             if re-authentication fails due to invalid credentials or other
     *             security configuration errors
     * @throws IOException
     *             if read/write fails due to an I/O error
     * @throws IllegalStateException
     *             if this channel is not "ready"
     */
    // DECISION: Client-side re-authentication is gated on three conditions: (1) channel not
    // muted, (2) no mid-write in progress, (3) session expiration time has passed. The midWrite
    // check prevents re-auth from interrupting an in-flight request, which would corrupt the
    // wire protocol. The receive field is set to null because the current in-progress receive
    // will be passed to the new authenticator via ReauthenticationContext.
    public boolean maybeBeginClientReauthentication(Supplier<Long> nowNanosSupplier)
            throws AuthenticationException, IOException {
        if (!ready())
            throw new IllegalStateException(
                    "KafkaChannel should always be \"ready\" when it is checked for possible re-authentication");
        if (muteState != ChannelMuteState.NOT_MUTED || midWrite
                || authenticator.clientSessionReauthenticationTimeNanos() == null)
            return false;
        /*
         * We've delayed getting the time as long as possible in case we don't need it,
         * but at this point we need it -- so get it now.
         */
        long nowNanos = nowNanosSupplier.get();
        if (nowNanos < authenticator.clientSessionReauthenticationTimeNanos())
            return false;
        swapAuthenticatorsAndBeginReauthentication(new ReauthenticationContext(authenticator, receive, nowNanos));
        receive = null;
        return true;
    }
    
    /**
     * Return the number of milliseconds that elapsed while re-authenticating this
     * session from the perspective of this instance, if applicable, otherwise null.
     * The server-side perspective will yield a lower value than the client-side
     * perspective of the same re-authentication because the client-side observes an
     * additional network round-trip.
     * 
     * @return the number of milliseconds that elapsed while re-authenticating this
     *         session from the perspective of this instance, if applicable,
     *         otherwise null
     */
    public Long reauthenticationLatencyMs() {
        return authenticator.reauthenticationLatencyMs();
    }

    /**
     * Return true if this is a server-side channel and the given time is past the
     * session expiration time, if any, otherwise false
     * 
     * @param nowNanos
     *            the current time in nanoseconds as per {@code System.nanoTime()}
     * @return true if this is a server-side channel and the given time is past the
     *         session expiration time, if any, otherwise false
     */
    public boolean serverAuthenticationSessionExpired(long nowNanos) {
        Long serverSessionExpirationTimeNanos = authenticator.serverSessionExpirationTimeNanos();
        return serverSessionExpirationTimeNanos != null && nowNanos - serverSessionExpirationTimeNanos > 0;
    }
    
    /**
     * Return the (always non-null but possibly empty) client-side
     * {@link NetworkReceive} response that arrived during re-authentication but
     * is unrelated to re-authentication. This corresponds to a request sent
     * prior to the beginning of re-authentication; the request was made when the
     * channel was successfully authenticated, and the response arrived during the
     * re-authentication process.
     * 
     * @return client-side {@link NetworkReceive} response that arrived during
     *         re-authentication that is unrelated to re-authentication. This may
     *         be empty.
     */
    public Optional<NetworkReceive> pollResponseReceivedDuringReauthentication() {
        return authenticator.pollResponseReceivedDuringReauthentication();
    }
    
    /**
     * Return true if this is a server-side channel and the connected client has
     * indicated that it supports re-authentication, otherwise false
     * 
     * @return true if this is a server-side channel and the connected client has
     *         indicated that it supports re-authentication, otherwise false
     */
    boolean connectedClientSupportsReauthentication() {
        return authenticator.connectedClientSupportsReauthentication();
    }

    // SECURITY: Replaces the current authenticator with a fresh instance for re-authentication.
    // The new authenticator is responsible for closing the old one after extracting its state
    // (via ReauthenticationContext). The old authenticator's credentials are discarded during
    // this swap — ensure no references to stale credentials are retained.
    //
    // DECISION: Authenticator swap creates a new instance via authenticatorCreator Supplier,
    // delegating old-authenticator cleanup to the new authenticator (via ReauthenticationContext).
    // Alternative: In-place authenticator reset. Rationale: Fresh instance ensures no state
    // leakage from prior authentication, which is critical when switching between SASL mechanisms
    // or when the prior session's cryptographic material must be fully discarded.
    private void swapAuthenticatorsAndBeginReauthentication(ReauthenticationContext reauthenticationContext)
            throws IOException {
        // it is up to the new authenticator to close the old one
        // replace with a new one and begin the process of re-authenticating
        authenticator = authenticatorCreator.get();
        authenticator.reauthenticate(reauthenticationContext);
    }

    public ChannelMetadataRegistry channelMetadataRegistry() {
        return metadataRegistry;
    }


    /**
     * Maybe add write interest after re-authentication. This is to ensure that any pending write operation
     * is resumed.
     */
    public void maybeAddWriteInterestAfterReauth() {
        if (send != null)
            this.transportLayer.addInterestOps(SelectionKey.OP_WRITE);
    }
}
