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
import org.apache.kafka.common.MetricName;
import org.apache.kafka.common.errors.AuthenticationException;
import org.apache.kafka.common.memory.MemoryPool;
import org.apache.kafka.common.metrics.Metrics;
import org.apache.kafka.common.metrics.Sensor;
import org.apache.kafka.common.metrics.internals.IntGaugeSuite;
import org.apache.kafka.common.metrics.stats.Avg;
import org.apache.kafka.common.metrics.stats.CumulativeSum;
import org.apache.kafka.common.metrics.stats.Max;
import org.apache.kafka.common.metrics.stats.Meter;
import org.apache.kafka.common.metrics.stats.SampledStat;
import org.apache.kafka.common.metrics.stats.WindowedCount;
import org.apache.kafka.common.utils.LogContext;
import org.apache.kafka.common.utils.Time;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.UnresolvedAddressException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A nioSelector interface for doing non-blocking multi-connection network I/O.
 * <p>
 * This class works with {@link NetworkSend} and {@link NetworkReceive} to transmit size-delimited network requests and
 * responses.
 * <p>
 * A connection can be added to the nioSelector associated with an integer id by doing
 *
 * <pre>
 * nioSelector.connect(&quot;42&quot;, new InetSocketAddress(&quot;google.com&quot;, server.port), 64000, 64000);
 * </pre>
 *
 * The connect call does not block on the creation of the TCP connection, so the connect method only begins initiating
 * the connection. The successful invocation of this method does not mean a valid connection has been established.
 *
 * Sending requests, receiving responses, processing connection completions, and disconnections on the existing
 * connections are all done using the <code>poll()</code> call.
 *
 * <pre>
 * nioSelector.send(new NetworkSend(myDestination, myBytes));
 * nioSelector.send(new NetworkSend(myOtherDestination, myOtherBytes));
 * nioSelector.poll(TIMEOUT_MS);
 * </pre>
 *
 * The nioSelector maintains several lists that are reset by each call to <code>poll()</code> which are available via
 * various getters. These are reset by each call to <code>poll()</code>.
 *
 * This class is not thread safe!
 */
// SECURITY: (HIGH) Core NIO event loop handling ALL network I/O for Kafka clients and brokers.
// This class is the primary attack surface for connection-level denial-of-service (DoS) because it
// manages channel acceptance, read/write I/O, idle expiry, and authentication failure handling in a
// single-threaded select loop. A slow or malicious client can monopolize the selector thread by
// holding connections open without completing authentication, sending partial requests to keep
// channels alive, or flooding with connection attempts to exhaust file descriptors.
// Exploit: An attacker opens thousands of TCP connections without completing SASL/SSL handshakes,
// exhausting the selector's channel map and blocking legitimate clients from connecting. The
// IdleExpiryManager mitigates this but only after the configured idle timeout elapses.
// Improvement: Consider per-IP connection rate limiting at the Selector level, and enforce a
// maximum incomplete-authentication timeout shorter than the general idle timeout to shed
// unauthenticated connections more aggressively.
//
// CROSS-CUTTING: Depends on clients/.../network/KafkaChannel for per-connection state and I/O,
// clients/.../network/ChannelBuilder (SaslChannelBuilder, SslChannelBuilder, PlaintextChannelBuilder)
// for constructing authenticated channels, clients/.../memory/MemoryPool for receive buffer allocation,
// and clients/.../network/NetworkReceive / NetworkSend for framed message transport.
// Contract: KafkaChannel.ready() must return true only after authentication completes successfully.
// Impact: Changes to KafkaChannel mute/unmute semantics or ChannelBuilder authentication flow
// directly affect Selector's poll loop correctness and DoS resilience.
//
// DECISION: Single-threaded NIO selector pattern chosen over thread-per-connection model.
// Alternative: Thread-per-connection (simpler per-connection logic, natural isolation).
// Rationale: Kafka brokers handle thousands of concurrent connections; a thread-per-connection
// model would require thousands of OS threads with associated context-switch overhead and memory
// consumption. The NIO selector achieves O(1) connection management with a single thread, at the
// cost of requiring all operations to be non-blocking and the class being explicitly not thread-safe.
public class Selector implements Selectable, AutoCloseable {

    public static final long NO_IDLE_TIMEOUT_MS = -1;
    public static final int NO_FAILED_AUTHENTICATION_DELAY = 0;

    // DECISION: Three-tier close mode enum encodes the trade-off between data completeness and
    // resource reclamation. GRACEFUL allows in-flight receives to be processed (important for
    // acks=0 producers), NOTIFY_ONLY discards data but notifies upper layers, and
    // DISCARD_NO_NOTIFY silently drops the connection (used for local-initiated close).
    // Alternative: A single close() method with boolean flags. Rationale: The enum makes close
    // semantics explicit at each call site and prevents accidental flag combinations.
    private enum CloseMode {
        GRACEFUL(true),            // process outstanding buffered receives, notify disconnect
        NOTIFY_ONLY(true),         // discard any outstanding receives, notify disconnect
        DISCARD_NO_NOTIFY(false);  // discard any outstanding receives, no disconnect notification

        final boolean notifyDisconnect;

        CloseMode(boolean notifyDisconnect) {
            this.notifyDisconnect = notifyDisconnect;
        }
    }

    private final Logger log;
    private final java.nio.channels.Selector nioSelector;
    private final Map<String, KafkaChannel> channels;
    private final Set<KafkaChannel> explicitlyMutedChannels;
    private boolean outOfMemory;
    private final List<NetworkSend> completedSends;
    private final LinkedHashMap<String, NetworkReceive> completedReceives;
    private final Set<SelectionKey> immediatelyConnectedKeys;
    private final Map<String, KafkaChannel> closingChannels;
    private Set<SelectionKey> keysWithBufferedRead;
    private final Map<String, ChannelState> disconnected;
    private final List<String> connected;
    private final List<String> failedSends;
    private final Time time;
    private final SelectorMetrics sensors;
    private final ChannelBuilder channelBuilder;
    private final int maxReceiveSize;
    private final boolean recordTimePerConnection;
    private final IdleExpiryManager idleExpiryManager;
    private final LinkedHashMap<String, DelayedAuthenticationFailureClose> delayedClosingChannels;
    private final MemoryPool memoryPool;
    // DECISION: Low memory threshold set to 10% of total pool size. When available memory drops
    // below this threshold, selection key processing order is randomized to prevent starvation
    // of reads from connections that happen to appear last in the iteration order.
    // Alternative: Fixed byte threshold. Rationale: Proportional threshold adapts to different
    // pool sizes across broker and client configurations.
    private final long lowMemThreshold;
    // SECURITY: (MEDIUM) Configurable delay before closing channels after authentication failure.
    // This delay prevents timing-based probing of valid usernames by ensuring failed auth responses
    // take consistent time regardless of failure reason.
    // Exploit: Without this delay, an attacker could measure response times to distinguish
    // "invalid user" (fast reject) from "wrong password" (slower SCRAM computation), enabling
    // username enumeration.
    // Improvement: Consider adding jitter to the delay to further resist statistical timing analysis.
    private final int failedAuthenticationDelayMs;

    //indicates if the previous call to poll was able to make progress in reading already-buffered data.
    //this is used to prevent tight loops when memory is not available to read any more data
    private boolean madeReadProgressLastPoll = true;

    /**
     * Create a new nioSelector
     * @param maxReceiveSize Max size in bytes of a single network receive (use {@link NetworkReceive#UNLIMITED} for no limit)
     * @param connectionMaxIdleMs Max idle connection time (use {@link #NO_IDLE_TIMEOUT_MS} to disable idle timeout)
     * @param failedAuthenticationDelayMs Minimum time by which failed authentication response and channel close should be delayed by.
     *                                    Use {@link #NO_FAILED_AUTHENTICATION_DELAY} to disable this delay.
     * @param metrics Registry for Selector metrics
     * @param time Time implementation
     * @param metricGrpPrefix Prefix for the group of metrics registered by Selector
     * @param metricTags Additional tags to add to metrics registered by Selector
     * @param metricsPerConnection Whether or not to enable per-connection metrics
     * @param channelBuilder Channel builder for every new connection
     * @param logContext Context for logging with additional info
     */
    public Selector(int maxReceiveSize,
            long connectionMaxIdleMs,
            int failedAuthenticationDelayMs,
            Metrics metrics,
            Time time,
            String metricGrpPrefix,
            Map<String, String> metricTags,
            boolean metricsPerConnection,
            boolean recordTimePerConnection,
            ChannelBuilder channelBuilder,
            MemoryPool memoryPool,
            LogContext logContext) {
        try {
            this.nioSelector = java.nio.channels.Selector.open();
        } catch (IOException e) {
            throw new KafkaException(e);
        }
        this.maxReceiveSize = maxReceiveSize;
        this.time = time;
        this.channels = new HashMap<>();
        this.explicitlyMutedChannels = new HashSet<>();
        this.outOfMemory = false;
        this.completedSends = new ArrayList<>();
        this.completedReceives = new LinkedHashMap<>();
        this.immediatelyConnectedKeys = new HashSet<>();
        this.closingChannels = new HashMap<>();
        this.keysWithBufferedRead = new HashSet<>();
        this.connected = new ArrayList<>();
        this.disconnected = new HashMap<>();
        this.failedSends = new ArrayList<>();
        this.log = logContext.logger(Selector.class);
        this.sensors = new SelectorMetrics(metrics, metricGrpPrefix, metricTags, metricsPerConnection);
        this.channelBuilder = channelBuilder;
        this.recordTimePerConnection = recordTimePerConnection;
        this.idleExpiryManager = connectionMaxIdleMs < 0 ? null : new IdleExpiryManager(time, connectionMaxIdleMs);
        this.memoryPool = memoryPool;
        this.lowMemThreshold = (long) (0.1 * this.memoryPool.size());
        this.failedAuthenticationDelayMs = failedAuthenticationDelayMs;
        this.delayedClosingChannels = (failedAuthenticationDelayMs > NO_FAILED_AUTHENTICATION_DELAY) ? new LinkedHashMap<>() : null;
    }

    public Selector(int maxReceiveSize,
                    long connectionMaxIdleMs,
                    Metrics metrics,
                    Time time,
                    String metricGrpPrefix,
                    Map<String, String> metricTags,
                    boolean metricsPerConnection,
                    boolean recordTimePerConnection,
                    ChannelBuilder channelBuilder,
                    MemoryPool memoryPool,
                    LogContext logContext) {
        this(maxReceiveSize, connectionMaxIdleMs, NO_FAILED_AUTHENTICATION_DELAY, metrics, time, metricGrpPrefix, metricTags,
                metricsPerConnection, recordTimePerConnection, channelBuilder, memoryPool, logContext);
    }

    public Selector(int maxReceiveSize,
                    long connectionMaxIdleMs,
                    int failedAuthenticationDelayMs,
                    Metrics metrics,
                    Time time,
                    String metricGrpPrefix,
                    Map<String, String> metricTags,
                    boolean metricsPerConnection,
                    ChannelBuilder channelBuilder,
                    LogContext logContext) {
        this(maxReceiveSize, connectionMaxIdleMs, failedAuthenticationDelayMs, metrics, time, metricGrpPrefix, metricTags, metricsPerConnection, false, channelBuilder, MemoryPool.NONE, logContext);
    }

    public Selector(int maxReceiveSize,
                    long connectionMaxIdleMs,
                    Metrics metrics,
                    Time time,
                    String metricGrpPrefix,
                    Map<String, String> metricTags,
                    boolean metricsPerConnection,
                    ChannelBuilder channelBuilder,
                    LogContext logContext) {
        this(maxReceiveSize, connectionMaxIdleMs, NO_FAILED_AUTHENTICATION_DELAY, metrics, time, metricGrpPrefix, metricTags, metricsPerConnection, channelBuilder, logContext);
    }

    public Selector(long connectionMaxIdleMS, Metrics metrics, Time time, String metricGrpPrefix, ChannelBuilder channelBuilder, LogContext logContext) {
        this(NetworkReceive.UNLIMITED, connectionMaxIdleMS, metrics, time, metricGrpPrefix, Collections.emptyMap(), true, channelBuilder, logContext);
    }

    public Selector(long connectionMaxIdleMS, int failedAuthenticationDelayMs, Metrics metrics, Time time, String metricGrpPrefix, ChannelBuilder channelBuilder, LogContext logContext) {
        this(NetworkReceive.UNLIMITED, connectionMaxIdleMS, failedAuthenticationDelayMs, metrics, time, metricGrpPrefix, Collections.emptyMap(), true, channelBuilder, logContext);
    }

    /**
     * Begin connecting to the given address and add the connection to this nioSelector associated with the given id
     * number.
     * <p>
     * Note that this call only initiates the connection, which will be completed on a future {@link #poll(long)}
     * call. Check {@link #connected()} to see which (if any) connections have completed after a given poll call.
     * @param id The id for the new connection
     * @param address The address to connect to
     * @param sendBufferSize The send buffer for the new connection
     * @param receiveBufferSize The receive buffer for the new connection
     * @throws IllegalStateException if there is already a connection for that id
     * @throws IOException if DNS resolution fails on the hostname or if the broker is down
     */
    @Override
    public void connect(String id, InetSocketAddress address, int sendBufferSize, int receiveBufferSize) throws IOException {
        ensureNotRegistered(id);
        SocketChannel socketChannel = SocketChannel.open();
        SelectionKey key = null;
        try {
            configureSocketChannel(socketChannel, sendBufferSize, receiveBufferSize);
            boolean connected = doConnect(socketChannel, address);
            key = registerChannel(id, socketChannel, SelectionKey.OP_CONNECT);

            if (connected) {
                // OP_CONNECT won't trigger for immediately connected channels
                log.debug("Immediately connected to node {}", id);
                immediatelyConnectedKeys.add(key);
                key.interestOps(0);
            }
        } catch (IOException | RuntimeException e) {
            if (key != null)
                immediatelyConnectedKeys.remove(key);
            channels.remove(id);
            socketChannel.close();
            throw e;
        }
    }

    // Visible to allow test cases to override. In particular, we use this to implement a blocking connect
    // in order to simulate "immediately connected" sockets.
    protected boolean doConnect(SocketChannel channel, InetSocketAddress address) throws IOException {
        try {
            return channel.connect(address);
        } catch (UnresolvedAddressException e) {
            throw new IOException("Can't resolve address: " + address, e);
        }
    }

    private void configureSocketChannel(SocketChannel socketChannel, int sendBufferSize, int receiveBufferSize)
            throws IOException {
        socketChannel.configureBlocking(false);
        Socket socket = socketChannel.socket();
        socket.setKeepAlive(true);
        if (sendBufferSize != Selectable.USE_DEFAULT_BUFFER_SIZE)
            socket.setSendBufferSize(sendBufferSize);
        if (receiveBufferSize != Selectable.USE_DEFAULT_BUFFER_SIZE)
            socket.setReceiveBufferSize(receiveBufferSize);
        socket.setTcpNoDelay(true);
    }

    /**
     * Register the nioSelector with an existing channel
     * Use this on server-side, when a connection is accepted by a different thread but processed by the Selector
     * <p>
     * If a connection already exists with the same connection id in `channels` or `closingChannels`,
     * an exception is thrown. Connection ids must be chosen to avoid conflict when remote ports are reused.
     * Kafka brokers add an incrementing index to the connection id to avoid reuse in the timing window
     * where an existing connection may not yet have been closed by the broker when a new connection with
     * the same remote host:port is processed.
     * </p><p>
     * If a `KafkaChannel` cannot be created for this connection, the `socketChannel` is closed
     * and its selection key cancelled.
     * </p>
     */
    public void register(String id, SocketChannel socketChannel) throws IOException {
        ensureNotRegistered(id);
        registerChannel(id, socketChannel, SelectionKey.OP_READ);
        this.sensors.connectionCreated.record();
        // Default to empty client information as the ApiVersionsRequest is not
        // mandatory. In this case, we still want to account for the connection.
        ChannelMetadataRegistry metadataRegistry = this.channel(id).channelMetadataRegistry();
        if (metadataRegistry.clientInformation() == null)
            metadataRegistry.registerClientInformation(ClientInformation.EMPTY);
    }

    private void ensureNotRegistered(String id) {
        if (this.channels.containsKey(id))
            throw new IllegalStateException("There is already a connection for id " + id);
        if (this.closingChannels.containsKey(id))
            throw new IllegalStateException("There is already a connection for id " + id + " that is still being closed");
    }

    protected SelectionKey registerChannel(String id, SocketChannel socketChannel, int interestedOps) throws IOException {
        SelectionKey key = socketChannel.register(nioSelector, interestedOps);
        KafkaChannel channel = buildAndAttachKafkaChannel(socketChannel, id, key);
        this.channels.put(id, channel);
        if (idleExpiryManager != null)
            idleExpiryManager.update(channel.id(), time.nanoseconds());
        return key;
    }

    private KafkaChannel buildAndAttachKafkaChannel(SocketChannel socketChannel, String id, SelectionKey key) throws IOException {
        ChannelMetadataRegistry metadataRegistry = null;
        try {
            metadataRegistry = new SelectorChannelMetadataRegistry();
            KafkaChannel channel = channelBuilder.buildChannel(id, key, maxReceiveSize, memoryPool, metadataRegistry);
            key.attach(channel);
            return channel;
        } catch (Exception e) {
            try {
                socketChannel.close();
            } finally {
                key.cancel();
            }
            // Ideally, these resources are closed by the KafkaChannel but if the KafkaChannel is not created to an
            // error, this builder should close the resources it has created instead.
            Utils.closeQuietly(metadataRegistry, "metadataRegistry");
            throw new IOException("Channel could not be created for socket " + socketChannel, e);
        }
    }

    /**
     * Interrupt the nioSelector if it is blocked waiting to do I/O.
     */
    @Override
    public void wakeup() {
        this.nioSelector.wakeup();
    }

    /**
     * Close this selector and all associated connections
     */
    @Override
    public void close() {
        List<String> connections = new ArrayList<>(channels.keySet());
        AtomicReference<Throwable> firstException = new AtomicReference<>();
        Utils.closeAllQuietly(firstException, "release connections",
                connections.stream().map(id -> (AutoCloseable) () -> close(id)).toArray(AutoCloseable[]::new));
        // If there is any exception thrown in close(id), we should still be able
        // to close the remaining objects, especially the sensors because keeping
        // the sensors may lead to failure to start up the ReplicaFetcherThread if
        // the old sensors with the same names has not yet been cleaned up.
        Utils.closeQuietly(nioSelector, "nioSelector", firstException);
        Utils.closeQuietly(sensors, "sensors", firstException);
        Utils.closeQuietly(channelBuilder, "channelBuilder", firstException);
        Throwable exception = firstException.get();
        if (exception instanceof RuntimeException && !(exception instanceof SecurityException)) {
            throw (RuntimeException) exception;
        }
    }

    /**
     * Queue the given request for sending in the subsequent {@link #poll(long)} calls
     * @param send The request to send
     */
    public void send(NetworkSend send) {
        String connectionId = send.destinationId();
        KafkaChannel channel = openOrClosingChannelOrFail(connectionId);
        if (closingChannels.containsKey(connectionId)) {
            // ensure notification via `disconnected`, leave channel in the state in which closing was triggered
            this.failedSends.add(connectionId);
        } else {
            try {
                channel.setSend(send);
            } catch (Exception e) {
                // update the state for consistency, the channel will be discarded after `close`
                channel.state(ChannelState.FAILED_SEND);
                // ensure notification via `disconnected` when `failedSends` are processed in the next poll
                this.failedSends.add(connectionId);
                close(channel, CloseMode.DISCARD_NO_NOTIFY);
                if (!(e instanceof CancelledKeyException)) {
                    log.error("Unexpected exception during send, closing connection {} and rethrowing exception.",
                            connectionId, e);
                    throw e;
                }
            }
        }
    }

    /**
     * Do whatever I/O can be done on each connection without blocking. This includes completing connections, completing
     * disconnections, initiating new sends, or making progress on in-progress sends or receives.
     *
     * When this call is completed the user can check for completed sends, receives, connections or disconnects using
     * {@link #completedSends()}, {@link #completedReceives()}, {@link #connected()}, {@link #disconnected()}. These
     * lists will be cleared at the beginning of each `poll` call and repopulated by the call if there is
     * any completed I/O.
     *
     * In the "Plaintext" setting, we are using socketChannel to read & write to the network. But for the "SSL" setting,
     * we encrypt the data before we use socketChannel to write data to the network, and decrypt before we return the responses.
     * This requires additional buffers to be maintained as we are reading from network, since the data on the wire is encrypted
     * we won't be able to read exact no.of bytes as kafka protocol requires. We read as many bytes as we can, up to SSLEngine's
     * application buffer size. This means we might be reading additional bytes than the requested size.
     * If there is no further data to read from socketChannel selector won't invoke that channel and we have additional bytes
     * in the buffer. To overcome this issue we added "keysWithBufferedRead" map which tracks channels which have data in the SSL
     * buffers. If there are channels with buffered data that can by processed, we set "timeout" to 0 and process the data even
     * if there is no more data to read from the socket.
     *
     * At most one entry is added to "completedReceives" for a channel in each poll. This is necessary to guarantee that
     * requests from a channel are processed on the broker in the order they are sent. Since outstanding requests added
     * by SocketServer to the request queue may be processed by different request handler threads, requests on each
     * channel must be processed one-at-a-time to guarantee ordering.
     *
     * @param timeout The amount of time to wait, in milliseconds, which must be non-negative
     * @throws IllegalArgumentException If `timeout` is negative
     * @throws IllegalStateException If a send is given for which we have no existing connection or for which there is
     *         already an in-progress send
     */
    // COMPLEXITY: Method size ~72 lines — multi-phase I/O polling with memory pressure recovery,
    // NIO select, three-pass key processing (buffered, ready, immediately-connected), delayed
    // channel close completion, and idle connection expiry.
    // Structure: (1) Memory recovery — unmute channels if memory pressure has lifted;
    // (2) NIO select with adaptive timeout (0 if buffered data or immediate connections exist);
    // (3) Three pollSelectionKeys passes: buffered-data keys, socket-ready keys, immediately-connected keys;
    // (4) Post-I/O delayed close completion; (5) Idle connection expiry check.
    // Key paths: Fast path when no ready keys and no buffered data skips all processing;
    // memory-pressure path shuffles key order to prevent starvation.
    @Override
    public void poll(long timeout) throws IOException {
        if (timeout < 0)
            throw new IllegalArgumentException("timeout should be >= 0");

        boolean madeReadProgressLastCall = madeReadProgressLastPoll;
        clear();

        boolean dataInBuffers = !keysWithBufferedRead.isEmpty();

        if (!immediatelyConnectedKeys.isEmpty() || (madeReadProgressLastCall && dataInBuffers))
            timeout = 0;

        if (!memoryPool.isOutOfMemory() && outOfMemory) {
            //we have recovered from memory pressure. unmute any channel not explicitly muted for other reasons
            log.trace("Broker no longer low on memory - unmuting incoming sockets");
            for (KafkaChannel channel : channels.values()) {
                if (channel.isInMutableState() && !explicitlyMutedChannels.contains(channel)) {
                    channel.maybeUnmute();
                }
            }
            outOfMemory = false;
        }

        /* check ready keys */
        long startSelect = time.nanoseconds();
        int numReadyKeys = select(timeout);
        long endSelect = time.nanoseconds();
        this.sensors.selectTime.record(endSelect - startSelect, time.milliseconds(), false);

        if (numReadyKeys > 0 || !immediatelyConnectedKeys.isEmpty() || dataInBuffers) {
            Set<SelectionKey> readyKeys = this.nioSelector.selectedKeys();

            // Poll from channels that have buffered data (but nothing more from the underlying socket)
            if (dataInBuffers) {
                keysWithBufferedRead.removeAll(readyKeys); //so no channel gets polled twice
                Set<SelectionKey> toPoll = keysWithBufferedRead;
                keysWithBufferedRead = new HashSet<>(); //poll() calls will repopulate if needed
                pollSelectionKeys(toPoll, false, endSelect);
            }

            // Poll from channels where the underlying socket has more data
            pollSelectionKeys(readyKeys, false, endSelect);
            // Clear all selected keys so that they are excluded from the ready count for the next select
            readyKeys.clear();

            pollSelectionKeys(immediatelyConnectedKeys, true, endSelect);
            immediatelyConnectedKeys.clear();
        } else {
            madeReadProgressLastPoll = true; //no work is also "progress"
        }

        long endIo = time.nanoseconds();
        this.sensors.ioTime.record(endIo - endSelect, time.milliseconds(), false);

        // Close channels that were delayed and are now ready to be closed
        completeDelayedChannelClose(endIo);

        // we use the time at the end of select to ensure that we don't close any connections that
        // have just been processed in pollSelectionKeys
        maybeCloseOldestConnection(endSelect);
    }

    /**
     * handle any ready I/O on a set of selection keys
     * @param selectionKeys set of keys to handle
     * @param isImmediatelyConnected true if running over a set of keys for just-connected sockets
     * @param currentTimeNanos time at which set of keys was determined
     */
    // COMPLEXITY: Method size ~121 lines — per-key I/O dispatch handling connection completion,
    // authentication handshake, read, write, and error recovery for each selected channel.
    // Structure: For each key: (1) finish TCP connect if connectable; (2) drive authentication
    // handshake via channel.prepare() if connected but not ready; (3) read if ready and readable
    // with no completed receive pending; (4) track buffered-read keys; (5) attempt write if
    // channel has pending send; (6) close defunct keys. Exception handling distinguishes IOException
    // (normal disconnect), AuthenticationException (auth failure with optional delayed close), and
    // unexpected errors (logged as warnings).
    // Key paths: Authentication success records metrics and logs; re-authentication updates
    // separate sensors; delayed auth failure close defers channel teardown by configured delay.
    //
    // SECURITY: (HIGH) This method drives the authentication state machine for every connection.
    // The channel.prepare() call invokes SASL/SSL handshake processing. A malicious client that
    // connects but never completes the handshake holds a channel in the not-ready state indefinitely,
    // consuming selector resources.
    // Exploit: An attacker opens connections and sends partial SASL handshake data, keeping channels
    // in the prepare() loop across multiple poll cycles without ever completing authentication,
    // thereby exhausting the channel map capacity.
    // Improvement: Enforce a per-channel authentication timeout that closes channels still in
    // prepare() state after a configurable deadline, independent of the general idle timeout.
    // package-private for testing
    void pollSelectionKeys(Set<SelectionKey> selectionKeys,
                           boolean isImmediatelyConnected,
                           long currentTimeNanos) {
        for (SelectionKey key : determineHandlingOrder(selectionKeys)) {
            KafkaChannel channel = channel(key);
            long channelStartTimeNanos = recordTimePerConnection ? time.nanoseconds() : 0;
            boolean sendFailed = false;
            String nodeId = channel.id();

            // register all per-connection metrics at once
            sensors.maybeRegisterConnectionMetrics(nodeId);
            if (idleExpiryManager != null)
                idleExpiryManager.update(nodeId, currentTimeNanos);

            try {
                /* complete any connections that have finished their handshake (either normally or immediately) */
                if (isImmediatelyConnected || key.isConnectable()) {
                    if (channel.finishConnect()) {
                        this.connected.add(nodeId);
                        this.sensors.connectionCreated.record();

                        SocketChannel socketChannel = (SocketChannel) key.channel();
                        log.debug("Created socket with SO_RCVBUF = {}, SO_SNDBUF = {}, SO_TIMEOUT = {} to node {}",
                                socketChannel.socket().getReceiveBufferSize(),
                                socketChannel.socket().getSendBufferSize(),
                                socketChannel.socket().getSoTimeout(),
                                nodeId);
                    } else {
                        continue;
                    }
                }

                /* if channel is not ready finish prepare */
                if (channel.isConnected() && !channel.ready()) {
                    channel.prepare();
                    if (channel.ready()) {
                        long readyTimeMs = time.milliseconds();
                        boolean isReauthentication = channel.successfulAuthentications() > 1;
                        if (isReauthentication) {
                            sensors.successfulReauthentication.record(1.0, readyTimeMs);
                            channel.maybeAddWriteInterestAfterReauth();
                            if (channel.reauthenticationLatencyMs() == null)
                                log.warn(
                                    "Should never happen: re-authentication latency for a re-authenticated channel was null; continuing...");
                            else
                                sensors.reauthenticationLatency
                                    .record(channel.reauthenticationLatencyMs().doubleValue(), readyTimeMs);
                        } else {
                            sensors.successfulAuthentication.record(1.0, readyTimeMs);
                            if (!channel.connectedClientSupportsReauthentication())
                                sensors.successfulAuthenticationNoReauth.record(1.0, readyTimeMs);
                        }
                        log.debug("Successfully {}authenticated with {}", isReauthentication ?
                            "re-" : "", channel.socketDescription());
                    }
                }
                if (channel.ready() && channel.state() == ChannelState.NOT_CONNECTED)
                    channel.state(ChannelState.READY);
                Optional<NetworkReceive> responseReceivedDuringReauthentication = channel.pollResponseReceivedDuringReauthentication();
                responseReceivedDuringReauthentication.ifPresent(receive -> {
                    long currentTimeMs = time.milliseconds();
                    addToCompletedReceives(channel, receive, currentTimeMs);
                });

                //if channel is ready and has bytes to read from socket or buffer, and has no
                //previous completed receive then read from it
                if (channel.ready() && (key.isReadable() || channel.hasBytesBuffered()) && !hasCompletedReceive(channel)
                        && !explicitlyMutedChannels.contains(channel)) {
                    attemptRead(channel);
                }

                if (channel.hasBytesBuffered() && !explicitlyMutedChannels.contains(channel)) {
                    //this channel has bytes enqueued in intermediary buffers that we could not read
                    //(possibly because no memory). it may be the case that the underlying socket will
                    //not come up in the next poll() and so we need to remember this channel for the
                    //next poll call otherwise data may be stuck in said buffers forever. If we attempt
                    //to process buffered data and no progress is made, the channel buffered status is
                    //cleared to avoid the overhead of checking every time.
                    keysWithBufferedRead.add(key);
                }

                /* if channel is ready write to any sockets that have space in their buffer and for which we have data */

                long nowNanos = channelStartTimeNanos != 0 ? channelStartTimeNanos : currentTimeNanos;
                try {
                    attemptWrite(key, channel, nowNanos);
                } catch (Exception e) {
                    sendFailed = true;
                    throw e;
                }

                /* cancel any defunct sockets */
                if (!key.isValid())
                    close(channel, CloseMode.GRACEFUL);

            } catch (Exception e) {
                String desc = String.format("%s (channelId=%s)", channel.socketDescription(), channel.id());
                if (e instanceof IOException) {
                    log.debug("Connection with {} disconnected", desc, e);
                } else if (e instanceof AuthenticationException) {
                    boolean isReauthentication = channel.successfulAuthentications() > 0;
                    if (isReauthentication)
                        sensors.failedReauthentication.record();
                    else
                        sensors.failedAuthentication.record();
                    String exceptionMessage = e.getMessage();
                    if (e instanceof DelayedResponseAuthenticationException)
                        exceptionMessage = e.getCause().getMessage();
                    log.info("Failed {}authentication with {} ({})", isReauthentication ? "re-" : "",
                        desc, exceptionMessage);
                } else {
                    log.warn("Unexpected error from {}; closing connection", desc, e);
                }

                if (e instanceof DelayedResponseAuthenticationException)
                    maybeDelayCloseOnAuthenticationFailure(channel);
                else
                    close(channel, sendFailed ? CloseMode.NOTIFY_ONLY : CloseMode.GRACEFUL);
            } finally {
                maybeRecordTimePerConnection(channel, channelStartTimeNanos);
            }
        }
    }

    private void attemptWrite(SelectionKey key, KafkaChannel channel, long nowNanos) throws IOException {
        if (channel.hasSend()
                && channel.ready()
                && key.isWritable()
                && !channel.maybeBeginClientReauthentication(() -> nowNanos)) {
            write(channel);
        }
    }

    // package-private for testing
    void write(KafkaChannel channel) throws IOException {
        String nodeId = channel.id();
        long bytesSent = channel.write();
        NetworkSend send = channel.maybeCompleteSend();
        // We may complete the send with bytesSent < 1 if `TransportLayer.hasPendingWrites` was true and `channel.write()`
        // caused the pending writes to be written to the socket channel buffer
        if (bytesSent > 0 || send != null) {
            long currentTimeMs = time.milliseconds();
            if (bytesSent > 0)
                this.sensors.recordBytesSent(nodeId, bytesSent, currentTimeMs);
            if (send != null) {
                this.completedSends.add(send);
                this.sensors.recordCompletedSend(nodeId, send.size(), currentTimeMs);
            }
        }
    }

    // DECISION: Key processing order is randomized under memory pressure to prevent read starvation.
    // Alternative: Always process in NIO iteration order (deterministic but unfair under pressure).
    // Rationale: NIO selection key iteration order may be stable across invocations, causing the
    // same channels to be processed first. Under low memory, early channels consume available
    // buffers while later channels are perpetually starved. Shuffling ensures fair access.
    private Collection<SelectionKey> determineHandlingOrder(Set<SelectionKey> selectionKeys) {
        //it is possible that the iteration order over selectionKeys is the same every invocation.
        //this may cause starvation of reads when memory is low. to address this we shuffle the keys if memory is low.
        if (!outOfMemory && memoryPool.availableMemory() < lowMemThreshold) {
            List<SelectionKey> shuffledKeys = new ArrayList<>(selectionKeys);
            Collections.shuffle(shuffledKeys);
            return shuffledKeys;
        } else {
            return selectionKeys;
        }
    }

    // SECURITY: (MEDIUM) Read path enforces maxReceiveSize via NetworkReceive to prevent a
    // malicious client from sending an oversized request that exhausts broker heap memory.
    // The channel auto-mutes itself when the MemoryPool cannot allocate a receive buffer,
    // setting outOfMemory=true to trigger global back-pressure in the next poll cycle.
    // Exploit: A client sends a request header declaring a very large payload size, forcing
    // the selector to attempt a large buffer allocation. The maxReceiveSize cap and memory
    // pool back-pressure mitigate this, but the pool must be correctly sized.
    // Improvement: Consider per-connection memory accounting to prevent a single connection
    // from consuming a disproportionate share of the memory pool.
    private void attemptRead(KafkaChannel channel) throws IOException {
        String nodeId = channel.id();

        long bytesReceived = channel.read();
        if (bytesReceived != 0) {
            long currentTimeMs = time.milliseconds();
            sensors.recordBytesReceived(nodeId, bytesReceived, currentTimeMs);
            madeReadProgressLastPoll = true;

            NetworkReceive receive = channel.maybeCompleteReceive();
            if (receive != null) {
                addToCompletedReceives(channel, receive, currentTimeMs);
            }
        }
        if (channel.isMuted()) {
            outOfMemory = true; //channel has muted itself due to memory pressure.
        } else {
            madeReadProgressLastPoll = true;
        }
    }

    private boolean maybeReadFromClosingChannel(KafkaChannel channel) {
        boolean hasPending;
        if (channel.state().state() != ChannelState.State.READY)
            hasPending = false;
        else if (explicitlyMutedChannels.contains(channel) || hasCompletedReceive(channel))
            hasPending = true;
        else {
            try {
                attemptRead(channel);
                hasPending = hasCompletedReceive(channel);
            } catch (Exception e) {
                log.trace("Read from closing channel failed, ignoring exception", e);
                hasPending = false;
            }
        }
        return hasPending;
    }

    // Record time spent in pollSelectionKeys for channel (moved into a method to keep checkstyle happy)
    private void maybeRecordTimePerConnection(KafkaChannel channel, long startTimeNanos) {
        if (recordTimePerConnection)
            channel.addNetworkThreadTimeNanos(time.nanoseconds() - startTimeNanos);
    }

    @Override
    public List<NetworkSend> completedSends() {
        return this.completedSends;
    }

    @Override
    public Collection<NetworkReceive> completedReceives() {
        return this.completedReceives.values();
    }

    @Override
    public Map<String, ChannelState> disconnected() {
        return this.disconnected;
    }

    @Override
    public List<String> connected() {
        return this.connected;
    }

    @Override
    public void mute(String id) {
        KafkaChannel channel = openOrClosingChannelOrFail(id);
        mute(channel);
    }

    private void mute(KafkaChannel channel) {
        channel.mute();
        explicitlyMutedChannels.add(channel);
        keysWithBufferedRead.remove(channel.selectionKey());
    }

    @Override
    public void unmute(String id) {
        KafkaChannel channel = openOrClosingChannelOrFail(id);
        unmute(channel);
    }

    private void unmute(KafkaChannel channel) {
        // Remove the channel from explicitlyMutedChannels only if the channel has been actually unmuted.
        if (channel.maybeUnmute()) {
            explicitlyMutedChannels.remove(channel);
            if (channel.hasBytesBuffered()) {
                keysWithBufferedRead.add(channel.selectionKey());
                madeReadProgressLastPoll = true;
            }
        }
    }

    @Override
    public void muteAll() {
        for (KafkaChannel channel : this.channels.values())
            mute(channel);
    }

    @Override
    public void unmuteAll() {
        for (KafkaChannel channel : this.channels.values())
            unmute(channel);
    }

    // package-private for testing
    void completeDelayedChannelClose(long currentTimeNanos) {
        if (delayedClosingChannels == null)
            return;

        while (!delayedClosingChannels.isEmpty()) {
            DelayedAuthenticationFailureClose delayedClose = delayedClosingChannels.values().iterator().next();
            if (!delayedClose.tryClose(currentTimeNanos))
                break;
        }
    }

    // SECURITY: (MEDIUM) Idle connection expiry closes the least-recently-used connection when
    // the idle timeout elapses. This bounds resource consumption from connections that complete
    // authentication but then go silent (slowloris-style resource exhaustion).
    // Exploit: An attacker completes authentication on many connections and then holds them idle
    // just under the timeout, periodically sending keep-alive pings to prevent expiry while
    // consuming file descriptors and channel map entries.
    // Improvement: Enforce a hard per-IP connection limit in addition to idle timeout to prevent
    // a single source from monopolizing connection slots.
    private void maybeCloseOldestConnection(long currentTimeNanos) {
        if (idleExpiryManager == null)
            return;

        Map.Entry<String, Long> expiredConnection = idleExpiryManager.pollExpiredConnection(currentTimeNanos);
        if (expiredConnection != null) {
            String connectionId = expiredConnection.getKey();
            KafkaChannel channel = this.channels.get(connectionId);
            if (channel != null) {
                if (log.isTraceEnabled())
                    log.trace("About to close the idle connection from {} due to being idle for {} millis",
                            connectionId, (currentTimeNanos - expiredConnection.getValue()) / 1000 / 1000);
                channel.state(ChannelState.EXPIRED);
                close(channel, CloseMode.GRACEFUL);
            }
        }
    }

    /**
     * Clears completed receives. This is used by SocketServer to remove references to
     * receive buffers after processing completed receives, without waiting for the next
     * poll().
     */
    public void clearCompletedReceives() {
        this.completedReceives.clear();
    }

    /**
     * Clears completed sends. This is used by SocketServer to remove references to
     * send buffers after processing completed sends, without waiting for the next
     * poll().
     */
    public void clearCompletedSends() {
        this.completedSends.clear();
    }

    /**
     * Clears all the results from the previous poll. This is invoked by Selector at the start of
     * a poll() when all the results from the previous poll are expected to have been handled.
     * <p>
     * SocketServer uses {@link #clearCompletedSends()} and {@link #clearCompletedReceives()} to
     * clear `completedSends` and `completedReceives` as soon as they are processed to avoid
     * holding onto large request/response buffers from multiple connections longer than necessary.
     * Clients rely on Selector invoking {@link #clear()} at the start of each poll() since memory usage
     * is less critical and clearing once-per-poll provides the flexibility to process these results in
     * any order before the next poll.
     */
    // COMPLEXITY: Method size ~39 lines — resets per-poll state lists and processes closing
    // channels. Structure: (1) Clear completedSends, completedReceives, connected, disconnected;
    // (2) Iterate closingChannels: attempt final read, close if no pending receives or if send
    // failed; (3) Convert failedSends to disconnect notifications; (4) Reset progress flag.
    // Key paths: closingChannels iteration may trigger reads from channels with buffered data
    // (GRACEFUL close mode), allowing acks=0 producer records to be fully processed before teardown.
    private void clear() {
        this.completedSends.clear();
        this.completedReceives.clear();
        this.connected.clear();
        this.disconnected.clear();

        // Remove closed channels after all their buffered receives have been processed or if a send was requested
        for (Iterator<Map.Entry<String, KafkaChannel>> it = closingChannels.entrySet().iterator(); it.hasNext(); ) {
            KafkaChannel channel = it.next().getValue();
            boolean sendFailed = failedSends.remove(channel.id());
            boolean hasPending = false;
            if (!sendFailed)
                hasPending = maybeReadFromClosingChannel(channel);
            if (!hasPending) {
                doClose(channel, true);
                it.remove();
            }
        }

        for (String channel : this.failedSends)
            this.disconnected.put(channel, ChannelState.FAILED_SEND);
        this.failedSends.clear();
        this.madeReadProgressLastPoll = false;
    }

    /**
     * Check for data, waiting up to the given timeout.
     *
     * @param timeoutMs Length of time to wait, in milliseconds, which must be non-negative
     * @return The number of keys ready
     */
    private int select(long timeoutMs) throws IOException {
        if (timeoutMs < 0L)
            throw new IllegalArgumentException("timeout should be >= 0");

        if (timeoutMs == 0L)
            return this.nioSelector.selectNow();
        else
            return this.nioSelector.select(timeoutMs);
    }

    /**
     * Close the connection identified by the given id
     */
    public void close(String id) {
        KafkaChannel channel = this.channels.get(id);
        if (channel != null) {
            // There is no disconnect notification for local close, but updating
            // channel state here anyway to avoid confusion.
            channel.state(ChannelState.LOCAL_CLOSE);
            close(channel, CloseMode.DISCARD_NO_NOTIFY);
        } else {
            KafkaChannel closingChannel = this.closingChannels.remove(id);
            // Close any closing channel, leave the channel in the state in which closing was triggered
            if (closingChannel != null)
                doClose(closingChannel, false);
        }
    }

    // SECURITY: (HIGH) Delays channel close after authentication failure to prevent timing-based
    // username enumeration. The delay is configured by failedAuthenticationDelayMs and ensures
    // that failed authentication responses are sent before the channel is torn down.
    // Exploit: Without this delay, an attacker could use response timing differences to enumerate
    // valid usernames (fast reject for unknown user vs. slower SCRAM computation for known user).
    // Improvement: Add random jitter to the delay to defeat statistical timing analysis across
    // multiple probes.
    private void maybeDelayCloseOnAuthenticationFailure(KafkaChannel channel) {
        DelayedAuthenticationFailureClose delayedClose = new DelayedAuthenticationFailureClose(channel, failedAuthenticationDelayMs);
        if (delayedClosingChannels != null)
            delayedClosingChannels.put(channel.id(), delayedClose);
        else
            delayedClose.closeNow();
    }

    private void handleCloseOnAuthenticationFailure(KafkaChannel channel) {
        try {
            channel.completeCloseOnAuthenticationFailure();
        } catch (Exception e) {
            log.error("Exception handling close on authentication failure node {}", channel.id(), e);
        } finally {
            close(channel, CloseMode.GRACEFUL);
        }
    }

    /**
     * Begin closing this connection.
     * If 'closeMode' is `CloseMode.GRACEFUL`, the channel is disconnected here, but outstanding receives
     * are processed. The channel is closed when there are no outstanding receives or if a send is
     * requested. For other values of `closeMode`, outstanding receives are discarded and the channel
     * is closed immediately.
     *
     * The channel will be added to disconnect list when it is actually closed if `closeMode.notifyDisconnect`
     * is true.
     */
    // SECURITY: (MEDIUM) Channel close must clean up all state maps (channels, closingChannels,
    // delayedClosingChannels, idleExpiryManager, immediatelyConnectedKeys) to prevent resource
    // leaks that could be exploited for DoS. The GRACEFUL mode retains the channel in
    // closingChannels to process buffered receives, creating a window where the channel consumes
    // resources after disconnect.
    // Exploit: A client that disconnects mid-stream with buffered data forces the channel into
    // closingChannels, where it remains until the next poll drains buffered receives. Many such
    // connections could accumulate in closingChannels.
    // Improvement: Bound the number of channels in closingChannels and force-close the oldest
    // when the limit is exceeded.
    private void close(KafkaChannel channel, CloseMode closeMode) {
        channel.disconnect();

        // Ensure that `connected` does not have closed channels. This could happen if `prepare` throws an exception
        // in the `poll` invocation when `finishConnect` succeeds
        connected.remove(channel.id());

        // Keep track of closed channels with pending receives so that all received records
        // may be processed. For example, when producer with acks=0 sends some records and
        // closes its connections, a single poll() in the broker may receive records and
        // handle close(). When the remote end closes its connection, the channel is retained until
        // a send fails or all outstanding receives are processed. Mute state of disconnected channels
        // are tracked to ensure that requests are processed one-by-one by the broker to preserve ordering.
        if (closeMode == CloseMode.GRACEFUL && maybeReadFromClosingChannel(channel)) {
            closingChannels.put(channel.id(), channel);
            log.debug("Tracking closing connection {} to process outstanding requests", channel.id());
        } else {
            doClose(channel, closeMode.notifyDisconnect);
        }
        this.channels.remove(channel.id());

        if (delayedClosingChannels != null)
            delayedClosingChannels.remove(channel.id());

        if (idleExpiryManager != null)
            idleExpiryManager.remove(channel.id());
    }

    private void doClose(KafkaChannel channel, boolean notifyDisconnect) {
        SelectionKey key = channel.selectionKey();
        try {
            immediatelyConnectedKeys.remove(key);
            keysWithBufferedRead.remove(key);
            channel.close();
        } catch (IOException e) {
            log.error("Exception closing connection to node {}:", channel.id(), e);
        } finally {
            key.cancel();
            key.attach(null);
        }

        this.sensors.connectionClosed.record();
        this.explicitlyMutedChannels.remove(channel);
        if (notifyDisconnect)
            this.disconnected.put(channel.id(), channel.state());
    }

    /**
     * check if channel is ready
     */
    @Override
    public boolean isChannelReady(String id) {
        KafkaChannel channel = this.channels.get(id);
        return channel != null && channel.ready();
    }

    private KafkaChannel openOrClosingChannelOrFail(String id) {
        KafkaChannel channel = this.channels.get(id);
        if (channel == null)
            channel = this.closingChannels.get(id);
        if (channel == null)
            throw new IllegalStateException("Attempt to retrieve channel for which there is no connection. Connection id " + id + " existing connections " + channels.keySet());
        return channel;
    }

    /**
     * Return the selector channels.
     */
    public List<KafkaChannel> channels() {
        return new ArrayList<>(channels.values());
    }

    /**
     * Return the channel associated with this connection or `null` if there is no channel associated with the
     * connection.
     */
    public KafkaChannel channel(String id) {
        return this.channels.get(id);
    }

    /**
     * Return the channel with the specified id if it was disconnected, but not yet closed
     * since there are outstanding messages to be processed.
     */
    public KafkaChannel closingChannel(String id) {
        return closingChannels.get(id);
    }

    /**
     * Returns the lowest priority channel chosen using the following sequence:
     *   1) If one or more channels are in closing state, return any one of them
     *   2) If idle expiry manager is enabled, return the least recently updated channel
     *   3) Otherwise return any of the channels
     *
     * This method is used to close a channel to accommodate a new channel on the inter-broker listener
     * when broker-wide `max.connections` limit is enabled.
     */
    public KafkaChannel lowestPriorityChannel() {
        KafkaChannel channel = null;
        if (!closingChannels.isEmpty()) {
            channel = closingChannels.values().iterator().next();
        } else if (idleExpiryManager != null && !idleExpiryManager.lruConnections.isEmpty()) {
            String channelId = idleExpiryManager.lruConnections.keySet().iterator().next();
            channel = channel(channelId);
        } else if (!channels.isEmpty()) {
            channel = channels.values().iterator().next();
        }
        return channel;
    }

    /**
     * Get the channel associated with selectionKey
     */
    private KafkaChannel channel(SelectionKey key) {
        return (KafkaChannel) key.attachment();
    }

    /**
     * Check if given channel has a completed receive
     */
    private boolean hasCompletedReceive(KafkaChannel channel) {
        return completedReceives.containsKey(channel.id());
    }

    /**
     * adds a receive to completed receives
     */
    private void addToCompletedReceives(KafkaChannel channel, NetworkReceive networkReceive, long currentTimeMs) {
        if (hasCompletedReceive(channel))
            throw new IllegalStateException("Attempting to add second completed receive to channel " + channel.id());

        this.completedReceives.put(channel.id(), networkReceive);
        sensors.recordCompletedReceive(channel.id(), networkReceive.size(), currentTimeMs);
    }

    // only for testing
    public Set<SelectionKey> keys() {
        return new HashSet<>(nioSelector.keys());
    }


    class SelectorChannelMetadataRegistry implements ChannelMetadataRegistry {
        private CipherInformation cipherInformation;
        private ClientInformation clientInformation;

        @Override
        public void registerCipherInformation(final CipherInformation cipherInformation) {
            if (this.cipherInformation != null) {
                if (this.cipherInformation.equals(cipherInformation))
                    return;
                sensors.connectionsByCipher.decrement(this.cipherInformation);
            }

            this.cipherInformation = cipherInformation;
            sensors.connectionsByCipher.increment(cipherInformation);
        }

        @Override
        public CipherInformation cipherInformation() {
            return cipherInformation;
        }

        @Override
        public void registerClientInformation(final ClientInformation clientInformation) {
            if (this.clientInformation != null) {
                if (this.clientInformation.equals(clientInformation))
                    return;
                sensors.connectionsByClient.decrement(this.clientInformation);
            }

            this.clientInformation = clientInformation;
            sensors.connectionsByClient.increment(clientInformation);
        }

        @Override
        public ClientInformation clientInformation() {
            return clientInformation;
        }

        @Override
        public void close() {
            if (this.cipherInformation != null) {
                sensors.connectionsByCipher.decrement(this.cipherInformation);
                this.cipherInformation = null;
            }

            if (this.clientInformation != null) {
                sensors.connectionsByClient.decrement(this.clientInformation);
                this.clientInformation = null;
            }
        }
    }

    // CROSS-CUTTING: Depends on clients/.../metrics/Metrics for sensor registration,
    // clients/.../metrics/internals/IntGaugeSuite for connection-by-cipher and connection-by-client
    // gauges. These metrics are consumed by JMX monitoring, broker health dashboards, and alerting.
    // Contract: Sensor names must be unique per Selector instance (ensured by tagsSuffix).
    // Impact: Changes to metric naming or sensor structure affect monitoring integrations.
    class SelectorMetrics implements AutoCloseable {
        private final Metrics metrics;
        private final Map<String, String> metricTags;
        private final boolean metricsPerConnection;
        private final String metricGrpName;
        private final String perConnectionMetricGrpName;

        public final Sensor connectionClosed;
        public final Sensor connectionCreated;
        public final Sensor successfulAuthentication;
        public final Sensor successfulReauthentication;
        public final Sensor successfulAuthenticationNoReauth;
        public final Sensor reauthenticationLatency;
        public final Sensor failedAuthentication;
        public final Sensor failedReauthentication;
        public final Sensor bytesTransferred;
        public final Sensor bytesSent;
        public final Sensor requestsSent;
        public final Sensor bytesReceived;
        public final Sensor responsesReceived;
        public final Sensor selectTime;
        public final Sensor ioTime;
        public final IntGaugeSuite<CipherInformation> connectionsByCipher;
        public final IntGaugeSuite<ClientInformation> connectionsByClient;

        /* Names of metrics that are not registered through sensors */
        private final List<MetricName> topLevelMetricNames = new ArrayList<>();
        private final List<Sensor> sensors = new ArrayList<>();

        public SelectorMetrics(Metrics metrics, String metricGrpPrefix, Map<String, String> metricTags, boolean metricsPerConnection) {
            this.metrics = metrics;
            this.metricTags = metricTags;
            this.metricsPerConnection = metricsPerConnection;
            this.metricGrpName = metricGrpPrefix + "-metrics";
            this.perConnectionMetricGrpName = metricGrpPrefix + "-node-metrics";
            StringBuilder tagsSuffix = new StringBuilder();

            for (Map.Entry<String, String> tag: metricTags.entrySet()) {
                tagsSuffix.append(tag.getKey());
                tagsSuffix.append("-");
                tagsSuffix.append(tag.getValue());
            }

            this.connectionClosed = sensor("connections-closed:" + tagsSuffix);
            this.connectionClosed.add(createMeter(metrics, metricGrpName, metricTags,
                    "connection-close", "connections closed"));

            this.connectionCreated = sensor("connections-created:" + tagsSuffix);
            this.connectionCreated.add(createMeter(metrics, metricGrpName, metricTags,
                    "connection-creation", "new connections established"));

            this.successfulAuthentication = sensor("successful-authentication:" + tagsSuffix);
            this.successfulAuthentication.add(createMeter(metrics, metricGrpName, metricTags,
                    "successful-authentication", "connections with successful authentication"));

            this.successfulReauthentication = sensor("successful-reauthentication:" + tagsSuffix);
            this.successfulReauthentication.add(createMeter(metrics, metricGrpName, metricTags,
                    "successful-reauthentication", "successful re-authentication of connections"));

            this.successfulAuthenticationNoReauth = sensor("successful-authentication-no-reauth:" + tagsSuffix);
            MetricName successfulAuthenticationNoReauthMetricName = metrics.metricName(
                    "successful-authentication-no-reauth-total", metricGrpName,
                    "The total number of connections with successful authentication where the client does not support re-authentication",
                    metricTags);
            this.successfulAuthenticationNoReauth.add(successfulAuthenticationNoReauthMetricName, new CumulativeSum());

            this.failedAuthentication = sensor("failed-authentication:" + tagsSuffix);
            this.failedAuthentication.add(createMeter(metrics, metricGrpName, metricTags,
                    "failed-authentication", "connections with failed authentication"));

            this.failedReauthentication = sensor("failed-reauthentication:" + tagsSuffix);
            this.failedReauthentication.add(createMeter(metrics, metricGrpName, metricTags,
                    "failed-reauthentication", "failed re-authentication of connections"));

            this.reauthenticationLatency = sensor("reauthentication-latency:" + tagsSuffix);
            MetricName reauthenticationLatencyMaxMetricName = metrics.metricName("reauthentication-latency-max",
                    metricGrpName, "The max latency observed due to re-authentication",
                    metricTags);
            this.reauthenticationLatency.add(reauthenticationLatencyMaxMetricName, new Max());
            MetricName reauthenticationLatencyAvgMetricName = metrics.metricName("reauthentication-latency-avg",
                    metricGrpName, "The average latency observed due to re-authentication",
                    metricTags);
            this.reauthenticationLatency.add(reauthenticationLatencyAvgMetricName, new Avg());

            this.bytesTransferred = sensor("bytes-sent-received:" + tagsSuffix);
            bytesTransferred.add(createMeter(metrics, metricGrpName, metricTags, new WindowedCount(),
                    "network-io", "network operations (reads or writes) on all connections"));

            this.bytesSent = sensor("bytes-sent:" + tagsSuffix, bytesTransferred);
            this.bytesSent.add(createMeter(metrics, metricGrpName, metricTags,
                    "outgoing-byte", "outgoing bytes sent to all servers"));

            this.requestsSent = sensor("requests-sent:" + tagsSuffix);
            this.requestsSent.add(createMeter(metrics, metricGrpName, metricTags, new WindowedCount(),
                    "request", "requests sent"));
            MetricName metricName = metrics.metricName("request-size-avg", metricGrpName, "The average size of requests sent.", metricTags);
            this.requestsSent.add(metricName, new Avg());
            metricName = metrics.metricName("request-size-max", metricGrpName, "The maximum size of any request sent.", metricTags);
            this.requestsSent.add(metricName, new Max());

            this.bytesReceived = sensor("bytes-received:" + tagsSuffix, bytesTransferred);
            this.bytesReceived.add(createMeter(metrics, metricGrpName, metricTags,
                    "incoming-byte", "bytes read off all sockets"));

            this.responsesReceived = sensor("responses-received:" + tagsSuffix);
            this.responsesReceived.add(createMeter(metrics, metricGrpName, metricTags,
                    new WindowedCount(), "response", "responses received"));

            this.selectTime = sensor("select-time:" + tagsSuffix);
            this.selectTime.add(createMeter(metrics, metricGrpName, metricTags,
                    new WindowedCount(), "select", "times the I/O layer checked for new I/O to perform"));
            metricName = metrics.metricName("io-wait-time-ns-avg", metricGrpName, "The average length of time the I/O thread spent waiting for a socket ready for reads or writes in nanoseconds.", metricTags);
            this.selectTime.add(metricName, new Avg());
            this.selectTime.add(createIOThreadRatioMeter(metrics, metricGrpName, metricTags, "io-wait", "waiting"));

            this.ioTime = sensor("io-time:" + tagsSuffix);
            metricName = metrics.metricName("io-time-ns-avg", metricGrpName, "The average length of time for I/O per select call in nanoseconds.", metricTags);
            this.ioTime.add(metricName, new Avg());
            this.ioTime.add(createIOThreadRatioMeter(metrics, metricGrpName, metricTags, "io", "doing I/O"));

            this.connectionsByCipher = new IntGaugeSuite<>(log, "sslCiphers", metrics,
                cipherInformation -> {
                    Map<String, String> tags = new LinkedHashMap<>();
                    tags.put("cipher", cipherInformation.cipher());
                    tags.put("protocol", cipherInformation.protocol());
                    tags.putAll(metricTags);
                    return metrics.metricName("connections", metricGrpName, "The number of connections with this SSL cipher and protocol.", tags);
                }, 100);

            this.connectionsByClient = new IntGaugeSuite<>(log, "clients", metrics,
                clientInformation -> {
                    Map<String, String> tags = new LinkedHashMap<>();
                    tags.put("clientSoftwareName", clientInformation.softwareName());
                    tags.put("clientSoftwareVersion", clientInformation.softwareVersion());
                    tags.putAll(metricTags);
                    return metrics.metricName("connections", metricGrpName, "The number of connections with this client and version.", tags);
                }, 100);

            metricName = metrics.metricName("connection-count", metricGrpName, "The current number of active connections.", metricTags);
            topLevelMetricNames.add(metricName);
            this.metrics.addMetric(metricName, (config, now) -> channels.size());
        }

        private Meter createMeter(Metrics metrics, String groupName, Map<String, String> metricTags,
                SampledStat stat, String baseName, String descriptiveName) {
            MetricName rateMetricName = metrics.metricName(baseName + "-rate", groupName,
                            String.format("The number of %s per second", descriptiveName), metricTags);
            MetricName totalMetricName = metrics.metricName(baseName + "-total", groupName,
                            String.format("The total number of %s", descriptiveName), metricTags);
            if (stat == null)
                return new Meter(rateMetricName, totalMetricName);
            else
                return new Meter(stat, rateMetricName, totalMetricName);
        }

        private Meter createMeter(Metrics metrics, String groupName,  Map<String, String> metricTags,
                String baseName, String descriptiveName) {
            return createMeter(metrics, groupName, metricTags, null, baseName, descriptiveName);
        }

        private Meter createIOThreadRatioMeter(Metrics metrics, String groupName,  Map<String, String> metricTags,
                                               String baseName, String action) {
            MetricName rateMetricName = metrics.metricName(baseName + "-ratio", groupName,
                String.format("The fraction of time the I/O thread spent %s", action), metricTags);
            MetricName totalMetricName = metrics.metricName(baseName + "-time-ns-total", groupName,
                String.format("The total time the I/O thread spent %s", action), metricTags);
            return new Meter(TimeUnit.NANOSECONDS, rateMetricName, totalMetricName);
        }

        private Sensor sensor(String name, Sensor... parents) {
            Sensor sensor = metrics.sensor(name, parents);
            sensors.add(sensor);
            return sensor;
        }

        public void maybeRegisterConnectionMetrics(String connectionId) {
            if (!connectionId.isEmpty() && metricsPerConnection) {
                // if one sensor of the metrics has been registered for the connection,
                // then all other sensors should have been registered; and vice versa
                String nodeRequestName = "node-" + connectionId + ".requests-sent";
                Sensor nodeRequest = this.metrics.getSensor(nodeRequestName);
                if (nodeRequest == null) {
                    Map<String, String> tags = new LinkedHashMap<>(metricTags);
                    tags.put("node-id", "node-" + connectionId);

                    nodeRequest = sensor(nodeRequestName);
                    nodeRequest.add(createMeter(metrics, perConnectionMetricGrpName, tags, new WindowedCount(), "request", "requests sent"));
                    MetricName metricName = metrics.metricName("request-size-avg", perConnectionMetricGrpName, "The average size of requests sent.", tags);
                    nodeRequest.add(metricName, new Avg());
                    metricName = metrics.metricName("request-size-max", perConnectionMetricGrpName, "The maximum size of any request sent.", tags);
                    nodeRequest.add(metricName, new Max());

                    String bytesSentName = "node-" + connectionId + ".bytes-sent";
                    Sensor bytesSent = sensor(bytesSentName);
                    bytesSent.add(createMeter(metrics, perConnectionMetricGrpName, tags, "outgoing-byte", "outgoing bytes"));

                    String nodeResponseName = "node-" + connectionId + ".responses-received";
                    Sensor nodeResponse = sensor(nodeResponseName);
                    nodeResponse.add(createMeter(metrics, perConnectionMetricGrpName, tags, new WindowedCount(), "response", "responses received"));

                    String bytesReceivedName = "node-" + connectionId + ".bytes-received";
                    Sensor bytesReceive = sensor(bytesReceivedName);
                    bytesReceive.add(createMeter(metrics, perConnectionMetricGrpName, tags, "incoming-byte", "incoming bytes"));

                    String nodeTimeName = "node-" + connectionId + ".latency";
                    Sensor nodeRequestTime = sensor(nodeTimeName);
                    metricName = metrics.metricName("request-latency-avg", perConnectionMetricGrpName, tags);
                    nodeRequestTime.add(metricName, new Avg());
                    metricName = metrics.metricName("request-latency-max", perConnectionMetricGrpName, tags);
                    nodeRequestTime.add(metricName, new Max());
                }
            }
        }

        public void recordBytesSent(String connectionId, long bytes, long currentTimeMs) {
            this.bytesSent.record(bytes, currentTimeMs, false);
            if (!connectionId.isEmpty()) {
                String bytesSentName = "node-" + connectionId + ".bytes-sent";
                Sensor bytesSent = this.metrics.getSensor(bytesSentName);
                if (bytesSent != null)
                    bytesSent.record(bytes, currentTimeMs);
            }
        }

        public void recordCompletedSend(String connectionId, long totalBytes, long currentTimeMs) {
            requestsSent.record(totalBytes, currentTimeMs, false);
            if (!connectionId.isEmpty()) {
                String nodeRequestName = "node-" + connectionId + ".requests-sent";
                Sensor nodeRequest = this.metrics.getSensor(nodeRequestName);
                if (nodeRequest != null)
                    nodeRequest.record(totalBytes, currentTimeMs);
            }
        }

        public void recordBytesReceived(String connectionId, long bytes, long currentTimeMs) {
            this.bytesReceived.record(bytes, currentTimeMs, false);
            if (!connectionId.isEmpty()) {
                String bytesReceivedName = "node-" + connectionId + ".bytes-received";
                Sensor bytesReceived = this.metrics.getSensor(bytesReceivedName);
                if (bytesReceived != null)
                    bytesReceived.record(bytes, currentTimeMs);
            }
        }

        public void recordCompletedReceive(String connectionId, long totalBytes, long currentTimeMs) {
            responsesReceived.record(totalBytes, currentTimeMs, false);
            if (!connectionId.isEmpty()) {
                String nodeRequestName = "node-" + connectionId + ".responses-received";
                Sensor nodeRequest = this.metrics.getSensor(nodeRequestName);
                if (nodeRequest != null)
                    nodeRequest.record(totalBytes, currentTimeMs);
            }
        }

        public void close() {
            for (MetricName metricName : topLevelMetricNames)
                metrics.removeMetric(metricName);
            for (Sensor sensor : sensors)
                metrics.removeSensor(sensor.name());
            connectionsByCipher.close();
            connectionsByClient.close();
        }
    }

    /**
     * Encapsulate a channel that must be closed after a specific delay has elapsed due to authentication failure.
     */
    // SECURITY: (HIGH) Delayed close mechanism for authentication failures — the channel remains
    // open for failedAuthenticationDelayMs to send the error response before teardown. This
    // prevents timing side-channels but creates a resource-consumption window.
    // Exploit: An attacker rapidly sends invalid credentials to accumulate channels in the
    // delayedClosingChannels map, each held open for the delay period, consuming file descriptors.
    // Improvement: Cap the maximum number of simultaneous delayed-close channels and immediately
    // close the oldest when the cap is exceeded.
    private class DelayedAuthenticationFailureClose {
        private final KafkaChannel channel;
        private final long endTimeNanos;
        private boolean closed;

        /**
         * @param channel The channel whose close is being delayed
         * @param delayMs The amount of time by which the operation should be delayed
         */
        public DelayedAuthenticationFailureClose(KafkaChannel channel, int delayMs) {
            this.channel = channel;
            this.endTimeNanos = time.nanoseconds() + (delayMs * 1000L * 1000L);
            this.closed = false;
        }

        /**
         * Try to close this channel if the delay has expired.
         * @param currentTimeNanos The current time
         * @return True if the delay has expired and the channel was closed; false otherwise
         */
        public final boolean tryClose(long currentTimeNanos) {
            if (endTimeNanos <= currentTimeNanos)
                closeNow();
            return closed;
        }

        /**
         * Close the channel now, regardless of whether the delay has expired or not.
         */
        public final void closeNow() {
            if (closed)
                throw new IllegalStateException("Attempt to close a channel that has already been closed");
            handleCloseOnAuthenticationFailure(channel);
            closed = true;
        }
    }

    // DECISION: LRU-based idle connection tracking using LinkedHashMap with accessOrder=true.
    // Alternative: Priority queue keyed by last-active timestamp (O(log n) insertion/removal).
    // Rationale: LinkedHashMap with access-order provides O(1) amortized update on each channel
    // activity and O(1) polling of the oldest entry. The priority queue alternative would require
    // O(log n) per update, which adds up with thousands of connections polled per cycle.
    // helper class for tracking least recently used connections to enable idle connection closing
    private static class IdleExpiryManager {
        private final Map<String, Long> lruConnections;
        private final long connectionsMaxIdleNanos;
        private long nextIdleCloseCheckTime;

        public IdleExpiryManager(Time time, long connectionsMaxIdleMs) {
            this.connectionsMaxIdleNanos = connectionsMaxIdleMs * 1000 * 1000;
            // initial capacity and load factor are default, we set them explicitly because we want to set accessOrder = true
            this.lruConnections = new LinkedHashMap<>(16, .75F, true);
            this.nextIdleCloseCheckTime = time.nanoseconds() + this.connectionsMaxIdleNanos;
        }

        public void update(String connectionId, long currentTimeNanos) {
            lruConnections.put(connectionId, currentTimeNanos);
        }

        public Map.Entry<String, Long> pollExpiredConnection(long currentTimeNanos) {
            if (currentTimeNanos <= nextIdleCloseCheckTime)
                return null;

            if (lruConnections.isEmpty()) {
                nextIdleCloseCheckTime = currentTimeNanos + connectionsMaxIdleNanos;
                return null;
            }

            Map.Entry<String, Long> oldestConnectionEntry = lruConnections.entrySet().iterator().next();
            Long connectionLastActiveTime = oldestConnectionEntry.getValue();
            nextIdleCloseCheckTime = connectionLastActiveTime + connectionsMaxIdleNanos;

            if (currentTimeNanos > nextIdleCloseCheckTime)
                return oldestConnectionEntry;
            else
                return null;
        }

        public void remove(String connectionId) {
            lruConnections.remove(connectionId);
        }
    }

    //package-private for testing
    boolean isOutOfMemory() {
        return outOfMemory;
    }

    //package-private for testing
    boolean isMadeReadProgressLastPoll() {
        return madeReadProgressLastPoll;
    }

    // package-private for testing
    Map<?, ?> delayedClosingChannels() {
        return delayedClosingChannels;
    }
}
