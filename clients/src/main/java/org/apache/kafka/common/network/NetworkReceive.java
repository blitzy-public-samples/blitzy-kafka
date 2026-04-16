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

import org.apache.kafka.common.memory.MemoryPool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ScatteringByteChannel;

/**
 * A size delimited Receive that consists of a 4 byte network-ordered size N followed by N bytes of content
 *
 * @implNote
 * <b>DECISION:</b> Implements a two-phase incremental read: (1) read 4-byte size
 * prefix, (2) allocate and fill payload buffer. This length-prefixed framing is
 * Kafka's wire protocol foundation. The MemoryPool integration enables broker-side
 * buffer pooling to control memory consumption under high connection counts.
 * Alternative: Delimiter-based framing (e.g., newline) — rejected because binary
 * protocol data may contain any byte value; length-prefixing provides unambiguous
 * message boundaries with O(1) size determination.
 *
 * <b>CROSS-CUTTING:</b> Used by {@code KafkaChannel.read()} and
 * {@code Selector.attemptRead()} (both in {@code o.a.k.common.network}) for all
 * inbound receive operations. The {@link org.apache.kafka.common.memory.MemoryPool}
 * dependency connects this class to the {@code common/memory/} package.
 * Contract: callers must invoke {@link #readFrom} repeatedly until
 * {@link #complete()} returns {@code true}.
 * Impact: if the wire protocol framing changes (e.g., variable-length size prefix),
 * this class and every consumer of it must be updated in lockstep.
 */
public class NetworkReceive implements Receive {

    public static final String UNKNOWN_SOURCE = "";
    public static final int UNLIMITED = -1;
    private static final Logger log = LoggerFactory.getLogger(NetworkReceive.class);
    // DECISION: EMPTY_BUFFER is a singleton zero-capacity ByteBuffer reused for
    // zero-length payloads (e.g., SASL handshake frames with empty body). This
    // avoids a MemoryPool allocation for a degenerate case.
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0);

    private final String source;
    // DECISION: The size buffer is exactly 4 bytes — matching the Kafka wire
    // protocol's big-endian int32 length prefix. Allocated eagerly in every
    // constructor because every receive must read the size prefix first.
    private final ByteBuffer size;
    // SECURITY: SEC-NET-010 (MEDIUM) maxSize limits the maximum allowed receive size to
    // Why: Network receive buffers handle untrusted data from
    // the network that could be crafted for attacks.
    // prevent a malicious client from sending an extremely large size prefix
    // (e.g., Integer.MAX_VALUE) that would cause the broker to allocate a huge
    // buffer, leading to OOM denial-of-service.
    // Risk: An attacker sends a crafted 4-byte size prefix with value ~2 GB,
    // causing the broker to attempt allocating a 2 GB ByteBuffer, exhausting
    // heap and crashing the JVM.
    // Mitigation: InvalidReceiveException is thrown when receiveSize < 0 or
    // receiveSize > maxSize. The maxSize is configured via
    // socket.request.max.bytes (default 100 MB) on the broker.
    // Improvement: Consider logging the source address when rejecting oversized
    // receives for security audit trail; currently only the size is logged.
    // Exploit: An attacker could exhaust server resources by sending oversized or excessive requests.
    private final int maxSize;
    // CROSS-CUTTING: MemoryPool is provided by the common/memory/ package and
    // shared across all channels within a single Selector. Broker-side pooling
    // (GC-free reuse of direct ByteBuffers) depends on callers invoking
    // close() to release buffers back to the pool.
    private final MemoryPool memoryPool;
    private int requestedBufferSize = -1;
    private ByteBuffer buffer;


    public NetworkReceive(String source, ByteBuffer buffer) {
        this(UNLIMITED, source);
        this.buffer = buffer;
    }

    public NetworkReceive(String source) {
        this(UNLIMITED, source);
    }

    public NetworkReceive(int maxSize, String source) {
        this(maxSize, source, MemoryPool.NONE);
    }

    public NetworkReceive(int maxSize, String source, MemoryPool memoryPool) {
        this.source = source;
        this.size = ByteBuffer.allocate(4);
        this.buffer = null;
        this.maxSize = maxSize;
        this.memoryPool = memoryPool;
    }

    public NetworkReceive() {
        this(UNKNOWN_SOURCE);
    }

    @Override
    public String source() {
        return source;
    }

    @Override
    public boolean complete() {
        return !size.hasRemaining() && buffer != null && !buffer.hasRemaining();
    }

    // COMPLEXITY: Method size ~33 lines — two-phase NIO read with three
    // sequential stages and multiple exit paths.
    // Structure:
    //   Phase 1 (lines 1-17): Read 4-byte size prefix from channel; on
    //     completion, validate receive size against maxSize bounds. Throws
    //     InvalidReceiveException on negative or oversized values. Assigns
    //     EMPTY_BUFFER when receiveSize == 0 (zero-copy shortcut).
    //   Phase 2 (lines 18-22): If size is known but buffer is null, attempt
    //     deferred allocation from MemoryPool. If pool is exhausted,
    //     allocation is deferred — the channel will be muted to create
    //     backpressure (see Selector.attemptRead).
    //   Phase 3 (lines 23-29): If buffer is allocated, read payload bytes
    //     from channel into the buffer.
    // Key exit paths: EOFException on premature channel close (phase 1 or
    //   phase 3); InvalidReceiveException on invalid size (phase 1); normal
    //   return with cumulative bytes-read count.
    //
    // DECISION: Buffer allocation is deferred from MemoryPool until the size
    // prefix is fully known. If MemoryPool.tryAllocate() returns null (pool
    // exhausted), the receive stays in a partial state (size read, buffer not
    // allocated). The caller detects this via requiredMemoryAmountKnown()
    // and memoryAllocated() and mutes the channel, creating backpressure
    // instead of blocking the Selector thread.
    // EMPTY_BUFFER optimisation: when receiveSize == 0, no pool allocation is
    // needed — the singleton EMPTY_BUFFER is reused.
    public long readFrom(ScatteringByteChannel channel) throws IOException {
        int read = 0;
        if (size.hasRemaining()) {
            int bytesRead = channel.read(size);
            if (bytesRead < 0)
                throw new EOFException();
            read += bytesRead;
            if (!size.hasRemaining()) {
                size.rewind();
                int receiveSize = size.getInt();
                if (receiveSize < 0)
                    throw new InvalidReceiveException("Invalid receive (size = " + receiveSize + ")");
                if (maxSize != UNLIMITED && receiveSize > maxSize)
                    throw new InvalidReceiveException("Invalid receive (size = " + receiveSize + " larger than " + maxSize + ")");
                requestedBufferSize = receiveSize; // may be 0 for some payloads (SASL)
                if (receiveSize == 0) {
                    buffer = EMPTY_BUFFER;
                }
            }
        }
        if (buffer == null && requestedBufferSize != -1) { // we know the size we want but haven't been able to allocate it yet
            buffer = memoryPool.tryAllocate(requestedBufferSize);
            if (buffer == null)
                log.trace("Broker low on memory - could not allocate buffer of size {} for source {}", requestedBufferSize, source);
        }
        if (buffer != null) {
            int bytesRead = channel.read(buffer);
            if (bytesRead < 0)
                throw new EOFException();
            read += bytesRead;
        }

        return read;
    }

    // CROSS-CUTTING: requiredMemoryAmountKnown() and memoryAllocated() are
    // polled by Selector.attemptRead() to decide whether to mute the channel
    // when the MemoryPool cannot satisfy the allocation. Together they form
    // the backpressure signaling contract between NetworkReceive and Selector.
    @Override
    public boolean requiredMemoryAmountKnown() {
        return requestedBufferSize != -1;
    }

    @Override
    public boolean memoryAllocated() {
        return buffer != null;
    }


    // CROSS-CUTTING: close() releases the payload buffer back to the shared
    // MemoryPool. Failure to call close() leaks pooled memory and eventually
    // starves other channels. The EMPTY_BUFFER singleton is excluded because
    // it was never allocated from the pool.
    @Override
    public void close() throws IOException {
        if (buffer != null && buffer != EMPTY_BUFFER) {
            memoryPool.release(buffer);
            buffer = null;
        }
    }

    public ByteBuffer payload() {
        return this.buffer;
    }

    public int bytesRead() {
        if (buffer == null)
            return size.position();
        return buffer.position() + size.position();
    }

    /**
     * Returns the total size of the receive including payload and size buffer
     * for use in metrics. This is consistent with {@link NetworkSend#size()}
     */
    public int size() {
        return payload().limit() + size.limit();
    }

}
