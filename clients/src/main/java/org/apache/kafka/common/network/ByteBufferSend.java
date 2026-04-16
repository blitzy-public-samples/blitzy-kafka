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

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * A send backed by an array of byte buffers
 */
// DECISION: ByteBufferSend implements Send for one or more ByteBuffers, using
// GatheringByteChannel.write(ByteBuffer[]) for efficient scatter/gather I/O.
// The pending flag tracks whether the TransportLayer has buffered writes that haven't
// been flushed to the network socket yet (relevant for SSL where SSLEngine may buffer data).
// Alternative: Single-buffer Send — rejected because Kafka protocol responses often consist
// of a header buffer + payload buffer, and scatter/gather avoids copying them together.
public class ByteBufferSend implements Send {

    private final long size;
    protected final ByteBuffer[] buffers;
    private long remaining;
    private boolean pending = false;

    public ByteBufferSend(ByteBuffer... buffers) {
        this.buffers = buffers;
        for (ByteBuffer buffer : buffers)
            remaining += buffer.remaining();
        this.size = remaining;
    }

    public ByteBufferSend(ByteBuffer[] buffers, long size) {
        this.buffers = buffers;
        this.size = size;
        this.remaining = size;
    }

    @Override
    public boolean completed() {
        return remaining <= 0 && !pending;
    }

    @Override
    public long size() {
        return this.size;
    }

    @Override
    public long writeTo(TransferableChannel channel) throws IOException {
        long written = channel.write(buffers);
        if (written < 0)
            throw new EOFException("Wrote negative bytes to channel. This shouldn't happen.");
        remaining -= written;
        pending = channel.hasPendingWrites();
        return written;
    }

    public long remaining() {
        return remaining;
    }

    @Override
    public String toString() {
        return "ByteBufferSend(" +
            ", size=" + size +
            ", remaining=" + remaining +
            ", pending=" + pending +
            ')';
    }

    // DECISION: Factory method that prepends a 4-byte big-endian length prefix to a ByteBuffer.
    // This matches Kafka's wire protocol framing convention (length-prefixed messages).
    // The size prefix includes only the payload size, not itself, matching the NetworkReceive
    // expectation that the 4-byte size header encodes the remaining payload length.
    public static ByteBufferSend sizePrefixed(ByteBuffer buffer) {
        ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
        sizeBuffer.putInt(0, buffer.remaining());
        return new ByteBufferSend(sizeBuffer, buffer);
    }
}
