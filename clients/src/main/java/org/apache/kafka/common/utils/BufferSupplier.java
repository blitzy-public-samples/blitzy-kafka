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

package org.apache.kafka.common.utils;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple non-threadsafe interface for caching byte buffers. This is suitable for simple cases like ensuring that
 * a given KafkaConsumer reuses the same decompression buffer when iterating over fetched records. For small record
 * batches, allocating a potentially large buffer (64 KB for LZ4) will dominate the cost of decompressing and
 * iterating over the records in the batch.
 */
// DECISION: Abstract ByteBuffer pool with three strategies: NO_CACHING (always allocate),
// DefaultSupplier (size-bucketed Deque<ByteBuffer> pool), GrowableBufferSupplier (single reusable
// growing buffer). Alternative: Fixed-size buffer pool or Netty's PooledByteBufAllocator.
// Rationale: Kafka's decompression paths need temporary buffers of varying sizes -- the bucketed
// pool (DefaultSupplier) avoids repeated allocation for common sizes while the growable variant
// is optimal for single-threaded record batch processing where one buffer suffices.
//
// CROSS-CUTTING: Consumed by common/record/DefaultRecordBatch for decompression buffer
// management, and by ChunkedBytesStream for pooled I/O buffering. Passed through the
// record deserialization pipeline from Selector -> SocketServer -> FetchProcessor.
public abstract class BufferSupplier implements AutoCloseable {

    public static final BufferSupplier NO_CACHING = new BufferSupplier() {
        @Override
        public ByteBuffer get(int capacity) {
            return ByteBuffer.allocate(capacity);
        }

        @Override
        public void release(ByteBuffer buffer) {}

        @Override
        public void close() {}
    };

    public static BufferSupplier create() {
        return new DefaultSupplier();
    }

    /**
     * Supply a buffer with the required capacity. This may return a cached buffer or allocate a new instance.
     */
    public abstract ByteBuffer get(int capacity);

    /**
     * Return the provided buffer to be reused by a subsequent call to `get`.
     */
    public abstract void release(ByteBuffer buffer);

    /**
     * Release all resources associated with this supplier.
     */
    public abstract void close();

    // DECISION: Map<Integer, Deque<ByteBuffer>> keyed by exact capacity. Alternative: Power-of-2
    // size classes. Rationale: Kafka protocol messages have well-known sizes -- exact-match pooling
    // avoids wasting memory on oversized buffers. NOT thread-safe -- designed for single-threaded
    // per-connection processing in Selector/Processor threads.
    private static class DefaultSupplier extends BufferSupplier {
        // We currently use a single block size, so optimise for that case
        private final Map<Integer, Deque<ByteBuffer>> bufferMap = new HashMap<>(1);

        @Override
        public ByteBuffer get(int size) {
            Deque<ByteBuffer> bufferQueue = bufferMap.get(size);
            if (bufferQueue == null || bufferQueue.isEmpty())
                return ByteBuffer.allocate(size);
            else
                return bufferQueue.pollFirst();
        }

        @Override
        public void release(ByteBuffer buffer) {
            buffer.clear();
            // We currently keep a single buffer in flight, so optimise for that case
            Deque<ByteBuffer> bufferQueue = bufferMap.computeIfAbsent(buffer.capacity(), k -> new ArrayDeque<>(1));
            bufferQueue.addLast(buffer);
        }

        @Override
        public void close() {
            bufferMap.clear();
        }
    }

    /**
     * Simple buffer supplier for single-threaded usage. It caches a single buffer, which grows
     * monotonically as needed to fulfill the allocation request.
     */
    // DECISION: Single buffer that grows to max observed size. Alternative: Shrinking buffer.
    // Rationale: In record batch decompression, buffer sizes tend to stabilize -- keeping the
    // high-water-mark buffer avoids repeated reallocation. Memory is reclaimed when the supplier
    // is closed (e.g., channel close).
    public static class GrowableBufferSupplier extends BufferSupplier {
        private ByteBuffer cachedBuffer;

        @Override
        public ByteBuffer get(int minCapacity) {
            if (cachedBuffer != null && cachedBuffer.capacity() >= minCapacity) {
                ByteBuffer res = cachedBuffer;
                cachedBuffer = null;
                return res;
            } else {
                cachedBuffer = null;
                return ByteBuffer.allocate(minCapacity);
            }
        }

        @Override
        public void release(ByteBuffer buffer) {
            buffer.clear();
            cachedBuffer = buffer;
        }

        @Override
        public void close() {
            cachedBuffer = null;
        }
    }

}
