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

import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.ScatteringByteChannel;

/**
 * This interface models the in-progress reading of data from a channel to a source identified by an integer id
 */
// DECISION: Minimal interface for incoming network data. Defines readFrom(ScatteringByteChannel)
// and complete()/requiredMemoryAmountKnown()/memoryAllocated()/source() for progressive read
// tracking. The readFrom() contract supports incremental reads — callers invoke it repeatedly
// until complete() returns true, matching NIO non-blocking semantics where read() returns
// partial data when the socket buffer is not yet full.
// Alternative: Buffered blocking read — rejected for the same single-threaded non-blocking
// event loop reasons as Send.
//
// CROSS-CUTTING: Core receive abstraction consumed by Selector.pollSelectionKeys() for
// inbound data. Implementation: NetworkReceive (size-prefixed framing). Used by KafkaChannel
// to hold the current in-progress receive. Any change to this interface affects Selector's
// read path and all protocol-level receive processing across clients/ and core/ modules.
public interface Receive extends Closeable {

    /**
     * The numeric id of the source from which we are receiving data.
     */
    String source();

    /**
     * Are we done receiving data?
     */
    // DECISION: complete() signals that the full message has been read. Implementations
    // (e.g., NetworkReceive) expose payload data only after complete() returns true.
    // Calling payload accessors before completion is undefined — this contract ensures
    // no partial data is exposed to upper protocol layers.
    boolean complete();

    /**
     * Read bytes into this receive from the given channel
     * @param channel The channel to read from
     * @return The number of bytes read
     * @throws IOException If the reading fails
     */
    long readFrom(ScatteringByteChannel channel) throws IOException;

    /**
     * Do we know yet how much memory we require to fully read this
     */
    // DECISION: requiredMemoryAmountKnown() returns true once the 4-byte size prefix has been
    // read, enabling the memory pool to allocate the exact buffer size needed. This two-phase
    // approach (read size, then allocate, then read payload) minimizes over-allocation and
    // supports memory pool integration for backpressure in Selector.
    boolean requiredMemoryAmountKnown();

    /**
     * Has the underlying memory required to complete reading been allocated yet?
     */
    boolean memoryAllocated();
}
