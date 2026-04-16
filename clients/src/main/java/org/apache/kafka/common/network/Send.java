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

import java.io.IOException;

// CROSS-CUTTING: Core send abstraction consumed by Selector.send(), KafkaChannel.setSend(),
// and all protocol-level send operations. Implementations: ByteBufferSend, NetworkSend,
// MultiRecordsSend, and RecordsSend (in clients/common/record/). Any change to this interface
// propagates to all modules that construct or process outgoing Kafka protocol messages,
// including core/ (RequestChannel, RequestHandlerHelper), clients/ (NetworkClient,
// SaslServerAuthenticator, SaslClientAuthenticator), and jmh-benchmarks/.
// Contract: Callers must loop writeTo() until completed() returns true; size() must return
// the total byte count determined at construction time.
// Impact: Adding or changing methods here requires updates across all Send implementations
// and every call site that interacts with outgoing network data.

// DECISION: Minimal interface for outgoing network data. Defines writeTo(TransferableChannel)
// and completed()/size() for progress tracking. The writeTo() contract allows partial writes
// — callers must loop until completed() returns true, which matches NIO's non-blocking
// write semantics where SocketChannel.write() may write fewer bytes than requested.
// Alternative: Provide a blocking send abstraction — rejected to support the single-threaded
// non-blocking event loop model in Selector where a single thread services many channels.
// Risk: Callers that forget to loop until completed() may silently drop data.

/**
 * This interface models the in-progress sending of data.
 */
public interface Send {

    /**
     * Is this send complete?
     */
    boolean completed();

    /**
     * Write some as-yet unwritten bytes from this send to the provided channel. It may take multiple calls for the send
     * to be completely written
     * @param channel The Channel to write to
     * @return The number of bytes written
     * @throws IOException If the write fails
     */
    long writeTo(TransferableChannel channel) throws IOException;

    /**
     * Size of the send
     */
    long size();

}
