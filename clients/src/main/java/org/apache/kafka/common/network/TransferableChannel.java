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
import java.nio.channels.FileChannel;
import java.nio.channels.GatheringByteChannel;

/**
 * Extends GatheringByteChannel with the minimal set of methods required by the Send interface. Supporting TLS and
 * efficient zero copy transfers are the main reasons for the additional methods.
 * 
 * @see SslTransportLayer
 */
// DECISION: Extension of GatheringByteChannel that adds hasPendingWrites() and
// transferFrom(FileChannel, position, count). The transferFrom() method enables zero-copy
// file transfer when the underlying channel supports it (PlaintextTransportLayer uses
// FileChannel.transferTo -> sendfile(2) syscall). For encrypted channels (SslTransportLayer),
// transferFrom() must read into a user-space buffer then encrypt, so zero-copy is not possible.
// Alternative: Use GatheringByteChannel directly and handle file transfers externally -- rejected
// because the channel knows whether zero-copy is possible (plaintext vs SSL) and can choose
// the optimal transfer strategy.
//
// CROSS-CUTTING: Extended by TransportLayer. Implementations: PlaintextTransportLayer (zero-copy
// via FileChannel.transferTo), SslTransportLayer (buffered copy through SSLEngine).
// Impact: The transferFrom() contract affects log fetch performance -- plaintext gets zero-copy
// kernel-to-socket transfer while SSL requires additional data copies through user space.
public interface TransferableChannel extends GatheringByteChannel {

    /**
     * @return true if there are any pending writes. false if the implementation directly write all data to output.
     */
    // DECISION: Boolean method allowing callers to check if the channel has unflushed write data.
    // This is essential for the Selector's send-completion tracking: a send is only considered
    // complete when hasPendingWrites() returns false. Without this, the Selector would need to
    // track write buffer state externally, duplicating logic from the transport layer.
    boolean hasPendingWrites();

    /**
     * Transfers bytes from `fileChannel` to this `TransferableChannel`.
     *
     * This method will delegate to {@link FileChannel#transferTo(long, long, java.nio.channels.WritableByteChannel)},
     * but it will unwrap the destination channel, if possible, in order to benefit from zero copy. This is required
     * because the fast path of `transferTo` is only executed if the destination buffer inherits from an internal JDK
     * class.
     *
     * @param fileChannel The source channel
     * @param position The position within the file at which the transfer is to begin; must be non-negative
     * @param count The maximum number of bytes to be transferred; must be non-negative
     * @return The number of bytes, possibly zero, that were actually transferred
     * @see FileChannel#transferTo(long, long, java.nio.channels.WritableByteChannel)
     */
    long transferFrom(FileChannel fileChannel, long position, long count) throws IOException;
}
