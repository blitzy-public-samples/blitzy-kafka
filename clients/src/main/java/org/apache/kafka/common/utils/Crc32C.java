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
import java.util.zip.CRC32C;
import java.util.zip.Checksum;

/**
 * A class that can be used to compute the CRC32C (Castagnoli) of a ByteBuffer or array of bytes.
 *
 * NOTE: This class is intended for INTERNAL usage only within Kafka.
 */
// DECISION: CRC32C (Castagnoli) rather than CRC32 (ISO 3309) for record batch checksums.
// Alternative: CRC32, xxHash, MurmurHash. Rationale: CRC32C has hardware acceleration on
// modern x86 CPUs via SSE 4.2 instruction set (intrinsified by HotSpot JIT), making it
// 5-10x faster than software CRC32. This is performance-critical — every record batch
// produced and consumed computes a CRC32C checksum. Kafka switched from CRC32 to CRC32C
// in record format v2 (KIP-98).
//
// CROSS-CUTTING: Used by common/record/DefaultRecord and DefaultRecordBatch for record
// integrity verification. Every produce and fetch path computes CRC32C — this is one of
// the hottest code paths in Kafka.
public final class Crc32C {

    private Crc32C() {}

    /**
     * Compute the CRC32C (Castagnoli) of the segment of the byte array given by the specified size and offset
     *
     * @param bytes The bytes to checksum
     * @param offset the offset at which to begin the checksum computation
     * @param size the number of bytes to checksum
     * @return The CRC32C
     */
    public static long compute(byte[] bytes, int offset, int size) {
        // DECISION: Delegates to JDK's built-in CRC32C (Java 9+). Previously Kafka bundled
        // its own CRC32C implementation for Java 8 compatibility. Since Kafka now requires
        // Java 11+, the JDK implementation (which is hardware-accelerated) is preferred.
        Checksum crc = new CRC32C();
        crc.update(bytes, offset, size);
        return crc.getValue();
    }

    /**
     * Compute the CRC32C (Castagnoli) of a byte buffer from a given offset (relative to the buffer's current position)
     *
     * @param buffer The buffer with the underlying data
     * @param offset The offset relative to the current position
     * @param size The number of bytes beginning from the offset to include
     * @return The CRC32C
     */
    public static long compute(ByteBuffer buffer, int offset, int size) {
        Checksum crc = new CRC32C();
        Checksums.update(crc, buffer, offset, size);
        return crc.getValue();
    }
}
