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

// DECISION: Extends KafkaException (unchecked, inherits RuntimeException) rather than IOException (checked)
// because an invalid receive (negative size or exceeding maxSize) indicates either a protocol violation
// by the sender or data corruption — not a transient I/O condition. Catching this exception
// triggers connection closure rather than retry.
// Used by: NetworkReceive.readFrom() when the 4-byte size prefix is negative or exceeds
// the configured maxSize (socket.request.max.bytes), preventing buffer allocation DoS.
public class InvalidReceiveException extends KafkaException {

    public InvalidReceiveException(String message) {
        super(message);
    }

}
