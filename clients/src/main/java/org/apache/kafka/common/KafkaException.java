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
package org.apache.kafka.common;

/**
 * The base class of all other Kafka exceptions
 *
 * @implNote DECISION: Root exception for all Kafka client-side errors. Extends
 * RuntimeException (unchecked) rather than checked Exception. Alternative: Checked
 * exception hierarchy. Rationale: Kafka operations (produce, consume, admin) are
 * typically called in functional/streaming contexts (lambdas, Stream API) where checked
 * exceptions are impractical. Unchecked exceptions propagate naturally through callback
 * chains and {@code Future.get()} wrapping.
 *
 * <p>CROSS-CUTTING: Base exception type for entire Kafka client ecosystem. Subclassed
 * by {@code common/errors/ApiException} (server-reported errors),
 * {@code common/errors/RetriableException} (transient failures), and dozens of specific
 * exception types. All Kafka clients (producer, consumer, admin, streams, connect) throw
 * KafkaException or subclasses.
 */
public class KafkaException extends RuntimeException {

    // DECISION: Explicit serialVersionUID ensures binary compatibility of serialized
    // exceptions across Kafka versions.
    private static final long serialVersionUID = 1L;

    public KafkaException(String message, Throwable cause) {
        super(message, cause);
    }

    public KafkaException(String message) {
        super(message);
    }

    public KafkaException(Throwable cause) {
        super(cause);
    }

    public KafkaException() {
        super();
    }

}
