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
package org.apache.kafka.streams.processor.internals;

import org.apache.kafka.common.metrics.Sensor;

import org.slf4j.Logger;

/**
 * Centralizes the observability side effects that accompany writing a record to a
 * Dead Letter Queue (DLQ) topic through the opt-in, DSL-level DLQ layer: recording the
 * {@code dlq-records-sent} sensor and emitting a single WARN log that identifies the failure
 * without exposing the record key/value payload.
 *
 * <p>This helper is invoked <em>only</em> on the opt-in DLQ send path — that is, only when the
 * effective deserialization exception handler is the
 * {@link DeadLetterQueueDeserializationExceptionHandler DLQ-aware decorator} produced by a topology
 * that opted in via
 * {@link org.apache.kafka.streams.kstream.KStream#withDeadLetterQueue(String, org.apache.kafka.streams.kstream.DeadLetterQueueOptions)}
 * or the global {@code default.deadletterqueue.*} configuration. It is therefore <strong>not</strong>
 * invoked for the pre-existing KIP-1034 global-config DLQ path or for custom exception handlers, so
 * topologies that do not opt in keep byte-for-byte identical error-handling behaviour.
 *
 * <p>All invocations happen on the failure branch only, so this adds no overhead to the non-failing
 * record path.
 */
final class DeadLetterQueueObserver {

    private DeadLetterQueueObserver() {
        // stateless helper; not instantiable
    }

    /**
     * Records the DLQ sensor once and logs a single WARN describing the dead-lettered record.
     * Must be called exactly once per DLQ failure event (not once per produced record), and
     * only from within an opt-in DLQ send branch.
     *
     * @param log                  the calling site's logger
     * @param dlqRecordsSentSensor the task-scoped {@code dlq-records-sent} sensor
     * @param exceptionClassName   the fully-qualified class name of the triggering exception
     * @param topic                the source topic of the failed record (may be null)
     * @param partition            the source partition of the failed record
     * @param offset               the source offset of the failed record
     */
    static void record(final Logger log,
                        final Sensor dlqRecordsSentSensor,
                        final String exceptionClassName,
                        final String topic,
                        final int partition,
                        final long offset) {
        dlqRecordsSentSensor.record();
        log.warn(
            "Sent a failed record to the dead letter queue. exceptionClass=[{}] topic=[{}] partition=[{}] offset=[{}]",
            exceptionClassName,
            topic,
            partition,
            offset
        );
    }
}
