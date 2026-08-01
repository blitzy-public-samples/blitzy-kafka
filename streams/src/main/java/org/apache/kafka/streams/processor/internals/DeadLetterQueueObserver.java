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
 * Centralizes the observability side effects that accompany writing records to a
 * Dead Letter Queue (DLQ) topic through the opt-in, DSL-level DLQ layer: incrementing the
 * {@code dlq-records-sent} sensor <em>once per DLQ record that the broker acknowledges</em> and emitting a single
 * WARN log <em>once per failure event</em> that identifies the failure without exposing the record key/value payload.
 *
 * <p>This helper is invoked <em>only</em> on the opt-in DLQ send path — that is, only when the effective
 * deserialization / processing / production exception handler is the matching
 * {@link org.apache.kafka.streams.kstream.internals.DeadLetterQueueExceptionHandlerDecorator DLQ-aware decorator}
 * produced by a topology that opted in via
 * {@link org.apache.kafka.streams.kstream.KStream#withDeadLetterQueue(String, org.apache.kafka.streams.kstream.DeadLetterQueueOptions)}
 * or the global {@code default.deadletterqueue.*} configuration. It is therefore <strong>not</strong>
 * invoked for the pre-existing KIP-1034 global-config DLQ path or for custom exception handlers, so
 * topologies that do not opt in keep byte-for-byte identical error-handling behaviour.
 *
 * <p>The two side effects are split deliberately (MA-08 / MA-09 / P5-05):
 * <ul>
 *   <li>{@link #recordSent(Sensor)} is called once for <em>each</em> DLQ record whose production the broker has
 *       acknowledged, from the producer send callback (ack-based counting), so the {@code dlq-records-sent-total}
 *       metric counts DLQ records that were confirmed persisted rather than send attempts or failure events. A DLQ
 *       send that fails is deliberately not counted — it is escalated exactly once through the record collector's
 *       recursion guard and surfaced as an ERROR — so the metric never reports a false success.</li>
 *   <li>{@link #warn(Logger, String, String, int, long)} is called once for each failure <em>event</em>, when the
 *       record is <em>routed</em> to the DLQ (attempt semantics, before the asynchronous acknowledgement), and emits
 *       a single targeted WARN carrying only the exception class and the source coordinates — never the throwable and
 *       never the key/value payload — so no stacktrace or sensitive record content is leaked to the log, and the log
 *       never claims a confirmed write before the broker has acknowledged it (P9-02).</li>
 * </ul>
 *
 * <p>The WARN and the record-routing happen on the failure branch only, so this adds no overhead to the non-failing
 * record path; the metric increment additionally happens only on the asynchronous producer callback for the DLQ
 * record.
 */
final class DeadLetterQueueObserver {

    private DeadLetterQueueObserver() {
        // stateless helper; not instantiable
    }

    /**
     * Increment the task-scoped {@code dlq-records-sent} sensor for a single DLQ record. Must be called once per DLQ
     * record whose production has been <em>acknowledged</em> by the broker — i.e. from the producer send callback's
     * success branch (ack-based counting) — so the resulting {@code dlq-records-sent-total} metric counts DLQ records
     * that were confirmed persisted rather than send attempts or failure events (MA-08 / P5-05). It must <em>not</em>
     * be called at the send-attempt point, because a DLQ send can still fail asynchronously; a failed DLQ send is
     * escalated exactly once by the record collector and is not counted here.
     *
     * <p>The sensor must be resolved on the calling {@code StreamThread} (not inside the producer callback, which
     * runs on the producer's Sender thread) and captured for the callback, so it carries the correct
     * {@code thread-id} tag. {@code Sensor.record()} is thread-safe, so invoking it from the Sender thread is safe.
     *
     * @param dlqRecordsSentSensor the task-scoped {@code dlq-records-sent} sensor
     */
    static void recordSent(final Sensor dlqRecordsSentSensor) {
        dlqRecordsSentSensor.record();
    }

    /**
     * Emit a single WARN describing a dead-lettered failure event. Must be called exactly once per failure event
     * (not once per produced record), when the record is <em>routed</em> to the DLQ — i.e. at the send-attempt point,
     * before the asynchronous acknowledgement. The message therefore uses attempt wording ("Routing a failed
     * record...") and never claims a confirmed write, so it stays truthful even if the DLQ send subsequently fails
     * (P9-02); a failed DLQ send is surfaced separately as an ERROR by the record collector's recursion guard, and a
     * successful one is reflected by the {@code dlq-records-sent-total} metric increment on acknowledgement. The
     * message deliberately carries only the exception class name and the source coordinates — it does
     * <strong>not</strong> pass the throwable (so no stacktrace is logged) and does not include the record key/value
     * payload — centralizing DLQ logging and preventing the sensitive-data leak of MA-09.
     *
     * @param log                the calling site's logger
     * @param exceptionClassName the fully-qualified class name of the triggering exception
     * @param topic              the source topic of the failed record (may be {@code null} when unavailable)
     * @param partition          the source partition of the failed record ({@code -1} when unavailable)
     * @param offset             the source offset of the failed record ({@code -1} when unavailable)
     */
    static void warn(final Logger log,
                     final String exceptionClassName,
                     final String topic,
                     final int partition,
                     final long offset) {
        log.warn(
            "Routing a failed record to the dead letter queue. exceptionClass=[{}] topic=[{}] partition=[{}] offset=[{}]",
            exceptionClassName,
            topic,
            partition,
            offset
        );
    }
}
