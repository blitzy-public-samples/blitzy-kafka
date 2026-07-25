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
package org.apache.kafka.streams.errors.internals;

import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.errors.ErrorHandlerContext;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Internal, stateless builder that assembles the {@link ProducerRecord} sent to a Dead Letter Queue (DLQ)
 * topic by the opt-in, DSL-level DLQ layer (enabled via
 * {@link org.apache.kafka.streams.kstream.KStream#withDeadLetterQueue(String, DeadLetterQueueOptions)}).
 *
 * <p>This builder is the opt-in-layer analogue of {@link ExceptionHandlerUtils}: it produces a
 * {@code ProducerRecord<byte[], byte[]>} that carries the <em>original</em> (non-deserialized) key and value
 * bytes of the failed record so that downstream tooling can inspect or replay it. It differs from
 * {@link ExceptionHandlerUtils} in three deliberate ways that keep the two DLQ schemes independent and
 * coexisting (see {@code StreamsConfig.ERRORS_DEAD_LETTER_QUEUE_TOPIC_NAME_CONFIG} for the pre-existing
 * KIP-1034 scheme):
 * <ul>
 *     <li>it uses the {@code dlq.*} header naming family (mirroring the Kafka Connect DLQ context headers)
 *         rather than the {@code __streams.errors.*} family;</li>
 *     <li>it adds a dedicated {@link #HEADER_FAILURE_TIMESTAMP} header carrying the wall-clock time at which
 *         the failure was dead-lettered, and it does not emit a stack-trace header;</li>
 *     <li>it honours the {@link DeadLetterQueueOptions#includeHeaders() header-inclusion toggle}.</li>
 * </ul>
 *
 * <h2>Original bytes are preserved verbatim</h2>
 * <p>Per the DLQ feature's success criteria, the DLQ record carries the failed record's original key/value
 * bytes <em>exactly</em> as received: the builder never truncates, pads, copies, or otherwise mutates them,
 * and — when header inclusion is enabled — it always emits <em>exactly the six</em> {@code dlq.*} headers
 * declared below, no more and no fewer. The bytes are passed through by reference (no defensive copy), so the
 * failure path adds no memory amplification. Bounding the <em>physical</em> size of a DLQ record is delegated
 * to the shared producer / broker message-size configuration (for example {@code max.request.size} and the
 * topic's {@code max.message.bytes}); the builder does <em>not</em> apply
 * {@link DeadLetterQueueOptions#maxRecordSize()} as a value truncation, because truncating would break the
 * original-bytes guarantee that inspection/replay tooling relies on.
 *
 * <h2>Timestamps</h2>
 * <p>Two independent timestamps are recorded, with distinct meanings:
 * <ul>
 *     <li>the outgoing {@link ProducerRecord}'s own timestamp is the failed record's <em>source event time</em>
 *         ({@link ErrorHandlerContext#timestamp()}) when it is available. When the source timestamp is
 *         unavailable — {@link ErrorHandlerContext#timestamp()} returns a negative value such as
 *         {@code ConsumerRecord.NO_TIMESTAMP} ({@code -1}) — the record timestamp is left {@code null} so the
 *         producer stamps the send time. This guard is required because {@link ProducerRecord} rejects a
 *         negative non-null timestamp; building must never throw for a DLQ-eligible record, otherwise the
 *         record would be lost instead of dead-lettered;</li>
 *     <li>the {@link #HEADER_FAILURE_TIMESTAMP} header carries the wall-clock time (epoch millis) at which the
 *         failure was dead-lettered — i.e. when this builder ran — which is independent of, and generally
 *         later than, the source event time above.</li>
 * </ul>
 *
 * <h2>Data classification / privacy</h2>
 * <p>When header inclusion is enabled (the default), the {@link #HEADER_EXCEPTION_MESSAGE} header carries the
 * exception message verbatim. An exception message can contain sensitive data (for example fragments of the
 * offending payload) and is not size-bounded by this builder. Operators who must not expose such data on the
 * DLQ topic — or who need to keep DLQ records small — should disable header inclusion via
 * {@link DeadLetterQueueOptions#withIncludeHeaders(boolean) withIncludeHeaders(false)}, which suppresses all
 * {@code dlq.*} headers while still preserving the original key/value bytes.
 *
 * <p>The class is stateless (only {@code static} methods) and therefore thread-safe, which is required because
 * DLQ records may be built concurrently across multiple {@code StreamThread} instances. The public
 * {@code build*} methods and the six {@code HEADER_*} constants are consumed from other packages (the DLQ-aware
 * handler decorator and the runtime send sites), so they are intentionally {@code public}.
 */
public final class DlqRecordBuilder {

    /** Header carrying the fully-qualified class name of the exception that caused the failure. */
    public static final String HEADER_EXCEPTION_CLASS = "dlq.exception.class";
    /** Header carrying the exception message (its value is {@code null} when the exception carried no message). */
    public static final String HEADER_EXCEPTION_MESSAGE = "dlq.exception.message";
    /** Header carrying the source topic of the failed record. */
    public static final String HEADER_SOURCE_TOPIC = "dlq.source.topic";
    /** Header carrying the source partition of the failed record. */
    public static final String HEADER_SOURCE_PARTITION = "dlq.source.partition";
    /** Header carrying the source offset of the failed record. */
    public static final String HEADER_SOURCE_OFFSET = "dlq.source.offset";
    /** Header carrying the wall-clock timestamp (epoch millis) at which the record was dead-lettered. */
    public static final String HEADER_FAILURE_TIMESTAMP = "dlq.failure.timestamp";

    private DlqRecordBuilder() {
        // stateless utility; not instantiable
    }

    /**
     * Build the (single-element) list of DLQ records for a failed record, or an empty list when the supplied
     * DLQ topic is {@code null} (i.e. the opt-in layer is not active for this record).
     *
     * @param dlqTopic  the resolved DLQ topic name; if {@code null} an empty list is returned
     * @param key       the original (non-deserialized) key bytes of the failed record (may be {@code null})
     * @param value     the original (non-deserialized) value bytes of the failed record (may be {@code null})
     * @param context   the error handler context of the failure (source coordinates and timestamp)
     * @param exception  the exception that caused the failure
     * @param options   the effective DLQ options (currently the header-inclusion toggle)
     * @return a singleton list holding the built DLQ record, or an empty list when {@code dlqTopic} is null
     */
    public static List<ProducerRecord<byte[], byte[]>> buildDeadLetterQueueRecords(final String dlqTopic,
                                                                                   final byte[] key,
                                                                                   final byte[] value,
                                                                                   final ErrorHandlerContext context,
                                                                                   final Exception exception,
                                                                                   final DeadLetterQueueOptions options) {
        if (dlqTopic == null) {
            return Collections.emptyList();
        }
        return Collections.singletonList(buildDeadLetterQueueRecord(dlqTopic, key, value, context, exception, options));
    }

    /**
     * Build a single DLQ {@link ProducerRecord} for the supplied failed record.
     *
     * <p>The outgoing record carries the <em>original</em> key/value bytes verbatim (never truncated or copied)
     * and, unless {@link DeadLetterQueueOptions#includeHeaders()} is {@code false}, exactly the six {@code dlq.*}
     * diagnostic headers declared on this class. The producer-record timestamp is the source record's event time
     * ({@link ErrorHandlerContext#timestamp()}), or {@code null} when that timestamp is unavailable
     * (negative, e.g. {@code ConsumerRecord.NO_TIMESTAMP}); the wall-clock failure time is recorded separately in
     * {@link #HEADER_FAILURE_TIMESTAMP}. See the class Javadoc for the full timestamp and data-classification
     * contract.
     *
     * @param dlqTopic  the resolved (non-null) DLQ topic name
     * @param key       the original key bytes (may be {@code null})
     * @param value     the original value bytes (may be {@code null})
     * @param context   the error handler context of the failure
     * @param exception  the exception that caused the failure
     * @param options   the effective DLQ options
     * @return the DLQ record to produce
     */
    public static ProducerRecord<byte[], byte[]> buildDeadLetterQueueRecord(final String dlqTopic,
                                                                            final byte[] key,
                                                                            final byte[] value,
                                                                            final ErrorHandlerContext context,
                                                                            final Exception exception,
                                                                            final DeadLetterQueueOptions options) {
        Objects.requireNonNull(dlqTopic, "dlqTopic cannot be null while building a dead letter queue record");
        Objects.requireNonNull(context, "error handler context cannot be null while building a dead letter queue record");
        Objects.requireNonNull(exception, "exception cannot be null while building a dead letter queue record");
        Objects.requireNonNull(options, "dead letter queue options cannot be null while building a dead letter queue record");

        // The source record's event time may be unavailable: ErrorHandlerContext.timestamp() returns a negative
        // value (e.g. ConsumerRecord.NO_TIMESTAMP == -1) in that case. ProducerRecord rejects a negative non-null
        // timestamp, so map any unavailable/negative value to null (the producer then stamps the send time).
        // Building must never throw for a DLQ-eligible record, otherwise the record would be lost rather than
        // dead-lettered. (This is a deliberate divergence from ExceptionHandlerUtils, which does not guard.)
        final long sourceTimestamp = context.timestamp();
        final Long recordTimestamp = sourceTimestamp < 0 ? null : Long.valueOf(sourceTimestamp);

        // Original key/value bytes are carried verbatim: no truncation and no defensive copy, so the DLQ record
        // preserves the exact bytes of the failed record and the failure path adds no memory amplification.
        final ProducerRecord<byte[], byte[]> producerRecord =
            new ProducerRecord<>(dlqTopic, null, recordTimestamp, key, value);

        if (options.includeHeaders()) {
            try (StringSerializer stringSerializer = new StringSerializer()) {
                producerRecord.headers().add(HEADER_EXCEPTION_CLASS,
                    stringSerializer.serialize(null, exception.getClass().getName()));
                producerRecord.headers().add(HEADER_EXCEPTION_MESSAGE,
                    stringSerializer.serialize(null, exception.getMessage()));
                producerRecord.headers().add(HEADER_SOURCE_TOPIC,
                    stringSerializer.serialize(null, context.topic()));
                producerRecord.headers().add(HEADER_SOURCE_PARTITION,
                    stringSerializer.serialize(null, String.valueOf(context.partition())));
                producerRecord.headers().add(HEADER_SOURCE_OFFSET,
                    stringSerializer.serialize(null, String.valueOf(context.offset())));
                producerRecord.headers().add(HEADER_FAILURE_TIMESTAMP,
                    stringSerializer.serialize(null, String.valueOf(System.currentTimeMillis())));
            }
        }

        return producerRecord;
    }
}
