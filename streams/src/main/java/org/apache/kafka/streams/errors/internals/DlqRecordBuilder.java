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

import java.util.Arrays;
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
 *     <li>it honours the {@link DeadLetterQueueOptions#includeHeaders() header-inclusion toggle} and the
 *         {@link DeadLetterQueueOptions#maxRecordSize() maximum record (value) size}.</li>
 * </ul>
 *
 * <p>When the configured {@link DeadLetterQueueOptions#maxRecordSize() max record size} is exceeded by the
 * value payload, the value is <em>truncated</em> to fit and a {@link #HEADER_VALUE_TRUNCATED} header is added;
 * the record is <em>never dropped</em>, preserving the guarantee that every DLQ-eligible failed record lands
 * on the DLQ topic.
 *
 * <p>The class is stateless (only {@code static} methods) and therefore thread-safe, which is required because
 * DLQ records may be built concurrently across multiple {@code StreamThread} instances.
 */
public final class DlqRecordBuilder {

    /** Header carrying the fully-qualified class name of the exception that caused the failure. */
    public static final String HEADER_EXCEPTION_CLASS = "dlq.exception.class";
    /** Header carrying the exception message (may be absent if the exception carried no message). */
    public static final String HEADER_EXCEPTION_MESSAGE = "dlq.exception.message";
    /** Header carrying the source topic of the failed record. */
    public static final String HEADER_SOURCE_TOPIC = "dlq.source.topic";
    /** Header carrying the source partition of the failed record. */
    public static final String HEADER_SOURCE_PARTITION = "dlq.source.partition";
    /** Header carrying the source offset of the failed record. */
    public static final String HEADER_SOURCE_OFFSET = "dlq.source.offset";
    /** Header carrying the wall-clock timestamp (epoch millis) at which the record was dead-lettered. */
    public static final String HEADER_FAILURE_TIMESTAMP = "dlq.failure.timestamp";
    /**
     * Header added (with the string value {@code "true"}) when the value payload was truncated to satisfy
     * {@link DeadLetterQueueOptions#maxRecordSize()}. Absent when no truncation occurred.
     */
    public static final String HEADER_VALUE_TRUNCATED = "dlq.value.truncated";

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
     * @param options   the effective DLQ options (header toggle and max record size)
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
     * <p>The outgoing record carries the original key/value bytes (with the value truncated to
     * {@link DeadLetterQueueOptions#maxRecordSize()} when necessary) and, unless
     * {@link DeadLetterQueueOptions#includeHeaders()} is {@code false}, the six {@code dlq.*} diagnostic
     * headers plus (when truncation occurred) the {@link #HEADER_VALUE_TRUNCATED} marker. The producer-record
     * timestamp is taken from {@link ErrorHandlerContext#timestamp()} so the DLQ record preserves the source
     * record's event time; the wall-clock failure time is recorded separately in {@link #HEADER_FAILURE_TIMESTAMP}.
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

        final int maxRecordSize = options.maxRecordSize();
        final boolean truncate = value != null
            && maxRecordSize >= 0
            && maxRecordSize != DeadLetterQueueOptions.NO_MAX_RECORD_SIZE
            && value.length > maxRecordSize;
        final byte[] outgoingValue = truncate ? Arrays.copyOf(value, maxRecordSize) : value;

        final ProducerRecord<byte[], byte[]> producerRecord =
            new ProducerRecord<>(dlqTopic, null, context.timestamp(), key, outgoingValue);

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
                if (truncate) {
                    producerRecord.headers().add(HEADER_VALUE_TRUNCATED,
                        stringSerializer.serialize(null, "true"));
                }
            }
        }

        return producerRecord;
    }
}
