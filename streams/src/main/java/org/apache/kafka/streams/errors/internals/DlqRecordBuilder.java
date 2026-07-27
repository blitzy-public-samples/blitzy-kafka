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
 *     <li>it honours the {@link DeadLetterQueueOptions#includeHeaders() header-inclusion toggle}.</li>
 * </ul>
 *
 * <h2>Original bytes and the {@code maxRecordSize} bound</h2>
 * <p>By default ({@link DeadLetterQueueOptions#NO_MAX_RECORD_SIZE}, the value applied by
 * {@link DeadLetterQueueOptions#with(String)}) the DLQ record carries the failed record's original key/value
 * bytes <em>exactly</em> as received: the builder does not truncate, pad, copy, or otherwise mutate them (the
 * bytes are passed through by reference), so the default failure path adds no memory amplification and inspection
 * / replay tooling sees the verbatim payload. This satisfies the "original key/value bytes" success criterion for
 * the default configuration.
 * <p>When the caller sets a positive {@link DeadLetterQueueOptions#maxRecordSize()}, the builder bounds the
 * <em>combined key + value</em> byte length of the outgoing record to at most that many bytes. Because keys are
 * small identifiers that must be preserved for correlation, the key is always carried verbatim and only the
 * <em>value</em> is truncated: the value budget is {@code maxRecordSize - key.length}, and an over-budget value is
 * truncated to its first {@code max(0, maxRecordSize - key.length)} bytes (reduced to an empty value when the key
 * alone already meets or exceeds the bound). This is an explicit, opt-in trade-off of full-fidelity payload for a
 * bounded record size; it is documented on {@link DeadLetterQueueOptions#withMaxRecordSize(int)}. Truncation only
 * ever <em>shrinks</em> a record and <em>never drops it</em>, so enabling a size bound never causes the builder to
 * discard a record it was asked to build (whether that record is ultimately produced is subject to the shared
 * producer/broker limits noted below and to best-effort delivery — a DLQ write that itself fails is escalated once
 * rather than retried).
 * <p>Truncation is made explicit rather than silent: when (and only when) the value is truncated <em>and</em>
 * {@link DeadLetterQueueOptions#includeHeaders() header inclusion} is enabled, the builder adds the annotation
 * headers {@link #HEADER_VALUE_TRUNCATED} ({@code "true"}) and {@link #HEADER_VALUE_ORIGINAL_SIZE} (the original
 * value byte length) alongside the six core {@code dlq.*} headers below. When the value is <em>not</em> truncated,
 * exactly the six core headers are emitted (no annotation). When header inclusion is disabled, the value is still
 * bounded but <em>no</em> {@code dlq.*} header — core or annotation — is written. Physical size is additionally
 * bounded, as before, by the shared producer / broker message-size configuration (for example
 * {@code max.request.size} and the topic's {@code max.message.bytes}).
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
 * exception message. An exception message can contain sensitive data (for example fragments of the offending
 * payload), so the builder <em>bounds</em> it: a message longer than {@link #MAX_EXCEPTION_MESSAGE_LENGTH}
 * characters is truncated to that length before being written to the header. This prevents an adversarial or
 * pathological exception message from producing an unbounded DLQ record and limits how much payload-derived text
 * is exposed. Operators who must not expose such data on the DLQ topic at all — or who need to keep DLQ records
 * as small as possible — should disable header inclusion via
 * {@link DeadLetterQueueOptions#withIncludeHeaders(boolean) withIncludeHeaders(false)}, which suppresses all
 * {@code dlq.*} headers while still preserving the (optionally size-bounded) key/value bytes. Because the DLQ
 * topic can carry payload-derived data, it must be secured with the same care as the source topic (topic ACLs).
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

    /**
     * Annotation header, present <em>only</em> when the record's value was truncated to satisfy
     * {@link DeadLetterQueueOptions#maxRecordSize()}. Its value is the literal string {@code "true"}. This header
     * makes truncation explicit rather than silent (a consumer of the DLQ topic can detect that the carried value
     * is a prefix of the original), and it is emitted only on the truncation branch and only when
     * {@link DeadLetterQueueOptions#includeHeaders() header inclusion} is enabled. See the class Javadoc
     * ("Original bytes and the {@code maxRecordSize} bound").
     */
    public static final String HEADER_VALUE_TRUNCATED = "dlq.value.truncated";

    /**
     * Annotation header, present <em>only</em> when the record's value was truncated, carrying the original
     * (pre-truncation) value length in bytes as a decimal string. Paired with {@link #HEADER_VALUE_TRUNCATED}, it
     * lets a DLQ consumer see exactly how many bytes were dropped. Emitted only on the truncation branch and only
     * when {@link DeadLetterQueueOptions#includeHeaders() header inclusion} is enabled.
     */
    public static final String HEADER_VALUE_ORIGINAL_SIZE = "dlq.value.original.size";

    /**
     * Upper bound (in {@code char}s / UTF-16 code units) on the exception-message text written to
     * {@link #HEADER_EXCEPTION_MESSAGE}. An exception message longer than this is truncated to at most this many
     * code units, on a Unicode <em>code-point boundary</em> (a surrogate pair is never split), which caps how much
     * payload-derived text can be exposed on the DLQ topic and prevents an adversarial message from producing an
     * unbounded DLQ record. See the class Javadoc ("Data classification / privacy").
     */
    public static final int MAX_EXCEPTION_MESSAGE_LENGTH = 2048;

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
     * <p>The outgoing record carries the <em>original</em> key bytes verbatim and the original value bytes bounded
     * so that the combined key+value length does not exceed {@link DeadLetterQueueOptions#maxRecordSize()}
     * (verbatim by reference with the default {@link DeadLetterQueueOptions#NO_MAX_RECORD_SIZE}; the value is
     * truncated when a positive limit is set — see {@link #boundValueToMaxRecordSize(byte[], byte[], int)}) and,
     * unless {@link DeadLetterQueueOptions#includeHeaders()} is {@code false}, the six core {@code dlq.*}
     * diagnostic headers declared on this class — plus the two annotation headers
     * {@link #HEADER_VALUE_TRUNCATED} and {@link #HEADER_VALUE_ORIGINAL_SIZE} when (and only when) the value was
     * truncated. The producer-record timestamp is the source record's event time
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

        // Bound the outgoing record to maxRecordSize. With NO_MAX_RECORD_SIZE (the default) the original value
        // bytes are carried through verbatim by reference (no copy, no memory amplification). With a positive
        // limit the COMBINED key + value byte length is bounded by truncating the value only (the key is always
        // carried verbatim, as keys are small identifiers used for correlation) — an explicit, opt-in size bound
        // that shrinks but never discards the record (size limiting never reduces DLQ coverage).
        final byte[] boundedValue = boundValueToMaxRecordSize(key, value, options.maxRecordSize());
        // Reference inequality is a reliable truncation signal: boundValueToMaxRecordSize returns the SAME array
        // by reference when it does not truncate and a fresh (shorter) array only when it truncates.
        final boolean valueTruncated = boundedValue != value;

        final ProducerRecord<byte[], byte[]> producerRecord =
            new ProducerRecord<>(dlqTopic, null, recordTimestamp, key, boundedValue);

        if (options.includeHeaders()) {
            try (StringSerializer stringSerializer = new StringSerializer()) {
                producerRecord.headers().add(HEADER_EXCEPTION_CLASS,
                    stringSerializer.serialize(null, exception.getClass().getName()));
                producerRecord.headers().add(HEADER_EXCEPTION_MESSAGE,
                    stringSerializer.serialize(null, boundExceptionMessage(exception.getMessage())));
                producerRecord.headers().add(HEADER_SOURCE_TOPIC,
                    stringSerializer.serialize(null, context.topic()));
                producerRecord.headers().add(HEADER_SOURCE_PARTITION,
                    stringSerializer.serialize(null, String.valueOf(context.partition())));
                producerRecord.headers().add(HEADER_SOURCE_OFFSET,
                    stringSerializer.serialize(null, String.valueOf(context.offset())));
                producerRecord.headers().add(HEADER_FAILURE_TIMESTAMP,
                    stringSerializer.serialize(null, String.valueOf(System.currentTimeMillis())));
                // Annotate truncation (AAP §0.5.2: truncate AND annotate, never drop). These two annotation
                // headers are emitted only when the value was actually truncated, so the common (non-truncated)
                // path still carries exactly the six core headers. The value is guaranteed non-null here because
                // truncation only ever occurs for a non-null, non-empty value.
                if (valueTruncated) {
                    producerRecord.headers().add(HEADER_VALUE_TRUNCATED,
                        stringSerializer.serialize(null, "true"));
                    producerRecord.headers().add(HEADER_VALUE_ORIGINAL_SIZE,
                        stringSerializer.serialize(null, String.valueOf(value.length)));
                }
            }
        }

        return producerRecord;
    }

    /**
     * Bound the DLQ record's <em>combined key + value</em> byte length to {@code maxRecordSize} by truncating the
     * value only.
     *
     * <p>When {@code maxRecordSize} indicates no limit ({@link DeadLetterQueueOptions#NO_MAX_RECORD_SIZE}, or
     * defensively any non-positive value), or the value is {@code null}/empty, or the key and value together are
     * already within the limit, the original value array is returned <em>by reference</em> so the common path
     * performs no allocation. Otherwise the value is truncated to a fresh array holding its first
     * {@code max(0, maxRecordSize - key.length)} bytes so that {@code key.length + value.length <= maxRecordSize}
     * (the value is reduced to empty when the key alone already meets or exceeds the bound). The key is never
     * truncated. Truncation only ever shrinks the record and never drops it.
     *
     * @param key           the original key bytes (may be {@code null}); always carried verbatim, never truncated
     * @param value         the original value bytes (may be {@code null})
     * @param maxRecordSize the configured maximum combined key+value size in bytes
     *                      ({@link DeadLetterQueueOptions#NO_MAX_RECORD_SIZE} means no limit)
     * @return the original value (by reference) when the combined size is within the limit, otherwise a truncated
     *         copy sized so the combined key+value length does not exceed {@code maxRecordSize}
     */
    private static byte[] boundValueToMaxRecordSize(final byte[] key, final byte[] value, final int maxRecordSize) {
        // NO_MAX_RECORD_SIZE (Integer.MAX_VALUE) or any non-positive value means "no limit". DeadLetterQueueOptions
        // only ever supplies NO_MAX_RECORD_SIZE or a strictly-positive value, but guard defensively.
        if (value == null || value.length == 0
            || maxRecordSize == DeadLetterQueueOptions.NO_MAX_RECORD_SIZE || maxRecordSize <= 0) {
            return value;
        }
        final int keyLength = key == null ? 0 : key.length;
        // The value budget is what remains of maxRecordSize after the (verbatim) key; never negative.
        final int valueBudget = Math.max(0, maxRecordSize - keyLength);
        if (value.length <= valueBudget) {
            return value;
        }
        return Arrays.copyOf(value, valueBudget);
    }

    /**
     * Bound the exception-message text written to {@link #HEADER_EXCEPTION_MESSAGE} to at most
     * {@link #MAX_EXCEPTION_MESSAGE_LENGTH} {@code char}s (UTF-16 code units), truncating on a Unicode
     * <em>code-point boundary</em> so a surrogate pair is never split.
     *
     * <p>If the last {@code char} that would be kept is a high surrogate, its low-surrogate partner falls just
     * past the cut, so keeping it alone would corrupt the trailing character. In that case the cut is stepped back
     * by one {@code char} so the whole code point is dropped and the returned string is at most
     * {@code MAX_EXCEPTION_MESSAGE_LENGTH} — never {@code MAX_EXCEPTION_MESSAGE_LENGTH} with a dangling surrogate.
     *
     * @param message the raw exception message (may be {@code null})
     * @return {@code null} when the input is {@code null}; the message unchanged when within the limit; otherwise
     *         its longest code-point-boundary prefix of at most {@link #MAX_EXCEPTION_MESSAGE_LENGTH} code units
     */
    private static String boundExceptionMessage(final String message) {
        if (message == null || message.length() <= MAX_EXCEPTION_MESSAGE_LENGTH) {
            return message;
        }
        int end = MAX_EXCEPTION_MESSAGE_LENGTH;
        // If the last kept char is a lone high surrogate (its low-surrogate partner sits at index `end`, which is
        // being dropped), step back so the pair is dropped as a unit rather than split.
        if (Character.isHighSurrogate(message.charAt(end - 1))) {
            end--;
        }
        return message.substring(0, end);
    }
}
