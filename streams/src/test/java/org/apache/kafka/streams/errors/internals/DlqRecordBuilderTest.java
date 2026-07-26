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

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.streams.errors.ErrorHandlerContext;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.streams.processor.TaskId;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link DlqRecordBuilder}, the opt-in DSL-level Dead Letter Queue record builder.
 *
 * <p>These tests lock the authoritative DLQ <em>wire contract</em> for the {@code dlq.*} scheme:
 * <ul>
 *     <li>at {@link DeadLetterQueueOptions#NO_MAX_RECORD_SIZE} (the default) the original key/value bytes are
 *         preserved <em>verbatim</em> (passed through by reference, never truncated, padded, or copied); when a
 *         positive {@link DeadLetterQueueOptions#maxRecordSize()} is set, an over-limit value is truncated to
 *         that many bytes (the record is still produced, never dropped) while the key is always verbatim;</li>
 *     <li>exactly the six {@code dlq.*} headers are emitted when header inclusion is enabled — no seventh
 *         header (no {@code dlq.value.truncated}) and no stack-trace header — and zero headers when it is
 *         disabled;</li>
 *     <li>the {@code dlq.exception.message} header is bounded to
 *         {@link DlqRecordBuilder#MAX_EXCEPTION_MESSAGE_LENGTH} characters;</li>
 *     <li>the producer-record timestamp is the source event time, or {@code null} when the source timestamp is
 *         unavailable ({@code ConsumerRecord.NO_TIMESTAMP}), so building never throws;</li>
 *     <li>the {@code dlq.failure.timestamp} header is the wall-clock dead-letter time.</li>
 * </ul>
 *
 * <p>Header names are asserted using <em>literal</em> wire strings (not the {@link DlqRecordBuilder} constants)
 * so the on-the-wire contract is pinned independently of the implementation constants; a dedicated test then
 * verifies the public constants equal those literals. This coverage targets the {@code dlq.*} scheme only and
 * is fully independent of the pre-existing KIP-1034 {@code __streams.errors.*} path
 * ({@link ExceptionHandlerUtils}), which remains unchanged.
 */
public class DlqRecordBuilderTest {

    private static final StringDeserializer STRING_DESERIALIZER = new StringDeserializer();

    private static final String SOURCE_TOPIC = "source-topic";
    private static final int SOURCE_PARTITION = 3;
    private static final long SOURCE_OFFSET = 42L;
    private static final long SOURCE_TIMESTAMP = 1_000L;
    private static final String DLQ_TOPIC = "my-dlq";

    // Literal on-the-wire header names — deliberately NOT referencing DlqRecordBuilder.HEADER_* so that a change
    // to an implementation constant cannot silently move the wire contract. The constant/literal equivalence is
    // asserted separately in shouldExposePublicHeaderConstantsMatchingWireNames().
    private static final String WIRE_EXCEPTION_CLASS = "dlq.exception.class";
    private static final String WIRE_EXCEPTION_MESSAGE = "dlq.exception.message";
    private static final String WIRE_SOURCE_TOPIC = "dlq.source.topic";
    private static final String WIRE_SOURCE_PARTITION = "dlq.source.partition";
    private static final String WIRE_SOURCE_OFFSET = "dlq.source.offset";
    private static final String WIRE_FAILURE_TIMESTAMP = "dlq.failure.timestamp";
    /** A seventh header that MUST NOT appear: the removed, non-contractual truncation marker. */
    private static final String WIRE_VALUE_TRUNCATED = "dlq.value.truncated";

    /** The exact, complete set of headers the builder must emit when header inclusion is enabled. */
    private static final List<String> EXPECTED_HEADER_KEYS = List.of(
        WIRE_EXCEPTION_CLASS,
        WIRE_EXCEPTION_MESSAGE,
        WIRE_SOURCE_TOPIC,
        WIRE_SOURCE_PARTITION,
        WIRE_SOURCE_OFFSET,
        WIRE_FAILURE_TIMESTAMP);

    private static ErrorHandlerContext context() {
        return context(SOURCE_TIMESTAMP);
    }

    private static ErrorHandlerContext context(final long timestamp) {
        // A null ProcessorContext is sufficient: DlqRecordBuilder only reads the stored coordinates/timestamp and
        // takes the key/value bytes from its explicit parameters (not from the context's raw bytes).
        return new DefaultErrorHandlerContext(
            null,
            SOURCE_TOPIC,
            SOURCE_PARTITION,
            SOURCE_OFFSET,
            null,
            "source-node",
            new TaskId(0, 0),
            timestamp,
            null,
            null
        );
    }

    private static String header(final Headers headers, final String key) {
        return STRING_DESERIALIZER.deserialize(null, headers.lastHeader(key).value());
    }

    private static List<String> headerKeys(final Headers headers) {
        final List<String> keys = new ArrayList<>();
        for (final Header h : headers) {
            keys.add(h.key());
        }
        return keys;
    }

    /**
     * Assert the record carries EXACTLY the six {@code dlq.*} headers — no seventh marker and no stack-trace
     * header — pinning the exact-header-count contract.
     */
    private static void assertExactlySixHeaders(final Headers headers) {
        final List<String> keys = headerKeys(headers);
        assertEquals(6, keys.size(), "expected exactly the six dlq.* headers but found: " + keys);
        assertTrue(keys.containsAll(EXPECTED_HEADER_KEYS), "missing one of the six dlq.* headers: " + keys);
        assertFalse(keys.contains(WIRE_VALUE_TRUNCATED), "the removed dlq.value.truncated header must not appear");
        for (final String key : keys) {
            assertFalse(key.contains("stacktrace"), "no stack-trace header must be emitted: " + key);
            assertFalse(key.startsWith("__streams.errors"), "KIP-1034 headers must not leak into the dlq.* scheme: " + key);
        }
    }

    @Test
    public void shouldBuildRecordWithExactlySixHeadersRawBytesAndEventTimeTimestamp() {
        final byte[] key = "raw-key".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "raw-value".getBytes(StandardCharsets.UTF_8);
        final RuntimeException exception = new IllegalStateException("boom");

        final long before = System.currentTimeMillis();
        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), exception, DeadLetterQueueOptions.with(DLQ_TOPIC));
        final long after = System.currentTimeMillis();

        assertEquals(DLQ_TOPIC, record.topic());
        assertNull(record.partition());
        // producer-record timestamp is the source record's event time
        assertEquals(SOURCE_TIMESTAMP, record.timestamp());
        // original (raw) bytes are preserved verbatim AND by reference (no defensive copy / memory amplification)
        assertArrayEquals(key, record.key());
        assertArrayEquals(value, record.value());
        assertSame(key, record.key());
        assertSame(value, record.value());

        final Headers headers = record.headers();
        // exactly the six dlq.* headers, no seventh/stack-trace header
        assertExactlySixHeaders(headers);
        // exact values, asserted against literal wire names
        assertEquals(IllegalStateException.class.getName(), header(headers, WIRE_EXCEPTION_CLASS));
        assertEquals("boom", header(headers, WIRE_EXCEPTION_MESSAGE));
        assertEquals(SOURCE_TOPIC, header(headers, WIRE_SOURCE_TOPIC));
        assertEquals(String.valueOf(SOURCE_PARTITION), header(headers, WIRE_SOURCE_PARTITION));
        assertEquals(String.valueOf(SOURCE_OFFSET), header(headers, WIRE_SOURCE_OFFSET));
        // failure timestamp is the wall-clock dead-letter time: deterministically within the measured window
        final long failureTs = Long.parseLong(header(headers, WIRE_FAILURE_TIMESTAMP));
        assertTrue(failureTs >= before && failureTs <= after,
            "dlq.failure.timestamp " + failureTs + " must be a wall-clock value within [" + before + ", " + after + "]");
        // the removed truncation marker must never be present
        assertNull(headers.lastHeader(WIRE_VALUE_TRUNCATED));
    }

    @Test
    public void shouldSetProducerRecordTimestampToNullWhenSourceTimestampUnavailable() {
        final byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "v".getBytes(StandardCharsets.UTF_8);
        final RuntimeException exception = new RuntimeException("x");

        // ErrorHandlerContext.timestamp() may be -1 (ConsumerRecord.NO_TIMESTAMP) when unavailable. Previously
        // this crashed ProducerRecord's constructor (negative non-null timestamp) and prevented DLQ delivery.
        final ProducerRecord<byte[], byte[]> noTimestampRecord = assertDoesNotThrow(() ->
            DlqRecordBuilder.buildDeadLetterQueueRecord(
                DLQ_TOPIC, key, value, context(ConsumerRecord.NO_TIMESTAMP), exception,
                DeadLetterQueueOptions.with(DLQ_TOPIC)));
        assertNull(noTimestampRecord.timestamp(),
            "an unavailable source timestamp must map to a null producer-record timestamp");
        // the record is still fully built with all six headers
        assertExactlySixHeaders(noTimestampRecord.headers());

        // the guard is `< 0`, not merely `== -1`: any negative source timestamp maps to null and never throws
        final ProducerRecord<byte[], byte[]> arbitraryNegativeRecord = assertDoesNotThrow(() ->
            DlqRecordBuilder.buildDeadLetterQueueRecord(
                DLQ_TOPIC, key, value, context(-123_456L), exception,
                DeadLetterQueueOptions.with(DLQ_TOPIC)));
        assertNull(arbitraryNegativeRecord.timestamp());
    }

    @Test
    public void shouldOmitAllHeadersWhenHeaderInclusionDisabled() {
        final byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "v".getBytes(StandardCharsets.UTF_8);

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withIncludeHeaders(false));

        // zero dlq.* headers
        assertEquals(0, headerKeys(record.headers()).size());
        assertFalse(record.headers().iterator().hasNext());
        // bytes are still preserved verbatim even when headers are disabled
        assertArrayEquals(key, record.key());
        assertArrayEquals(value, record.value());
    }

    @Test
    public void shouldPassValueThroughVerbatimByReferenceWhenNoMaxRecordSize() {
        // Default contract (NO_MAX_RECORD_SIZE): the original value bytes are carried through verbatim, by
        // reference (no copy, no memory amplification), satisfying the "original key/value bytes" success
        // criterion. Exactly six headers, no seventh truncation marker.
        final byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "0123456789".getBytes(StandardCharsets.UTF_8); // 10 bytes

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC)); // NO_MAX_RECORD_SIZE default

        assertSame(value, record.value(), "value must be passed through by reference at NO_MAX_RECORD_SIZE");
        assertSame(key, record.key(), "key must always be passed through by reference");
        assertExactlySixHeaders(record.headers());
        assertNull(record.headers().lastHeader(WIRE_VALUE_TRUNCATED));
    }

    @Test
    public void shouldTruncateValueToMaxRecordSizeWhenLarger() {
        // Functional maxRecordSize (CR-04): an over-limit value is truncated to its first maxRecordSize bytes.
        // The record is still produced (never dropped) with exactly six headers and NO seventh marker header.
        final byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "0123456789".getBytes(StandardCharsets.UTF_8); // 10 bytes
        final int maxRecordSize = 4;

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(maxRecordSize));

        assertEquals(maxRecordSize, record.value().length, "value must be truncated to maxRecordSize bytes");
        assertArrayEquals("0123".getBytes(StandardCharsets.UTF_8), record.value(),
            "truncated value must be the original value's first maxRecordSize bytes");
        assertArrayEquals(key, record.key(), "key must never be truncated");
        assertSame(key, record.key());
        assertExactlySixHeaders(record.headers());
        assertNull(record.headers().lastHeader(WIRE_VALUE_TRUNCATED), "no seventh truncation marker header");
    }

    @Test
    public void shouldPreserveValueVerbatimWhenLengthEqualsMaxRecordSize() {
        // Exact boundary: value length == maxRecordSize is within the limit, so it is preserved verbatim by
        // reference (only a strictly-larger value is truncated).
        final byte[] value = "0123".getBytes(StandardCharsets.UTF_8); // 4 bytes

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, "k".getBytes(StandardCharsets.UTF_8), value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(4));

        assertSame(value, record.value(), "value at the exact limit must not be copied or truncated");
        assertNull(record.headers().lastHeader(WIRE_VALUE_TRUNCATED));
    }

    @Test
    public void shouldTruncateOversizeValueAndEmitNoHeadersWhenHeaderInclusionDisabled() {
        // maxRecordSize applies regardless of the header toggle: an over-limit value is truncated AND zero
        // headers are emitted when header inclusion is disabled.
        final byte[] value = "0123456789".getBytes(StandardCharsets.UTF_8); // 10 bytes

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, "k".getBytes(StandardCharsets.UTF_8), value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(4).withIncludeHeaders(false));

        assertEquals(4, record.value().length, "value must still be truncated when headers are disabled");
        assertArrayEquals("0123".getBytes(StandardCharsets.UTF_8), record.value());
        assertEquals(0, headerKeys(record.headers()).size());
    }

    @Test
    public void shouldNotAllocateForLargeValueAtNoMaxRecordSizeButBoundItWhenLimited() {
        // Aliasing/allocation safety at the default: a multi-MiB value is passed through by reference (no copy)
        // when NO_MAX_RECORD_SIZE. When a small limit is set, the value is bounded to that limit while the (small)
        // key is still passed through verbatim.
        final byte[] largeKey = new byte[16];
        final byte[] largeValue = new byte[2 * 1024 * 1024]; // 2 MiB

        final ProducerRecord<byte[], byte[]> verbatim = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, largeKey, largeValue, context(), new RuntimeException("big"),
            DeadLetterQueueOptions.with(DLQ_TOPIC)); // NO_MAX_RECORD_SIZE
        assertSame(largeValue, verbatim.value(), "value must be passed through without copying at NO_MAX_RECORD_SIZE");

        final ProducerRecord<byte[], byte[]> bounded = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, largeKey, largeValue, context(), new RuntimeException("big"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(1024));
        assertSame(largeKey, bounded.key(), "key must be passed through without copying");
        assertEquals(1024, bounded.value().length, "value must be bounded to maxRecordSize");
        assertExactlySixHeaders(bounded.headers());
        assertNull(bounded.headers().lastHeader(WIRE_VALUE_TRUNCATED));
    }

    @Test
    public void shouldBoundExceptionMessageAndOmitItWhenHeadersDisabled() {
        // Security / data-classification (MA-06): a large (potentially sensitive) exception message is bounded to
        // MAX_EXCEPTION_MESSAGE_LENGTH characters in the dlq.exception.message header, and fully omitted when
        // headers are disabled.
        final StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 5_000; i++) {
            builder.append('x');
        }
        final String longMessage = builder.toString();
        final RuntimeException exception = new RuntimeException(longMessage);
        final byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "v".getBytes(StandardCharsets.UTF_8);

        final ProducerRecord<byte[], byte[]> withHeaders = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), exception, DeadLetterQueueOptions.with(DLQ_TOPIC));
        final String recorded = header(withHeaders.headers(), WIRE_EXCEPTION_MESSAGE);
        assertEquals(DlqRecordBuilder.MAX_EXCEPTION_MESSAGE_LENGTH, recorded.length(),
            "the exception message must be bounded to MAX_EXCEPTION_MESSAGE_LENGTH characters");
        assertEquals(longMessage.substring(0, DlqRecordBuilder.MAX_EXCEPTION_MESSAGE_LENGTH), recorded,
            "the bounded message must be the original message's first MAX_EXCEPTION_MESSAGE_LENGTH characters");

        final ProducerRecord<byte[], byte[]> withoutHeaders = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), exception,
            DeadLetterQueueOptions.with(DLQ_TOPIC).withIncludeHeaders(false));
        assertNull(withoutHeaders.headers().lastHeader(WIRE_EXCEPTION_MESSAGE),
            "disabling headers must suppress the exception-message header");
        assertEquals(0, headerKeys(withoutHeaders.headers()).size());
    }

    @Test
    public void shouldCarryShortExceptionMessageVerbatim() {
        // A message within the bound is carried unchanged.
        final RuntimeException exception = new RuntimeException("short message");
        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, "k".getBytes(StandardCharsets.UTF_8), "v".getBytes(StandardCharsets.UTF_8),
            context(), exception, DeadLetterQueueOptions.with(DLQ_TOPIC));
        assertEquals("short message", header(record.headers(), WIRE_EXCEPTION_MESSAGE));
    }

    @Test
    public void shouldUseProvidedResolvedTopicVerbatim() {
        // The builder places the RESOLVED topic argument on the record verbatim; it is a payload builder and does
        // NOT re-validate topic names — authoritative Kafka topic-name validation is the responsibility of the
        // upstream configuration/options/DSL resolution layer (DeadLetterQueueOptions.with, KStreamImpl,
        // StreamsConfig). Here a distinct resolved-topic string is passed to show it is used as-is; the options
        // object independently carries a (validated) topic.
        final String resolvedTopic = "resolved.dlq.topic";

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            resolvedTopic, "k".getBytes(StandardCharsets.UTF_8), "v".getBytes(StandardCharsets.UTF_8),
            context(), new RuntimeException("x"), DeadLetterQueueOptions.with(DLQ_TOPIC));

        assertEquals(resolvedTopic, record.topic());
    }

    @Test
    public void shouldHandleNullKeyValueAndNullExceptionMessage() {
        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, null, null, context(), new RuntimeException(), DeadLetterQueueOptions.with(DLQ_TOPIC));

        assertNull(record.key());
        assertNull(record.value());
        assertExactlySixHeaders(record.headers());
        assertEquals(RuntimeException.class.getName(), header(record.headers(), WIRE_EXCEPTION_CLASS));
        // a null exception message serializes to a null header value (the header is still present)
        assertNotNull(record.headers().lastHeader(WIRE_EXCEPTION_MESSAGE));
        assertNull(record.headers().lastHeader(WIRE_EXCEPTION_MESSAGE).value());
    }

    @Test
    public void shouldExposePublicHeaderConstantsMatchingWireNames() {
        // Pin the public constants to the exact on-the-wire names so any accidental drift is caught, and confirm
        // the removed truncation-marker constant no longer exists as one of the emitted headers.
        assertEquals(WIRE_EXCEPTION_CLASS, DlqRecordBuilder.HEADER_EXCEPTION_CLASS);
        assertEquals(WIRE_EXCEPTION_MESSAGE, DlqRecordBuilder.HEADER_EXCEPTION_MESSAGE);
        assertEquals(WIRE_SOURCE_TOPIC, DlqRecordBuilder.HEADER_SOURCE_TOPIC);
        assertEquals(WIRE_SOURCE_PARTITION, DlqRecordBuilder.HEADER_SOURCE_PARTITION);
        assertEquals(WIRE_SOURCE_OFFSET, DlqRecordBuilder.HEADER_SOURCE_OFFSET);
        assertEquals(WIRE_FAILURE_TIMESTAMP, DlqRecordBuilder.HEADER_FAILURE_TIMESTAMP);
    }

    @Test
    public void shouldReturnSingletonListWhenTopicProvided() {
        final List<ProducerRecord<byte[], byte[]>> records = DlqRecordBuilder.buildDeadLetterQueueRecords(
            DLQ_TOPIC, "k".getBytes(StandardCharsets.UTF_8), "v".getBytes(StandardCharsets.UTF_8),
            context(), new RuntimeException("x"), DeadLetterQueueOptions.with(DLQ_TOPIC));

        assertEquals(1, records.size());
        assertNotNull(records.get(0));
        assertEquals(DLQ_TOPIC, records.get(0).topic());
    }

    @Test
    public void shouldReturnEmptyListWhenTopicIsNull() {
        final List<ProducerRecord<byte[], byte[]>> records = DlqRecordBuilder.buildDeadLetterQueueRecords(
            null, "k".getBytes(StandardCharsets.UTF_8), "v".getBytes(StandardCharsets.UTF_8),
            context(), new RuntimeException("x"), DeadLetterQueueOptions.with("unused"));

        assertTrue(records.isEmpty());
    }

    @Test
    public void shouldThrowOnNullRequiredArgumentsForSingleRecordBuild() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC);
        final ErrorHandlerContext ctx = context();
        final RuntimeException ex = new RuntimeException("x");

        assertThrows(NullPointerException.class, () ->
            DlqRecordBuilder.buildDeadLetterQueueRecord(null, null, null, ctx, ex, options));
        assertThrows(NullPointerException.class, () ->
            DlqRecordBuilder.buildDeadLetterQueueRecord(DLQ_TOPIC, null, null, null, ex, options));
        assertThrows(NullPointerException.class, () ->
            DlqRecordBuilder.buildDeadLetterQueueRecord(DLQ_TOPIC, null, null, ctx, null, options));
        assertThrows(NullPointerException.class, () ->
            DlqRecordBuilder.buildDeadLetterQueueRecord(DLQ_TOPIC, null, null, ctx, ex, null));
    }
}
