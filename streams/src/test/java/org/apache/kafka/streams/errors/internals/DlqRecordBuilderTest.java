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
 *     <li>the original key/value bytes are preserved <em>verbatim</em> (never truncated, padded, or copied),
 *         regardless of {@link DeadLetterQueueOptions#maxRecordSize()};</li>
 *     <li>exactly the six {@code dlq.*} headers are emitted when header inclusion is enabled — no seventh
 *         header (no {@code dlq.value.truncated}) and no stack-trace header — and zero headers when it is
 *         disabled;</li>
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
    public void shouldPreserveOriginalValueBytesWhenLargerThanMaxRecordSize() {
        // Authoritative contract: original bytes are preserved verbatim and exactly six headers are emitted, even
        // when the value exceeds the configured maxRecordSize. The builder never truncates and never adds a
        // seventh dlq.value.truncated header. (Replaces the previous truncate-and-annotate test, which codified
        // the two CRITICAL production defects.)
        final byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "0123456789".getBytes(StandardCharsets.UTF_8); // 10 bytes
        final int maxRecordSize = 4;

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(maxRecordSize));

        // full original value preserved (not truncated to maxRecordSize), by reference
        assertArrayEquals(value, record.value());
        assertEquals(value.length, record.value().length);
        assertSame(value, record.value());
        assertArrayEquals(key, record.key());
        // exactly six headers; NO truncation marker
        assertExactlySixHeaders(record.headers());
        assertNull(record.headers().lastHeader(WIRE_VALUE_TRUNCATED));
    }

    @Test
    public void shouldPreserveOriginalBytesWhenMaxRecordSizeIsZero() {
        // A zero max-record-size must NOT empty or drop the value: original bytes are still preserved verbatim.
        final byte[] value = "0123456789".getBytes(StandardCharsets.UTF_8);

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, "k".getBytes(StandardCharsets.UTF_8), value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(0));

        assertArrayEquals(value, record.value());
        assertSame(value, record.value());
        assertNull(record.headers().lastHeader(WIRE_VALUE_TRUNCATED));
        assertExactlySixHeaders(record.headers());
    }

    @Test
    public void shouldPreserveValueWhenLengthEqualsMaxRecordSize() {
        // Exact boundary: value length == maxRecordSize is preserved unchanged with no marker.
        final byte[] value = "0123".getBytes(StandardCharsets.UTF_8); // 4 bytes

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, "k".getBytes(StandardCharsets.UTF_8), value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(4));

        assertArrayEquals(value, record.value());
        assertNull(record.headers().lastHeader(WIRE_VALUE_TRUNCATED));
    }

    @Test
    public void shouldPreserveOversizeValueAndEmitNoHeadersWhenHeaderInclusionDisabled() {
        // Previously the value was silently truncated even when headers were disabled (so no marker could warn).
        // Now: the full value is preserved verbatim AND zero headers are emitted.
        final byte[] value = "0123456789".getBytes(StandardCharsets.UTF_8); // 10 bytes

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, "k".getBytes(StandardCharsets.UTF_8), value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(4).withIncludeHeaders(false));

        assertArrayEquals(value, record.value());
        assertSame(value, record.value());
        assertEquals(0, headerKeys(record.headers()).size());
    }

    @Test
    public void shouldNotAllocateOrTruncateForLargeKeyAndValue() {
        // Huge-allocation / aliasing safety: with a small maxRecordSize and multi-MiB payloads, the builder must
        // pass the SAME byte arrays through (no truncated copy) so the failure path adds no memory amplification.
        final byte[] largeKey = new byte[1024 * 1024];      // 1 MiB
        final byte[] largeValue = new byte[2 * 1024 * 1024]; // 2 MiB

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, largeKey, largeValue, context(), new RuntimeException("big"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(1024));

        assertSame(largeKey, record.key(), "key must be passed through without copying");
        assertSame(largeValue, record.value(), "value must be passed through without truncation or copying");
        assertExactlySixHeaders(record.headers());
        assertNull(record.headers().lastHeader(WIRE_VALUE_TRUNCATED));
    }

    @Test
    public void shouldCarryExceptionMessageVerbatimAndOmitItWhenHeadersDisabled() {
        // Data-classification / privacy: a large (and potentially sensitive) exception message is carried verbatim
        // in the dlq.exception.message header when headers are enabled, and fully omitted when they are disabled —
        // the documented escape hatch for operators who must not expose such data on the DLQ topic.
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
        assertEquals(longMessage, header(withHeaders.headers(), WIRE_EXCEPTION_MESSAGE),
            "the exception message must be carried verbatim (never truncated) when headers are enabled");

        final ProducerRecord<byte[], byte[]> withoutHeaders = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), exception,
            DeadLetterQueueOptions.with(DLQ_TOPIC).withIncludeHeaders(false));
        assertNull(withoutHeaders.headers().lastHeader(WIRE_EXCEPTION_MESSAGE),
            "disabling headers must suppress the exception-message header");
        assertEquals(0, headerKeys(withoutHeaders.headers()).size());
    }

    @Test
    public void shouldUseProvidedDlqTopicVerbatim() {
        // The builder places the RESOLVED topic on the record verbatim; it does NOT validate topic names —
        // authoritative Kafka topic-name validation is the responsibility of the configuration/options resolution
        // layer, not this payload builder. Even a string that is not a valid Kafka topic name is passed through.
        final String unvalidatedTopic = "dlq topic!";

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            unvalidatedTopic, "k".getBytes(StandardCharsets.UTF_8), "v".getBytes(StandardCharsets.UTF_8),
            context(), new RuntimeException("x"), DeadLetterQueueOptions.with(unvalidatedTopic));

        assertEquals(unvalidatedTopic, record.topic());
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
