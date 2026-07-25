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
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.streams.errors.ErrorHandlerContext;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.streams.processor.TaskId;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link DlqRecordBuilder}, the opt-in DSL-level Dead Letter Queue record builder. Verifies the
 * six {@code dlq.*} headers, the producer-record timestamp/raw-bytes, the header-inclusion toggle, and the
 * max-record-size truncate-and-annotate behaviour. Mirrors {@code ExceptionHandlerUtilsTest} for the pre-existing
 * KIP-1034 record builder.
 */
public class DlqRecordBuilderTest {

    private static final StringDeserializer STRING_DESERIALIZER = new StringDeserializer();

    private static final String SOURCE_TOPIC = "source-topic";
    private static final int SOURCE_PARTITION = 3;
    private static final long SOURCE_OFFSET = 42L;
    private static final long SOURCE_TIMESTAMP = 1_000L;
    private static final String DLQ_TOPIC = "my-dlq";

    private static ErrorHandlerContext context() {
        // A null ProcessorContext is sufficient: DlqRecordBuilder only reads the stored coordinates/timestamp.
        return new DefaultErrorHandlerContext(
            null,
            SOURCE_TOPIC,
            SOURCE_PARTITION,
            SOURCE_OFFSET,
            null,
            "source-node",
            new TaskId(0, 0),
            SOURCE_TIMESTAMP,
            "raw-key".getBytes(StandardCharsets.UTF_8),
            "raw-value".getBytes(StandardCharsets.UTF_8)
        );
    }

    private static String header(final Headers headers, final String key) {
        return STRING_DESERIALIZER.deserialize(null, headers.lastHeader(key).value());
    }

    @Test
    public void shouldBuildRecordWithAllSixHeadersRawBytesAndTimestamp() {
        final byte[] key = "raw-key".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "raw-value".getBytes(StandardCharsets.UTF_8);
        final RuntimeException exception = new IllegalStateException("boom");

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), exception, DeadLetterQueueOptions.with(DLQ_TOPIC));

        assertEquals(DLQ_TOPIC, record.topic());
        assertNull(record.partition());
        // producer-record timestamp is taken from the source record's event time
        assertEquals(SOURCE_TIMESTAMP, record.timestamp());
        // original (raw) bytes are preserved verbatim
        assertArrayEquals(key, record.key());
        assertArrayEquals(value, record.value());

        final Headers headers = record.headers();
        assertEquals(IllegalStateException.class.getName(), header(headers, DlqRecordBuilder.HEADER_EXCEPTION_CLASS));
        assertEquals("boom", header(headers, DlqRecordBuilder.HEADER_EXCEPTION_MESSAGE));
        assertEquals(SOURCE_TOPIC, header(headers, DlqRecordBuilder.HEADER_SOURCE_TOPIC));
        assertEquals(String.valueOf(SOURCE_PARTITION), header(headers, DlqRecordBuilder.HEADER_SOURCE_PARTITION));
        assertEquals(String.valueOf(SOURCE_OFFSET), header(headers, DlqRecordBuilder.HEADER_SOURCE_OFFSET));
        // failure timestamp is wall-clock millis and must be a parseable, positive value
        final long failureTs = Long.parseLong(header(headers, DlqRecordBuilder.HEADER_FAILURE_TIMESTAMP));
        assertTrue(failureTs > 0L);
        // no truncation occurred, so the truncation marker must be absent
        assertNull(headers.lastHeader(DlqRecordBuilder.HEADER_VALUE_TRUNCATED));
    }

    @Test
    public void shouldOmitAllHeadersWhenHeaderInclusionDisabled() {
        final byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "v".getBytes(StandardCharsets.UTF_8);

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withIncludeHeaders(false));

        assertFalse(record.headers().iterator().hasNext());
        // bytes are still preserved even when headers are disabled
        assertArrayEquals(key, record.key());
        assertArrayEquals(value, record.value());
    }

    @Test
    public void shouldTruncateValueAndAnnotateWhenExceedingMaxRecordSize() {
        final byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        final byte[] value = "0123456789".getBytes(StandardCharsets.UTF_8); // 10 bytes
        final int maxRecordSize = 4;

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, key, value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(maxRecordSize));

        // value is truncated to fit, never dropped
        assertEquals(maxRecordSize, record.value().length);
        assertArrayEquals("0123".getBytes(StandardCharsets.UTF_8), record.value());
        // truncation is annotated
        assertEquals("true", header(record.headers(), DlqRecordBuilder.HEADER_VALUE_TRUNCATED));
    }

    @Test
    public void shouldNotTruncateWhenValueWithinMaxRecordSize() {
        final byte[] value = "abc".getBytes(StandardCharsets.UTF_8); // 3 bytes

        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, null, value, context(), new RuntimeException("x"),
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(8));

        assertArrayEquals(value, record.value());
        assertNull(record.headers().lastHeader(DlqRecordBuilder.HEADER_VALUE_TRUNCATED));
    }

    @Test
    public void shouldHandleNullKeyValueAndNullExceptionMessage() {
        final ProducerRecord<byte[], byte[]> record = DlqRecordBuilder.buildDeadLetterQueueRecord(
            DLQ_TOPIC, null, null, context(), new RuntimeException(), DeadLetterQueueOptions.with(DLQ_TOPIC));

        assertNull(record.key());
        assertNull(record.value());
        assertEquals(RuntimeException.class.getName(), header(record.headers(), DlqRecordBuilder.HEADER_EXCEPTION_CLASS));
        // a null exception message serializes to a null header value
        assertNull(record.headers().lastHeader(DlqRecordBuilder.HEADER_EXCEPTION_MESSAGE).value());
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
