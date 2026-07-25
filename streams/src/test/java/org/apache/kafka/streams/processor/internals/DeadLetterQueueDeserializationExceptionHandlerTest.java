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

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.streams.errors.DeserializationExceptionHandler;
import org.apache.kafka.streams.errors.internals.DefaultErrorHandlerContext;
import org.apache.kafka.streams.errors.internals.DlqRecordBuilder;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.streams.processor.TaskId;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Direct unit tests for {@link DeadLetterQueueDeserializationExceptionHandler}, the internal decorator that
 * implements the opt-in DSL Dead Letter Queue (DLQ) capability for deserialization failures at a source node.
 *
 * <p>The tests pin the AAP-critical contracts of the decorator in isolation from the {@code RecordDeserializer}
 * send site:
 * <ul>
 *     <li>the three constructor {@code requireNonNull} guards (delegate, topic, options) with their exact
 *         messages;</li>
 *     <li>{@link DeadLetterQueueDeserializationExceptionHandler#configure(Map)} delegates to the wrapped handler
 *         ("decorate, do not modify");</li>
 *     <li>the {@code deadLetterQueueTopic()} / {@code deadLetterQueueOptions()} getters expose the resolved
 *         topic and options;</li>
 *     <li>{@code handleError} returns {@code RESUME} carrying a single {@code dlq.*} record built from the
 *         {@link ConsumerRecord}'s original key/value bytes (deliberately different from the error-context raw
 *         bytes here, to prove the {@link ConsumerRecord} bytes are used), with the {@code dlq.*} diagnostic
 *         headers populated and <em>no</em> legacy KIP-1034 {@code __streams.errors.*} header present.</li>
 * </ul>
 */
public class DeadLetterQueueDeserializationExceptionHandlerTest {

    private static final String DLQ_TOPIC = "dlq-topic";

    private static final String SOURCE_TOPIC = "source-topic";
    private static final int SOURCE_PARTITION = 3;
    private static final long SOURCE_OFFSET = 42L;
    private static final long SOURCE_TIMESTAMP = 1_000L;

    // The error-context raw bytes are intentionally DIFFERENT from the ConsumerRecord bytes so the tests can prove
    // that handleError builds the DLQ record from ConsumerRecord.key()/value(), not from the context raw bytes.
    private static final byte[] CONTEXT_RAW_KEY = "ctx-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CONTEXT_RAW_VALUE = "ctx-value".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RECORD_KEY = "rec-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RECORD_VALUE = "rec-value".getBytes(StandardCharsets.UTF_8);

    private static final DeadLetterQueueOptions OPTIONS = DeadLetterQueueOptions.with(DLQ_TOPIC);

    private static final StringDeserializer STRING_DESERIALIZER = new StringDeserializer();

    private static DefaultErrorHandlerContext context() {
        // A null ProcessorContext is sufficient: the builder only reads the stored coordinates/timestamp/raw bytes.
        return new DefaultErrorHandlerContext(
            null,
            SOURCE_TOPIC,
            SOURCE_PARTITION,
            SOURCE_OFFSET,
            null,
            "source-node",
            new TaskId(0, 0),
            SOURCE_TIMESTAMP,
            CONTEXT_RAW_KEY,
            CONTEXT_RAW_VALUE
        );
    }

    private static ConsumerRecord<byte[], byte[]> consumerRecord() {
        return new ConsumerRecord<>(SOURCE_TOPIC, SOURCE_PARTITION, SOURCE_OFFSET, RECORD_KEY, RECORD_VALUE);
    }

    private static String header(final Headers headers, final String key) {
        return STRING_DESERIALIZER.deserialize(null, headers.lastHeader(key).value());
    }

    @Test
    public void shouldThrowNullPointerExceptionWhenDelegateIsNull() {
        final NullPointerException exception = assertThrows(NullPointerException.class,
            () -> new DeadLetterQueueDeserializationExceptionHandler(null, DLQ_TOPIC, OPTIONS));
        assertEquals("delegate deserialization exception handler cannot be null", exception.getMessage());
    }

    @Test
    public void shouldThrowNullPointerExceptionWhenTopicIsNull() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final NullPointerException exception = assertThrows(NullPointerException.class,
            () -> new DeadLetterQueueDeserializationExceptionHandler(delegate, null, OPTIONS));
        assertEquals("dlqTopic cannot be null", exception.getMessage());
    }

    @Test
    public void shouldThrowNullPointerExceptionWhenOptionsIsNull() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final NullPointerException exception = assertThrows(NullPointerException.class,
            () -> new DeadLetterQueueDeserializationExceptionHandler(delegate, DLQ_TOPIC, null));
        assertEquals("dead letter queue options cannot be null", exception.getMessage());
    }

    @Test
    public void shouldDelegateConfigureToWrappedHandler() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final DeadLetterQueueDeserializationExceptionHandler handler =
            new DeadLetterQueueDeserializationExceptionHandler(delegate, DLQ_TOPIC, OPTIONS);
        final Map<String, Object> configs = Map.of("some.config", "value");

        handler.configure(configs);

        verify(delegate).configure(configs);
    }

    @Test
    public void shouldExposeResolvedTopicAndOptionsViaGetters() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(1024);
        final DeadLetterQueueDeserializationExceptionHandler handler =
            new DeadLetterQueueDeserializationExceptionHandler(delegate, DLQ_TOPIC, options);

        assertEquals(DLQ_TOPIC, handler.deadLetterQueueTopic());
        assertSame(options, handler.deadLetterQueueOptions());
    }

    @Test
    public void shouldResumeWithDlqRecordBuiltFromConsumerRecordBytes() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final DeadLetterQueueDeserializationExceptionHandler handler =
            new DeadLetterQueueDeserializationExceptionHandler(delegate, DLQ_TOPIC, OPTIONS);

        final DeserializationExceptionHandler.Response response =
            handler.handleError(context(), consumerRecord(), new SerializationException("boom"));

        assertEquals(DeserializationExceptionHandler.Result.RESUME, response.result());
        final List<ProducerRecord<byte[], byte[]>> records = response.deadLetterQueueRecords();
        assertEquals(1, records.size());
        final ProducerRecord<byte[], byte[]> dlqRecord = records.get(0);
        assertEquals(DLQ_TOPIC, dlqRecord.topic());
        // the DLQ record must carry the ConsumerRecord's ORIGINAL bytes, NOT the (different) error-context raw bytes
        assertArrayEquals(RECORD_KEY, dlqRecord.key());
        assertArrayEquals(RECORD_VALUE, dlqRecord.value());
        // the producer-record timestamp is taken from the error context
        assertEquals(SOURCE_TIMESTAMP, dlqRecord.timestamp());
    }

    @Test
    public void shouldPopulateDlqHeadersAndOmitLegacyStreamsErrorsHeaders() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final DeadLetterQueueDeserializationExceptionHandler handler =
            new DeadLetterQueueDeserializationExceptionHandler(delegate, DLQ_TOPIC, OPTIONS);

        final SerializationException exception = new SerializationException("deserialization failed");
        final DeserializationExceptionHandler.Response response =
            handler.handleError(context(), consumerRecord(), exception);

        final Headers headers = response.deadLetterQueueRecords().get(0).headers();
        assertEquals(SerializationException.class.getName(), header(headers, DlqRecordBuilder.HEADER_EXCEPTION_CLASS));
        assertEquals("deserialization failed", header(headers, DlqRecordBuilder.HEADER_EXCEPTION_MESSAGE));
        assertEquals(SOURCE_TOPIC, header(headers, DlqRecordBuilder.HEADER_SOURCE_TOPIC));
        assertEquals(String.valueOf(SOURCE_PARTITION), header(headers, DlqRecordBuilder.HEADER_SOURCE_PARTITION));
        assertEquals(String.valueOf(SOURCE_OFFSET), header(headers, DlqRecordBuilder.HEADER_SOURCE_OFFSET));
        assertNotNull(headers.lastHeader(DlqRecordBuilder.HEADER_FAILURE_TIMESTAMP));
        // the dlq.* scheme must NOT emit the legacy KIP-1034 __streams.errors.* headers (in particular no stacktrace)
        assertNull(headers.lastHeader("__streams.errors.exception"));
        assertNull(headers.lastHeader("__streams.errors.stacktrace"));
    }
}
