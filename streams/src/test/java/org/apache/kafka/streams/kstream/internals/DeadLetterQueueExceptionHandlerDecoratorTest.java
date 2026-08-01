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
package org.apache.kafka.streams.kstream.internals;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.errors.TimeoutException;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.streams.errors.DeserializationExceptionHandler;
import org.apache.kafka.streams.errors.ProcessingExceptionHandler;
import org.apache.kafka.streams.errors.ProductionExceptionHandler;
import org.apache.kafka.streams.errors.internals.DefaultErrorHandlerContext;
import org.apache.kafka.streams.errors.internals.DlqRecordBuilder;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.streams.processor.TaskId;
import org.apache.kafka.streams.processor.api.Record;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.kafka.streams.StreamsConfig.DEFAULT_DEAD_LETTER_QUEUE_ENABLED_CONFIG;
import static org.apache.kafka.streams.StreamsConfig.DEFAULT_DEAD_LETTER_QUEUE_TOPIC_CONFIG;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the three internal {@link DeadLetterQueueExceptionHandlerDecorator} nested decorators
 * ({@code DeserializationDecorator}, {@code ProductionDecorator} and {@code ProcessingDecorator}).
 *
 * <p>Because {@code resolveTopic}, {@code isEnabled} and the eligibility classifier are internal helpers, they are
 * exercised through the public {@code configure} / {@code handleError} / {@code handleSerializationError} entry
 * points and asserted on the returned {@code Response}. The tests pin the AAP-critical contracts:
 * <ul>
 *     <li>effective-topic precedence: DSL topic &rarr; options topic &rarr; global default topic;</li>
 *     <li>the enablement matrix (DSL/options opt-in always enables; the global-only path defers to
 *         {@code default.deadletterqueue.enabled}; a {@code null} resolved topic disables);</li>
 *     <li>the delegate is invoked <em>exactly once</em> and its response is returned unchanged whenever the DLQ is
 *         disabled or the failure is ineligible (preserving custom / KIP-1034 / FAIL decisions);</li>
 *     <li>eligibility: retriable and fatal/framework failures are never dead-lettered, and a punctuation-origin
 *         processing failure (no source record) is excluded;</li>
 *     <li>forced resume is applied only to eligible, opted-in records (a delegate {@code FAIL} is overridden to
 *         {@code RESUME} only then);</li>
 *     <li>{@code null}-delegate defaults (resume for deserialization/processing; retry-or-fail for production);</li>
 *     <li>raw-byte selection per path (deserialization: context bytes then {@code ConsumerRecord} bytes;
 *         production: the offending output-record bytes; serialization/processing: error-context bytes); and</li>
 *     <li><em>exactly one</em> routing result per failure — the built {@code dlq.*} record <em>replaces</em> any
 *         records the delegate produced, so an opted-in node never double-routes.</li>
 * </ul>
 */
public class DeadLetterQueueExceptionHandlerDecoratorTest {

    private static final String DLQ_DSL_TOPIC = "dsl-dlq";
    private static final String OPTIONS_TOPIC = "options-dlq";
    private static final String GLOBAL_TOPIC = "global-dlq";

    private static final String SOURCE_TOPIC = "source-topic";
    private static final int SOURCE_PARTITION = 7;
    private static final long SOURCE_OFFSET = 99L;
    private static final long SOURCE_TIMESTAMP = 1_234L;

    private static final byte[] RAW_KEY = "raw-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RAW_VALUE = "raw-value".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RECORD_KEY = "record-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RECORD_VALUE = "record-value".getBytes(StandardCharsets.UTF_8);

    private static final StringDeserializer STRING_DESERIALIZER = new StringDeserializer();

    private static DefaultErrorHandlerContext context(final byte[] sourceRawKey, final byte[] sourceRawValue) {
        // A null ProcessorContext is sufficient: the decorators only read the stored coordinates/timestamp/raw bytes.
        return new DefaultErrorHandlerContext(
            null,
            SOURCE_TOPIC,
            SOURCE_PARTITION,
            SOURCE_OFFSET,
            null,
            "source-node",
            new TaskId(0, 0),
            SOURCE_TIMESTAMP,
            sourceRawKey,
            sourceRawValue
        );
    }

    private static DefaultErrorHandlerContext context() {
        return context(RAW_KEY, RAW_VALUE);
    }

    // A punctuation-origin error context: no source record, so topic is null and partition/offset are the -1
    // sentinel (see ErrorHandlerContext#topic()/partition()/offset()).
    private static DefaultErrorHandlerContext punctuationContext() {
        return new DefaultErrorHandlerContext(
            null,
            null,
            -1,
            -1,
            null,
            "source-node",
            new TaskId(0, 0),
            SOURCE_TIMESTAMP,
            null,
            null
        );
    }

    private static Map<String, Object> configs(final String globalTopic, final boolean globalEnabled) {
        final Map<String, Object> configs = new HashMap<>();
        if (globalTopic != null) {
            configs.put(DEFAULT_DEAD_LETTER_QUEUE_TOPIC_CONFIG, globalTopic);
        }
        configs.put(DEFAULT_DEAD_LETTER_QUEUE_ENABLED_CONFIG, globalEnabled);
        return configs;
    }

    private static ConsumerRecord<byte[], byte[]> consumerRecord() {
        return new ConsumerRecord<>(SOURCE_TOPIC, SOURCE_PARTITION, SOURCE_OFFSET, RECORD_KEY, RECORD_VALUE);
    }

    private static ProducerRecord<byte[], byte[]> producerRecord() {
        return new ProducerRecord<>("output-topic", RECORD_KEY, RECORD_VALUE);
    }

    // An error context carrying a specific processorNodeId (the node in which a processing/production failure
    // occurred) plus a valid source record, so processing eligibility passes. Used by the node-scoped routing tests.
    private static DefaultErrorHandlerContext contextForNode(final String processorNodeId) {
        return new DefaultErrorHandlerContext(
            null,
            SOURCE_TOPIC,
            SOURCE_PARTITION,
            SOURCE_OFFSET,
            null,
            processorNodeId,
            new TaskId(0, 0),
            SOURCE_TIMESTAMP,
            RAW_KEY,
            RAW_VALUE
        );
    }

    private static String header(final Headers headers, final String key) {
        return STRING_DESERIALIZER.deserialize(null, headers.lastHeader(key).value());
    }

    // ------------------------------------------------------------------------------------------------------------
    // DeserializationDecorator
    // ------------------------------------------------------------------------------------------------------------

    @Test
    public void shouldResolveDslTopicOverOptionsAndGlobalForDeserialization() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(DeserializationExceptionHandler.Response.resume());

        // DSL topic supplied AND an options topic AND a global topic: the DSL topic must win.
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(
                delegate, DLQ_DSL_TOPIC, DeadLetterQueueOptions.with(OPTIONS_TOPIC));
        decorator.configure(configs(GLOBAL_TOPIC, true));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        assertEquals(DeserializationExceptionHandler.Result.RESUME, response.result());
        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(DLQ_DSL_TOPIC, response.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldResolveOptionsTopicOverGlobalForDeserialization() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(DeserializationExceptionHandler.Response.resume());

        // No DSL topic, but an options topic and a global topic: the options topic must win over the global one.
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(
                delegate, null, DeadLetterQueueOptions.with(OPTIONS_TOPIC));
        decorator.configure(configs(GLOBAL_TOPIC, true));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(OPTIONS_TOPIC, response.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldResolveGlobalTopicWhenNeitherDslNorOptionsForDeserialization() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(DeserializationExceptionHandler.Response.resume());

        // Global-only path: no DSL topic and no options, but the global default is enabled with a topic set.
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(delegate, null, null);
        decorator.configure(configs(GLOBAL_TOPIC, true));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(GLOBAL_TOPIC, response.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldNotRouteDeserializationWhenGlobalDisabledAndNoOptIn() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final DeserializationExceptionHandler.Response delegateResponse =
            DeserializationExceptionHandler.Response.fail();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        // A topic is resolvable from the global config, but the global switch is off and there is no DSL/options
        // opt-in, so the decorator must return the delegate response verbatim (byte-for-byte legacy behaviour).
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(delegate, null, null);
        decorator.configure(configs(GLOBAL_TOPIC, false));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        assertSame(delegateResponse, response);
        assertTrue(response.deadLetterQueueRecords().isEmpty());
    }

    @Test
    public void shouldNotRouteDeserializationWhenNoTopicResolvable() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final DeserializationExceptionHandler.Response delegateResponse =
            DeserializationExceptionHandler.Response.resume();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        // No topic at any level (and enabled=true is irrelevant): a null resolved topic disables DLQ routing.
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(delegate, null, null);
        decorator.configure(configs(null, true));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        assertSame(delegateResponse, response);
    }

    @Test
    public void shouldEnableDeserializationViaOptionsEvenWhenGlobalDisabled() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(DeserializationExceptionHandler.Response.resume());

        // An explicit options opt-in must enable DLQ routing regardless of the global enabled=false switch.
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(
                delegate, null, DeadLetterQueueOptions.with(OPTIONS_TOPIC));
        decorator.configure(configs(GLOBAL_TOPIC, false));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(OPTIONS_TOPIC, response.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldResumeWithDlqRecordWhenDeserializationDelegateIsNull() {
        // A null delegate is treated as an implicit resume; with a DSL opt-in a DLQ record is still produced.
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(null, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        assertEquals(DeserializationExceptionHandler.Result.RESUME, response.result());
        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(DLQ_DSL_TOPIC, response.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldReplaceDelegateRecordsWithSingleDlqRecordForDeserialization() {
        // no-double-routing: if the wrapped delegate (e.g. an existing KIP-1034 handler) already produced a DLQ
        // record, the decorator must REPLACE it with exactly one dlq.* record — never emit both.
        final ProducerRecord<byte[], byte[]> delegateRecord =
            new ProducerRecord<>("delegate-dlq", "dk".getBytes(StandardCharsets.UTF_8), "dv".getBytes(StandardCharsets.UTF_8));
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        when(delegate.handleError(any(), any(), any()))
            .thenReturn(DeserializationExceptionHandler.Response.resume(Collections.singletonList(delegateRecord)));

        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        final List<ProducerRecord<byte[], byte[]>> records = response.deadLetterQueueRecords();
        assertEquals(1, records.size());
        assertEquals(DLQ_DSL_TOPIC, records.get(0).topic());
        assertNotSame(delegateRecord, records.get(0));
        // delegate invoked exactly once — its side effects and decision are observed, not suppressed
        verify(delegate).handleError(any(), any(), any());
    }

    @Test
    public void shouldOverrideDelegateFailWithResumeForEligibleOptedInDeserialization() {
        // forced resume is scoped to eligible + opted-in records: a delegate that FAILs is overridden to RESUME so
        // a DLQ-eligible deserialization failure is dead-lettered and the thread continues.
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(DeserializationExceptionHandler.Response.fail());

        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), new RuntimeException("boom"));

        assertEquals(DeserializationExceptionHandler.Result.RESUME, response.result());
        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(DLQ_DSL_TOPIC, response.deadLetterQueueRecords().get(0).topic());
        verify(delegate).handleError(any(), any(), any());
    }

    @Test
    public void shouldNotRouteFatalDeserializationFailureEvenWhenOptedIn() {
        // A fatal/framework failure (here an Error carried as the cause) must never be dead-lettered — the
        // delegate's decision is preserved even though the node opted in.
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final DeserializationExceptionHandler.Response delegateResponse =
            DeserializationExceptionHandler.Response.fail();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final DeserializationExceptionHandler.Response response = decorator.handleError(
            context(), consumerRecord(), new RuntimeException("wrapper", new OutOfMemoryError("fatal")));

        assertSame(delegateResponse, response);
        assertTrue(response.deadLetterQueueRecords().isEmpty());
    }

    @Test
    public void shouldUseContextRawBytesAndPopulateHeadersForDeserializationDlqRecord() {
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(null, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final RuntimeException exception = new IllegalStateException("kaboom");
        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(), consumerRecord(), exception);

        final ProducerRecord<byte[], byte[]> dlqRecord = response.deadLetterQueueRecords().get(0);
        // the ORIGINAL raw bytes from the error context are preserved (not the deserialized/record bytes)
        assertArrayEquals(RAW_KEY, dlqRecord.key());
        assertArrayEquals(RAW_VALUE, dlqRecord.value());
        assertEquals(SOURCE_TIMESTAMP, dlqRecord.timestamp());
        // the diagnostic dlq.* headers are populated from the error context and exception
        final Headers headers = dlqRecord.headers();
        assertEquals(IllegalStateException.class.getName(), header(headers, DlqRecordBuilder.HEADER_EXCEPTION_CLASS));
        assertEquals("kaboom", header(headers, DlqRecordBuilder.HEADER_EXCEPTION_MESSAGE));
        assertEquals(SOURCE_TOPIC, header(headers, DlqRecordBuilder.HEADER_SOURCE_TOPIC));
        assertEquals(String.valueOf(SOURCE_PARTITION), header(headers, DlqRecordBuilder.HEADER_SOURCE_PARTITION));
        assertEquals(String.valueOf(SOURCE_OFFSET), header(headers, DlqRecordBuilder.HEADER_SOURCE_OFFSET));
    }

    @Test
    public void shouldFallBackToConsumerRecordBytesWhenContextRawBytesNullForDeserialization() {
        // When the error context carries no raw bytes, the decorator falls back to the ConsumerRecord's bytes.
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(null, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final DeserializationExceptionHandler.Response response =
            decorator.handleError(context(null, null), consumerRecord(), new RuntimeException("boom"));

        final ProducerRecord<byte[], byte[]> dlqRecord = response.deadLetterQueueRecords().get(0);
        assertArrayEquals(RECORD_KEY, dlqRecord.key());
        assertArrayEquals(RECORD_VALUE, dlqRecord.value());
    }

    @Test
    public void shouldDelegateConfigureToWrappedDeserializationHandler() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(delegate, DLQ_DSL_TOPIC, null);
        final Map<String, Object> configs = configs(GLOBAL_TOPIC, true);

        decorator.configure(configs);

        verify(delegate).configure(configs);
    }

    // ------------------------------------------------------------------------------------------------------------
    // ProductionDecorator
    // ------------------------------------------------------------------------------------------------------------

    @Test
    public void shouldPassThroughRetryVerbatimWithoutDlqRecordsForProduction() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        final ProductionExceptionHandler.Response retry = ProductionExceptionHandler.Response.retry();
        when(delegate.handleError(any(), any(), any())).thenReturn(retry);

        // Retriable production failures must NOT be dead-lettered: the RETRY response is returned verbatim.
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(GLOBAL_TOPIC, true));

        final ProductionExceptionHandler.Response response =
            decorator.handleError(context(), producerRecord(), new TimeoutException("retry me"));

        assertSame(retry, response);
        assertEquals(ProductionExceptionHandler.Result.RETRY, response.result());
        assertTrue(response.deadLetterQueueRecords().isEmpty());
    }

    @Test
    public void shouldRetryWhenProductionDelegateNullAndRetriableException() {
        // A null delegate defaults to RETRY for a retriable exception, so the record stays on the producer retry
        // path and is not dead-lettered.
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(null, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProductionExceptionHandler.Response response =
            decorator.handleError(context(), producerRecord(), new TimeoutException("retry me"));

        assertEquals(ProductionExceptionHandler.Result.RETRY, response.result());
        assertTrue(response.deadLetterQueueRecords().isEmpty());
    }

    @Test
    public void shouldRouteToDlqWhenProductionDelegateNullAndNonRetriable() {
        // A null delegate defaults to FAIL for a non-retriable exception; with DLQ enabled the decorator resumes
        // and routes the record to the DLQ topic.
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(null, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProductionExceptionHandler.Response response =
            decorator.handleError(context(), producerRecord(), new RuntimeException("non-retriable"));

        assertEquals(ProductionExceptionHandler.Result.RESUME, response.result());
        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(DLQ_DSL_TOPIC, response.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldRouteToDlqWhenProductionDelegateFailsNonRetriable() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(ProductionExceptionHandler.Response.fail());

        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProductionExceptionHandler.Response response =
            decorator.handleError(context(), producerRecord(), new RuntimeException("non-retriable"));

        assertEquals(ProductionExceptionHandler.Result.RESUME, response.result());
        assertEquals(1, response.deadLetterQueueRecords().size());
        final ProducerRecord<byte[], byte[]> dlqRecord = response.deadLetterQueueRecords().get(0);
        assertEquals(DLQ_DSL_TOPIC, dlqRecord.topic());
        // a produce failure dead-letters the offending OUTPUT record's bytes (not the source-context bytes)
        assertArrayEquals(RECORD_KEY, dlqRecord.key());
        assertArrayEquals(RECORD_VALUE, dlqRecord.value());
        verify(delegate).handleError(any(), any(), any());
    }

    @Test
    public void shouldNotRouteFatalProductionFailureEvenWhenOptedIn() {
        // A fatal/framework production failure (here an authorization error) must never be dead-lettered.
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        final ProductionExceptionHandler.Response delegateResponse = ProductionExceptionHandler.Response.fail();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProductionExceptionHandler.Response response = decorator.handleError(
            context(), producerRecord(),
            new org.apache.kafka.common.errors.TopicAuthorizationException("no acl"));

        assertSame(delegateResponse, response);
        assertTrue(response.deadLetterQueueRecords().isEmpty());
    }

    @Test
    public void shouldNotRouteProductionWhenDisabled() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        final ProductionExceptionHandler.Response delegateResponse = ProductionExceptionHandler.Response.fail();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        // No opt-in and the global switch is off: the delegate response is returned verbatim.
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, (String) null, null);
        decorator.configure(configs(GLOBAL_TOPIC, false));

        final ProductionExceptionHandler.Response response =
            decorator.handleError(context(), producerRecord(), new RuntimeException("non-retriable"));

        assertSame(delegateResponse, response);
    }

    @Test
    public void shouldPassThroughRetryVerbatimOnSerializationError() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        final ProductionExceptionHandler.Response retry = ProductionExceptionHandler.Response.retry();
        when(delegate.handleSerializationError(any(), any(), any(), any())).thenReturn(retry);

        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(GLOBAL_TOPIC, true));

        final ProductionExceptionHandler.Response response = decorator.handleSerializationError(
            context(), producerRecord(), new SerializationException("bad"),
            ProductionExceptionHandler.SerializationExceptionOrigin.VALUE);

        assertSame(retry, response);
        assertTrue(response.deadLetterQueueRecords().isEmpty());
    }

    @Test
    public void shouldBuildDlqFromContextBytesOnSerializationError() {
        // On a serialization failure the offending record's byte[] payload is unavailable, so the decorator falls
        // back to the raw bytes captured in the error context. A null delegate defaults to FAIL, and with DLQ
        // enabled the decorator resumes and routes.
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(null, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProductionExceptionHandler.Response response = decorator.handleSerializationError(
            context(), producerRecord(), new SerializationException("bad"),
            ProductionExceptionHandler.SerializationExceptionOrigin.KEY);

        assertEquals(ProductionExceptionHandler.Result.RESUME, response.result());
        assertEquals(1, response.deadLetterQueueRecords().size());
        final ProducerRecord<byte[], byte[]> dlqRecord = response.deadLetterQueueRecords().get(0);
        assertEquals(DLQ_DSL_TOPIC, dlqRecord.topic());
        assertArrayEquals(RAW_KEY, dlqRecord.key());
        assertArrayEquals(RAW_VALUE, dlqRecord.value());
    }

    @Test
    public void shouldNotRouteSerializationErrorWhenDisabled() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        final ProductionExceptionHandler.Response delegateResponse = ProductionExceptionHandler.Response.fail();
        when(delegate.handleSerializationError(any(), any(), any(), any())).thenReturn(delegateResponse);

        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, (String) null, null);
        decorator.configure(configs(null, false));

        final ProductionExceptionHandler.Response response = decorator.handleSerializationError(
            context(), producerRecord(), new SerializationException("bad"),
            ProductionExceptionHandler.SerializationExceptionOrigin.VALUE);

        assertSame(delegateResponse, response);
    }

    @Test
    public void shouldDelegateConfigureToWrappedProductionHandler() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, DLQ_DSL_TOPIC, null);
        final Map<String, Object> configs = configs(GLOBAL_TOPIC, true);

        decorator.configure(configs);

        verify(delegate).configure(configs);
    }

    // ------------------------------------------------------------------------------------------------------------
    // ProcessingDecorator
    // ------------------------------------------------------------------------------------------------------------

    @Test
    public void shouldResumeWithDlqFromContextBytesWhenProcessingFails() {
        final ProcessingExceptionHandler delegate = mock(ProcessingExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(ProcessingExceptionHandler.Response.resume());

        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProcessingExceptionHandler.Response response =
            decorator.handleError(context(), new Record<>("k", "v", SOURCE_TIMESTAMP), new RuntimeException("boom"));

        assertEquals(ProcessingExceptionHandler.Result.RESUME, response.result());
        assertEquals(1, response.deadLetterQueueRecords().size());
        final ProducerRecord<byte[], byte[]> dlqRecord = response.deadLetterQueueRecords().get(0);
        assertEquals(DLQ_DSL_TOPIC, dlqRecord.topic());
        // processing failures preserve the ORIGINAL source-record bytes from the error context (not the typed record)
        assertArrayEquals(RAW_KEY, dlqRecord.key());
        assertArrayEquals(RAW_VALUE, dlqRecord.value());
    }

    @Test
    public void shouldResumeWithDlqRecordWhenProcessingDelegateIsNull() {
        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(null, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProcessingExceptionHandler.Response response =
            decorator.handleError(context(), new Record<>("k", "v", SOURCE_TIMESTAMP), new RuntimeException("boom"));

        assertEquals(ProcessingExceptionHandler.Result.RESUME, response.result());
        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(DLQ_DSL_TOPIC, response.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldResolveGlobalTopicForProcessingWhenEnabled() {
        final ProcessingExceptionHandler delegate = mock(ProcessingExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(ProcessingExceptionHandler.Response.resume());

        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, (String) null, null);
        decorator.configure(configs(GLOBAL_TOPIC, true));

        final ProcessingExceptionHandler.Response response =
            decorator.handleError(context(), new Record<>("k", "v", SOURCE_TIMESTAMP), new RuntimeException("boom"));

        assertEquals(1, response.deadLetterQueueRecords().size());
        assertEquals(GLOBAL_TOPIC, response.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldNotRouteProcessingWhenDisabled() {
        final ProcessingExceptionHandler delegate = mock(ProcessingExceptionHandler.class);
        final ProcessingExceptionHandler.Response delegateResponse = ProcessingExceptionHandler.Response.resume();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, (String) null, null);
        decorator.configure(configs(GLOBAL_TOPIC, false));

        final ProcessingExceptionHandler.Response response =
            decorator.handleError(context(), new Record<>("k", "v", SOURCE_TIMESTAMP), new RuntimeException("boom"));

        assertSame(delegateResponse, response);
    }

    @Test
    public void shouldReplaceDelegateRecordsWithSingleDlqRecordForProcessing() {
        // no-double-routing: the built dlq.* record REPLACES any records the delegate produced.
        final ProducerRecord<byte[], byte[]> delegateRecord =
            new ProducerRecord<>("delegate-dlq", "dk".getBytes(StandardCharsets.UTF_8), "dv".getBytes(StandardCharsets.UTF_8));
        final ProcessingExceptionHandler delegate = mock(ProcessingExceptionHandler.class);
        when(delegate.handleError(any(), any(), any()))
            .thenReturn(ProcessingExceptionHandler.Response.resume(Collections.singletonList(delegateRecord)));

        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProcessingExceptionHandler.Response response =
            decorator.handleError(context(), new Record<>("k", "v", SOURCE_TIMESTAMP), new RuntimeException("boom"));

        final List<ProducerRecord<byte[], byte[]>> records = response.deadLetterQueueRecords();
        assertEquals(1, records.size());
        assertEquals(DLQ_DSL_TOPIC, records.get(0).topic());
        assertNotSame(delegateRecord, records.get(0));
        assertNotNull(records.get(0).value());
        verify(delegate).handleError(any(), any(), any());
    }

    @Test
    public void shouldNotRouteProcessingPunctuationFailureWithNoSourceRecord() {
        // A punctuation-origin failure has no source record (topic == null, partition/offset == -1), so there is
        // nothing to dead-letter: the delegate's decision is preserved even though the node opted in.
        final ProcessingExceptionHandler delegate = mock(ProcessingExceptionHandler.class);
        final ProcessingExceptionHandler.Response delegateResponse = ProcessingExceptionHandler.Response.resume();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final ProcessingExceptionHandler.Response response = decorator.handleError(
            punctuationContext(), new Record<>("k", "v", SOURCE_TIMESTAMP), new RuntimeException("in punctuate"));

        assertSame(delegateResponse, response);
        assertTrue(response.deadLetterQueueRecords().isEmpty());
    }

    @Test
    public void shouldDelegateConfigureToWrappedProcessingHandler() {
        final ProcessingExceptionHandler delegate = mock(ProcessingExceptionHandler.class);
        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, DLQ_DSL_TOPIC, null);
        final Map<String, Object> configs = configs(GLOBAL_TOPIC, true);

        decorator.configure(configs);

        verify(delegate).configure(configs);
    }

    // ------------------------------------------------------------------------------------------------------------
    // P5-02: a non-null delegate that returns a null Response is a contract violation. The decorator must fail fast
    // with a clear NullPointerException naming the offending handler, rather than NPE'ing opaquely later while
    // inspecting response.result(). (The delegate==null case is a separate, supported default and is covered above.)
    // ------------------------------------------------------------------------------------------------------------

    @Test
    public void shouldThrowWhenDeserializationDelegateReturnsNullResponse() {
        final DeserializationExceptionHandler delegate = mock(DeserializationExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(null);

        final DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.DeserializationDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final NullPointerException e = assertThrows(NullPointerException.class,
            () -> decorator.handleError(context(), consumerRecord(), new RuntimeException("boom")));
        assertTrue(e.getMessage().contains("DeserializationExceptionHandler"),
            "message should name the offending handler: " + e.getMessage());
    }

    @Test
    public void shouldThrowWhenProductionDelegateReturnsNullResponse() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(null);

        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final NullPointerException e = assertThrows(NullPointerException.class,
            () -> decorator.handleError(context(), producerRecord(), new RuntimeException("boom")));
        assertTrue(e.getMessage().contains("ProductionExceptionHandler"),
            "message should name the offending handler: " + e.getMessage());
    }

    @Test
    public void shouldThrowWhenProductionDelegateReturnsNullResponseOnSerializationError() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        when(delegate.handleSerializationError(any(), any(), any(), any())).thenReturn(null);

        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final NullPointerException e = assertThrows(NullPointerException.class,
            () -> decorator.handleSerializationError(context(), producerRecord(),
                new SerializationException("bad"), ProductionExceptionHandler.SerializationExceptionOrigin.VALUE));
        assertTrue(e.getMessage().contains("ProductionExceptionHandler"),
            "message should name the offending handler: " + e.getMessage());
    }

    @Test
    public void shouldThrowWhenProcessingDelegateReturnsNullResponse() {
        final ProcessingExceptionHandler delegate = mock(ProcessingExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(null);

        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, DLQ_DSL_TOPIC, null);
        decorator.configure(configs(null, false));

        final NullPointerException e = assertThrows(NullPointerException.class,
            () -> decorator.handleError(context(), new Record<>("k", "v", SOURCE_TIMESTAMP),
                new RuntimeException("boom")));
        assertTrue(e.getMessage().contains("ProcessingExceptionHandler"),
            "message should name the offending handler: " + e.getMessage());
    }

    // ------------------------------------------------------------------------------------------------------------
    // P4-01: processing/production routing is keyed by the FAILING node (ErrorHandlerContext#processorNodeId()), not
    // by source topic. An opt-in on one branch must therefore route only that branch's nodes and must NOT leak into
    // an unopted sibling branch that shares the same source topic.
    // ------------------------------------------------------------------------------------------------------------

    @Test
    public void shouldRouteProductionToPerNodeDlqTopicByFailingNodeId() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(ProductionExceptionHandler.Response.fail());

        final Map<String, DeadLetterQueueOptions> byNode = new HashMap<>();
        byNode.put("sink-A", DeadLetterQueueOptions.with("dlq-A"));
        byNode.put("sink-B", DeadLetterQueueOptions.with("dlq-B"));
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, byNode, null);
        decorator.configure(configs(null, false));

        // A produce failure at sink-A routes to dlq-A; the same failure at sink-B routes to dlq-B - each opted-in
        // node keeps its own DLQ policy within the one shared production handler.
        final ProductionExceptionHandler.Response a =
            decorator.handleError(contextForNode("sink-A"), producerRecord(), new RuntimeException("boom"));
        assertEquals(ProductionExceptionHandler.Result.RESUME, a.result());
        assertEquals("dlq-A", a.deadLetterQueueRecords().get(0).topic());

        final ProductionExceptionHandler.Response b =
            decorator.handleError(contextForNode("sink-B"), producerRecord(), new RuntimeException("boom"));
        assertEquals("dlq-B", b.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldNotRouteProductionForUnoptedSiblingNode() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        final ProductionExceptionHandler.Response delegateResponse = ProductionExceptionHandler.Response.fail();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        final Map<String, DeadLetterQueueOptions> byNode = new HashMap<>();
        byNode.put("sink-A", DeadLetterQueueOptions.with("dlq-A"));
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, byNode, null);
        decorator.configure(configs(null, false));

        // A failure at an unopted sibling (sink-B) with no global default must fall through to the delegate response
        // VERBATIM - the opt-in on sink-A must not leak into sink-B (P4-01).
        final ProductionExceptionHandler.Response passthrough =
            decorator.handleError(contextForNode("sink-B"), producerRecord(), new RuntimeException("boom"));
        assertSame(delegateResponse, passthrough);
        assertTrue(passthrough.deadLetterQueueRecords().isEmpty());
    }

    @Test
    public void shouldFallBackToGlobalForUnoptedNodeWhenGlobalEnabled() {
        final ProductionExceptionHandler delegate = mock(ProductionExceptionHandler.class);
        when(delegate.handleError(any(), any(), any())).thenReturn(ProductionExceptionHandler.Response.fail());

        final Map<String, DeadLetterQueueOptions> byNode = new HashMap<>();
        byNode.put("sink-A", DeadLetterQueueOptions.with("dlq-A"));
        // Per-node opt-in for sink-A PLUS a global fallback: sink-A keeps its own topic; every other node uses the
        // global default (DSL -> global precedence, resolved per failing node).
        final DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(
                delegate, byNode, DeadLetterQueueOptions.with(GLOBAL_TOPIC));
        decorator.configure(configs(GLOBAL_TOPIC, true));

        final ProductionExceptionHandler.Response a =
            decorator.handleError(contextForNode("sink-A"), producerRecord(), new RuntimeException("boom"));
        assertEquals("dlq-A", a.deadLetterQueueRecords().get(0).topic());

        final ProductionExceptionHandler.Response b =
            decorator.handleError(contextForNode("sink-B"), producerRecord(), new RuntimeException("boom"));
        assertEquals(GLOBAL_TOPIC, b.deadLetterQueueRecords().get(0).topic());
    }

    @Test
    public void shouldRouteProcessingToPerNodeDlqTopicByFailingNodeIdAndIsolateSibling() {
        final ProcessingExceptionHandler delegate = mock(ProcessingExceptionHandler.class);
        final ProcessingExceptionHandler.Response delegateResponse = ProcessingExceptionHandler.Response.fail();
        when(delegate.handleError(any(), any(), any())).thenReturn(delegateResponse);

        final Map<String, DeadLetterQueueOptions> byNode = new HashMap<>();
        byNode.put("proc-A", DeadLetterQueueOptions.with("dlq-A"));
        final DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator decorator =
            new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, byNode, null);
        decorator.configure(configs(null, false));

        // Failure at the opted-in processor node routes to its DLQ topic.
        final ProcessingExceptionHandler.Response routed =
            decorator.handleError(contextForNode("proc-A"), new Record<>("k", "v", SOURCE_TIMESTAMP),
                new RuntimeException("boom"));
        assertEquals(ProcessingExceptionHandler.Result.RESUME, routed.result());
        assertEquals("dlq-A", routed.deadLetterQueueRecords().get(0).topic());

        // Failure at an unopted sibling processor node (no global) falls through to the delegate response verbatim.
        final ProcessingExceptionHandler.Response passthrough =
            decorator.handleError(contextForNode("proc-B"), new Record<>("k", "v", SOURCE_TIMESTAMP),
                new RuntimeException("boom"));
        assertSame(delegateResponse, passthrough);
        assertTrue(passthrough.deadLetterQueueRecords().isEmpty());
    }
}
