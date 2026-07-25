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
import org.apache.kafka.streams.errors.DeserializationExceptionHandler;
import org.apache.kafka.streams.errors.ErrorHandlerContext;
import org.apache.kafka.streams.errors.internals.DlqRecordBuilder;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;

import java.util.Map;
import java.util.Objects;

/**
 * Internal, DLQ-aware decorator for a source node's {@link DeserializationExceptionHandler} that implements the
 * opt-in, DSL-level Dead Letter Queue (DLQ) capability for deserialization failures.
 *
 * <p>This decorator wraps the topology's configured deserialization exception handler and is installed
 * <em>only</em> for source nodes that opted in — either through the DSL call
 * {@link org.apache.kafka.streams.kstream.KStream#withDeadLetterQueue(String, DeadLetterQueueOptions)} or through
 * the global {@code default.deadletterqueue.*} configuration. It follows the feature's guiding principle
 * ("decorate, do not modify"): the public {@link DeserializationExceptionHandler} interface is untouched, and the
 * decorator delegates {@link #configure(Map)} to the wrapped handler so any user configuration still takes effect.
 *
 * <p>On a deserialization failure the decorator builds a {@code dlq.*} DLQ record from the original (raw) key/value
 * bytes via {@link DlqRecordBuilder} and returns {@link Response#resume(java.util.List) RESUME} carrying that record,
 * which the existing send site in {@link RecordDeserializer} produces through the shared Streams producer. Returning
 * {@code RESUME} realises the opt-in contract that a DLQ-eligible failure is dead-lettered and processing continues
 * rather than terminating the {@code StreamThread}. Because the decorator is only ever instantiated for opted-in
 * source nodes, topologies that do not opt in never see it and keep byte-for-byte identical error handling.
 *
 * <p>Instances are effectively immutable (the wrapped handler, topic and options are {@code final}) and therefore
 * safe to share across the concurrent {@code StreamThread} instances that a source node may be assigned to.
 */
public class DeadLetterQueueDeserializationExceptionHandler implements DeserializationExceptionHandler {

    private final DeserializationExceptionHandler delegate;
    private final String dlqTopic;
    private final DeadLetterQueueOptions options;

    /**
     * @param delegate the topology's configured deserialization exception handler to wrap (must not be null)
     * @param dlqTopic the resolved, effective DLQ topic name for this source node (must not be null)
     * @param options  the effective DLQ options (header toggle and max record size; must not be null)
     */
    public DeadLetterQueueDeserializationExceptionHandler(final DeserializationExceptionHandler delegate,
                                                          final String dlqTopic,
                                                          final DeadLetterQueueOptions options) {
        this.delegate = Objects.requireNonNull(delegate, "delegate deserialization exception handler cannot be null");
        this.dlqTopic = Objects.requireNonNull(dlqTopic, "dlqTopic cannot be null");
        this.options = Objects.requireNonNull(options, "dead letter queue options cannot be null");
    }

    @Override
    public void configure(final Map<String, ?> configs) {
        // Preserve any configuration side effects of the wrapped handler ("decorate, do not modify").
        delegate.configure(configs);
    }

    @Override
    public Response handleError(final ErrorHandlerContext context,
                                final ConsumerRecord<byte[], byte[]> record,
                                final Exception exception) {
        // Opt-in DLQ routing: build the dlq.* record from the ORIGINAL (non-deserialized) key/value bytes and
        // resume processing. The record is produced by the RecordDeserializer send site through the shared producer.
        return Response.resume(
            DlqRecordBuilder.buildDeadLetterQueueRecords(
                dlqTopic,
                record.key(),
                record.value(),
                context,
                exception,
                options
            )
        );
    }

    /**
     * @return the effective DLQ topic this decorator routes failed records to
     */
    public String deadLetterQueueTopic() {
        return dlqTopic;
    }

    /**
     * @return the effective DLQ options this decorator applies
     */
    public DeadLetterQueueOptions deadLetterQueueOptions() {
        return options;
    }
}
