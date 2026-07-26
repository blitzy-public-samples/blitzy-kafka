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

import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.Serializer;
import org.apache.kafka.streams.processor.StreamPartitioner;

import java.util.Map;

public interface RecordCollector {

    <K, V> void send(final String topic,
                     final K key,
                     final V value,
                     final Headers headers,
                     final Integer partition,
                     final Long timestamp,
                     final Serializer<K> keySerializer,
                     final Serializer<V> valueSerializer,
                     final String processorNodeId,
                     final InternalProcessorContext<Void, Void> context);

    <K, V> void send(final String topic,
                     final K key,
                     final V value,
                     final Headers headers,
                     final Long timestamp,
                     final Serializer<K> keySerializer,
                     final Serializer<V> valueSerializer,
                     final String processorNodeId,
                     final InternalProcessorContext<Void, Void> context,
                     final StreamPartitioner<? super K, ? super V> partitioner);

    <K, V> void send(K key,
                     V value,
                     String processorNodeId,
                     InternalProcessorContext<?, ?> context,
                     ProducerRecord<byte[], byte[]> serializedRecord);

    /**
     * Send an already-serialized Dead Letter Queue (DLQ) record produced by the opt-in, DSL-level DLQ layer.
     *
     * <p>DLQ records are a <em>best-effort side output</em>: they are produced through the same Streams producer as
     * every other record (reusing its security/authentication configuration and, under exactly-once, participating in
     * the task's transaction), but a DLQ record that itself fails to produce must <strong>not</strong> be routed back
     * through the {@link org.apache.kafka.streams.errors.ProductionExceptionHandler}. Doing so could return yet another
     * DLQ record and recurse indefinitely. Implementations that route through the production error path (such as
     * {@link RecordCollectorImpl}) therefore override this method to escalate a failed DLQ send exactly once through
     * the uncaught-exception path instead of re-handling it.
     *
     * <p>The default implementation simply delegates to {@link #send(Object, Object, String, InternalProcessorContext,
     * ProducerRecord)} so that test doubles and collectors that do not implement the production error path inherit
     * safe behaviour without change.
     *
     * @param deadLetterQueueRecord the fully-serialized {@code ProducerRecord<byte[], byte[]>} to route to the DLQ topic
     * @param processorNodeId       the id of the processor node on whose behalf the record is being sent
     * @param context               the current processor context
     */
    default void sendDeadLetterQueueRecord(final ProducerRecord<byte[], byte[]> deadLetterQueueRecord,
                                           final String processorNodeId,
                                           final InternalProcessorContext<?, ?> context) {
        send(
            deadLetterQueueRecord.key(),
            deadLetterQueueRecord.value(),
            processorNodeId,
            context,
            deadLetterQueueRecord
        );
    }

    /**
     * Initialize the internal {@link Producer}; note this function should be made idempotent
     *
     * @throws org.apache.kafka.common.errors.TimeoutException if producer initializing txn id timed out
     */
    void initialize();

    /**
     * Flush the internal {@link Producer}.
     */
    void flush();

    /**
     * Clean close the internal {@link Producer}.
     */
    void closeClean();

    /**
     * Dirty close the internal {@link Producer}.
     */
    void closeDirty();

    /**
     * The last acked offsets from the internal {@link Producer}.
     *
     * @return an immutable map from TopicPartition to offset
     */
    Map<TopicPartition, Long> offsets();

    /**
     * A supplier of a {@link RecordCollectorImpl} instance.
     */
    // TODO: after we have done KAFKA-9088 we should just add this function
    // to InternalProcessorContext interface
    interface Supplier {
        /**
         * Get the record collector.
         * @return the record collector
         */
        RecordCollector recordCollector();
    }
}
