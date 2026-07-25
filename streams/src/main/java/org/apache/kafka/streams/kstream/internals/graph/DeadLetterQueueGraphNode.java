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

package org.apache.kafka.streams.kstream.internals.graph;

import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;

/**
 * Represents an opt-in Dead Letter Queue (DLQ) node in the logical topology.
 *
 * <p>This node is created by {@code KStreamImpl#withDeadLetterQueue(String, DeadLetterQueueOptions)} to carry the
 * resolved DLQ configuration - the DSL-specified DLQ topic and the immutable {@link DeadLetterQueueOptions} (max
 * record size and header-inclusion toggle) - onto the topology build graph. At task initialization the runtime
 * reads this configuration to attach the DLQ-aware exception-handler decorator to this sub-topology's source
 * node(s) (for deserialization-failure routing) and downstream processor node(s) (for processing-failure routing).
 *
 * <p>The node itself performs a plain pass-through at runtime: it extends {@link ProcessorGraphNode} and inherits
 * its {@code writeToTopology} behavior, which adds the pass-through processor supplied through the given
 * {@link ProcessorParameters}. It does not change record keys or values and does not force a repartition.
 */
public class DeadLetterQueueGraphNode<K, V> extends ProcessorGraphNode<K, V> {

    private final String dlqTopic;
    private final DeadLetterQueueOptions deadLetterQueueOptions;

    public DeadLetterQueueGraphNode(final String nodeName,
                                    final ProcessorParameters<K, V, ?, ?> processorParameters,
                                    final String dlqTopic,
                                    final DeadLetterQueueOptions deadLetterQueueOptions) {
        super(nodeName, processorParameters);
        this.dlqTopic = dlqTopic;
        this.deadLetterQueueOptions = deadLetterQueueOptions;
    }

    public String dlqTopic() {
        return dlqTopic;
    }

    public DeadLetterQueueOptions deadLetterQueueOptions() {
        return deadLetterQueueOptions;
    }

    @Override
    public String toString() {
        return "DeadLetterQueueNode{" +
               "dlqTopic=" + dlqTopic +
               ", deadLetterQueueOptions=" + deadLetterQueueOptions +
               "} " + super.toString();
    }
}
