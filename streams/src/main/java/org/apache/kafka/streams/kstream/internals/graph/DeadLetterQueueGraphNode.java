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
import org.apache.kafka.streams.processor.internals.InternalTopologyBuilder;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

/**
 * A metadata-only node that records an opt-in Dead Letter Queue (DLQ) policy on the logical topology.
 *
 * <p>This node is created by {@code KStreamImpl#withDeadLetterQueue(String, DeadLetterQueueOptions)} to carry the
 * resolved DLQ configuration - the DSL-specified DLQ topic and the immutable {@link DeadLetterQueueOptions} (max
 * record size and header-inclusion toggle) - onto the topology build graph as a dedicated sub-graph node. Carrying
 * the policy on this node (rather than mutating shared source node objects) gives every {@code withDeadLetterQueue}
 * call deterministic, per-sub-graph scope: sibling branches, repeated calls, and merges each resolve their own
 * originating source boundary independently, and conflicting configuration on the same source is rejected
 * deterministically by {@link InternalTopologyBuilder#markSourceNodeForDeadLetterQueue}.
 *
 * <p>Unlike an ordinary processor node this node adds <em>no</em> processing step to the topology: it does not call
 * {@code addProcessor}/{@code addSource} and therefore never changes the topology shape, record keys, or values,
 * and never forces a repartition. Its sole effect, applied in {@link #writeToTopology(InternalTopologyBuilder)}
 * (which runs after topology optimization), is to mark the originating source node(s) of this sub-topology as
 * opted in to the DLQ so that records failing deserialization at those sources are routed to {@code dlqTopic}.
 * Topologies that never call {@code withDeadLetterQueue} never create this node and are completely unaffected.
 */
public class DeadLetterQueueGraphNode<K, V> extends GraphNode {

    private final String dlqTopic;
    private final DeadLetterQueueOptions deadLetterQueueOptions;

    public DeadLetterQueueGraphNode(final String nodeName,
                                    final String dlqTopic,
                                    final DeadLetterQueueOptions deadLetterQueueOptions) {
        super(nodeName);
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
    public void writeToTopology(final InternalTopologyBuilder topologyBuilder) {
        // Resolve the originating source boundary of this sub-topology from the (already optimized) build graph and
        // mark each such source for DLQ routing. Marking is conflict-aware in the topology builder: identical
        // configuration on a shared source is idempotent, conflicting configuration raises a TopologyException.
        for (final String sourceName : resolveSourceNames(this)) {
            topologyBuilder.markSourceNodeForDeadLetterQueue(sourceName, dlqTopic, deadLetterQueueOptions);
        }
    }

    /**
     * Walk the build graph upward from {@code startNode} (following parent links) and collect the names of the
     * source nodes that bound the current sub-topology.
     *
     * <p>Traversal stops at each boundary: a {@link StreamSourceNode} contributes its own node name, while a
     * {@link BaseRepartitionNode} contributes the name of the source that reads back from its repartition topic
     * ({@link BaseRepartitionNode#sourceName()}) and is <em>not</em> traversed past. Stopping at the repartition
     * boundary is what makes a post-repartition {@code withDeadLetterQueue} call mark the internal repartition
     * source (the deserialization boundary that actually feeds this sub-topology) rather than the original
     * external source upstream of the repartition.
     *
     * @param startNode the graph node to start the upward search from
     * @return the set of originating source node names (never null; may be empty only if no source is reachable)
     */
    public static Set<String> resolveSourceNames(final GraphNode startNode) {
        final Set<String> sourceNames = new HashSet<>();
        final Set<GraphNode> visited = new HashSet<>();
        final Deque<GraphNode> toVisit = new ArrayDeque<>();
        toVisit.add(startNode);
        while (!toVisit.isEmpty()) {
            final GraphNode current = toVisit.poll();
            if (current == null || !visited.add(current)) {
                continue;
            }
            if (current instanceof StreamSourceNode) {
                // A source node is a sub-topology boundary and a topology root; do not traverse beyond it.
                sourceNames.add(current.nodeName());
            } else if (current instanceof BaseRepartitionNode) {
                // The sub-topology downstream of a repartition reads from the internal repartition source, not the
                // original external source; mark that repartition source and stop at this boundary.
                sourceNames.add(((BaseRepartitionNode<?, ?>) current).sourceName());
            } else {
                toVisit.addAll(current.parentNodes());
            }
        }
        return sourceNames;
    }

    @Override
    public String toString() {
        return "DeadLetterQueueGraphNode{" +
               "dlqTopic=" + dlqTopic +
               ", deadLetterQueueOptions=" + deadLetterQueueOptions +
               "} " + super.toString();
    }
}
