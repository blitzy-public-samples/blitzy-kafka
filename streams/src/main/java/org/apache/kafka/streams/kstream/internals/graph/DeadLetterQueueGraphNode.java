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
import java.util.Optional;
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
 * (which runs after topology optimization), is twofold: (1) it marks the originating source node(s) of this
 * sub-topology (resolved upward via {@link #resolveSourceNames}) so that records failing <em>deserialization</em> at
 * those sources are routed to {@code dlqTopic} — deserialization is keyed by source topic because a record is
 * deserialized before it is routed to any branch; and (2) it marks every processor and sink node in the opted-in
 * sub-graph downstream of the opt-in node (resolved via {@link #collectRoutingNodeNames}) so that a
 * <em>processing</em> exception at a processor node or a <em>produce/serialization</em> exception at a sink node is
 * routed to {@code dlqTopic}. Processing/production routing is keyed by the failing node
 * ({@link org.apache.kafka.streams.errors.ErrorHandlerContext#processorNodeId()}) rather than the source topic, so
 * an opt-in on one branch never leaks into an unopted sibling branch and a dynamically-matched {@code Pattern} topic
 * routes by stable node identity. Topologies that never call {@code withDeadLetterQueue} never create this node and
 * are completely unaffected.
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
        // (1) Deserialization boundary (source-scoped): resolve the originating source boundary of this sub-topology
        // from the (already optimized) build graph and mark each such source for DLQ routing, so records that fail
        // deserialization at those sources are routed to the DLQ. A source deserializes each record before it is
        // routed to any downstream branch, so its policy is keyed by source topic. Marking is conflict-aware in the
        // topology builder: identical configuration on a shared source is idempotent, conflicting configuration
        // raises a TopologyException.
        for (final String sourceName : resolveSourceNames(this)) {
            topologyBuilder.markSourceNodeForDeadLetterQueue(sourceName, dlqTopic, deadLetterQueueOptions);
        }
        // (2) Processing/production boundary (node-scoped): mark every processor and sink node in the opted-in
        // sub-graph downstream of the opt-in node, so a processing exception at a processor node or a
        // produce/serialization exception at a sink node is routed to the DLQ. This is resolved at runtime by
        // ErrorHandlerContext#processorNodeId(): node-scoping keeps the opt-in from leaking into an unopted sibling
        // branch (P4-01) and routes a failure from a dynamically-matched Pattern topic by stable node identity
        // rather than a build-time topic name (P16-01/P16-02). Names that do not resolve to a processor or sink node
        // are ignored by the topology builder.
        for (final String nodeName : collectRoutingNodeNames(this)) {
            topologyBuilder.markProcessorNodeForDeadLetterQueue(nodeName, dlqTopic, deadLetterQueueOptions);
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

    /**
     * Walk the build graph downward from the opt-in node (the parent of this metadata node) following child links,
     * collecting the names of every node in the opted-in sub-graph. These are the nodes whose processing/production
     * failures should be routed to the DLQ, resolved at runtime by
     * {@link org.apache.kafka.streams.errors.ErrorHandlerContext#processorNodeId()}.
     *
     * <p>The traversal starts at this metadata node's parent (the stream the DSL call was made on — because
     * {@code withDeadLetterQueue} returns the same stream, downstream operations attach to that parent) and descends
     * through its {@link GraphNode#children() children}. It skips {@link DeadLetterQueueGraphNode} metadata nodes
     * (which have no runtime node) and stops at each {@link BaseRepartitionNode}: a repartition begins a new
     * sub-topology (a distinct task with its own exception handlers), so the opt-in is scoped to the sub-topology in
     * which it was declared — symmetric with the upward deserialization boundary in {@link #resolveSourceNames}. Any
     * source-node names collected on the way are harmless because the topology builder ignores names that do not
     * resolve to a processor or sink node.
     *
     * @param dlqMetadataNode this metadata node, whose parent is the opt-in node
     * @return the set of node names in the opted-in sub-graph to mark for processing/production DLQ routing
     */
    public static Set<String> collectRoutingNodeNames(final GraphNode dlqMetadataNode) {
        final Set<String> nodeNames = new HashSet<>();
        final Set<GraphNode> visited = new HashSet<>();
        final Deque<GraphNode> toVisit = new ArrayDeque<>();
        // Seed with the opt-in node(s) — the parent(s) of this metadata node — not the metadata node itself.
        toVisit.addAll(dlqMetadataNode.parentNodes());
        while (!toVisit.isEmpty()) {
            final GraphNode current = toVisit.poll();
            if (current == null || !visited.add(current)) {
                continue;
            }
            if (current instanceof DeadLetterQueueGraphNode) {
                // Metadata-only sibling: no runtime node and no children to traverse.
                continue;
            }
            if (current instanceof BaseRepartitionNode) {
                // A repartition starts a new sub-topology; the opt-in does not cross this boundary. Do not mark or
                // traverse past it (symmetric with the upward deserialization boundary in resolveSourceNames).
                continue;
            }
            if (!(current instanceof StreamSourceNode)) {
                // A source node is the DESERIALIZATION boundary; it is routed separately and source-scoped (via
                // resolveSourceNames / markSourceNodeForDeadLetterQueue) and never processes or produces, so it is
                // not part of the processing/production node map. Still descend THROUGH it (below) to reach the
                // downstream processing/production nodes that this opt-in covers — the opt-in is commonly declared
                // directly on the source stream, so the source is the traversal root.
                nodeNames.add(current.nodeName());
            }
            toVisit.addAll(current.children());
        }
        return nodeNames;
    }

    /**
     * Determine whether the supplied {@code dlqTopic} collides with an originating source topic of the sub-graph
     * rooted at {@code startNode}: either a concrete source topic whose name equals {@code dlqTopic}, or a source
     * topic <em>pattern</em> that matches {@code dlqTopic}. Routing dead-lettered records to a topic that is
     * itself a source of the same stream feeds failures straight back in, so a single bad record can be
     * re-consumed, fail again, and be dead-lettered repeatedly — amplifying one record into many. Callers reject
     * such a configuration at topology-build time (see {@code KStreamImpl#withDeadLetterQueue}).
     *
     * <p>The traversal mirrors {@link #resolveSourceNames(GraphNode)}: it inspects each originating
     * {@link StreamSourceNode} (the deserialization boundary) and does not traverse past a
     * {@link BaseRepartitionNode} (whose downstream reads from an internal repartition topic, never the DLQ
     * topic).
     *
     * @param startNode the graph node to start the upward search from
     * @param dlqTopic  the resolved DLQ topic name to test for a source collision
     * @return a human-readable description of the collision, or {@link Optional#empty()} when there is none
     */
    public static Optional<String> findSourceTopicCollision(final GraphNode startNode, final String dlqTopic) {
        final Set<GraphNode> visited = new HashSet<>();
        final Deque<GraphNode> toVisit = new ArrayDeque<>();
        toVisit.add(startNode);
        while (!toVisit.isEmpty()) {
            final GraphNode current = toVisit.poll();
            if (current == null || !visited.add(current)) {
                continue;
            }
            if (current instanceof StreamSourceNode) {
                final SourceGraphNode<?, ?> source = (SourceGraphNode<?, ?>) current;
                if (source.topicNames().isPresent() && source.topicNames().get().contains(dlqTopic)) {
                    return Optional.of("source topic '" + dlqTopic + "'");
                }
                if (source.topicPattern().isPresent() && source.topicPattern().get().matcher(dlqTopic).matches()) {
                    return Optional.of("source topic pattern '" + source.topicPattern().get().pattern() + "'");
                }
                // A source node is a sub-topology boundary; do not traverse beyond it.
            } else if (current instanceof BaseRepartitionNode) {
                // The sub-topology downstream of a repartition reads from an internal repartition topic, not the
                // DLQ topic; stop at this boundary (consistent with resolveSourceNames).
                continue;
            } else {
                toVisit.addAll(current.parentNodes());
            }
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return "DeadLetterQueueGraphNode{" +
               "dlqTopic=" + dlqTopic +
               ", deadLetterQueueOptions=" + deadLetterQueueOptions +
               "} " + super.toString();
    }
}
