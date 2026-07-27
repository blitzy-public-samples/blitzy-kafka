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

import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.errors.ProcessingExceptionHandler;
import org.apache.kafka.streams.errors.ProductionExceptionHandler;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.streams.kstream.internals.DeadLetterQueueExceptionHandlerDecorator;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Installs the opt-in, DSL-level Dead Letter Queue (DLQ) layer onto the <em>task/subtopology-scoped</em> exception
 * handlers — the {@link ProcessingExceptionHandler} (shared by every {@link ProcessorNode} in a subtopology) and the
 * {@link ProductionExceptionHandler} (held by the task's {@link RecordCollectorImpl}) — by wrapping the configured
 * handler in the matching {@link DeadLetterQueueExceptionHandlerDecorator per-source-origin DLQ decorator}.
 *
 * <p>Unlike the deserialization handler, which is resolved <em>per source node</em> (each {@link RecordQueue}
 * carries its own source and therefore its own DLQ policy), a subtopology has a <em>single</em> processing handler
 * and a <em>single</em> production handler shared across all of its nodes. A subtopology may nevertheless contain
 * several opted-in sub-graphs that route to <em>different</em> DLQ topics (for example two branches of a
 * {@code split()} each configured via
 * {@link org.apache.kafka.streams.kstream.KStream#withDeadLetterQueue(String, DeadLetterQueueOptions)}, or a
 * {@code merge}). This installer therefore builds an immutable {@code Map<nodeName, DeadLetterQueueOptions>} from the
 * subtopology's processor and sink nodes (each marked by {@link InternalTopologyBuilder#markProcessorNodeForDeadLetterQueue})
 * and hands it to the decorator, which routes each failed record to the DLQ policy of the <em>node in which the
 * failure occurred</em> ({@link org.apache.kafka.streams.errors.ErrorHandlerContext#processorNodeId()}, falling back
 * to the global default). Keying by node rather than by source topic keeps an opt-in on one branch from leaking into
 * an unopted sibling branch (P4-01) and routes a failure from a dynamically-matched {@code Pattern} topic by stable
 * node identity rather than a build-time topic name (P16-01 / P16-02), while preserving independent per-sub-graph
 * policies and the DSL &rarr; global precedence.
 *
 * <p>When neither any source opts in nor the global {@code default.deadletterqueue.*} default is enabled, the
 * configured handler is returned <strong>unchanged</strong>, so topologies that do not opt in retain byte-for-byte
 * identical error-handling behaviour and incur zero overhead on the non-failing path.
 *
 * <p>The class is stateless (only {@code static} methods) and therefore thread-safe; it is package-private because
 * it is an internal wiring detail of the {@code processor.internals} runtime.
 */
final class DeadLetterQueueInstaller {

    private DeadLetterQueueInstaller() {
        // stateless installer; not instantiable
    }

    /**
     * Build the immutable per-node DLQ policy map for a subtopology: for every processor or sink node that a DSL
     * {@code withDeadLetterQueue} opt-in marked (see
     * {@link InternalTopologyBuilder#markProcessorNodeForDeadLetterQueue}), map the node's name to its resolved
     * {@link DeadLetterQueueOptions}. Returns an empty map when no node opted in.
     *
     * <p>Processing and production failures are keyed by the <em>node</em> in which they occur — resolved at runtime
     * by {@link org.apache.kafka.streams.errors.ErrorHandlerContext#processorNodeId()} — rather than by source topic.
     * Node-scoping is what keeps an opt-in on one branch from leaking into an unopted sibling branch (P4-01) and what
     * routes a failure from a dynamically-matched {@code Pattern} topic by stable node identity rather than a
     * build-time topic name (P16-01 / P16-02). The map covers processor nodes (processing exceptions) and sink nodes
     * (produce/serialization exceptions); the runtime passes the sink node's name as the {@code processorNodeId} for
     * production failures, so both tiers resolve against the same map.
     *
     * @param topology the subtopology whose nodes are inspected
     * @return an immutable {@code nodeName -> options} map (possibly empty)
     */
    static Map<String, DeadLetterQueueOptions> dlqOptionsByProcessorNode(final ProcessorTopology topology) {
        Map<String, DeadLetterQueueOptions> byNode = null;
        for (final ProcessorNode<?, ?, ?, ?> node : topology.processors()) {
            final String dlqTopic = node.dlqRoutingTopic();
            if (dlqTopic != null) {
                final DeadLetterQueueOptions options = node.dlqRoutingOptions() != null
                    ? node.dlqRoutingOptions()
                    : DeadLetterQueueOptions.with(dlqTopic);
                if (byNode == null) {
                    byNode = new HashMap<>();
                }
                byNode.put(node.name(), options);
            }
        }
        // Return an unmodifiable snapshot so the documented immutability contract holds even before the decorator
        // constructors defensively copy it (P4-03). Collections.emptyMap() is already immutable.
        return byNode == null ? Collections.emptyMap() : Map.copyOf(byNode);
    }

    /**
     * Resolve the global fallback options from the {@code default.deadletterqueue.*} settings, or {@code null} when
     * the global default is disabled or its topic is unset/blank. The topic is assumed already validated at
     * {@code StreamsConfig} construction time (fail-fast); {@link DeadLetterQueueOptions#with(String)} re-validates
     * defensively.
     *
     * @param globalEnabled the {@code default.deadletterqueue.enabled} switch
     * @param globalTopic   the {@code default.deadletterqueue.topic} value (may be {@code null})
     * @return the global fallback options, or {@code null} when the global default does not apply
     */
    static DeadLetterQueueOptions globalOptions(final boolean globalEnabled, final String globalTopic) {
        if (globalEnabled && globalTopic != null && !globalTopic.trim().isEmpty()) {
            return DeadLetterQueueOptions.with(globalTopic);
        }
        return null;
    }

    /**
     * Resolve the global fallback options from a raw application-config map (for example
     * {@code processorContext.appConfigs()}), coercing the {@code default.deadletterqueue.enabled} value from either a
     * {@link Boolean} or its string form. Returns {@code null} when the global default does not apply. This mirrors
     * the coercion used when resolving the per-source deserialization handler, so the deserialization, processing and
     * production tiers all interpret the global default identically.
     *
     * @param appConfigs the raw application configuration map
     * @return the global fallback options, or {@code null} when the global default does not apply
     */
    static DeadLetterQueueOptions globalOptions(final Map<String, Object> appConfigs) {
        final Object enabledValue = appConfigs.get(StreamsConfig.DEFAULT_DEAD_LETTER_QUEUE_ENABLED_CONFIG);
        final boolean globalEnabled = enabledValue instanceof Boolean
            ? (Boolean) enabledValue
            : Boolean.parseBoolean(String.valueOf(enabledValue));
        final Object topicValue = appConfigs.get(StreamsConfig.DEFAULT_DEAD_LETTER_QUEUE_TOPIC_CONFIG);
        final String globalTopic = topicValue == null ? null : String.valueOf(topicValue);
        return globalOptions(globalEnabled, globalTopic);
    }

    /**
     * Wrap the subtopology's configured {@link ProcessingExceptionHandler} in the DLQ-aware decorator when the
     * subtopology opted in (via any source or the global default); otherwise return {@code delegate} unchanged.
     *
     * @param delegate      the configured processing exception handler (already configured)
     * @param topology      the subtopology being installed
     * @param globalOptions the resolved global fallback options, or {@code null} when the global default is off
     * @return the (possibly wrapped) handler
     */
    static ProcessingExceptionHandler maybeWrapProcessingHandler(final ProcessingExceptionHandler delegate,
                                                                 final ProcessorTopology topology,
                                                                 final DeadLetterQueueOptions globalOptions) {
        final Map<String, DeadLetterQueueOptions> byNode = dlqOptionsByProcessorNode(topology);
        if (byNode.isEmpty() && globalOptions == null) {
            return delegate;
        }
        return new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, byNode, globalOptions);
    }

    /**
     * Wrap the subtopology's configured {@link ProductionExceptionHandler} in the DLQ-aware decorator when the
     * subtopology opted in (via any source or the global default); otherwise return {@code delegate} unchanged.
     *
     * @param delegate      the configured production exception handler (already configured)
     * @param topology      the subtopology being installed
     * @param globalOptions the resolved global fallback options, or {@code null} when the global default is off
     * @return the (possibly wrapped) handler
     */
    static ProductionExceptionHandler maybeWrapProductionHandler(final ProductionExceptionHandler delegate,
                                                                 final ProcessorTopology topology,
                                                                 final DeadLetterQueueOptions globalOptions) {
        final Map<String, DeadLetterQueueOptions> byNode = dlqOptionsByProcessorNode(topology);
        if (byNode.isEmpty() && globalOptions == null) {
            return delegate;
        }
        return new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, byNode, globalOptions);
    }
}
