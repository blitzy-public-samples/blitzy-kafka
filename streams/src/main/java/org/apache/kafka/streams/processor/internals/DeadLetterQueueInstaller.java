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
 * and a <em>single</em> production handler shared across all of its sources. A subtopology may nevertheless contain
 * several sources that opted in to <em>different</em> DLQ topics (for example a {@code merge} of two streams each
 * configured via {@link org.apache.kafka.streams.kstream.KStream#withDeadLetterQueue(String, DeadLetterQueueOptions)}).
 * This installer therefore builds an immutable {@code Map<sourceTopic, DeadLetterQueueOptions>} from the subtopology's
 * source nodes and hands it to the decorator, which routes each failed record to the DLQ policy of its
 * <em>originating source topic</em> (falling back to the global default), preserving independent per-source policies
 * and the DSL-per-source &rarr; global precedence.
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
     * Build the immutable per-source-origin DLQ policy map for a subtopology: for every source topic whose source
     * node was marked by a DSL {@code withDeadLetterQueue} opt-in, map the source topic to its resolved
     * {@link DeadLetterQueueOptions}. Returns an empty map when no source opted in.
     *
     * @param topology the subtopology whose sources are inspected
     * @return an immutable {@code sourceTopic -> options} map (possibly empty)
     */
    static Map<String, DeadLetterQueueOptions> dlqOptionsBySourceTopic(final ProcessorTopology topology) {
        Map<String, DeadLetterQueueOptions> bySourceTopic = null;
        for (final String sourceTopic : topology.sourceTopics()) {
            final SourceNode<?, ?> source = topology.source(sourceTopic);
            if (source == null) {
                continue;
            }
            final String dlqTopic = source.deadLetterQueueTopic();
            if (dlqTopic != null) {
                final DeadLetterQueueOptions options = source.deadLetterQueueOptions() != null
                    ? source.deadLetterQueueOptions()
                    : DeadLetterQueueOptions.with(dlqTopic);
                if (bySourceTopic == null) {
                    bySourceTopic = new HashMap<>();
                }
                bySourceTopic.put(sourceTopic, options);
            }
        }
        return bySourceTopic == null ? Collections.emptyMap() : bySourceTopic;
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
        final Map<String, DeadLetterQueueOptions> bySourceTopic = dlqOptionsBySourceTopic(topology);
        if (bySourceTopic.isEmpty() && globalOptions == null) {
            return delegate;
        }
        return new DeadLetterQueueExceptionHandlerDecorator.ProcessingDecorator(delegate, bySourceTopic, globalOptions);
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
        final Map<String, DeadLetterQueueOptions> bySourceTopic = dlqOptionsBySourceTopic(topology);
        if (bySourceTopic.isEmpty() && globalOptions == null) {
            return delegate;
        }
        return new DeadLetterQueueExceptionHandlerDecorator.ProductionDecorator(delegate, bySourceTopic, globalOptions);
    }
}
