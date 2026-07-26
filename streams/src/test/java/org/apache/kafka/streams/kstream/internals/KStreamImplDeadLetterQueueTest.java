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

import org.apache.kafka.common.errors.InvalidTopicException;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.TopologyWrapper;
import org.apache.kafka.streams.errors.TopologyException;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.processor.internals.ProcessorTopology;
import org.apache.kafka.streams.processor.internals.SourceNode;
import org.apache.kafka.test.StreamsTestUtils;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the DSL wiring, graph-node liveness, and per-sub-graph scope semantics of
 * {@link KStream#withDeadLetterQueue(String, DeadLetterQueueOptions)} as implemented by {@link KStreamImpl}.
 *
 * <p>The opt-in DLQ policy is carried on a dedicated {@code DeadLetterQueueGraphNode} in the stream's sub-graph
 * (never by mutating shared source objects); the resulting per-source DLQ configuration is asserted on the built
 * {@link ProcessorTopology}. Because {@code KStreamImpl} no longer mutates source graph nodes, any DLQ
 * configuration observed on a built source proves the metadata graph node is live and consumed during topology
 * construction.
 */
public class KStreamImplDeadLetterQueueTest {

    private final Properties props = StreamsTestUtils.getStreamsConfig(Serdes.String(), Serdes.String());
    private final Consumed<String, String> consumed = Consumed.with(Serdes.String(), Serdes.String());

    private ProcessorTopology buildProcessorTopology(final StreamsBuilder builder) {
        final Topology topology = builder.build();
        return TopologyWrapper.getInternalTopologyBuilder(topology)
            .rewriteTopology(new StreamsConfig(props))
            .buildTopology();
    }

    private List<SourceNode<?, ?>> sourcesMarkedFor(final ProcessorTopology topology, final String dlqTopic) {
        return topology.sources().stream()
            .filter(source -> dlqTopic.equals(source.deadLetterQueueTopic()))
            .collect(Collectors.toList());
    }

    // ------------------------------------------------------------------------------------------------------------
    // CR-01 (graph node live) + basic single-source scope
    // ------------------------------------------------------------------------------------------------------------

    @Test
    public void shouldMarkOriginatingSourceViaLiveGraphNode() {
        final StreamsBuilder builder = new StreamsBuilder();
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with("dlq").withMaxRecordSize(512);
        builder.stream("input", consumed)
            .mapValues(v -> v)
            .withDeadLetterQueue("dlq", options);

        final ProcessorTopology topology = buildProcessorTopology(builder);
        final SourceNode<?, ?> source = topology.source("input");
        assertNotNull(source);
        assertEquals("dlq", source.deadLetterQueueTopic());
        assertSame(options, source.deadLetterQueueOptions());
        assertEquals(1, sourcesMarkedFor(topology, "dlq").size());
    }

    @Test
    public void shouldMarkSourceWhenCalledDirectlyOnSourceStream() {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream("input", consumed)
            .withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"));

        final ProcessorTopology topology = buildProcessorTopology(builder);
        assertEquals("dlq", topology.source("input").deadLetterQueueTopic());
    }

    @Test
    public void shouldLeaveNonOptedInTopologyWithoutAnyDlqConfiguration() {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream("input", consumed).mapValues(v -> v).to("output");

        final ProcessorTopology topology = buildProcessorTopology(builder);
        assertTrue(topology.sources().stream().allMatch(s -> s.deadLetterQueueTopic() == null));
    }

    // ------------------------------------------------------------------------------------------------------------
    // CR-03 scope semantics: merge, branches, repeated calls, repartition
    // ------------------------------------------------------------------------------------------------------------

    @Test
    public void shouldMarkAllOriginatingSourcesOfAMergedStream() {
        final StreamsBuilder builder = new StreamsBuilder();
        final KStream<String, String> a = builder.stream("inputA", consumed);
        final KStream<String, String> b = builder.stream("inputB", consumed);
        a.merge(b).withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"));

        final ProcessorTopology topology = buildProcessorTopology(builder);
        assertEquals("dlq", topology.source("inputA").deadLetterQueueTopic());
        assertEquals("dlq", topology.source("inputB").deadLetterQueueTopic());
        assertEquals(2, sourcesMarkedFor(topology, "dlq").size());
    }

    @Test
    public void shouldAllowSiblingBranchesToShareTheSameDlqConfigIdempotently() {
        final StreamsBuilder builder = new StreamsBuilder();
        final KStream<String, String> source = builder.stream("input", consumed);
        source.filter((k, v) -> true).withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"));
        source.filter((k, v) -> false).withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"));

        final ProcessorTopology topology = buildProcessorTopology(builder);
        assertEquals("dlq", topology.source("input").deadLetterQueueTopic());
        assertEquals(1, sourcesMarkedFor(topology, "dlq").size());
    }

    @Test
    public void shouldRejectSiblingBranchesWithConflictingDlqTopicsOnTheSameSource() {
        final StreamsBuilder builder = new StreamsBuilder();
        final KStream<String, String> source = builder.stream("input", consumed);
        source.filter((k, v) -> true).withDeadLetterQueue("dlq-a", DeadLetterQueueOptions.with("dlq-a"));
        source.filter((k, v) -> false).withDeadLetterQueue("dlq-b", DeadLetterQueueOptions.with("dlq-b"));

        final TopologyException exception = assertThrows(TopologyException.class, builder::build);
        assertTrue(exception.getMessage().contains("Conflicting dead letter queue configuration"));
    }

    @Test
    public void shouldRejectRepeatedCallsWithConflictingOptionsOnTheSameSource() {
        final StreamsBuilder builder = new StreamsBuilder();
        final KStream<String, String> stream = builder.stream("input", consumed).mapValues(v -> v);
        stream.withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq").withMaxRecordSize(256));
        stream.withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq").withMaxRecordSize(512));

        assertThrows(TopologyException.class, builder::build);
    }

    @Test
    public void shouldAllowRepeatedCallsWithIdenticalConfigOnTheSameSource() {
        final StreamsBuilder builder = new StreamsBuilder();
        final KStream<String, String> stream = builder.stream("input", consumed).mapValues(v -> v);
        stream.withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"));
        stream.withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"));

        final ProcessorTopology topology = buildProcessorTopology(builder);
        assertEquals("dlq", topology.source("input").deadLetterQueueTopic());
        assertEquals(1, sourcesMarkedFor(topology, "dlq").size());
    }

    @Test
    public void shouldMarkRepartitionSourceRatherThanOriginalExternalSourceAfterRepartition() {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream("input", consumed)
            .selectKey((k, v) -> k)
            .repartition()
            .mapValues(v -> v)
            .withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"));

        final ProcessorTopology topology = buildProcessorTopology(builder);

        // The original external source is upstream of the repartition boundary and must NOT be marked.
        final SourceNode<?, ?> externalSource = topology.source("input");
        assertNotNull(externalSource);
        assertNull(externalSource.deadLetterQueueTopic());

        // Exactly one (internal repartition) source is marked, and it is not the external source.
        final List<SourceNode<?, ?>> marked = sourcesMarkedFor(topology, "dlq");
        assertEquals(1, marked.size());
        assertNotSame(externalSource, marked.get(0));
    }

    // ------------------------------------------------------------------------------------------------------------
    // MA-01: argument validation and topic coherence
    // ------------------------------------------------------------------------------------------------------------

    @Test
    public void shouldThrowOnNullDlqTopic() {
        final KStream<String, String> stream = new StreamsBuilder().stream("input", consumed);
        assertThrows(NullPointerException.class,
            () -> stream.withDeadLetterQueue(null, DeadLetterQueueOptions.with("dlq")));
    }

    @Test
    public void shouldThrowOnNullOptions() {
        final KStream<String, String> stream = new StreamsBuilder().stream("input", consumed);
        assertThrows(NullPointerException.class, () -> stream.withDeadLetterQueue("dlq", null));
    }

    @Test
    public void shouldThrowOnBlankDlqTopic() {
        final KStream<String, String> stream = new StreamsBuilder().stream("input", consumed);
        assertThrows(IllegalArgumentException.class,
            () -> stream.withDeadLetterQueue("   ", DeadLetterQueueOptions.with("dlq")));
    }

    @Test
    public void shouldThrowOnInvalidDlqTopicName() {
        final KStream<String, String> stream = new StreamsBuilder().stream("input", consumed);
        // The argument is validated with Kafka's canonical topic validator at the DSL call site.
        assertThrows(InvalidTopicException.class,
            () -> stream.withDeadLetterQueue("bad topic", DeadLetterQueueOptions.with("valid-dlq")));
    }

    @Test
    public void shouldRejectTopicMismatchBetweenArgumentAndOptions() {
        final KStream<String, String> stream = new StreamsBuilder().stream("input", consumed);
        final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
            () -> stream.withDeadLetterQueue("dlq-a", DeadLetterQueueOptions.with("dlq-b")));
        assertTrue(exception.getMessage().contains("does not match"));
    }

    @Test
    public void shouldReturnSameStreamInstanceForFluentChaining() {
        final KStream<String, String> stream = new StreamsBuilder().stream("input", consumed).mapValues(v -> v);
        final KStream<String, String> result =
            stream.withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"));
        assertSame(stream, result);
    }
}
