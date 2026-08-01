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

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.TopologyWrapper;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.test.StreamsTestUtils;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit coverage for {@link DeadLetterQueueInstaller#dlqOptionsByProcessorNode(ProcessorTopology)}.
 *
 * <p>Focuses on the immutability contract documented by that helper (P4-03): the returned
 * {@code nodeName -> options} map (keyed by the processor/sink node in which a processing/production failure occurs,
 * per the node-lineage design that fixes P4-01/P16-01/P16-02) must reject mutation regardless of whether any node
 * opted in.
 */
public class DeadLetterQueueInstallerTest {

    private final Properties props = StreamsTestUtils.getStreamsConfig(Serdes.String(), Serdes.String());
    private final Consumed<String, String> consumed = Consumed.with(Serdes.String(), Serdes.String());

    private ProcessorTopology buildProcessorTopology(final StreamsBuilder builder) {
        final Topology topology = builder.build();
        return TopologyWrapper.getInternalTopologyBuilder(topology)
            .rewriteTopology(new StreamsConfig(props))
            .buildTopology();
    }

    @Test
    public void shouldReturnUnmodifiableMapWhenANodeOptedIn() {
        final StreamsBuilder builder = new StreamsBuilder();
        // The opt-in marks every downstream processor/sink node (here the mapValues processor and the sink) for
        // node-scoped processing/production DLQ routing; the source is marked separately for deserialization only.
        builder.stream("input", consumed)
            .withDeadLetterQueue("dlq", DeadLetterQueueOptions.with("dlq"))
            .mapValues(v -> v)
            .to("output");

        final Map<String, DeadLetterQueueOptions> byNode =
            DeadLetterQueueInstaller.dlqOptionsByProcessorNode(buildProcessorTopology(builder));

        // Both the mapValues processor node and the sink node are opted in; each resolves to the "dlq" topic.
        assertEquals(2, byNode.size());
        assertTrue(byNode.values().stream().allMatch(o -> "dlq".equals(o.dlqTopic())));
        assertNotNull(byNode);

        // P4-03: the documented "immutable" contract must actually hold — mutation is rejected.
        assertThrows(UnsupportedOperationException.class,
            () -> byNode.put("other", DeadLetterQueueOptions.with("other")));
        assertThrows(UnsupportedOperationException.class,
            () -> byNode.remove(byNode.keySet().iterator().next()));
        assertThrows(UnsupportedOperationException.class, byNode::clear);
    }

    @Test
    public void shouldReturnEmptyImmutableMapWhenNoNodeOptedIn() {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream("input", consumed).mapValues(v -> v).to("output");

        final Map<String, DeadLetterQueueOptions> byNode =
            DeadLetterQueueInstaller.dlqOptionsByProcessorNode(buildProcessorTopology(builder));

        assertTrue(byNode.isEmpty());
        assertThrows(UnsupportedOperationException.class,
            () -> byNode.put("other", DeadLetterQueueOptions.with("other")));
    }
}
