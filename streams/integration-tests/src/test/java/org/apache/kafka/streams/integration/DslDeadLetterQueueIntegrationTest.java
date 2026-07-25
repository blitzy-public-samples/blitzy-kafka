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
package org.apache.kafka.streams.integration;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.KeyValue;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.errors.LogAndContinueExceptionHandler;
import org.apache.kafka.streams.integration.utils.EmbeddedKafkaCluster;
import org.apache.kafka.streams.integration.utils.IntegrationTestUtils;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.streams.kstream.Produced;
import org.apache.kafka.test.StreamsTestUtils;
import org.apache.kafka.test.TestUtils;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static java.util.Collections.singletonList;
import static org.apache.kafka.streams.integration.utils.IntegrationTestUtils.startApplicationAndWaitUntilRunning;
import static org.apache.kafka.streams.utils.TestUtils.safeUniqueTestName;
import static org.apache.kafka.streams.utils.TestUtils.waitForApplicationState;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("integration")
@Timeout(60)
public class DslDeadLetterQueueIntegrationTest {

    private static final int NUM_BROKERS = 3;
    private static EmbeddedKafkaCluster cluster;

    private static final int NUM_TOPIC_PARTITIONS = 3;
    private static final String INPUT_TOPIC = "inputTopic";
    private static final String OUTPUT_TOPIC = "outputTopic";
    private static final String DLQ_TOPIC = "dlqTopic";

    // The six dlq.* header names are asserted as STRING LITERALS: the record builder is internal and its
    // constant identifiers are not a pinned contract, but the emitted header names are. Note this scheme
    // deliberately diverges from the legacy per-record error headers used by the global-config DLQ path.
    private static final String DLQ_HEADER_EXCEPTION_CLASS = "dlq.exception.class";
    private static final String DLQ_HEADER_EXCEPTION_MESSAGE = "dlq.exception.message";
    private static final String DLQ_HEADER_SOURCE_TOPIC = "dlq.source.topic";
    private static final String DLQ_HEADER_SOURCE_PARTITION = "dlq.source.partition";
    private static final String DLQ_HEADER_SOURCE_OFFSET = "dlq.source.offset";
    private static final String DLQ_HEADER_FAILURE_TIMESTAMP = "dlq.failure.timestamp";

    private String applicationId;
    private final List<KeyValue<String, byte[]>> bytesData = prepareBytesData();

    @BeforeAll
    public static void startCluster() throws IOException {
        cluster = new EmbeddedKafkaCluster(NUM_BROKERS);
        cluster.start();
    }

    @AfterAll
    public static void closeCluster() {
        cluster.stop();
        cluster = null;
    }

    @BeforeEach
    public void createTopics(final TestInfo testInfo) throws Exception {
        applicationId = "appId-" + safeUniqueTestName(testInfo);
        cluster.deleteTopics(
            INPUT_TOPIC,
            OUTPUT_TOPIC,
            DLQ_TOPIC);
        cluster.createTopic(INPUT_TOPIC, NUM_TOPIC_PARTITIONS, 1);
        cluster.createTopic(OUTPUT_TOPIC, NUM_TOPIC_PARTITIONS, 1);
        cluster.createTopic(DLQ_TOPIC, NUM_TOPIC_PARTITIONS, 1);
    }

    // POSITIVE PATH: the DSL opt-in call routes a deserialization failure to the DLQ topic and resumes.
    @Test
    public void shouldRouteDeserializationFailureToDlqViaDsl() throws Exception {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream(INPUT_TOPIC, Consumed.with(Serdes.String(), Serdes.Long()))
            .withDeadLetterQueue(DLQ_TOPIC, DeadLetterQueueOptions.with(DLQ_TOPIC))
            .mapValues((k, v) -> String.valueOf(v))
            .to(OUTPUT_TOPIC, Produced.with(Serdes.String(), Serdes.String()));

        final Properties properties = new Properties();
        properties.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        // Deliberately do NOT set the global DLQ topic config and do NOT set a custom deserialization
        // handler: the DSL opt-in alone must drive DLQ routing and resume rather than fail-fast.

        try (final KafkaStreams streams = new KafkaStreams(builder.build(), getConfig(properties))) {
            startApplicationAndWaitUntilRunning(streams);

            IntegrationTestUtils.produceKeyValuesSynchronously(
                INPUT_TOPIC,
                bytesData,
                TestUtils.producerConfig(cluster.bootstrapServers(), StringSerializer.class, ByteArraySerializer.class),
                cluster.time);

            // The two valid records continue through the topology to the output topic (resume behavior).
            final List<ConsumerRecord<String, String>> outputRecords =
                readResult(OUTPUT_TOPIC, 2, StringDeserializer.class, StringDeserializer.class, 30000L);
            assertEquals(2, outputRecords.size());
            assertEquals("1", outputRecords.get(0).value());
            assertEquals("3", outputRecords.get(1).value());

            // The failing record lands on the DLQ topic within one poll cycle.
            final List<ConsumerRecord<byte[], byte[]>> dlqRecords =
                readResult(DLQ_TOPIC, 1, ByteArrayDeserializer.class, ByteArrayDeserializer.class, 30000L);
            assertEquals(1, dlqRecords.size());
            final ConsumerRecord<byte[], byte[]> dlqRecord = dlqRecords.get(0);

            // The original key/value bytes are preserved.
            assertEquals("key", new String(dlqRecord.key()));
            assertEquals("value", new String(dlqRecord.value()));

            // dlq.exception.class carries the BARE class name (diverges from the legacy toString() scheme).
            assertNotNull(dlqRecord.headers().lastHeader(DLQ_HEADER_EXCEPTION_CLASS));
            assertEquals(
                "org.apache.kafka.common.errors.SerializationException",
                new String(dlqRecord.headers().lastHeader(DLQ_HEADER_EXCEPTION_CLASS).value()));

            assertNotNull(dlqRecord.headers().lastHeader(DLQ_HEADER_EXCEPTION_MESSAGE));
            assertEquals(
                "Size of data received by LongDeserializer is not 8",
                new String(dlqRecord.headers().lastHeader(DLQ_HEADER_EXCEPTION_MESSAGE).value()));

            assertNotNull(dlqRecord.headers().lastHeader(DLQ_HEADER_SOURCE_TOPIC));
            assertEquals(
                INPUT_TOPIC,
                new String(dlqRecord.headers().lastHeader(DLQ_HEADER_SOURCE_TOPIC).value()));

            assertNotNull(dlqRecord.headers().lastHeader(DLQ_HEADER_SOURCE_PARTITION));
            assertTrue(Integer.parseInt(
                new String(dlqRecord.headers().lastHeader(DLQ_HEADER_SOURCE_PARTITION).value())) >= 0);

            assertNotNull(dlqRecord.headers().lastHeader(DLQ_HEADER_SOURCE_OFFSET));
            assertTrue(Long.parseLong(
                new String(dlqRecord.headers().lastHeader(DLQ_HEADER_SOURCE_OFFSET).value())) >= 0);

            assertNotNull(dlqRecord.headers().lastHeader(DLQ_HEADER_FAILURE_TIMESTAMP));
            assertTrue(Long.parseLong(
                new String(dlqRecord.headers().lastHeader(DLQ_HEADER_FAILURE_TIMESTAMP).value())) >= 0);

            // The DSL opt-in resumes rather than fail-fast: the application never transitions to ERROR.
            assertThrows(
                AssertionError.class,
                () -> waitForApplicationState(singletonList(streams), KafkaStreams.State.ERROR, Duration.ofSeconds(10)));
            waitForApplicationState(singletonList(streams), KafkaStreams.State.RUNNING, Duration.ofSeconds(5));
        }
    }

    // REGRESSION: a topology WITHOUT the DSL opt-in behaves exactly as before and writes nothing to the DLQ.
    @Test
    public void shouldNotWriteToDlqWhenNotOptedIn() throws Exception {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream(INPUT_TOPIC, Consumed.with(Serdes.String(), Serdes.Long()))
            .mapValues((k, v) -> String.valueOf(v))
            .to(OUTPUT_TOPIC, Produced.with(Serdes.String(), Serdes.String()));

        final Properties properties = new Properties();
        properties.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        // Pre-existing default behavior: log-and-continue skips the bad record; no DLQ is configured anywhere.
        properties.put(
            StreamsConfig.DESERIALIZATION_EXCEPTION_HANDLER_CLASS_CONFIG,
            LogAndContinueExceptionHandler.class.getName());

        try (final KafkaStreams streams = new KafkaStreams(builder.build(), getConfig(properties))) {
            startApplicationAndWaitUntilRunning(streams);

            IntegrationTestUtils.produceKeyValuesSynchronously(
                INPUT_TOPIC,
                bytesData,
                TestUtils.producerConfig(cluster.bootstrapServers(), StringSerializer.class, ByteArraySerializer.class),
                cluster.time);

            // Valid records still reach the output topic; the bad record is skipped (unchanged legacy behavior).
            final List<ConsumerRecord<String, String>> outputRecords =
                readResult(OUTPUT_TOPIC, 2, StringDeserializer.class, StringDeserializer.class, 30000L);
            assertEquals(2, outputRecords.size());
            assertEquals("1", outputRecords.get(0).value());
            assertEquals("3", outputRecords.get(1).value());

            // Zero DLQ writes: reading a single DLQ record must time out, proving no behavioral change.
            assertThrows(
                AssertionError.class,
                () -> readResult(DLQ_TOPIC, 1, ByteArrayDeserializer.class, ByteArrayDeserializer.class, 10000L));
        }
    }

    private Properties getConfig(final Properties properties) {
        return StreamsTestUtils.getStreamsConfig(
            applicationId,
            cluster.bootstrapServers(),
            Serdes.StringSerde.class.getName(),
            Serdes.StringSerde.class.getName(),
            properties);
    }

    private List<KeyValue<String, byte[]>> prepareBytesData() {
        final List<KeyValue<String, byte[]>> data = new ArrayList<>();

        data.add(new KeyValue<>("key", ByteBuffer.allocate(Long.BYTES).putLong(1L).array()));
        data.add(new KeyValue<>("key", "value".getBytes()));
        data.add(new KeyValue<>("key", ByteBuffer.allocate(Long.BYTES).putLong(3L).array()));

        return data;
    }

    private <K, V> List<ConsumerRecord<K, V>> readResult(final String topic,
                                                         final int numberOfRecords,
                                                         final Class<? extends Deserializer<K>> keyDeserializer,
                                                         final Class<? extends Deserializer<V>> valueDeserializer,
                                                         final long timeout) throws Exception {
        return IntegrationTestUtils.waitUntilMinRecordsReceived(
            TestUtils.consumerConfig(cluster.bootstrapServers(), keyDeserializer, valueDeserializer),
            topic,
            numberOfRecords,
            timeout);
    }

}
