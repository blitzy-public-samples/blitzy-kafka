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
import org.apache.kafka.streams.errors.internals.DlqRecordBuilder;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for the opt-in, DSL-level Dead Letter Queue (DLQ) capability enabled via
 * {@link org.apache.kafka.streams.kstream.KStream#withDeadLetterQueue(String, DeadLetterQueueOptions)}.
 *
 * <p>These tests exercise the new opt-in layer end-to-end with an {@link EmbeddedKafkaCluster}, distinct from the
 * pre-existing KIP-1034 global-config path covered by {@code DeadLetterQueueIntegrationTest}:
 * <ul>
 *     <li>{@link #shouldRouteDeserializationFailureToDlqViaDslOptIn()} verifies that a deserialization failure on an
 *         opted-in stream lands the original bytes plus the six {@code dlq.*} headers on the configured DLQ topic,
 *         that valid records continue to the output topic, and that the stream does not terminate (zero uncaught
 *         terminations when DLQ is enabled);</li>
 *     <li>{@link #shouldFailFastAndNotDeadLetterForNonOptInTopology()} is a regression guard: a topology that does
 *         NOT opt in retains byte-for-byte identical default (fail-fast) error handling and produces no DLQ records;</li>
 *     <li>{@link #shouldNotWriteToDlqForNonOptInLogAndContinueTopology()} is the complementary regression guard: a
 *         non-opted-in topology configured with the log-and-continue handler still skips the bad record and writes
 *         nothing to the DLQ, confirming neither pre-existing non-DLQ path is perturbed by the feature.</li>
 * </ul>
 */
@Tag("integration")
@Timeout(60)
public class DeadLetterQueueDslIntegrationTest {
    private static final int NUM_BROKERS = 3;

    private static EmbeddedKafkaCluster cluster;

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

    private String applicationId;
    private static final int NUM_TOPIC_PARTITIONS = 3;
    private static final String INPUT_TOPIC = "inputTopic";
    private static final String OUTPUT_TOPIC = "outputTopic";
    private static final String DLQ_TOPIC = "dlqTopic";

    private final List<KeyValue<String, byte[]>> bytesData = prepareBytesData();

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

    @Test
    public void shouldRouteDeserializationFailureToDlqViaDslOptIn() throws Exception {
        try (final KafkaStreams streams = getDslOptInStreams()) {

            startApplicationAndWaitUntilRunning(streams);

            // Produce data to the input topic; the second record ("value") is not a valid Long and fails deserialization.
            IntegrationTestUtils.produceKeyValuesSynchronously(
                INPUT_TOPIC,
                bytesData,
                TestUtils.producerConfig(cluster.bootstrapServers(), StringSerializer.class, ByteArraySerializer.class),
                cluster.time
            );

            // Valid records continue to the output topic (the DLQ opt-in resumes processing after dead-lettering).
            final List<ConsumerRecord<String, String>> outputRecords =
                readResult(OUTPUT_TOPIC, 2, StringDeserializer.class, StringDeserializer.class, 30000L);
            assertEquals(2, outputRecords.size(), "Two valid records should reach the output topic");
            assertEquals("1", outputRecords.get(0).value(), "First output record should be the first valid one");
            assertEquals("3", outputRecords.get(1).value(), "Second output record should be the third valid one");

            // The failed record lands on the DLQ topic with the original bytes and the six dlq.* headers.
            final List<ConsumerRecord<byte[], byte[]>> dlqRecords =
                readResult(DLQ_TOPIC, 1, ByteArrayDeserializer.class, ByteArrayDeserializer.class, 30000L);
            assertEquals(1, dlqRecords.size(), "Exactly one record should be dead-lettered");

            // The stream must NOT terminate — zero uncaught terminations when DLQ is enabled, even though the
            // default deserialization handler is fail-fast (the opt-in decorator resumes).
            assertThrows(AssertionError.class,
                () -> waitForApplicationState(singletonList(streams), KafkaStreams.State.ERROR, Duration.ofSeconds(10)));
            waitForApplicationState(singletonList(streams), KafkaStreams.State.RUNNING, Duration.ofSeconds(5));

            final ConsumerRecord<byte[], byte[]> dlqRecord = dlqRecords.get(0);
            // Original key/value bytes are preserved verbatim.
            assertEquals("key", new String(dlqRecord.key()), "DLQ record should carry the original key bytes");
            assertEquals("value", new String(dlqRecord.value()), "DLQ record should carry the original value bytes");

            // The six dlq.* diagnostic headers.
            assertEquals(
                "org.apache.kafka.common.errors.SerializationException",
                new String(dlqRecord.headers().lastHeader(DlqRecordBuilder.HEADER_EXCEPTION_CLASS).value()));
            assertTrue(
                new String(dlqRecord.headers().lastHeader(DlqRecordBuilder.HEADER_EXCEPTION_MESSAGE).value())
                    .contains("Size of data received by LongDeserializer is not 8"),
                "Exception message header should describe the deserialization failure");
            assertEquals(
                INPUT_TOPIC,
                new String(dlqRecord.headers().lastHeader(DlqRecordBuilder.HEADER_SOURCE_TOPIC).value()));
            assertEquals(
                "1",
                new String(dlqRecord.headers().lastHeader(DlqRecordBuilder.HEADER_SOURCE_PARTITION).value()));
            assertEquals(
                "1",
                new String(dlqRecord.headers().lastHeader(DlqRecordBuilder.HEADER_SOURCE_OFFSET).value()));
            final long failureTimestamp = Long.parseLong(
                new String(dlqRecord.headers().lastHeader(DlqRecordBuilder.HEADER_FAILURE_TIMESTAMP).value()));
            assertTrue(failureTimestamp > 0L, "Failure timestamp header should be a positive epoch-millis value");

            // Exactly the six dlq.* headers are present — no more, no fewer. This pins the AAP's frozen six-header
            // contract end-to-end (the builder never adds a seventh "truncated" marker header).
            assertEquals(6, dlqRecord.headers().toArray().length,
                "DLQ record must carry exactly the six dlq.* headers");
        }
    }

    @Test
    public void shouldFailFastAndNotDeadLetterForNonOptInTopology() throws Exception {
        try (final KafkaStreams streams = getNonOptInStreams()) {

            startApplicationAndWaitUntilRunning(streams);

            // Produce the same data, including the record that fails Long deserialization.
            IntegrationTestUtils.produceKeyValuesSynchronously(
                INPUT_TOPIC,
                bytesData,
                TestUtils.producerConfig(cluster.bootstrapServers(), StringSerializer.class, ByteArraySerializer.class),
                cluster.time
            );

            // Regression: with no DLQ opt-in and the default (fail-fast) handler, the stream must transition to ERROR,
            // exactly as before this feature existed.
            waitForApplicationState(singletonList(streams), KafkaStreams.State.ERROR, Duration.ofSeconds(30));

            // And no records must be routed to the DLQ topic.
            assertThrows(AssertionError.class,
                () -> readResult(DLQ_TOPIC, 1, ByteArrayDeserializer.class, ByteArrayDeserializer.class, 10000L),
                "No records should be dead-lettered for a non-opted-in topology");
        }
    }

    @Test
    public void shouldNotWriteToDlqForNonOptInLogAndContinueTopology() throws Exception {
        try (final KafkaStreams streams = getNonOptInLogAndContinueStreams()) {

            startApplicationAndWaitUntilRunning(streams);

            // Produce the same data, including the record that fails Long deserialization.
            IntegrationTestUtils.produceKeyValuesSynchronously(
                INPUT_TOPIC,
                bytesData,
                TestUtils.producerConfig(cluster.bootstrapServers(), StringSerializer.class, ByteArraySerializer.class),
                cluster.time
            );

            // Regression (log-and-continue): with no DLQ opt-in and the LogAndContinue handler, the two valid records
            // still reach the output topic and the bad record is silently skipped — byte-for-byte legacy behaviour.
            final List<ConsumerRecord<String, String>> outputRecords =
                readResult(OUTPUT_TOPIC, 2, StringDeserializer.class, StringDeserializer.class, 30000L);
            assertEquals(2, outputRecords.size(), "Two valid records should reach the output topic");
            assertEquals("1", outputRecords.get(0).value());
            assertEquals("3", outputRecords.get(1).value());

            // And nothing is routed to the DLQ topic (no behavioural change from before this feature existed).
            assertThrows(AssertionError.class,
                () -> readResult(DLQ_TOPIC, 1, ByteArrayDeserializer.class, ByteArrayDeserializer.class, 10000L),
                "No records should be dead-lettered for a non-opted-in log-and-continue topology");
        }
    }

    @Test
    public void shouldIncurNoDlqWritesForAllValidRecordsWhenOptedIn() throws Exception {
        // MA-11 (failure-path-only overhead): a topology that opts in to the DLQ but processes only valid records
        // must write NOTHING to the DLQ topic — the DLQ machinery is confined to the exception branch, so the
        // non-failing (happy) path is untouched. This is the verifiable, mutation-sensitive guarantee behind the
        // "non-failure throughput is unaffected" performance goal; specific p99-latency figures are a design target
        // rather than a suite assertion, since a failure-path microbenchmark belongs in the dedicated JMH module.
        try (final KafkaStreams streams = getDslOptInStreams()) {
            startApplicationAndWaitUntilRunning(streams);

            // Only valid Long-encoded records — none fail deserialization.
            final List<KeyValue<String, byte[]>> allValid = new ArrayList<>();
            allValid.add(new KeyValue<>("key", ByteBuffer.allocate(Long.BYTES).putLong(10L).array()));
            allValid.add(new KeyValue<>("key", ByteBuffer.allocate(Long.BYTES).putLong(20L).array()));
            IntegrationTestUtils.produceKeyValuesSynchronously(
                INPUT_TOPIC,
                allValid,
                TestUtils.producerConfig(cluster.bootstrapServers(), StringSerializer.class, ByteArraySerializer.class),
                cluster.time
            );

            // All records flow through to the output topic...
            final List<ConsumerRecord<String, String>> outputRecords =
                readResult(OUTPUT_TOPIC, 2, StringDeserializer.class, StringDeserializer.class, 30000L);
            assertEquals(2, outputRecords.size(), "All valid records should reach the output topic");

            // ...and the DLQ topic receives nothing (reading even one record times out), proving the happy path
            // incurs zero DLQ overhead even when the topology has opted in.
            assertThrows(AssertionError.class,
                () -> readResult(DLQ_TOPIC, 1, ByteArrayDeserializer.class, ByteArrayDeserializer.class, 10000L),
                "An opted-in topology with only valid records must incur zero DLQ writes");
        }
    }

    private KafkaStreams getDslOptInStreams() {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream(INPUT_TOPIC, Consumed.with(Serdes.String(), Serdes.Long()))
            .withDeadLetterQueue(DLQ_TOPIC, DeadLetterQueueOptions.with(DLQ_TOPIC))
            .mapValues((k, v) -> String.valueOf(v))
            .to(OUTPUT_TOPIC, Produced.with(Serdes.String(), Serdes.String()));

        return new KafkaStreams(builder.build(), getBaseProperties());
    }

    private KafkaStreams getNonOptInStreams() {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream(INPUT_TOPIC, Consumed.with(Serdes.String(), Serdes.Long()))
            .mapValues((k, v) -> String.valueOf(v))
            .to(OUTPUT_TOPIC, Produced.with(Serdes.String(), Serdes.String()));

        return new KafkaStreams(builder.build(), getBaseProperties());
    }

    private KafkaStreams getNonOptInLogAndContinueStreams() {
        final StreamsBuilder builder = new StreamsBuilder();
        builder.stream(INPUT_TOPIC, Consumed.with(Serdes.String(), Serdes.Long()))
            .mapValues((k, v) -> String.valueOf(v))
            .to(OUTPUT_TOPIC, Produced.with(Serdes.String(), Serdes.String()));

        final Properties properties = getBaseProperties();
        // Pre-existing default (non-DLQ) behaviour: log-and-continue skips the bad record; no DLQ anywhere.
        properties.put(
            StreamsConfig.DESERIALIZATION_EXCEPTION_HANDLER_CLASS_CONFIG,
            LogAndContinueExceptionHandler.class.getName());
        return new KafkaStreams(builder.build(), properties);
    }

    private Properties getBaseProperties() {
        final Properties properties = new Properties();
        properties.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        // NOTE: deliberately does NOT set ERRORS_DEAD_LETTER_QUEUE_TOPIC_NAME_CONFIG — this exercises the new
        // opt-in DSL path, not the pre-existing KIP-1034 global-config path.
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
