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
package org.apache.kafka.common.internals;

import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.errors.InvalidTopicException;

import java.util.Set;
import java.util.function.Consumer;

// DECISION: Centralized topic name validation and internal topic registry. Alternative:
// Distribute validation into each module that creates topics. Rationale: Single validation
// point prevents inconsistent topic name rules across producer, consumer, admin, and server
// modules. Placing this in common/internals/ makes it available to all modules without
// exposing it as public API.
// CROSS-CUTTING: Consumed by clients/admin/KafkaAdminClient for topic creation validation,
// clients/producer/KafkaProducer for send-time topic validation, core/server/KafkaApis for
// server-side validation, and group-coordinator/ for internal topic identification.
// The internal topic constants are referenced across ALL modules: consumer offset commits
// (GROUP_METADATA_TOPIC_NAME), transactions (TRANSACTION_STATE_TOPIC_NAME), share groups
// (SHARE_GROUP_STATE_TOPIC_NAME), and KRaft (CLUSTER_METADATA_TOPIC_NAME).
public class Topic {

    // DECISION: Internal topic names use double-underscore prefix (__) convention to distinguish
    // system topics from user topics. These constants are the canonical source of truth for
    // internal topic names — all references should use these constants, not string literals.
    public static final String GROUP_METADATA_TOPIC_NAME = "__consumer_offsets";
    public static final String TRANSACTION_STATE_TOPIC_NAME = "__transaction_state";
    // DECISION: Added for KIP-932 (Share Groups). Follows the same double-underscore naming
    // convention as existing internal topics for consistency.
    public static final String SHARE_GROUP_STATE_TOPIC_NAME = "__share_group_state";
    // DECISION: KRaft mode metadata topic. Uses fixed partition 0 (line 31-34) because
    // cluster metadata is a single-partition log — no partitioning needed for the controller's
    // metadata journal.
    public static final String CLUSTER_METADATA_TOPIC_NAME = "__cluster_metadata";
    public static final TopicPartition CLUSTER_METADATA_TOPIC_PARTITION = new TopicPartition(
        CLUSTER_METADATA_TOPIC_NAME,
        0
    );
    public static final String LEGAL_CHARS = "[a-zA-Z0-9._-]";

    // DECISION: Set.of() immutable set for O(1) isInternal() lookup. Note that
    // CLUSTER_METADATA_TOPIC_NAME is NOT included — it is not considered an "internal topic"
    // in the consumer/producer sense (it's a KRaft system topic not exposed to clients).
    private static final Set<String> INTERNAL_TOPICS = Set.of(GROUP_METADATA_TOPIC_NAME, TRANSACTION_STATE_TOPIC_NAME, SHARE_GROUP_STATE_TOPIC_NAME);

    // DECISION: 249-character limit matches ZooKeeper znode name length constraint (historical).
    // Even in KRaft mode, this limit is preserved for backward compatibility with existing
    // topics and tooling that assumes this maximum.
    private static final int MAX_NAME_LENGTH = 249;

    public static void validate(String topic) {
        validate(topic, "Topic name", message -> {
            throw new InvalidTopicException(message);
        });
    }

    private static String detectInvalidTopic(String name) {
        if (name.isEmpty())
            return "the empty string is not allowed";
        if (".".equals(name))
            return "'.' is not allowed";
        if ("..".equals(name))
            return "'..' is not allowed";
        if (name.length() > MAX_NAME_LENGTH)
            return "the length of '" + name + "' is longer than the max allowed length " + MAX_NAME_LENGTH;
        if (!containsValidPattern(name))
            return "'" + name + "' contains one or more characters other than " +
                "ASCII alphanumerics, '.', '_' and '-'";
        return null;
    }

    public static boolean isValid(String name) {
        String reasonInvalid = detectInvalidTopic(name);
        return reasonInvalid == null;
    }

    public static void validate(String name, String logPrefix, Consumer<String> throwableConsumer) {
        String reasonInvalid = detectInvalidTopic(name);
        if (reasonInvalid != null) {
            throwableConsumer.accept(logPrefix + " is invalid: " +  reasonInvalid);
        }
    }

    public static boolean isInternal(String topic) {
        return INTERNAL_TOPICS.contains(topic);
    }

    // DECISION: Topic name collision detection for '.' and '_' characters. These characters
    // are interchangeable in JMX metric names (metrics replace '.' with '_'), so topics
    // "foo.bar" and "foo_bar" would produce identical metric names causing monitoring confusion.
    // unifyCollisionChars() normalizes both to '_' for comparison.
    /**
     * Due to limitations in metric names, topics with a period ('.') or underscore ('_') could collide.
     *
     * @param topic The topic to check for colliding character
     * @return true if the topic has collision characters
     */
    public static boolean hasCollisionChars(String topic) {
        return topic.contains("_") || topic.contains(".");
    }

    /**
     * Unify topic name with a period ('.') or underscore ('_'), this is only used to check collision and will not
     * be used to really change topic name.
     *
     * @param topic A topic to unify
     * @return A unified topic name
     */
    public static String unifyCollisionChars(String topic) {
        return topic.replace('.', '_');
    }

    /**
     * Returns true if the topicNames collide due to a period ('.') or underscore ('_') in the same position.
     *
     * @param topicA A topic to check for collision
     * @param topicB A topic to check for collision
     * @return true if the topics collide
     */
    public static boolean hasCollision(String topicA, String topicB) {
        return unifyCollisionChars(topicA).equals(unifyCollisionChars(topicB));
    }

    // DECISION: Manual character-by-character validation rather than regex Pattern.matches().
    // Alternative: Compile LEGAL_CHARS regex pattern. Rationale: This method is called for
    // every topic name validation (high frequency in admin operations and metadata processing).
    // Manual char checks avoid regex compilation/matching overhead. The comment at line 117
    // notes Character.isLetterOrDigit() is also avoided for performance.
    /**
     * Valid characters for Kafka topics are the ASCII alphanumerics, '.', '_', and '-'
     */
    static boolean containsValidPattern(String topic) {
        for (int i = 0; i < topic.length(); ++i) {
            char c = topic.charAt(i);

            // We don't use Character.isLetterOrDigit(c) because it's slower
            boolean validChar = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == '.' ||
                    c == '_' || c == '-';
            if (!validChar)
                return false;
        }
        return true;
    }
}
