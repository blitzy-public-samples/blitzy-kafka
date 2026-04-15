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
package org.apache.kafka.common;

import java.io.Serializable;
import java.util.Objects;

/**
 * A topic name and partition number
 *
 * @implNote DECISION: Immutable Serializable value type serving as the canonical partition
 * identity key across the entire Kafka ecosystem. Alternative: {@code Pair<String, Integer>}.
 * Rationale: First-class type enables type-safe APIs and domain-specific semantics. Implements
 * Serializable for RPC/serialization frameworks. Does NOT implement Comparable — ordering is
 * not required for partition identity.
 */
public final class TopicPartition implements Serializable {
    // CROSS-CUTTING: THE most widely-used type in Kafka — present in virtually every module:
    // Cluster partition indexing, producer batching (RecordAccumulator), consumer assignment
    // (SubscriptionState, ConsumerCoordinator), offset management, replication (ReplicaManager,
    // Partition), coordinator state, storage (Log, LogSegment), metadata (PartitionRegistration),
    // and streams task identity. Any change to this class affects the entire codebase.

    // DECISION: Explicit serialVersionUID for binary compatibility across Kafka versions when
    // TopicPartition is serialized (e.g., in RPC frameworks, test fixtures).
    private static final long serialVersionUID = -613627415771699627L;

    // DECISION: Lazy-cached hashCode with benign race pattern (same as Node). Initial value 0
    // serves as "not computed" sentinel. This is performance-critical — TopicPartition is the
    // most common map key in Kafka (used in millions of partition-to-X lookups).
    private int hash = 0;
    private final int partition;
    private final String topic;

    public TopicPartition(String topic, int partition) {
        this.partition = partition;
        this.topic = topic;
    }

    public int partition() {
        return partition;
    }

    public String topic() {
        return topic;
    }

    // DECISION: Prime-based hash combining partition (int) and topic (String). Does not use
    // Objects.hash() to avoid autoboxing partition to Integer in the varargs call — important
    // for GC pressure reduction at scale.
    @Override
    public int hashCode() {
        if (hash != 0)
            return hash;
        final int prime = 31;
        int result = prime + partition;
        result = prime * result + Objects.hashCode(topic);
        this.hash = result;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        TopicPartition other = (TopicPartition) obj;
        return partition == other.partition && Objects.equals(topic, other.topic);
    }

    @Override
    public String toString() {
        return topic + "-" + partition;
    }
}
