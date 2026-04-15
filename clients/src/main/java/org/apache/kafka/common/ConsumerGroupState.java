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

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The consumer group state.
 *
 * @implNote DECISION: Deprecated in favor of {@link GroupState} which supports all group types
 * (Classic, Consumer, Share, Streams). This enum was originally the only group state type when
 * Kafka only had consumer groups. Kept for backward API compatibility. Alternative: Remove
 * entirely. Rationale: Public API type used by existing admin tools — deprecation-then-removal
 * follows Kafka's API evolution policy.
 *
 * @deprecated Since 4.0. Use {@link GroupState} instead.
 */
@Deprecated
public enum ConsumerGroupState {
    UNKNOWN("Unknown"),
    PREPARING_REBALANCE("PreparingRebalance"),
    COMPLETING_REBALANCE("CompletingRebalance"),
    STABLE("Stable"),
    DEAD("Dead"),
    EMPTY("Empty"),
    ASSIGNING("Assigning"),
    RECONCILING("Reconciling");

    private static final Map<String, ConsumerGroupState> NAME_TO_ENUM = Arrays.stream(values())
        .collect(Collectors.toMap(state -> state.name.toUpperCase(Locale.ROOT), Function.identity()));

    private final String name;

    ConsumerGroupState(String name) {
        this.name = name;
    }

    /**
     * Case-insensitive consumer group state lookup by string name.
     */
    // DECISION: Returns UNKNOWN for unrecognized state strings rather than throwing —
    // matches GroupState.parse() graceful degradation contract.
    public static ConsumerGroupState parse(String name) {
        ConsumerGroupState state = NAME_TO_ENUM.get(name.toUpperCase(Locale.ROOT));
        return state == null ? UNKNOWN : state;
    }

    @Override
    public String toString() {
        return name;
    }
}
