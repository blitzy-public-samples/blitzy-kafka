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

import org.apache.kafka.common.ClusterResource;
import org.apache.kafka.common.ClusterResourceListener;

import java.util.ArrayList;
import java.util.List;

// DECISION: Composite listener pattern aggregating ClusterResourceListener instances into a
// single broadcaster. Alternative: EventBus or pub-sub pattern. Rationale: Simple list-based
// aggregation is sufficient for the small number of listeners (typically <10: interceptors,
// reporters, serializers) and avoids introducing framework dependencies. The instanceof-based
// maybeAdd() pattern allows callers to pass any object without knowing if it implements the
// listener interface — simplifying plugin registration in KafkaProducer/KafkaConsumer.
//
// CROSS-CUTTING: Instantiated by KafkaProducer, KafkaConsumer, and KafkaAdminClient during
// construction to register interceptors, serializers/deserializers, and metrics reporters
// that implement ClusterResourceListener. onUpdate() is called from Metadata.update() after
// successful metadata fetch to notify all registered listeners of the cluster identity.
// Contract: Not thread-safe for concurrent mutations; callers must synchronize.
public class ClusterResourceListeners {

    // DECISION: ArrayList (not synchronized) — thread safety is the caller's responsibility.
    // Alternative: CopyOnWriteArrayList for built-in thread safety. Rationale: Listeners are
    // registered during client construction (single-threaded) and onUpdate() is called from
    // the metadata update path which is already synchronized. CopyOnWriteArrayList would add
    // unnecessary overhead for the common case.
    private final List<ClusterResourceListener> clusterResourceListeners;

    public ClusterResourceListeners() {
        this.clusterResourceListeners = new ArrayList<>();
    }

    /**
     * Add only if the candidate implements {@link ClusterResourceListener}.
     * @param candidate Object which might implement {@link ClusterResourceListener}
     */
    // DECISION: instanceof check allows generic Object parameter — callers don't need to know
    // if an interceptor/serializer/reporter implements ClusterResourceListener. This duck-typing
    // approach simplifies the plugin registration loop in KafkaProducer/KafkaConsumer constructors.
    public void maybeAdd(Object candidate) {
        if (candidate instanceof ClusterResourceListener) {
            clusterResourceListeners.add((ClusterResourceListener) candidate);
        }
    }

    /**
     * Add all items who implement {@link ClusterResourceListener} from the list.
     * @param candidateList List of objects which might implement {@link ClusterResourceListener}
     */
    public void maybeAddAll(List<?> candidateList) {
        for (Object candidate : candidateList) {
            this.maybeAdd(candidate);
        }
    }

    /**
     * Send the updated cluster metadata to all {@link ClusterResourceListener}.
     * @param cluster Cluster metadata
     */
    public void onUpdate(ClusterResource cluster) {
        for (ClusterResourceListener clusterResourceListener : clusterResourceListeners) {
            clusterResourceListener.onUpdate(cluster);
        }
    }
}