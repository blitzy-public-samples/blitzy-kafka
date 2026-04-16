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
package org.apache.kafka.common.utils;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

/**
 * A simple read-optimized map implementation that synchronizes only writes and does a full copy on each modification.
 * <p>
 * Through the {@link org.apache.kafka.jmh.util.ConcurrentMapBenchmark}, we observed that in scenarios where
 * write operations (i.e. computeIfAbsent) constitute 10%, the get performance of CopyOnWriteMap is lower compared to
 * ConcurrentHashMap. However, when iterating over entrySet and values, CopyOnWriteMap performs better than ConcurrentHashMap.
 */
// DECISION: Volatile reference to immutable HashMap snapshot with synchronized copy-on-write
// mutations. Alternative: ConcurrentHashMap. Rationale: Per JMH benchmarks (referenced in
// Javadoc), CopyOnWriteMap has better iteration performance over entrySet/values than
// ConcurrentHashMap, which matters for metrics/JMX iteration. The tradeoff is higher write
// cost (full copy on each mutation), acceptable because Kafka's usage pattern is overwhelmingly
// read-heavy (metrics reads >> metric registrations). Thread-safety: volatile read provides
// happens-before guarantee; synchronized write prevents lost updates.
// CROSS-CUTTING: Used by common/metrics/Metrics for the metric registry (read-heavy, write-rare),
// and by metadata/TopicBasedRemoteLogMetadataManagerConfig for topic configuration tracking.
public class CopyOnWriteMap<K, V> implements ConcurrentMap<K, V> {

    // DECISION: Volatile ensures readers see the latest snapshot without synchronization.
    // The map reference is replaced atomically — readers never see a partially-mutated map.
    private volatile Map<K, V> map;

    public CopyOnWriteMap() {
        this.map = Collections.emptyMap();
    }

    public CopyOnWriteMap(Map<K, V> map) {
        this.map = Collections.unmodifiableMap(map);
    }

    @Override
    public boolean containsKey(Object k) {
        return map.containsKey(k);
    }

    @Override
    public boolean containsValue(Object v) {
        return map.containsValue(v);
    }

    @Override
    public Set<java.util.Map.Entry<K, V>> entrySet() {
        return map.entrySet();
    }

    @Override
    public V get(Object k) {
        return map.get(k);
    }

    @Override
    public boolean isEmpty() {
        return map.isEmpty();
    }

    @Override
    public Set<K> keySet() {
        return map.keySet();
    }

    @Override
    public int size() {
        return map.size();
    }

    @Override
    public Collection<V> values() {
        return map.values();
    }

    @Override
    public synchronized void clear() {
        this.map = Collections.emptyMap();
    }

    // DECISION: Write methods are synchronized to serialize mutations. The pattern is:
    // (1) copy existing map, (2) mutate copy, (3) assign new unmodifiable map to volatile field.
    // This ensures readers always see a consistent, complete snapshot.
    @Override
    public synchronized V put(K k, V v) {
        Map<K, V> copy = new HashMap<>(this.map);
        V prev = copy.put(k, v);
        this.map = Collections.unmodifiableMap(copy);
        return prev;
    }

    @Override
    public synchronized void putAll(Map<? extends K, ? extends V> entries) {
        Map<K, V> copy = new HashMap<>(this.map);
        copy.putAll(entries);
        this.map = Collections.unmodifiableMap(copy);
    }

    @Override
    public synchronized V remove(Object key) {
        Map<K, V> copy = new HashMap<>(this.map);
        V prev = copy.remove(key);
        this.map = Collections.unmodifiableMap(copy);
        return prev;
    }

    @Override
    public synchronized V putIfAbsent(K k, V v) {
        if (!containsKey(k))
            return put(k, v);
        else
            return get(k);
    }

    @Override
    public synchronized boolean remove(Object k, Object v) {
        if (containsKey(k) && get(k).equals(v)) {
            remove(k);
            return true;
        } else {
            return false;
        }
    }

    @Override
    public synchronized boolean replace(K k, V original, V replacement) {
        if (containsKey(k) && get(k).equals(original)) {
            put(k, replacement);
            return true;
        } else {
            return false;
        }
    }

    @Override
    public synchronized V replace(K k, V v) {
        if (containsKey(k)) {
            return put(k, v);
        } else {
            return null;
        }
    }

}
