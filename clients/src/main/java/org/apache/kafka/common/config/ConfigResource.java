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

package org.apache.kafka.common.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A class representing resources that have configs.
 *
 * @implNote DECISION: Final class with Type enum using byte IDs (power-of-2 bit flags: GROUP=32,
 * CLIENT_METRICS=16, BROKER_LOGGER=8, BROKER=4, TOPIC=2, UNKNOWN=0). Alternative: Sequential integer IDs.
 * Rationale: Power-of-2 IDs enable efficient bitmask-based filtering in IncrementalAlterConfigs requests
 * where multiple resource types can be specified simultaneously. UNKNOWN=0 is the zero value sentinel.
 */
public final class ConfigResource {

    // CROSS-CUTTING: Used by clients/admin/Admin.describeConfigs(), alterConfigs(), and
    // incrementalAlterConfigs() to identify the target resource. Also used by metadata/controller/
    // ConfigurationControlManager for config storage, and core/DynamicBrokerConfig for per-broker
    // and per-topic config management.

    /**
     * Type of resource.
     */
    public enum Type {
        GROUP((byte) 32),
        CLIENT_METRICS((byte) 16),
        BROKER_LOGGER((byte) 8),
        BROKER((byte) 4),
        TOPIC((byte) 2),
        UNKNOWN((byte) 0);

        // DECISION: Eagerly-built unmodifiable ID→Type lookup map. Uses UNKNOWN as default for
        // unrecognized IDs (forId returns UNKNOWN) for forward-compatible protocol handling.
        private static final Map<Byte, Type> TYPES = Collections.unmodifiableMap(
            Arrays.stream(values()).collect(Collectors.toMap(Type::id, Function.identity()))
        );

        private final byte id;

        Type(final byte id) {
            this.id = id;
        }

        public byte id() {
            return id;
        }

        public static Type forId(final byte id) {
            return TYPES.getOrDefault(id, UNKNOWN);
        }
    }

    private final Type type;
    private final String name;

    /**
     * Create an instance of this class with the provided parameters.
     *
     * @param type a non-null resource type
     * @param name a non-null resource name
     */
    public ConfigResource(Type type, String name) {
        Objects.requireNonNull(type, "type should not be null");
        Objects.requireNonNull(name, "name should not be null");
        this.type = type;
        this.name = name;
    }

    /**
     * Return the resource type.
     */
    public Type type() {
        return type;
    }

    /**
     * Return the resource name.
     */
    public String name() {
        return name;
    }

    /**
     * Returns true if this is the default resource of a resource type.
     * Resource name is empty for the default resource.
     */
    // DECISION: Default resource is identified by empty name string rather than a null or sentinel.
    // Alternative: Null name. Rationale: Empty string is a valid, non-null key for Map operations.
    public boolean isDefault() {
        return name.isEmpty();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        ConfigResource that = (ConfigResource) o;

        return type == that.type && name.equals(that.name);
    }

    @Override
    public int hashCode() {
        int result = type.hashCode();
        result = 31 * result + name.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "ConfigResource(type=" + type + ", name='" + name + "')";
    }
}
