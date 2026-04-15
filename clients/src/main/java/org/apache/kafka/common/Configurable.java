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

import java.util.Map;

/**
 * A Mix-in style interface for classes that are instantiated by reflection and need to take configuration parameters
 *
 * @implNote DECISION: Single-method mixin interface for reflection-based plugin initialization.
 * Alternative: Constructor injection or builder pattern. Rationale: Kafka plugins (serializers,
 * partitioners, interceptors, reporters) are instantiated via Class.forName().newInstance() which
 * requires a no-arg constructor — configure(Map) provides a uniform post-construction
 * initialization contract compatible with this reflection pattern. {@code Map<String,?>}
 * parameter type allows mixed value types without type-specific methods.
 */
// CROSS-CUTTING: Foundational plugin contract implemented by 50+ classes across all modules:
// Serializer, Deserializer, Partitioner, ProducerInterceptor, ConsumerInterceptor,
// MetricsReporter, Authorizer, SslEngineFactory, KafkaPrincipalBuilder, ConnectRestExtension,
// and all MessageFormatter implementations. Extended by Reconfigurable for hot-reload support.
public interface Configurable {

    /**
     * Configure this class with the given key-value pairs
     */
    void configure(Map<String, ?> configs);

}
