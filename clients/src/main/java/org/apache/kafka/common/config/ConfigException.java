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

import org.apache.kafka.common.KafkaException;

/**
 * Thrown if the user supplies an invalid configuration
 *
 * @implNote CROSS-CUTTING: Thrown by ConfigDef.parseType(), ConfigDef.parse(), AbstractConfig constructor,
 * and all ConfigProvider implementations when configuration values are invalid. Caught by config validation
 * frameworks across all Kafka modules (ProducerConfig, ConsumerConfig, StreamsConfig, etc.).
 * Extends KafkaException (unchecked) — callers handle via try-catch or let it propagate as a startup failure.
 */
public class ConfigException extends KafkaException {

    private static final long serialVersionUID = 1L;

    public ConfigException(String message) {
        super(message);
    }

    public ConfigException(String name, Object value) {
        this(name, value, null);
    }

    // DECISION: Three constructor overloads provide structured error messages with config name+value context.
    // Alternative: Single constructor with formatted string. Rationale: Structured constructors enforce
    // consistent error message format "Invalid value X for configuration Y: Z" across all config validation.
    public ConfigException(String name, Object value, String message) {
        super("Invalid value " + value + " for configuration " + name + (message == null ? "" : ": " + message));
    }

}
