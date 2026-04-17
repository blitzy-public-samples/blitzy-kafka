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
/**
 * Provides custom non-primitive types of configuration properties.
 * <strong>This package is not a supported Kafka API; the implementation may change without warning
 * between minor or patch releases.</strong>
 *
 * <p>CROSS-CUTTING: This subpackage provides specialized value wrappers for the
 * {@link org.apache.kafka.common.config.ConfigDef} type system. Currently contains
 * {@link Password} &mdash; the security-critical type that prevents credential exposure in log
 * statements, JMX attributes, {@code toString()} output, and configuration dumps. Every config
 * key declared with {@link org.apache.kafka.common.config.ConfigDef.Type#PASSWORD} stores its
 * parsed value as a {@link Password} instance.
 *
 * <p>Consumed by: {@code SslConfigs} (keystore/truststore passwords), {@code SaslConfigs}
 * (JAAS config), {@code BrokerSecurityConfigs}, Connect worker configs, and any custom
 * connector/client configuration that declares PASSWORD-typed keys.
 */
package org.apache.kafka.common.config.types;