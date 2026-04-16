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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A wrapper for Thread that sets things up nicely
 */
// DECISION: Thread subclass with daemon flag and UncaughtExceptionHandler. Alternative: Use
// ThreadFactory from java.util.concurrent. Rationale: KafkaThread provides a single point for
// (1) consistent thread naming (prefix-based for log correlation), (2) daemon flag control
// (daemon=true for background threads that shouldn't prevent JVM shutdown), and (3) centralized
// uncaught exception logging to prevent silent thread death. All Kafka background threads
// (heartbeat, sender, fetcher, cleaner) are KafkaThread instances.
// CROSS-CUTTING: Factory for all Kafka background threads. Used by Sender (producer I/O),
// Fetcher (consumer I/O), Heartbeat, Cleaner (log compaction), and controller event threads.
// Thread names follow the pattern "[clientId]-[role]" for operational observability.
public class KafkaThread extends Thread {

    private static final Logger log = LoggerFactory.getLogger(KafkaThread.class);
    
    public static KafkaThread daemon(final String name, Runnable runnable) {
        return new KafkaThread(name, runnable, true);
    }

    public static KafkaThread nonDaemon(final String name, Runnable runnable) {
        return new KafkaThread(name, runnable, false);
    }

    @SuppressWarnings("this-escape")
    public KafkaThread(final String name, boolean daemon) {
        super(name);
        configureThread(name, daemon);
    }

    @SuppressWarnings("this-escape")
    public KafkaThread(final String name, Runnable runnable, boolean daemon) {
        super(runnable, name);
        configureThread(name, daemon);
    }

    private void configureThread(final String name, boolean daemon) {
        setDaemon(daemon);
        // DECISION: Logs uncaught exceptions rather than swallowing them. The JVM default behavior for
        // uncaught exceptions is to print to stderr, which may be lost in container environments.
        // Logging through SLF4J ensures exceptions are captured by the configured logging framework.
        setUncaughtExceptionHandler((t, e) -> log.error("Uncaught exception in thread '{}':", name, e));
    }

}
