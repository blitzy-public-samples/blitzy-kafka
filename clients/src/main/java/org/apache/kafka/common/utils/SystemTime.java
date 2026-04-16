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

import org.apache.kafka.common.errors.TimeoutException;

import java.util.function.Supplier;

/**
 * A time implementation that uses the system clock and sleep call. Use `Time.SYSTEM` instead of creating an instance
 * of this class.
 */
// DECISION: Package-private singleton pattern — only accessible via Time.SYSTEM.
// Alternative: Public class with public constructor. Rationale: Singleton enforces that there
// is exactly one system time instance, preventing confusion from multiple instances. Package-
// private visibility forces all callers to use the Time.SYSTEM constant, ensuring consistent
// time abstraction usage across the codebase.
//
// CROSS-CUTTING: The sole production Time implementation. Transitively used by every Kafka
// client (KafkaProducer, KafkaConsumer, KafkaAdminClient) via Time.SYSTEM. Test code uses
// MockTime instead. Contract: milliseconds() returns wall-clock; nanoseconds() returns
// monotonic time. See Time.java for the abstraction contract.
class SystemTime implements Time {
    // DECISION: Eager initialization rather than lazy (no double-checked locking needed).
    // Rationale: SystemTime is stateless — eager init is safe and avoids synchronization overhead.
    private static final SystemTime SYSTEM_TIME = new SystemTime();

    public static SystemTime getSystemTime() {
        return SYSTEM_TIME;
    }

    // DECISION: Delegates to System.currentTimeMillis() (wall clock) for timestamps.
    // Alternative: System.nanoTime() converted to millis. Rationale: wall-clock time is needed
    // for protocol timeouts, expiry calculations, and log timestamps that must be comparable
    // across JVMs. nanoTime() is only monotonic within a single JVM.
    @Override
    public long milliseconds() {
        return System.currentTimeMillis();
    }

    // DECISION: Delegates to System.nanoTime() for monotonic high-resolution timing.
    // Used by Timer for deadline tracking where monotonicity is required.
    @Override
    public long nanoseconds() {
        return System.nanoTime();
    }

    @Override
    public void sleep(long ms) {
        Utils.sleep(ms);
    }

    // DECISION: Spin-wait loop with obj.wait(deadline - current) rather than a single wait().
    // Rationale: Object.wait() can wake spuriously — the loop ensures the condition is
    // re-checked and the deadline is re-evaluated after each wakeup. Throws TimeoutException
    // (Kafka's, not java.util.concurrent's) for consistency with client timeout handling.
    @Override
    public void waitObject(Object obj, Supplier<Boolean> condition, long deadlineMs) throws InterruptedException {
        synchronized (obj) {
            while (true) {
                if (condition.get())
                    return;

                long currentTimeMs = milliseconds();
                if (currentTimeMs >= deadlineMs)
                    throw new TimeoutException("Condition not satisfied before deadline");

                obj.wait(deadlineMs - currentTimeMs);
            }
        }
    }

    private SystemTime() {

    }
}
