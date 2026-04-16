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

import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

/**
 * An interface abstracting the clock to use in unit testing classes that make use of clock time.
 *
 * Implementations of this class should be thread-safe.
 */
// DECISION: Time abstraction for testability. Alternative: Call System.currentTimeMillis()
// and System.nanoTime() directly. Rationale: Direct system calls make deterministic testing
// impossible — MockTime allows tests to control clock progression, deadlines, and timeouts
// without real-time delays. This is critical for testing timeout-sensitive paths in consumer
// poll loops, producer batching, and coordinator heartbeats.
// CROSS-CUTTING: Foundational abstraction consumed by virtually every Kafka component:
// KafkaProducer, KafkaConsumer, KafkaAdminClient, NetworkClient, Selector, all coordinator
// implementations, StreamThread, Worker, and broker server classes. MockTime (in test scope)
// is the primary test implementation. SystemTime is the sole production implementation.
public interface Time {

    // DECISION: Eager singleton via SystemTime.getSystemTime() rather than lazy initialization.
    // Rationale: Time.SYSTEM is accessed on every client/broker instantiation — eager init avoids
    // synchronization overhead. The package-private SystemTime prevents direct construction.
    Time SYSTEM = SystemTime.getSystemTime();

    /**
     * Returns the current time in milliseconds.
     */
    // DECISION: Wall-clock time for timestamps written to records and logs. Not monotonic — subject
    // to NTP adjustments. Use nanoseconds() for measuring elapsed time intervals.
    long milliseconds();

    /**
     * Returns the value returned by `nanoseconds` converted into milliseconds.
     */
    // DECISION: Converts nanoseconds() to millis. Useful when a monotonic clock is needed but the
    // API contract requires millisecond granularity (e.g., JMX metrics reporting).
    default long hiResClockMs() {
        return TimeUnit.NANOSECONDS.toMillis(nanoseconds());
    }

    /**
     * Returns the current value of the running JVM's high-resolution time source, in nanoseconds.
     *
     * <p>This method can only be used to measure elapsed time and is
     * not related to any other notion of system or wall-clock time.
     * The value returned represents nanoseconds since some fixed but
     * arbitrary <i>origin</i> time (perhaps in the future, so values
     * may be negative).  The same origin is used by all invocations of
     * this method in an instance of a Java virtual machine; other
     * virtual machine instances are likely to use a different origin.
     */
    // DECISION: Monotonic high-resolution timer for elapsed time measurement. Used by Timer, backoff
    // calculations, and waitForFuture deadline tracking. Unlike milliseconds(), immune to clock drift.
    long nanoseconds();

    /**
     * Sleep for the given number of milliseconds
     */
    void sleep(long ms);

    /**
     * Wait for a condition using the monitor of a given object. This avoids the implicit
     * dependence on system time when calling {@link Object#wait()}.
     *
     * @param obj The object that will be waited with {@link Object#wait()}. Note that it is the responsibility
     *      of the caller to call notify on this object when the condition is satisfied.
     * @param condition The condition we are awaiting
     * @param deadlineMs The deadline timestamp at which to raise a timeout error
     *
     * @throws org.apache.kafka.common.errors.TimeoutException if the timeout expires before the condition is satisfied
     */
    // DECISION: Deadline-based wait abstraction. Alternative: Raw Object.wait(timeout). Rationale:
    // Object.wait(timeout) relies on wall-clock time which can drift. This method uses the Time
    // abstraction's deadline, enabling MockTime to advance and unblock waiters deterministically.
    void waitObject(Object obj, Supplier<Boolean> condition, long deadlineMs) throws InterruptedException;

    /**
     * Get a timer which is bound to this time instance and expires after the given timeout
     */
    // DECISION: Factory methods binding Timer to this Time instance. Ensures Timer uses the same
    // clock source (real or mock) as the caller, preventing clock skew in tests.
    default Timer timer(long timeoutMs) {
        return new Timer(this, timeoutMs);
    }

    /**
     * Get a timer which is bound to this time instance and expires after the given timeout
     */
    default Timer timer(Duration timeout) {
        return timer(timeout.toMillis());
    }

    /**
     * Wait for a future to complete, or time out.
     *
     * @param future        The future to wait for.
     * @param deadlineNs    The time in the future, in monotonic nanoseconds, to time out.
     * @return              The result of the future.
     * @param <T>           The type of the future.
     */
    // DECISION: Retry loop on TimeoutException rather than single-shot Future.get(). Rationale:
    // Some Future implementations may throw spurious TimeoutException if the deadline calculation
    // has nanosecond precision rounding. The retry loop re-checks the deadline with a fresh
    // nanoseconds() call, avoiding false timeouts from clock granularity.
    default <T> T waitForFuture(
        Future<T> future,
        long deadlineNs
    ) throws TimeoutException, InterruptedException, ExecutionException  {
        TimeoutException timeoutException = null;
        while (true) {
            long nowNs = nanoseconds();
            if (deadlineNs <= nowNs) {
                throw (timeoutException == null) ? new TimeoutException() : timeoutException;
            }
            long deltaNs = deadlineNs - nowNs;
            try {
                return future.get(deltaNs, TimeUnit.NANOSECONDS);
            } catch (TimeoutException t) {
                timeoutException = t;
            }
        }
    }
}
