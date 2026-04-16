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

import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;

/**
 * An interface for scheduling tasks for the future.
 *
 * Implementations of this class should be thread-safe.
 */
// DECISION: Separated scheduling concern from time-keeping (Time) to allow independent test
// substitution. Alternative: Combine scheduling into the Time interface. Rationale: Scheduling
// requires a ScheduledExecutorService (heavyweight), whereas Time is lightweight and widely used.
// Keeping them separate allows MockTime without requiring a mock executor for every test.
//
// CROSS-CUTTING: Used by core/DynamicBrokerConfig for scheduling delayed config reconfiguration
// tasks. SystemScheduler is the sole production implementation; test code can substitute a mock
// that executes scheduled callables immediately for deterministic testing.
public interface Scheduler {
    // DECISION: Companion singleton like Time.SYSTEM. Uses SystemScheduler which delegates to
    // ScheduledExecutorService.schedule() with real wall-clock delays.
    Scheduler SYSTEM = new SystemScheduler();

    /**
     * Get the timekeeper associated with this scheduler.
     */
    Time time();

    /**
     * Schedule a callable to be executed in the future on a
     * ScheduledExecutorService.  Note that the Callable may not be queued on
     * the executor until the designated time arrives.
     *
     * @param executor      The executor to use.
     * @param callable      The callable to execute.
     * @param delayMs       The delay to use, in milliseconds.
     * @param <T>           The return type of the callable.
     * @return              A future which will complete when the callable is finished.
     */
    <T> Future<T> schedule(final ScheduledExecutorService executor,
                           final Callable<T> callable, long delayMs);
}
