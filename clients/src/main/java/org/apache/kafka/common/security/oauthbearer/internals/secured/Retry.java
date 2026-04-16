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

package org.apache.kafka.common.security.oauthbearer.internals.secured;

import org.apache.kafka.common.utils.Time;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;

/**
 * Retry encapsulates the mechanism to perform a retry and then exponential
 * backoff using provided wait times between attempts.
 *
 * @param <R> Result type
 */

// DECISION: Simple retry loop with Thread.sleep() rather than ScheduledExecutorService.
// Alternatives: (1) ScheduledExecutorService for async retry, (2) Resilience4j or
// Failsafe library for retry + circuit breaker. Rationale: The OAUTHBEARER token retrieval
// and JWKS refresh are synchronous operations running in dedicated threads (Login thread for
// token retrieval, ScheduledExecutorService thread for JWKS refresh). Thread.sleep() via
// Time.sleep() is the simplest blocking retry that avoids additional thread pool overhead.
// Time abstraction enables deterministic testing. Risk: Thread.sleep() blocks the calling
// thread — acceptable for dedicated threads, but would be problematic on Kafka network threads.

// CROSS-CUTTING: Used by HttpJwtRetriever (token endpoint HTTP calls) and RefreshingHttpsJwks
// (JWKS endpoint refresh). Depends on: Time (testable clock + sleep), Retryable (operation
// interface), UnretryableException (short-circuit signal). No external library dependency.
// Contract: execute() blocks until success, unretryable error, or timeout. Thread-safe —
// no shared state between execute() calls (each creates its own retry state).
// Impact: Changes to backoff timing or retry classification affect all HTTP-based OAuth
// operations (token retrieval and JWKS refresh).
public class Retry<R> {

    private static final Logger log = LoggerFactory.getLogger(Retry.class);

    private final Time time;

    private final long retryBackoffMs;

    private final long retryBackoffMaxMs;

    public Retry(long retryBackoffMs, long retryBackoffMaxMs) {
        this(Time.SYSTEM, retryBackoffMs, retryBackoffMaxMs);
    }

    public Retry(Time time, long retryBackoffMs, long retryBackoffMaxMs) {
        this.time = time;
        this.retryBackoffMs = retryBackoffMs;
        this.retryBackoffMaxMs = retryBackoffMaxMs;

        if (this.retryBackoffMs < 0)
            throw new IllegalArgumentException(String.format("retryBackoffMs value (%d) must be non-negative", retryBackoffMs));

        if (this.retryBackoffMaxMs < 0)
            throw new IllegalArgumentException(String.format("retryBackoffMaxMs value (%d) must be non-negative", retryBackoffMaxMs));

        if (this.retryBackoffMaxMs < this.retryBackoffMs)
            throw new IllegalArgumentException(String.format("retryBackoffMaxMs value (%d) is less than retryBackoffMs value (%d)", retryBackoffMaxMs, retryBackoffMs));
    }

    // COMPLEXITY: 44 lines — Retry loop with exponential backoff and exception classification.
    // Structure: (1) Calculate endMs = now + retryBackoffMaxMs (line 64). (2) While loop
    // checking time <= endMs (line 68). (3) Call retryable.call() — on success, return
    // immediately (line 72). (4) UnretryableException → capture error, break immediately
    // (lines 73-79). (5) ExecutionException → log warning, compute exponential backoff
    // waitMs = backoffMs * 2^(attempt-1) capped at remaining time (lines 86-88), sleep if
    // waitMs > 0 else break (lines 90-98). (6) After loop, throw captured error or synthetic
    // IllegalStateException (lines 101-105). Key branches: success return, unretryable break,
    // retryable with sleep, retryable with timeout break. Exit: return R, throw ExecutionException.
    public R execute(Retryable<R> retryable) throws ExecutionException {
        // DECISION: retryBackoffMaxMs is used as the TOTAL retry window (endMs = now + maxMs), not
        // as the maximum single-backoff duration. Alternative: Use maxMs as the cap for individual
        // sleep durations. Rationale: Total window provides a hard upper bound on retry duration,
        // which is important for token retrieval during login (the Login thread blocks until success
        // or exhaustion). Constructor validates maxMs >= backoffMs to prevent impossible configurations.
        long endMs = time.milliseconds() + retryBackoffMaxMs;
        int currAttempt = 0;
        ExecutionException error = null;

        while (time.milliseconds() <= endMs) {
            currAttempt++;

            try {
                return retryable.call();
            } catch (UnretryableException e) {
                // We've deemed this error to not be worth retrying, so collect the error and
                // fail immediately.
                if (error == null)
                    error = new ExecutionException(e);

                break;
            } catch (ExecutionException e) {
                log.warn("Error during retry attempt {}", currAttempt, e);

                if (error == null)
                    error = e;

                // DECISION: Exponential backoff: waitMs = retryBackoffMs * 2^(attempt-1), capped at
                // remaining time (endMs - current). Alternative: (1) Fixed delay, (2) Jittered backoff
                // (add random component). Rationale: Exponential backoff reduces load on failing endpoints.
                // No jitter is applied — in a cluster with many clients, all clients may retry simultaneously
                // (thundering herd). Risk: Without jitter, correlated retries can overwhelm the OAuth provider.
                // Consider adding jitter in a future enhancement.
                long waitMs = retryBackoffMs * (long) Math.pow(2, currAttempt - 1);
                long diff = endMs - time.milliseconds();
                waitMs = Math.min(waitMs, diff);

                if (waitMs <= 0)
                    break;

                String message = String.format("Attempt %d to make call resulted in an error; sleeping %d ms before retrying",
                    currAttempt, waitMs);
                log.warn(message, e);

                time.sleep(waitMs);
            }
        }

        if (error == null)
            // Really shouldn't ever get to here, but...
            error = new ExecutionException(new IllegalStateException("Exhausted all retry attempts but no attempt returned value or encountered exception"));

        throw error;
    }

}
