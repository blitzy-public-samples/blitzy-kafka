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

import java.util.concurrent.ThreadLocalRandom;

/**
 * A utility class for keeping the parameters and providing the value of exponential
 * retry backoff, exponential reconnect backoff, exponential timeout, etc.
 * <p>
 * The formula is:
 * <pre>Backoff(attempts) = random(1 - jitter, 1 + jitter) * initialInterval * multiplier ^ attempts</pre>
 * If {$code maxInterval} is less that {@code initialInterval}, a constant backoff of
 * {@code maxInterval} will be provided. The jitter will never cause the backoff to exceed
 * {@code maxInterval}.
 * <p>
 * This class is thread-safe.
 */
// DECISION: Immutable, thread-safe jittered exponential backoff. Alternative: Mutable backoff
// with internal attempt counter. Rationale: Immutable design allows a single ExponentialBackoff
// instance to be shared across multiple threads/connections — each caller tracks its own attempt
// count. The jitter factor prevents thundering herd when multiple clients reconnect simultaneously.
//
// CROSS-CUTTING: Used by ClusterConnectionStates for connection retry backoff, by
// ConsumerCoordinator for rebalance retry, by TransactionManager for transaction retry,
// and by Metadata for metadata refresh backoff. The same instance is shared across all
// connections managed by a single NetworkClient.
public class ExponentialBackoff {
    private final long initialInterval;
    private final int multiplier;
    private final long maxInterval;
    private final double jitter;
    private final double expMax;

    // DECISION: Pre-computes expMax (maximum useful exponent) to avoid expensive Math.pow() for
    // attempts beyond the cap. When initialInterval * multiplier^attempts >= maxInterval, further
    // exponentiation is unnecessary — expMax short-circuits the computation.
    public ExponentialBackoff(long initialInterval, int multiplier, long maxInterval, double jitter) {
        this.initialInterval = Math.min(maxInterval, initialInterval);
        this.multiplier = multiplier;
        this.maxInterval = maxInterval;
        this.jitter = jitter;
        this.expMax = maxInterval > initialInterval ?
                Math.log(maxInterval / (double) Math.max(initialInterval, 1)) / Math.log(multiplier) : 0;
    }

    public long initialInterval() {
        return initialInterval;
    }

    // DECISION: Uses ThreadLocalRandom for jitter instead of Math.random(). Alternative:
    // SecureRandom. Rationale: Backoff jitter is not security-sensitive — ThreadLocalRandom
    // provides much lower contention than shared Random/SecureRandom instances, critical when
    // hundreds of connections compute backoff simultaneously during a broker failure.
    public long backoff(long attempts) {
        if (expMax == 0) {
            return initialInterval;
        }
        double exp = Math.min(attempts, this.expMax);
        double term = initialInterval * Math.pow(multiplier, exp);
        double randomFactor = jitter < Double.MIN_NORMAL ? 1.0 :
            ThreadLocalRandom.current().nextDouble(1 - jitter, 1 + jitter);
        long backoffValue = (long) (randomFactor * term);
        // DECISION: Final cap at maxInterval ensures jitter cannot push backoff above the configured
        // maximum. Without this, a jitter of 1.0+ could produce backoff exceeding maxInterval.
        return Math.min(backoffValue, maxInterval);
    }

    @Override
    public String toString() {
        return "ExponentialBackoff{" +
                "multiplier=" + multiplier +
                ", expMax=" + expMax +
                ", initialInterval=" + initialInterval +
                ", jitter=" + jitter +
                '}';
    }
}
