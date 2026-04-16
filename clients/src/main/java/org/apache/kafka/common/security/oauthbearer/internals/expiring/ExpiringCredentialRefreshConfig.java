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
package org.apache.kafka.common.security.oauthbearer.internals.expiring;

import org.apache.kafka.common.config.SaslConfigs;

import java.util.Map;
import java.util.Objects;

/**
 * Immutable refresh-related configuration for expiring credentials that can be
 * parsed from a producer/consumer/broker config.
 */
// SECURITY: SEC-OAUTH-072 (MEDIUM) Configuration values directly affect token availability and refresh timing.
// Why: Refresh parameters (window factor, jitter, min period, buffer) control when tokens are
// refreshed relative to their expiry. Misconfiguration can cause premature refreshes (DoS on
// the OAuth provider) or late refreshes (expired token errors, authentication failures).
// Exploit: If an attacker modifies the SASL config (e.g., via the dynamic config API on the
// broker with ALTER_CONFIGS permission), they could set loginRefreshWindowFactor to 0.0
// (refresh immediately after obtaining token) causing a tight loop of token requests that
// DoS the OAuth provider, or set it to 1.0 (refresh exactly at expiry time) causing all
// tokens to expire before refresh completes -- resulting in cluster-wide auth failures.
// Improvement: Validate refresh parameter ranges at construction time -- reject values outside
// reasonable bounds (e.g., factor must be in [0.5, 0.95], jitter must be in [0.0, 0.25]).
// Currently, range validation is performed at a higher level by SaslConfigs ConfigDef, but
// direct construction bypassing ConfigDef (e.g., in tests) can create invalid configs.
//
// CROSS-CUTTING: Consumed by ExpiringCredentialRefreshingLogin (in this package) which uses
// these config values for refresh scheduling -- window factor, jitter, min period, and buffer
// seconds drive the refresh timestamp computation in refreshMs(). Config keys are defined in
// org.apache.kafka.common.config.SaslConfigs: SASL_LOGIN_REFRESH_WINDOW_FACTOR,
// SASL_LOGIN_REFRESH_WINDOW_JITTER, SASL_LOGIN_REFRESH_MIN_PERIOD_SECONDS,
// SASL_LOGIN_REFRESH_BUFFER_SECONDS. Changes to these config defaults in SaslConfigs affect
// all OAUTHBEARER and Kerberos refresh timing across all clients and brokers.
public class ExpiringCredentialRefreshConfig {
    // DECISION: Immutable value object constructed from a raw config map. No range validation is
    // performed here -- values are validated at a higher level by SaslConfigs ConfigDef definitions.
    // Alternative: Validate ranges in this constructor (throw IllegalArgumentException for out-of-
    // range values). Rationale: Separation of validation (ConfigDef) from storage (this class).
    // Risk: Direct construction bypassing ConfigDef (e.g., in tests or custom integrations) could
    // create configs with invalid values (e.g., negative jitter, factor > 1.0).
    private final double loginRefreshWindowFactor;
    private final double loginRefreshWindowJitter;
    private final short loginRefreshMinPeriodSeconds;
    private final short loginRefreshBufferSeconds;
    private final boolean loginRefreshReloginAllowedBeforeLogout;

    /**
     * Constructor based on producer/consumer/broker configs and the indicated value
     * for whether or not client relogin is allowed before logout
     * 
     * @param configs
     *            the mandatory (but possibly empty) producer/consumer/broker
     *            configs upon which to build this instance
     * @param clientReloginAllowedBeforeLogout
     *            if the {@code LoginModule} and {@code SaslClient} implementations
     *            support multiple simultaneous login contexts on a single
     *            {@code Subject} at the same time. If true, then upon refresh,
     *            logout will only be invoked on the original {@code LoginContext}
     *            after a new one successfully logs in. This can be helpful if the
     *            original credential still has some lifetime left when an attempt
     *            to refresh the credential fails; the client will still be able to
     *            create new connections as long as the original credential remains
     *            valid. Otherwise, if logout is immediately invoked prior to
     *            relogin, a relogin failure leaves the client without the ability
     *            to connect until relogin does in fact succeed.
     */
    public ExpiringCredentialRefreshConfig(Map<String, ?> configs, boolean clientReloginAllowedBeforeLogout) {
        Objects.requireNonNull(configs);
        // DECISION: Raw map lookups with casting to wrapper types (Double, Short) rather than using
        // a typed config accessor (e.g., AbstractConfig.getDouble()). Alternative: Accept
        // AbstractConfig instead of Map<String, ?>. Rationale: Avoids dependency on AbstractConfig
        // for this small value object, keeping it lightweight and testable with plain Maps. Risk:
        // ClassCastException or NullPointerException if the map contains wrong types or missing keys.
        this.loginRefreshWindowFactor = (Double) configs.get(SaslConfigs.SASL_LOGIN_REFRESH_WINDOW_FACTOR);
        this.loginRefreshWindowJitter = (Double) configs.get(SaslConfigs.SASL_LOGIN_REFRESH_WINDOW_JITTER);
        this.loginRefreshMinPeriodSeconds = (Short) configs.get(SaslConfigs.SASL_LOGIN_REFRESH_MIN_PERIOD_SECONDS);
        this.loginRefreshBufferSeconds = (Short) configs.get(SaslConfigs.SASL_LOGIN_REFRESH_BUFFER_SECONDS);
        this.loginRefreshReloginAllowedBeforeLogout = clientReloginAllowedBeforeLogout;
    }

    /**
     * Background login refresh thread will sleep until the specified window factor
     * relative to the credential's total lifetime has been reached, at which time
     * it will try to refresh the credential.
     * 
     * @return the login refresh window factor
     */
    public double loginRefreshWindowFactor() {
        return loginRefreshWindowFactor;
    }

    /**
     * Amount of random jitter added to the background login refresh thread's sleep
     * time.
     * 
     * @return the login refresh window jitter
     */
    public double loginRefreshWindowJitter() {
        return loginRefreshWindowJitter;
    }

    /**
     * The desired minimum time between checks by the background login refresh
     * thread, in seconds
     * 
     * @return the desired minimum refresh period, in seconds
     */
    public short loginRefreshMinPeriodSeconds() {
        return loginRefreshMinPeriodSeconds;
    }

    /**
     * The amount of buffer time before expiration to maintain when refreshing. If a
     * refresh is scheduled to occur closer to expiration than the number of seconds
     * defined here then the refresh will be moved up to maintain as much of the
     * desired buffer as possible.
     * 
     * @return the refresh buffer, in seconds
     */
    public short loginRefreshBufferSeconds() {
        return loginRefreshBufferSeconds;
    }

    /**
     * If the LoginModule and SaslClient implementations support multiple
     * simultaneous login contexts on a single Subject at the same time. If true,
     * then upon refresh, logout will only be invoked on the original LoginContext
     * after a new one successfully logs in. This can be helpful if the original
     * credential still has some lifetime left when an attempt to refresh the
     * credential fails; the client will still be able to create new connections as
     * long as the original credential remains valid. Otherwise, if logout is
     * immediately invoked prior to relogin, a relogin failure leaves the client
     * without the ability to connect until relogin does in fact succeed.
     * 
     * @return true if relogin is allowed prior to discarding an existing
     *         (presumably unexpired) credential, otherwise false
     */
    public boolean loginRefreshReloginAllowedBeforeLogout() {
        return loginRefreshReloginAllowedBeforeLogout;
    }
}
