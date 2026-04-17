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
package org.apache.kafka.common.config.types;

/**
 * A wrapper class for passwords to hide them while logging a config.
 *
 * <p>SECURITY: Password.toString() is the primary defense against credential leakage in Kafka.
 * Every config key declared with {@link org.apache.kafka.common.config.ConfigDef.Type#PASSWORD}
 * stores its parsed value as a Password instance. When any code path implicitly stringifies a
 * config value (logging, exception messages, JMX attributes, toString() dumps), this class
 * returns {@link #HIDDEN} instead of the actual secret.
 *
 * <p>Risk: If a developer mistakenly uses {@link #value()} in a log statement instead of
 * relying on {@code toString()}, credentials will be exposed in plaintext. A bad actor with
 * access to log files, JMX endpoints, or monitoring dashboards could harvest exposed credentials
 * to gain unauthorized access to Kafka brokers, keystores, or external authentication systems.
 *
 * <p>Mitigation: All Kafka logging paths use {@code toString()} by convention.
 * {@link org.apache.kafka.common.config.ConfigDef} also masks Password defaults in
 * documentation output via {@code getConfigValue()}.
 *
 * <p>CROSS-CUTTING: Password is the value type for
 * {@link org.apache.kafka.common.config.ConfigDef.Type#PASSWORD}. Used by: SslConfigs
 * (keystore/truststore passwords), SaslConfigs (JAAS config), BrokerSecurityConfigs,
 * Connect worker configs for credential fields, and any custom config declaring PASSWORD-typed
 * keys. {@link org.apache.kafka.common.config.AbstractConfig} logAll() relies on
 * Password.toString() returning HIDDEN to safely log all config values at INFO level.
 */
public class Password {

    // DECISION: Public sentinel constant rather than a private implementation detail.
    // Alternative: Private constant with a static method isHidden(String). Rationale: HIDDEN is
    // used by external callers (e.g., ConfigCommand in tools/, Connect REST config API) to detect
    // redacted output and avoid displaying "[hidden]" as if it were a real password value.
    public static final String HIDDEN = "[hidden]";

    private final String value;

    /**
     * Construct a new Password object
     * @param value The value of a password
     */
    public Password(String value) {
        this.value = value;
    }

    // DECISION: hashCode() delegates to the actual password value, not the HIDDEN constant.
    // Alternative: Use HIDDEN.hashCode() (all Password instances hash identically). Rationale:
    // Delegating to the real value enables correct HashMap/HashSet behavior for Password-valued
    // configs — e.g., DynamicBrokerConfig can detect config changes by comparing old vs. new
    // Password instances in a Set.
    @Override
    public int hashCode() {
        return value.hashCode();
    }

    // DECISION: equals() compares actual password values, not the hidden representation.
    // Alternative: All Password instances are equal (since toString() is identical). Rationale:
    // Value-based equality enables config change detection — e.g., SslFactory checks if a new
    // SSL keystore password differs from the current one to determine if certificate rotation
    // requires an SSLContext rebuild.
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Password))
            return false;
        Password other = (Password) obj;
        return value.equals(other.value);
    }

    /**
     * Returns hidden password string
     *
     * @return hidden password string
     */
    // SECURITY: toString() always returns HIDDEN — this is the critical security contract.
    // Any implicit stringification (logging, JMX, exception messages) sees "[hidden]" instead
    // of the actual secret. This prevents credential leakage through log aggregation systems,
    // monitoring dashboards, or error reporting tools.
    // Improvement: Consider adding a static analysis rule (e.g., ErrorProne check) that flags
    // direct usage of Password.value() in logging contexts.
    @Override
    public String toString() {
        return HIDDEN;
    }

    /**
     * Returns real password string
     *
     * @return real password string
     */
    // SECURITY: value() exposes the raw secret — callers MUST ensure this is never passed to
    // logging, toString(), or any output channel. Legitimate uses: SSL/SASL subsystems that need
    // the actual credential for authentication handshakes (e.g., SslFactory configuring
    // KeyManagerFactory, ScramFormatter computing PBKDF2 derived keys).
    public String value() {
        return value;
    }
}
