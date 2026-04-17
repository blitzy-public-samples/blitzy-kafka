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

import java.util.List;
import java.util.Locale;

/**
 * Describes whether the server should require or request client authentication.
 *
 * @implNote DECISION: Three-value enum (REQUIRED, REQUESTED, NONE) maps directly to the javax.net.ssl SSLEngine
 * client authentication modes. Alternative: Boolean (require/no). Rationale: REQUESTED mode enables optional
 * mTLS where the server accepts but does not mandate client certificates — useful for mixed environments
 * during mTLS rollout. NONE disables client auth entirely.
 */
public enum SslClientAuth {
    // CROSS-CUTTING: Used by SslConfigs.SSL_CLIENT_AUTH_CONFIG, BrokerSecurityConfigs, and
    // SslFactory to configure javax.net.ssl.SSLEngine.setNeedClientAuth()/setWantClientAuth().
    REQUIRED,
    REQUESTED,
    NONE;

    public static final List<SslClientAuth> VALUES = List.of(SslClientAuth.values());

    // DECISION: Locale.ROOT for case-insensitive parsing prevents locale-dependent behavior
    // (e.g., Turkish-I problem). Returns null for unrecognized values rather than throwing —
    // caller is responsible for handling null (see BrokerSecurityConfigs validation).
    public static SslClientAuth forConfig(String key) {
        if (key == null) {
            return SslClientAuth.NONE;
        }
        String upperCaseKey = key.toUpperCase(Locale.ROOT);
        for (SslClientAuth auth : VALUES) {
            if (auth.name().equals(upperCaseKey)) {
                return auth;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return super.toString().toLowerCase(Locale.ROOT);
    }
}
