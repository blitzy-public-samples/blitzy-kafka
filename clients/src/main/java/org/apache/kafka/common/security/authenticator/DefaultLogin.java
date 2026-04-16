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
package org.apache.kafka.common.security.authenticator;

// DECISION: Separate DefaultLogin (no-refresh) from KerberosLogin (TGT refresh) and
// OAuthBearerRefreshingLogin (token refresh). Alternative: Single Login class with
// conditional refresh logic. Rationale: PLAIN and SCRAM authenticate once and credential
// refresh is unnecessary — a no-op implementation avoids background threads and complexity.
// The "kafka" service name is the standard JAAS application name for Kafka.
//
// CROSS-CUTTING: Extends AbstractLogin (this package). Used as the default Login
// implementation when no mechanism-specific login class is configured. Selected by
// LoginManager.acquireLoginManager() when SaslConfigs.SASL_LOGIN_CLASS is not set
// and the mechanism is not OAUTHBEARER (which defaults to OAuthBearerRefreshingLogin).
// Depended on by: LoginManager (login instance creation for PLAIN, SCRAM mechanisms).
/**
 * Default non-refreshing {@link Login} implementation for mechanisms that do not
 * require credential refresh (e.g., PLAIN, SCRAM).
 *
 * @implSpec SECURITY: (LOW) Default non-refreshing login implementation. close() is
 * a no-op, meaning the JAAS Subject and its credentials persist in memory until the
 * LoginManager releases its reference and the Login is garbage collected. For PLAIN
 * mechanism, this means the plaintext password stored in the Subject's private
 * credentials remains in heap memory for the connection's lifetime.
 * Improvement: Consider overriding close() to explicitly clear the Subject's private
 * credentials (Subject.getPrivateCredentials().clear()) to minimize credential exposure.
 */
public class DefaultLogin extends AbstractLogin {

    @Override
    public String serviceName() {
        return "kafka";
    }

    @Override
    public void close() {
    }
}
