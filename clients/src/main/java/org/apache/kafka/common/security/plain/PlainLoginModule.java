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
package org.apache.kafka.common.security.plain;

import org.apache.kafka.common.security.plain.internals.PlainSaslServerProvider;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

// SECURITY: (MEDIUM) JAAS LoginModule for SASL/PLAIN mechanism.
// Why: This module handles plaintext credential transfer into the JAAS Subject. Credentials
// stored in Subject.getPublicCredentials() (username) and Subject.getPrivateCredentials()
// (password) persist for the lifetime of the Subject and are accessible to any code with
// a reference to the Subject.
// Exploit: A malicious LoginModule loaded in the same JAAS stack could read the password from
// Subject.getPrivateCredentials(). If the Subject is inadvertently serialized or logged,
// credentials are exposed in cleartext.
// Improvement: Consider clearing credentials from the Subject on logout() rather than no-op,
// and use a dedicated credential wrapper with explicit zeroing on close.

// CROSS-CUTTING: Consumed by authenticator/SaslServerAuthenticator and
// authenticator/SaslClientAuthenticator when PLAIN mechanism is negotiated.
// Contract: This module must be specified in JAAS config for listener using PLAIN.
// Impact: If removed or misconfigured, SASL/PLAIN authentication fails at LoginContext creation.
public class PlainLoginModule implements LoginModule {

    private static final String USERNAME_CONFIG = "username";
    private static final String PASSWORD_CONFIG = "password";

    // DECISION: Static initializer registers PlainSaslServerProvider with JCA Security framework.
    // Alternatives: (1) Lazy registration on first use, (2) Explicit init call from broker startup.
    // Rationale: Static init ensures the PLAIN SASL mechanism is available before any LoginContext
    // is created, avoiding race conditions in concurrent authentication scenarios.
    // CROSS-CUTTING: Depends on plain/internals/PlainSaslServerProvider.initialize() which calls
    // java.security.Security.addProvider(). Impact: If PlainSaslServerProvider is not on classpath,
    // class loading of PlainLoginModule fails with NoClassDefFoundError.
    static {
        PlainSaslServerProvider.initialize();
    }

    // SECURITY: (MEDIUM) Credential extraction from JAAS options into Subject.
    // Why: Username is placed in publicCredentials (readable by any module); password in
    // privateCredentials (restricted by SecurityManager, if present).
    // Exploit: Without a SecurityManager (common in modern deployments), any code with Subject
    // access can call getPrivateCredentials() to retrieve the plaintext password.
    // Improvement: Wrap password in a destroyable credential object implementing
    // javax.security.auth.Destroyable for explicit lifecycle management.
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        String username = (String) options.get(USERNAME_CONFIG);
        if (username != null)
            subject.getPublicCredentials().add(username);
        String password = (String) options.get(PASSWORD_CONFIG);
        if (password != null)
            subject.getPrivateCredentials().add(password);
    }

    // DECISION: login(), commit(), logout() return true; abort() returns false.
    // Rationale: PlainLoginModule is a credential-transfer adapter, not an authenticator.
    // Actual credential validation is deferred to PlainServerCallbackHandler via SASL exchange.
    // This no-op pattern is intentional per JAAS LoginModule contract for mechanisms where
    // authentication happens outside the JAAS login phase.
    @Override
    public boolean login() {
        return true;
    }

    @Override
    public boolean logout() {
        return true;
    }

    @Override
    public boolean commit() {
        return true;
    }

    @Override
    public boolean abort() {
        return false;
    }
}
