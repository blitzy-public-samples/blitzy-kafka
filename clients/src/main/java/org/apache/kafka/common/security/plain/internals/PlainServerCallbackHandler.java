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

package org.apache.kafka.common.security.plain.internals;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.apache.kafka.common.security.plain.PlainLoginModule;
import org.apache.kafka.common.utils.Utils;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

// SECURITY: (MEDIUM) Server-side credential validation handler for SASL/PLAIN.
// Why: This handler validates received plaintext credentials against expected credentials
// stored in JAAS configuration entries. Credentials are compared using constant-time
// Utils.isEqualConstantTime() in authenticate(), correctly preventing timing side-channel attacks.
// Exploit: If the JAAS config file (containing user_<username>=<password> entries) has
// incorrect permissions, an attacker with filesystem access can read all plaintext passwords.
// The JAAS_USER_PREFIX pattern means passwords are stored as configuration values.
// Improvement: Consider supporting external credential stores (LDAP, database) as an
// alternative to JAAS file-based passwords for production deployments.
//
// CROSS-CUTTING: Implements auth/AuthenticateCallbackHandler interface.
// Depends on plain/PlainAuthenticateCallback (reads password(), sets authenticated()),
// JaasContext.configEntryOption() for credential lookup, and PlainLoginModule (JAAS config
// entry class name filter).
// Consumed by: authenticator/SaslServerAuthenticator when handling PLAIN mechanism callbacks.
// Contract: JAAS config must contain entries matching PlainLoginModule with
// user_<username>=<password> options.
// Impact: If JAAS entries are misconfigured, all PLAIN authentications fail silently
// (authenticate() returns false).
public class PlainServerCallbackHandler implements AuthenticateCallbackHandler {

    // DECISION: Uses "user_" prefix convention for JAAS option keys (e.g., user_admin=password).
    // Alternatives: (1) Separate credential file, (2) LDAP lookup, (3) Database-backed store.
    // Rationale: Consistent with ZooKeeper Digest-MD5 convention and keeps credential
    // configuration co-located with JAAS module configuration for simplicity.
    private static final String JAAS_USER_PREFIX = "user_";
    private List<AppConfigurationEntry> jaasConfigEntries;

    @Override
    public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        this.jaasConfigEntries = jaasConfigEntries;
    }

    // DECISION: Processes callbacks in array order, expecting NameCallback before
    // PlainAuthenticateCallback.
    // Rationale: The SASL framework guarantees callback ordering from
    // PlainSaslServer.evaluateResponse() which creates [NameCallback, PlainAuthenticateCallback]
    // in that order.
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        String username = null;
        for (Callback callback: callbacks) {
            if (callback instanceof NameCallback)
                username = ((NameCallback) callback).getDefaultName();
            else if (callback instanceof PlainAuthenticateCallback) {
                PlainAuthenticateCallback plainCallback = (PlainAuthenticateCallback) callback;
                boolean authenticated = authenticate(username, plainCallback.password());
                plainCallback.authenticated(authenticated);
            } else
                throw new UnsupportedCallbackException(callback);
        }
    }

    // SECURITY: (MEDIUM) Uses Utils.isEqualConstantTime() for constant-time password comparison.
    // Why: Prevents timing side-channel attacks where an attacker measures response time
    // differences to deduce password characters one by one.
    // Note: This is correctly implemented -- the constant-time comparison does NOT short-circuit
    // on the first mismatched character.
    protected boolean authenticate(String username, char[] password) throws IOException {
        if (username == null)
            return false;
        else {
            String expectedPassword = JaasContext.configEntryOption(jaasConfigEntries,
                    JAAS_USER_PREFIX + username,
                    PlainLoginModule.class.getName());
            return expectedPassword != null && Utils.isEqualConstantTime(password, expectedPassword.toCharArray());
        }
    }

    @Override
    public void close() throws KafkaException {
    }

}
