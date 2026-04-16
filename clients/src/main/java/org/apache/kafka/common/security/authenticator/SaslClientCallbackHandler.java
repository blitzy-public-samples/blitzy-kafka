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

import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.internals.SecurityManagerCompatibility;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.auth.SaslExtensionsCallback;
import org.apache.kafka.common.security.scram.ScramExtensionsCallback;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;

import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

/**
 * Default callback handler for Sasl clients. The callbacks required for the SASL mechanism
 * configured for the client should be supported by this callback handler. See
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/sasl/sasl-refguide.html">Java SASL API</a>
 * for the list of SASL callback handlers required for each SASL mechanism.
 *
 * For adding custom SASL extensions, a {@link SaslExtensions} may be added to the subject's public credentials
 *
 * @implSpec SECURITY: SEC-SASL-028 (MEDIUM) Client-side SASL callback handler receives and dispatches
 * Why: Callback handler processes credential requests during
 * SASL authentication, handling sensitive auth material.
 * credential callbacks from the JAAS/SASL framework. This handler extracts plaintext
 * credentials (username from public credentials, password from private credentials) from
 * the current JAAS Subject and passes them to the SASL mechanism.
 * Exploit: (1) Credential scope leakage -- if a callback handler retains references to
 * credentials beyond the mechanism scope, they persist in memory longer than necessary.
 * This handler does not retain references (credentials are extracted per-callback).
 * (2) Debug logging -- if SLF4J logging is at TRACE level and a custom callback handler
 * logs callback arguments, plaintext passwords could appear in log files.
 * Improvement: Consider zeroing the password char[] after SASL mechanism consumption
 * to minimize the time credentials exist in memory.
 */
// CROSS-CUTTING: Used by SaslClientAuthenticator for client-side credential provisioning
// during SASL exchange. Depends on: auth/AuthenticateCallbackHandler (interface),
// auth/SaslExtensions and SaslExtensionsCallback (extension passing), scram/
// ScramExtensionsCallback (SCRAM-specific extensions), scram/ScramMechanism (mechanism
// detection). The JAAS Subject is injected via SecurityManagerCompatibility.current().
// Contract: Must handle all callback types required by the configured SASL mechanism.
// Impact: If a callback type is unhandled, UnsupportedCallbackException causes auth failure.
public class SaslClientCallbackHandler implements AuthenticateCallbackHandler {

    private String mechanism;

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        this.mechanism  = saslMechanism;
    }

    // DECISION: Single handle() method with instanceof chain for 6 callback types rather
    // than separate handler methods per callback type. Alternatives: (1) Map<Class, Handler>
    // dispatch, (2) Visitor pattern. Rationale: SASL framework invokes handle() with mixed
    // callback arrays -- a linear scan with instanceof is the standard JAAS pattern and
    // matches the Java SASL API reference guide (linked in class Javadoc).
    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        // SECURITY: SEC-SASL-029 (MEDIUM) Uses SecurityManagerCompatibility.get().current() to obtain
        // Why: Callback handler processes credential requests during
        // SASL authentication, handling sensitive auth material.
        // the Subject from the current execution context. This replaces the deprecated
        // Subject.getSubject(AccessController.getContext()). If no Subject is available
        // (subject == null), NameCallback falls back to getDefaultName() and PasswordCallback
        // throws UnsupportedCallbackException -- preventing silent anonymous authentication.
        // Exploit: Malicious extensions or callback values could inject unexpected behavior into the auth flow.
        // Improvement: Validate all extension keys and values against an allowlist before processing.
        Subject subject = SecurityManagerCompatibility.get().current();
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nc = (NameCallback) callback;
                if (subject != null && !subject.getPublicCredentials(String.class).isEmpty()) {
                    nc.setName(subject.getPublicCredentials(String.class).iterator().next());
                } else
                    nc.setName(nc.getDefaultName());
            } else if (callback instanceof PasswordCallback) {
                // SECURITY: SEC-SASL-030 (HIGH) Extracts plaintext password from Subject's private
                // Why: Callback handler processes credential requests during
                // SASL authentication, handling sensitive auth material.
                // credentials. The password is converted to char[] from String, but the
                // source String remains in the Subject's credential set and in the JVM
                // string pool.
                // Exploit: A memory dump of the JVM heap could reveal the plaintext
                // password even after authentication completes. Java's String immutability
                // means the password cannot be zeroed in memory -- only the char[] copy
                // could be overwritten.
                // Improvement: Consider using char[] as the private credential type.
                if (subject != null && !subject.getPrivateCredentials(String.class).isEmpty()) {
                    char[] password = subject.getPrivateCredentials(String.class).iterator().next().toCharArray();
                    ((PasswordCallback) callback).setPassword(password);
                } else {
                    String errorMessage = "Could not login: the client is being asked for a password, but the Kafka" +
                             " client code does not currently support obtaining a password from the user.";
                    throw new UnsupportedCallbackException(callback, errorMessage);
                }
            } else if (callback instanceof RealmCallback) {
                RealmCallback rc = (RealmCallback) callback;
                rc.setText(rc.getDefaultText());
            } else if (callback instanceof AuthorizeCallback) {
                // SECURITY: SEC-SASL-031 (MEDIUM) Authorization check compares authenticationID ==
                // Why: Callback handler processes credential requests during
                // SASL authentication, handling sensitive auth material.
                // authorizationID. This prevents a client from requesting authorization
                // as a different identity than it authenticated as.
                // Exploit: If setAuthorized(true) were called unconditionally, any
                // authenticated client could impersonate any other identity via the
                // authorizationID.
                // Improvement: Consider logging failed authorization attempts for audit.
                AuthorizeCallback ac = (AuthorizeCallback) callback;
                String authId = ac.getAuthenticationID();
                String authzId = ac.getAuthorizationID();
                ac.setAuthorized(authId.equals(authzId));
                if (ac.isAuthorized())
                    ac.setAuthorizedID(authzId);
            } else if (callback instanceof ScramExtensionsCallback) {
                // DECISION: ScramExtensionsCallback checked before SaslExtensionsCallback
                // because SCRAM extensions are a superset of SASL extensions. If the
                // mechanism is SCRAM, extensions are delivered via ScramExtensionsCallback;
                // for non-GSSAPI mechanisms, SaslExtensionsCallback is used. This ordering
                // prevents double-delivery of extension data.
                // SECURITY: SEC-SASL-032 (LOW) SCRAM extensions and SASL extensions are extracted from
                // Why: Callback handler processes credential requests during
                // SASL authentication, handling sensitive auth material.
                // Subject's public credentials. Extensions are key-value pairs passed
                // during SASL exchange. GSSAPI is explicitly excluded from SaslExtensions
                // because GSSAPI uses a binary token format that doesn't support extension
                // key-value pairs.
                // Exploit: A compromised callback handler could intercept and log
                // SASL credentials (username/password) during the callback exchange.
                // Improvement: Sanitize and validate all callback values before
                // passing them to the SASL mechanism layer.
                // validation.
                if (ScramMechanism.isScram(mechanism) && subject != null && !subject.getPublicCredentials(Map.class).isEmpty()) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> extensions = (Map<String, String>) subject.getPublicCredentials(Map.class).iterator().next();
                    ((ScramExtensionsCallback) callback).extensions(extensions);
                }
            } else if (callback instanceof SaslExtensionsCallback) {
                if (!SaslConfigs.GSSAPI_MECHANISM.equals(mechanism) &&
                        subject != null && !subject.getPublicCredentials(SaslExtensions.class).isEmpty()) {
                    SaslExtensions extensions = subject.getPublicCredentials(SaslExtensions.class).iterator().next();
                    ((SaslExtensionsCallback) callback).extensions(extensions);
                }
            }  else {
                throw new UnsupportedCallbackException(callback, "Unrecognized SASL ClientCallback");
            }
        }
    }

    @Override
    public void close() {
    }
}
