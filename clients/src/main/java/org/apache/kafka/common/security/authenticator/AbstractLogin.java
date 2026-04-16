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

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.Login;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.RealmCallback;

/**
 * Base login class that implements methods common to typical SASL mechanisms.
 *
 * @implSpec SECURITY: (MEDIUM) JAAS Subject handling -- the Subject contains sensitive
 * credentials (passwords, tokens, Kerberos tickets) as private credentials.
 * The login() method creates a LoginContext with a null Subject parameter,
 * meaning the LoginContext creates a new Subject internally. This Subject's lifecycle
 * is tied to the LoginContext -- credentials persist until logout() clears them or the
 * LoginContext is garbage collected.
 * Exploit: If logout() is never called (e.g., due to exception during close()), the
 * Subject's private credentials (plaintext passwords, SCRAM secrets, OAuth tokens)
 * remain in JVM heap memory indefinitely. A heap dump or JVM memory inspector could
 * extract these credentials.
 * Improvement: Consider implementing a close() method in AbstractLogin that calls
 * loginContext.logout() to explicitly clear credentials, rather than delegating this
 * decision to each subclass.
 */
// DECISION: Template method pattern -- AbstractLogin implements the JAAS login lifecycle
// (configure -> login -> subject) while subclasses provide serviceName() and close().
// Alternatives: (1) Strategy pattern with Login interface only, (2) Builder pattern.
// Rationale: Most SASL mechanisms share identical login mechanics (LoginContext creation,
// callback handler wiring); only the service name and cleanup behavior differ. Template
// method avoids duplicating LoginContext setup across DefaultLogin, KerberosLogin,
// and OAuthBearerRefreshingLogin.

// CROSS-CUTTING: Extended by DefaultLogin (this package) for PLAIN/SCRAM,
// KerberosLogin (kerberos/) for GSSAPI with TGT renewal, and
// OAuthBearerRefreshingLogin (oauthbearer/) for token refresh.
// Depends on: auth/Login (interface contract), auth/AuthenticateCallbackHandler
// (callback handler interface for credential provisioning).
// Consumed by: LoginManager.acquireLoginManager() (instantiates via reflection).
// Contract: configure() MUST be called before login(). login() returns a LoginContext
// whose Subject contains the authenticated credentials. Thread-safety: NOT thread-safe;
// each Login instance should be used by a single thread or protected externally.
public abstract class AbstractLogin implements Login {
    private static final Logger log = LoggerFactory.getLogger(AbstractLogin.class);

    private String contextName;
    private Configuration configuration;
    private LoginContext loginContext;
    private AuthenticateCallbackHandler loginCallbackHandler;

    @Override
    public void configure(Map<String, ?> configs, String contextName, Configuration configuration,
                          AuthenticateCallbackHandler loginCallbackHandler) {
        this.contextName = contextName;
        this.configuration = configuration;
        this.loginCallbackHandler = loginCallbackHandler;
    }

    // SECURITY: (MEDIUM) LoginContext is created with null Subject, meaning JAAS
    // creates a fresh Subject. The loginCallbackHandler handles credential provisioning
    // (username/password/realm callbacks). On successful login, the Subject contains
    // the authenticated principal and mechanism-specific credentials. log.info() does
    // NOT log credentials or principal names -- intentional to prevent leakage.

    // DECISION: Passes null Subject to LoginContext constructor rather than a
    // pre-constructed Subject. This lets each JAAS login module populate the Subject
    // with its own credentials. Alternative: Pass a shared Subject to accumulate
    // credentials across multiple login modules. Rationale: Kafka's JAAS config uses
    // one login module per mechanism, so a fresh Subject avoids cross-contamination.
    @Override
    public LoginContext login() throws LoginException {
        loginContext = new LoginContext(contextName, null, loginCallbackHandler, configuration);
        loginContext.login();
        log.info("Successfully logged in.");
        return loginContext;
    }

    @Override
    public Subject subject() {
        return loginContext.getSubject();
    }

    protected String contextName() {
        return contextName;
    }

    protected Configuration configuration() {
        return configuration;
    }

    /**
     * Callback handler for creating login context. Login callback handlers
     * should support the callbacks required for the login modules used by
     * the KafkaServer and KafkaClient contexts. Kafka does not support
     * callback handlers which require additional user input.
     *
     */
    // CROSS-CUTTING: Default handler used by LoginManager when no mechanism-specific
    // login callback handler is configured (and mechanism is not OAUTHBEARER).
    // Also used as fallback in SaslServerCallbackHandler for GSSAPI realm handling.
    public static class DefaultLoginCallbackHandler implements AuthenticateCallbackHandler {

        @Override
        public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        }

        @Override
        public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    // DECISION: Uses nc.getDefaultName() as the name for NameCallback
                    // rather than extracting from Subject or configuration. This is
                    // the correct JAAS default behavior for non-interactive login
                    // modules that embed the principal name in login module options.
                    NameCallback nc = (NameCallback) callback;
                    nc.setName(nc.getDefaultName());
                } else if (callback instanceof PasswordCallback) {
                    // SECURITY: (MEDIUM) Rejects PasswordCallback with exception.
                    // Safety net preventing interactive password input blocking in
                    // non-interactive server/client environments. Prevents accidental
                    // use of interactive login modules (e.g., Krb5LoginModule without
                    // keytab) in production environments.
                    String errorMessage = "Could not login: the client is being asked for a password, but the Kafka" +
                                 " client code does not currently support obtaining a password from the user.";
                    throw new UnsupportedCallbackException(callback, errorMessage);
                } else if (callback instanceof RealmCallback) {
                    RealmCallback rc = (RealmCallback) callback;
                    rc.setText(rc.getDefaultText());
                } else {
                    throw new UnsupportedCallbackException(callback, "Unrecognized SASL Login callback");
                }
            }
        }

        @Override
        public void close() {
        }
    }
}
