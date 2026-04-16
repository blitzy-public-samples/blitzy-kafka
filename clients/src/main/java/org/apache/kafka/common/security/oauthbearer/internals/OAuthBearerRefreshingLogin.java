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
package org.apache.kafka.common.security.oauthbearer.internals;

import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.Login;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.internals.expiring.ExpiringCredential;
import org.apache.kafka.common.security.oauthbearer.internals.expiring.ExpiringCredentialRefreshConfig;
import org.apache.kafka.common.security.oauthbearer.internals.expiring.ExpiringCredentialRefreshingLogin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * This class is responsible for refreshing logins for both Kafka client and
 * server when the credential is an OAuth 2 bearer token communicated over
 * SASL/OAUTHBEARER. An OAuth 2 bearer token has a limited lifetime, and an
 * instance of this class periodically refreshes it so that the client can
 * create new connections to brokers on an ongoing basis.
 * <p>
 * This class does not need to be explicitly set via the
 * {@code sasl.login.class} client configuration property or the
 * {@code listener.name.sasl_[plaintext|ssl].oauthbearer.sasl.login.class}
 * broker configuration property when the SASL mechanism is OAUTHBEARER; it is
 * automatically set by default in that case.
 * <p>
 * The parameters that impact how the refresh algorithm operates are specified
 * as part of the producer/consumer/broker configuration and are as follows. See
 * the documentation for these properties elsewhere for details.
 * <table>
 * <tr>
 * <th>Producer/Consumer/Broker Configuration Property</th>
 * </tr>
 * <tr>
 * <td>{@code sasl.login.refresh.window.factor}</td>
 * </tr>
 * <tr>
 * <td>{@code sasl.login.refresh.window.jitter}</td>
 * </tr>
 * <tr>
 * <td>{@code sasl.login.refresh.min.period.seconds}</td>
 * </tr>
 * <tr>
 * <td>{@code sasl.login.refresh.min.buffer.seconds}</td>
 * </tr>
 * </table>
 * 
 * @see OAuthBearerLoginModule
 * @see SaslConfigs#SASL_LOGIN_REFRESH_WINDOW_FACTOR_DOC
 * @see SaslConfigs#SASL_LOGIN_REFRESH_WINDOW_JITTER_DOC
 * @see SaslConfigs#SASL_LOGIN_REFRESH_MIN_PERIOD_SECONDS_DOC
 * @see SaslConfigs#SASL_LOGIN_REFRESH_BUFFER_SECONDS_DOC
 */
// SECURITY: (HIGH) Token refresh lifecycle -- orchestrates periodic JWT refresh for
// both Kafka client and broker inter-broker communication.
// Why: Token refresh is critical to continuous authentication. If refresh fails silently,
// the broker/client continues with an expired credential until connection drops occur.
// Expired credentials cascade to authentication failures across all new connections.
// Exploit: Refresh failure suppression -- if the background refresh thread (in
// ExpiringCredentialRefreshingLogin) encounters a persistent failure (e.g., OAuth
// provider is down, network partition), connections using the stale token will
// gradually fail as the token expires. An attacker could trigger this by DoS-ing
// the OAuth token endpoint, causing all Kafka clients in the cluster to lose
// their ability to refresh tokens simultaneously.
// Improvement: Add metrics/alerts for refresh failures (e.g., a JMX gauge tracking
// "time since last successful refresh"). Consider circuit-breaker pattern for
// refresh retries to prevent thundering herd on the OAuth provider.
//
// CROSS-CUTTING: Extends auth/Login interface. Depends on expiring/ExpiringCredentialRefreshingLogin
// (background refresh scheduling), expiring/ExpiringCredentialRefreshConfig (refresh policy),
// expiring/ExpiringCredential (credential expiry contract), OAuthBearerToken (token interface).
// Used by: authenticator/LoginManager which creates Login instances for SASL authentication.
// OAuthBearerLoginModule.OAUTHBEARER_MECHANISM triggers automatic selection of this class
// as the Login implementation (see SaslConfigs.DEFAULT_SASL_OAUTHBEARER_LOGIN_CLASS).
// Contract: configure() then login(). close() interrupts background refresh thread.
// Impact: Changes to ExpiringCredentialRefreshingLogin refresh scheduling affect all
// OAUTHBEARER token refresh timing across clients and brokers.
public class OAuthBearerRefreshingLogin implements Login {
    private static final Logger log = LoggerFactory.getLogger(OAuthBearerRefreshingLogin.class);
    private ExpiringCredentialRefreshingLogin expiringCredentialRefreshingLogin = null;

    // COMPLEXITY: 48 lines -- Constructs ExpiringCredentialRefreshingLogin with an inline
    // ExpiringCredential adapter. The anonymous class maps OAuthBearerToken to ExpiringCredential
    // interface. Inner structure: creates ExpiringCredentialRefreshConfig from the provided config
    // map, then instantiates ExpiringCredentialRefreshingLogin with the anonymous ExpiringCredential
    // implementation. The ExpiringCredential adapter has 4 methods: principalName(), startTimeMs(),
    // expireTimeMs() (maps to lifetimeMs), and absoluteLastRefreshTimeMs() (always null).
    // Key: first token from Subject's private credentials is selected (no sorting).
    // Empty set returns null (no credential).
    @Override
    public void configure(Map<String, ?> configs, String contextName, Configuration configuration,
            AuthenticateCallbackHandler loginCallbackHandler) {
        /*
         * Specify this class as the one to synchronize on so that only one OAuth 2
         * Bearer Token is refreshed at a given time. Specify null if we don't mind
         * multiple simultaneously refreshes. Refreshes happen on the order of minutes
         * rather than seconds or milliseconds, and there are typically minutes of
         * lifetime remaining when the refresh occurs, so serializing them seems
         * reasonable.
         */
        // SECURITY: (MEDIUM) Refresh operations are serialized on OAuthBearerRefreshingLogin.class.
        // This means all instances in the same JVM share a single lock for token refresh,
        // preventing concurrent refresh storms. However, this also means a blocked refresh
        // (e.g., stuck HTTP call to OAuth provider) blocks ALL other refreshes in the JVM.
        //
        // DECISION: Uses OAuthBearerRefreshingLogin.class as the synchronization lock for all
        // refresh operations JVM-wide. Alternatives: (1) null -- no synchronization, allow
        // concurrent refreshes, (2) Per-instance lock -- each Login refreshes independently,
        // (3) Per-listener lock. Rationale: Serialization prevents thundering herd when multiple
        // Kafka clients share the same OAuth provider. Token refresh is infrequent (minutes)
        // with substantial remaining lifetime, so serialization overhead is negligible.
        // Risk: A hung refresh (e.g., TCP timeout to OAuth provider) blocks all refreshes.
        Class<OAuthBearerRefreshingLogin> classToSynchronizeOnPriorToRefresh = OAuthBearerRefreshingLogin.class;
        expiringCredentialRefreshingLogin = new ExpiringCredentialRefreshingLogin(contextName, configuration,
                new ExpiringCredentialRefreshConfig(configs, true), loginCallbackHandler,
                classToSynchronizeOnPriorToRefresh) {
            // SECURITY: (MEDIUM) ExpiringCredential adapter extracts token metadata from Subject
            // private credentials. privateCredentialTokens.iterator().next() selects the first
            // token without sorting -- during the brief multi-token refresh window, this may
            // select either the old or new token. The refresh scheduler uses expireTimeMs()
            // (mapped to token.lifetimeMs()) to compute the next refresh timestamp.
            // Note: absoluteLastRefreshTimeMs() returns null -- refresh is never explicitly
            // prohibited, relying only on the token expiry window for scheduling.
            //
            // DECISION: Wraps OAuthBearerToken in ExpiringCredential interface via anonymous class
            // rather than making OAuthBearerToken extend ExpiringCredential directly. Alternative:
            // OAuthBearerToken could implement ExpiringCredential. Rationale: Separation of
            // concerns -- OAuthBearerToken is a public API interface that should not be coupled
            // to the internal refresh scheduling infrastructure. The adapter allows the refresh
            // framework to be reused for non-OAuth credentials (e.g., Kerberos TGTs via
            // ExpiringCredentialRefreshingLogin).
            @Override
            public ExpiringCredential expiringCredential() {
                Set<OAuthBearerToken> privateCredentialTokens = expiringCredentialRefreshingLogin.subject()
                        .getPrivateCredentials(OAuthBearerToken.class);
                if (privateCredentialTokens.isEmpty())
                    return null;
                final OAuthBearerToken token = privateCredentialTokens.iterator().next();
                if (log.isDebugEnabled())
                    log.debug("Found expiring credential with principal '{}'.", token.principalName());
                return new ExpiringCredential() {
                    @Override
                    public String principalName() {
                        return token.principalName();
                    }

                    @Override
                    public Long startTimeMs() {
                        return token.startTimeMs();
                    }

                    @Override
                    public long expireTimeMs() {
                        return token.lifetimeMs();
                    }

                    // DECISION: Returns null -- never prohibits refresh. Alternative: Return
                    // token's expireTimeMs minus a buffer. Rationale: OAuth tokens should always
                    // attempt refresh before expiry. The refresh window/buffer config parameters
                    // in ExpiringCredentialRefreshConfig control the timing. Returning null
                    // leaves scheduling entirely to the base class.
                    @Override
                    public Long absoluteLastRefreshTimeMs() {
                        return null;
                    }
                };
            }
        };
    }

    @Override
    public void close() {
        if (expiringCredentialRefreshingLogin != null)
            expiringCredentialRefreshingLogin.close();
    }

    @Override
    public Subject subject() {
        return expiringCredentialRefreshingLogin != null ? expiringCredentialRefreshingLogin.subject() : null;
    }

    @Override
    public String serviceName() {
        return expiringCredentialRefreshingLogin != null ? expiringCredentialRefreshingLogin.serviceName() : null;
    }

    @Override
    public synchronized LoginContext login() throws LoginException {
        if (expiringCredentialRefreshingLogin != null)
            return expiringCredentialRefreshingLogin.login();
        throw new LoginException("Login was not configured properly");
    }
}
