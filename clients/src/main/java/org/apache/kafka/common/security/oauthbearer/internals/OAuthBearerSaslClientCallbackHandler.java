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

import org.apache.kafka.common.internals.SecurityManagerCompatibility;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.auth.SaslExtensionsCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

/**
 * An implementation of {@code AuthenticateCallbackHandler} that recognizes
 * {@link OAuthBearerTokenCallback} and retrieves OAuth 2 Bearer Token that was
 * created when the {@code OAuthBearerLoginModule} logged in by looking for an
 * instance of {@link OAuthBearerToken} in the {@code Subject}'s private
 * credentials. This class also recognizes {@link SaslExtensionsCallback} and retrieves any SASL extensions that were
 * created when the {@code OAuthBearerLoginModule} logged in by looking for an instance of {@link SaslExtensions}
 * in the {@code Subject}'s public credentials
 * <p>
 * Use of this class is configured automatically and does not need to be
 * explicitly set via the {@code sasl.client.callback.handler.class}
 * configuration property.
 */
// SECURITY: (LOW) Transfers OAuthBearerToken from JAAS Subject's private credentials to
// SASL callbacks during the client-side SASL exchange.
// Why: This handler accesses the Subject's private credential store which holds bearer tokens.
// The token selection logic (latest lifetime) could mask a token replacement attack.
// Exploit: If an attacker can inject a second OAuthBearerToken into the Subject's private
// credentials (e.g., via a compromised JAAS LoginModule sharing the same Subject), the
// handler will select the token with the longest lifetime — which could be the attacker's
// forged token with an artificially long expiration. The legitimate token would be ignored.
// Improvement: Consider logging the principalName of the selected token when multiple
// tokens exist, enabling audit detection of unexpected principal switches.
//
// CROSS-CUTTING: Depends on auth/AuthenticateCallbackHandler (contract interface),
// auth/SaslExtensions (public credential DTO), OAuthBearerToken (private credential),
// OAuthBearerTokenCallback (callback contract), SecurityManagerCompatibility (Subject access).
// Used by: OAuthBearerSaslClient via SASL factory (SaslClientFactory passes this as
// the CallbackHandler). Configured by LoginManager during SASL authentication setup.
// Contract: configure() must be called before handle(). Not thread-safe.
// Impact: Changes to OAuthBearerToken interface or Subject credential storage affect
// token retrieval behavior across all OAUTHBEARER client authentication paths.
public class OAuthBearerSaslClientCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger log = LoggerFactory.getLogger(OAuthBearerSaslClientCallbackHandler.class);
    private boolean configured = false;

    /**
     * Return true if this instance has been configured, otherwise false
     *
     * @return true if this instance has been configured, otherwise false
     */
    public boolean configured() {
        return configured;
    }

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        configured = true;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (!configured())
            throw new IllegalStateException("Callback handler not configured");
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback)
                handleCallback((OAuthBearerTokenCallback) callback);
            else if (callback instanceof SaslExtensionsCallback)
                handleCallback((SaslExtensionsCallback) callback, SecurityManagerCompatibility.get().current());
            else
                throw new UnsupportedCallbackException(callback);
        }
    }

    @Override
    public void close() {
        // empty
    }

    // SECURITY: (LOW) Token retrieval from Subject's private credentials. The private
    // credentials set is accessed via Subject.getPrivateCredentials() which requires
    // no special permissions in the current Kafka security model. The token's raw value
    // (a bearer JWT string) is accessible to any code that obtains a reference to the
    // returned OAuthBearerToken instance.
    // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
    // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
    private void handleCallback(OAuthBearerTokenCallback callback) throws IOException {
        if (callback.token() != null)
            throw new IllegalArgumentException("Callback had a token already");
        Subject subject = SecurityManagerCompatibility.get().current();
        Set<OAuthBearerToken> privateCredentials = subject != null
            ? subject.getPrivateCredentials(OAuthBearerToken.class)
            : Collections.emptySet();
        if (privateCredentials.isEmpty())
            throw new IOException("No OAuth Bearer tokens in Subject's private credentials");
        if (privateCredentials.size() == 1)
            callback.token(privateCredentials.iterator().next());
        else {
            // SECURITY: (LOW) Multi-token race window — during refresh, old and new tokens briefly
            // coexist. Selecting the longest-lived token is the correct choice for availability,
            // but note: an attacker who can inject tokens would exploit this exact behavior.
            // The WARN log message includes token lifetimes (dates) but not token values — correct.
            //
            // DECISION: Select token with longest lifetime when multiple exist, rather than
            // implementing a lock to prevent the multi-token window. Alternatives: (1) Use a
            // ReentrantLock to serialize refresh and callback, (2) Fail when multiple tokens exist.
            // Rationale: Lock-free approach avoids deadlock risk between SASL thread and refresh
            // thread. The multi-token window is O(milliseconds) during normal operation. This
            // also handles the KAFKA-7902 bug scenario gracefully. Risk: If more than 2 tokens
            // accumulate (leak), the WARN log is the only signal — no eviction occurs.
            // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
            // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
            /*
             * There a very small window of time upon token refresh (on the order of milliseconds)
             * where both an old and a new token appear on the Subject's private credentials.
             * Rather than implement a lock to eliminate this window, we will deal with it by
             * checking for the existence of multiple tokens and choosing the one that has the
             * longest lifetime.  It is also possible that a bug could cause multiple tokens to
             * exist (e.g. KAFKA-7902), so dealing with the unlikely possibility that occurs
             * during normal operation also allows us to deal more robustly with potential bugs.
             */
            // DECISION: Uses TreeSet with Comparator.comparingLong(lifetimeMs) for O(n log n)
            // sorting. Alternative: Stream.max(). Rationale: TreeSet provides natural ordering
            // with .first()/.last() access for both logging and selection in one pass.
            SortedSet<OAuthBearerToken> sortedByLifetime =
                new TreeSet<>(
                        Comparator.comparingLong(OAuthBearerToken::lifetimeMs));
            sortedByLifetime.addAll(privateCredentials);
            log.warn("Found {} OAuth Bearer tokens in Subject's private credentials; the oldest expires at {}, will use the newest, which expires at {}",
                sortedByLifetime.size(),
                new Date(sortedByLifetime.first().lifetimeMs()),
                new Date(sortedByLifetime.last().lifetimeMs()));
            callback.token(sortedByLifetime.last());
        }
    }

    /**
     * Attaches the first {@link SaslExtensions} found in the public credentials of the Subject
     */
    private static void handleCallback(SaslExtensionsCallback extensionsCallback, Subject subject) {
        if (subject != null && !subject.getPublicCredentials(SaslExtensions.class).isEmpty()) {
            SaslExtensions extensions = subject.getPublicCredentials(SaslExtensions.class).iterator().next();
            extensionsCallback.extensions(extensions);
        }
    }
}
