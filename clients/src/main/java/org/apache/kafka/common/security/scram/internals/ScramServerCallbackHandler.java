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
package org.apache.kafka.common.security.scram.internals;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.authenticator.CredentialCache;
import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.ScramCredentialCallback;
import org.apache.kafka.common.security.token.delegation.TokenInformation;
import org.apache.kafka.common.security.token.delegation.internals.DelegationTokenCache;
import org.apache.kafka.common.security.token.delegation.internals.DelegationTokenCredentialCallback;

import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

// SECURITY: (MEDIUM) Server-side credential lookup and delegation token handling.
// Why: This callback handler dispatches between regular SCRAM credentials (from CredentialCache)
// and delegation token credentials (from DelegationTokenCache). It is the primary integration
// point between SCRAM authentication and the delegation token system.
// Exploit: If the callback dispatch logic incorrectly routes a regular auth request to
// delegation token lookup (or vice versa), an attacker could authenticate with a delegation
// token credential against a regular SCRAM endpoint, potentially bypassing token expiry checks.
// The dispatch depends on callback type ordering in the Callback[] array -- if NameCallback
// appears after DelegationTokenCredentialCallback, username will be null during token lookup.
// Improvement: (1) Validate username is non-null before credential lookup. (2) Add explicit
// ordering validation of callbacks. (3) Log credential lookup path for security audit trail.
//
// DECISION: Single callback handler handles both regular SCRAM and delegation token auth modes.
// Alternatives: (1) Separate handlers per auth mode (ScramCallbackHandler + TokenCallbackHandler),
// (2) Strategy pattern with mode-specific credential resolvers.
// Rationale: Unified handler simplifies JAAS configuration and provider wiring. The dispatch
// is based on callback type (DelegationTokenCredentialCallback vs ScramCredentialCallback),
// which is determined by ScramSaslServer based on the tokenauth SCRAM extension.
//
// CROSS-CUTTING: This is the primary integration point between SCRAM authentication and
// credential storage systems:
// - Depends on authenticator/CredentialCache for regular SCRAM credential storage
// - Depends on token/delegation/internals/DelegationTokenCache for token credential storage
// - Depends on token/delegation/TokenInformation for token metadata (expiry timestamp)
// - Depends on scram/ScramCredentialCallback for regular SCRAM credential transfer
// - Depends on token/delegation/internals/DelegationTokenCredentialCallback for token transfer
// - Implements auth/AuthenticateCallbackHandler interface (module boundary contract)
// Consumed by: ScramSaslServer via CallbackHandler parameter in constructor.
// Created by: authenticator/SaslServerAuthenticator during SCRAM mechanism initialization.
// Impact: Changes to CredentialCache.Cache API or DelegationTokenCache API break credential lookup.
public class ScramServerCallbackHandler implements AuthenticateCallbackHandler {

    private final CredentialCache.Cache<ScramCredential> credentialCache;
    private final DelegationTokenCache tokenCache;
    private String saslMechanism;

    public ScramServerCallbackHandler(CredentialCache.Cache<ScramCredential> credentialCache,
                                      DelegationTokenCache tokenCache) {
        this.credentialCache = credentialCache;
        this.tokenCache = tokenCache;
    }

    @Override
    public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        this.saslMechanism = mechanism;
    }

    // DECISION: Callbacks are processed in iteration order -- NameCallback must appear before
    // credential callbacks to ensure username is available. This ordering is guaranteed by
    // ScramSaslServer.evaluateResponse() which constructs the Callback[] array with NameCallback first.
    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        String username = null;
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback)
                username = ((NameCallback) callback).getDefaultName();
            // SECURITY: (MEDIUM) Delegation token credential path -- looks up SCRAM credential from
            // token cache using saslMechanism and username (tokenId). Also retrieves token owner and
            // expiry timestamp. Risk: If tokenCache.credential() returns a credential for a different
            // mechanism (mechanism mismatch), the HMAC verification could silently fail or succeed
            // incorrectly. The tokenExpiryTimestamp is passed back to ScramSaslServer's
            // getNegotiatedProperty() for the authenticator layer to enforce.
            else if (callback instanceof DelegationTokenCredentialCallback) {
                DelegationTokenCredentialCallback tokenCallback = (DelegationTokenCredentialCallback) callback;
                tokenCallback.scramCredential(tokenCache.credential(saslMechanism, username));
                tokenCallback.tokenOwner(tokenCache.owner(username));
                TokenInformation tokenInfo = tokenCache.token(username);
                if (tokenInfo != null)
                    tokenCallback.tokenExpiryTimestamp(tokenInfo.expiryTimestamp());
            // SECURITY: Regular SCRAM credential path -- simple lookup from CredentialCache by username.
            // Null credential result is handled by ScramSaslServer.evaluateResponse() which throws
            // SaslException("Authentication failed: Invalid user credentials") -- correct fail-closed.
            } else if (callback instanceof ScramCredentialCallback) {
                ScramCredentialCallback sc = (ScramCredentialCallback) callback;
                sc.scramCredential(credentialCache.get(username));
            // SECURITY: Unknown callback types are rejected with UnsupportedCallbackException.
            // This prevents unexpected callback injection from a modified SASL framework.
            } else
                throw new UnsupportedCallbackException(callback);
        }
    }

    @Override
    public void close() {
    }
}
