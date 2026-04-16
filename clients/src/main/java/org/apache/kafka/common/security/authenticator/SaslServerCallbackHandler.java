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
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

/**
 * Default callback handler for Sasl servers. The callbacks required for all the SASL
 * mechanisms enabled in the server should be supported by this callback handler. See
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/sasl/sasl-refguide.html">Java SASL API</a>
 * for the list of SASL callback handlers required for each SASL mechanism.
 *
 * @implSpec SECURITY: (MEDIUM) Server-side SASL callback handler that dispatches
 * credential verification callbacks from the SASL framework. This default handler
 * supports only RealmCallback and AuthorizeCallback (for GSSAPI). Mechanism-specific
 * handlers (ScramServerCallbackHandler, OAuthBearerValidatorCallbackHandler) handle
 * credential verification for their respective mechanisms.
 * Exploit: handleAuthorizeCallback() unconditionally sets authorized=true and uses
 * authenticationID as the authorized identity. Correct for GSSAPI where the Kerberos
 * principal IS the authorized identity, but if this handler were accidentally used
 * for other mechanisms, it would bypass authorization — any authenticated identity
 * would be authorized without credential verification.
 * Improvement: Add a mechanism check in handleAuthorizeCallback() as defense-in-depth,
 * even though handle() already guards the AuthorizeCallback path with a GSSAPI check.
 */
// CROSS-CUTTING: Used by SaslServerAuthenticator for server-side GSSAPI callback
// handling. Registered by ChannelBuilders as the default server callback handler
// when no mechanism-specific handler is configured.
// Depends on: auth/AuthenticateCallbackHandler (interface), SaslConfigs.GSSAPI_MECHANISM.
// Contract: Must handle all callback types produced by the GSSAPI SaslServer.
// Impact: If handleAuthorizeCallback is modified, it affects Kerberos-authenticated
// client identity resolution for all GSSAPI connections.
public class SaslServerCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger LOG = LoggerFactory.getLogger(SaslServerCallbackHandler.class);

    private String mechanism;

    @Override
    public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        this.mechanism = mechanism;
    }

    // DECISION: Supports only RealmCallback and AuthorizeCallback (GSSAPI only).
    // All other callback types cause UnsupportedCallbackException. This is intentional:
    // mechanism-specific handlers (registered per mechanism in ChannelBuilders) handle
    // NameCallback, PasswordCallback, etc. This default handler is only used when no
    // mechanism-specific handler is configured, which should only happen for GSSAPI.
    // SECURITY: (LOW) Strict callback type checking — throws UnsupportedCallbackException
    // for any unrecognized callback. This prevents silent acceptance of callbacks that
    // this handler doesn't know how to process, which could mask authentication issues
    // or allow unexpected credential flows.
    // Exploit: Unauthorized access to the credential cache could expose authentication material.
    // Improvement: Limit cache access to authenticated callers and consider cache entry encryption at rest.
    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof RealmCallback)
                handleRealmCallback((RealmCallback) callback);
            else if (callback instanceof AuthorizeCallback && mechanism.equals(SaslConfigs.GSSAPI_MECHANISM))
                handleAuthorizeCallback((AuthorizeCallback) callback);
            else
                throw new UnsupportedCallbackException(callback);
        }
    }

    private void handleRealmCallback(RealmCallback rc) {
        LOG.trace("Client supplied realm: {} ", rc.getDefaultText());
        rc.setText(rc.getDefaultText());
    }

    // SECURITY: (MEDIUM) Kerberos authorization: sets authorized=true unconditionally.
    // Why: In GSSAPI, the authenticated identity (from Kerberos ticket) is inherently
    // authorized — there is no separate authorization step at the SASL level. The
    // actual authorization happens later via ACL checks (StandardAuthorizer).
    // Logging authenticationID and authorizationID is safe — these are Kerberos
    // principal names, not passwords or secrets.
    // Exploit: If the GSSAPI check in handle() is removed, this handler would authorize
    // any mechanism's clients unconditionally, bypassing credential verification.
    // DECISION: Uses authenticationID as authorizedID rather than authorizationID.
    // This means GSSAPI proxy authentication (authenticating as one principal but
    // authorizing as another) is not supported. Alternative: use authorizationID if
    // different from authenticationID. Rationale: Kafka does not support Kerberos
    // delegation/proxy authentication at the SASL level.
    // Improvement: Add state transition validation to reject unexpected state changes.
    private void handleAuthorizeCallback(AuthorizeCallback ac) {
        String authenticationID = ac.getAuthenticationID();
        String authorizationID = ac.getAuthorizationID();
        LOG.info("Successfully authenticated client: authenticationID={}; authorizationID={}.",
                authenticationID, authorizationID);
        ac.setAuthorized(true);
        ac.setAuthorizedID(authenticationID);
    }

    @Override
    public void close() {
    }
}
