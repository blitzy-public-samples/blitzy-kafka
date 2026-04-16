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

import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.authenticator.SaslInternalConfigs;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerExtensionsValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

/**
 * {@code SaslServer} implementation for SASL/OAUTHBEARER in Kafka. An instance
 * of {@link OAuthBearerToken} is available upon successful authentication via
 * the negotiated property "{@code OAUTHBEARER.token}"; the token could be used
 * in a custom authorizer (to authorize based on JWT claims rather than ACLs,
 * for example).
 */
/*
 * SECURITY: SEC-OAUTH-059 (HIGH) Broker-side SASL OAUTHBEARER server — parses client initial payload,
 * validates token via AuthenticateCallbackHandler, and enforces authorization ID matching.
 * Why: This is the broker's trust enforcement point for OAUTHBEARER — all token validation
 * is delegated to the callbackHandler. If the handler is misconfigured or compromised,
 * arbitrary tokens will be accepted.
 * Exploit: Token replay — the server does not track used token JTI (JWT ID) values. A
 * valid token intercepted from the network can be replayed within its validity window.
 * An attacker who captures a valid bearer token (e.g., via network sniffing on a
 * SASL_PLAINTEXT listener, log file access, or heap dump) can authenticate as the
 * token's principal until the token expires.
 * Improvement: Implement a short-lived JTI (JWT ID) cache for replay detection. Cache
 * TTL should match max token validity. Consider Caffeine with expireAfterWrite.
 */
/*
 * CROSS-CUTTING: Depends on auth/AuthenticateCallbackHandler (validation delegation),
 * OAuthBearerValidatorCallback (token transport), OAuthBearerExtensionsValidatorCallback
 * (extension validation), OAuthBearerClientInitialResponse (message parsing),
 * SaslInternalConfigs (credential lifetime key), OAuthBearerLoginModule (mechanism name).
 * Used by: authenticator/SaslServerAuthenticator which creates this via SASL SPI.
 * The OAuthBearerSaslServerFactory (inner class) is registered by
 * OAuthBearerSaslServerProvider. Consumer of OAuthBearerValidatorCallbackHandler output.
 * Contract: evaluateResponse() called by SaslServerAuthenticator. Single-threaded.
 */
public class OAuthBearerSaslServer implements SaslServer {

    private static final Logger log = LoggerFactory.getLogger(OAuthBearerSaslServer.class);
    // SECURITY: SEC-OAUTH-060 (LOW) Token exposed via getNegotiatedProperty() after successful auth,
    // enabling custom authorizers to access JWT claims for fine-grained authorization.
    // Why: Token object (and raw value) remains in memory until dispose() is called.
    // Exploit: Memory dump or heap analysis could extract valid tokens post-auth.
    // Improvement: Clear sensitive token fields eagerly; consider token wrapping.
    // DECISION: Token exposed via SASL negotiated properties rather than a separate API.
    // Alternative: Custom method on the SaslServer. Rationale: Using the standard SASL
    // negotiated property mechanism allows SaslServerAuthenticator to access the token
    // without coupling to OAuthBearerSaslServer specifically. This enables the custom
    // authorizer extension point documented in the class Javadoc.
    private static final String NEGOTIATED_PROPERTY_KEY_TOKEN = OAuthBearerLoginModule.OAUTHBEARER_MECHANISM + ".token";
    private static final String INTERNAL_ERROR_ON_SERVER = "Authentication could not be performed due to an internal error on the server";

    private final AuthenticateCallbackHandler callbackHandler;

    private boolean complete;
    private OAuthBearerToken tokenForNegotiatedProperty = null;
    private String errorMessage = null;
    private SaslExtensions extensions;

    public OAuthBearerSaslServer(CallbackHandler callbackHandler) {
        if (!(Objects.requireNonNull(callbackHandler) instanceof AuthenticateCallbackHandler))
            throw new IllegalArgumentException(String.format("Callback handler must be castable to %s: %s",
                    AuthenticateCallbackHandler.class.getName(), callbackHandler.getClass().getName()));
        this.callbackHandler = (AuthenticateCallbackHandler) callbackHandler;
    }

    /**
     * @throws SaslAuthenticationException
     *             if access token cannot be validated
     *             <p>
     *             <b>Note:</b> This method may throw
     *             {@link SaslAuthenticationException} to provide custom error
     *             messages to clients. But care should be taken to avoid including
     *             any information in the exception message that should not be
     *             leaked to unauthenticated clients. It may be safer to throw
     *             {@link SaslException} in some cases so that a standard error
     *             message is returned to clients.
     *             </p>
     */
    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException, SaslAuthenticationException {
        // SECURITY: SEC-OAUTH-061 (HIGH) Entry point for client authentication. Checks control-A
        // error ack — prevents retrying modified tokens in the same SASL exchange.
        // Why: Two-phase error protocol ensures exchange must restart on failure.
        // Exploit: Without ack, attacker could resend modified tokens in same session.
        // Improvement: Rate-limit SASL exchange attempts per connection.
        // DECISION: Uses control-A (0x01) error acknowledgment per RFC 7628. Alternative:
        // Immediately throw on first error without two-phase handshake. Rationale: The
        // two-phase pattern lets the client receive the JSON error response before the
        // connection is terminated, improving debuggability without sacrificing security.
        if (response.length == 1 && response[0] == OAuthBearerSaslClient.BYTE_CONTROL_A && errorMessage != null) {
            log.debug("Received %x01 response from client after it received our error");
            throw new SaslAuthenticationException(errorMessage);
        }
        errorMessage = null;

        OAuthBearerClientInitialResponse clientResponse;
        try {
            clientResponse = new OAuthBearerClientInitialResponse(response);
        } catch (SaslException e) {
            log.debug(e.getMessage());
            throw e;
        }

        return process(clientResponse.tokenValue(), clientResponse.authorizationId(), clientResponse.extensions());
    }

    @Override
    public String getAuthorizationID() {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return tokenForNegotiatedProperty.principalName();
    }

    @Override
    public String getMechanismName() {
        return OAuthBearerLoginModule.OAUTHBEARER_MECHANISM;
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        if (NEGOTIATED_PROPERTY_KEY_TOKEN.equals(propName))
            return tokenForNegotiatedProperty;
        if (SaslInternalConfigs.CREDENTIAL_LIFETIME_MS_SASL_NEGOTIATED_PROPERTY_KEY.equals(propName))
            return tokenForNegotiatedProperty.lifetimeMs();
        return extensions.map().get(propName);
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        throw new IllegalStateException("OAUTHBEARER supports neither integrity nor privacy");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        throw new IllegalStateException("OAUTHBEARER supports neither integrity nor privacy");
    }

    @Override
    public void dispose() {
        complete = false;
        tokenForNegotiatedProperty = null;
        extensions = null;
    }

    // SECURITY: SEC-OAUTH-062 (HIGH) Token validation delegated to callbackHandler.handle(). The
    // callback pattern means this class has NO control over the validation logic.
    // Why: If the handler is misconfigured or compromised, all tokens are accepted.
    // Exploit: Malicious callback handler plugin accepts all tokens unconditionally.
    // Improvement: Add server-side token format pre-validation before delegation.
    /*
     * COMPLEXITY: 31 lines — Token validation, authorization, and extension processing.
     * Structure: (1) Create OAuthBearerValidatorCallback, (2) Invoke callback handler,
     * (3) Check callback.token() for null → error path builds JSON error response,
     * (4) Validate authzId matches principal, (5) Process extensions, (6) Store token.
     * Key branches: token==null (error path), authzId non-empty mismatch (throw).
     * Exit paths: return error bytes (validation failure), throw SaslAuthenticationException
     * (authzId mismatch), return empty bytes on success.
     */
    private byte[] process(String tokenValue, String authorizationId, SaslExtensions extensions) throws SaslException {
        OAuthBearerValidatorCallback callback = new OAuthBearerValidatorCallback(tokenValue);
        try {
            callbackHandler.handle(new Callback[] {callback});
        } catch (IOException | UnsupportedCallbackException e) {
            handleCallbackError(e);
        }
        OAuthBearerToken token = callback.token();
        if (token == null) {
            errorMessage = jsonErrorResponse(callback.errorStatus(), callback.errorScope(),
                    callback.errorOpenIDConfiguration());
            log.debug(errorMessage);
            return errorMessage.getBytes(StandardCharsets.UTF_8);
        }
        /*
         * We support the client specifying an authorization ID as per the SASL
         * specification, but it must match the principal name if it is specified.
         */
        // SECURITY: SEC-OAUTH-063 (HIGH) Authorization ID must match token principalName to prevent
        // privilege escalation — client cannot authenticate with token A as user B.
        // Why: Without this check, a low-privilege token could gain elevated access.
        // Exploit: Remove check → any valid token holder impersonates any principal.
        // Improvement: Consider case-insensitive comparison for cross-system principals.
        // DECISION: Enforce exact match between authzId and token.principalName().
        // Alternative: Allow empty authzId as "use token principal" (the default case).
        // Rationale: Non-empty authzId MUST match to prevent impersonation. Empty authzId
        // (the common case) is allowed — the token's principal becomes the authorization ID.
        if (!authorizationId.isEmpty() && !authorizationId.equals(token.principalName()))
            throw new SaslAuthenticationException(String.format(
                    "Authentication failed: Client requested an authorization id (%s) that is different from the token's principal name (%s)",
                    authorizationId, token.principalName()));

        Map<String, String> validExtensions = processExtensions(token, extensions);

        tokenForNegotiatedProperty = token;
        this.extensions = new SaslExtensions(validExtensions);
        complete = true;
        log.debug("Successfully authenticate User={}", token.principalName());
        return new byte[0];
    }

    // SECURITY: SEC-OAUTH-064 (MEDIUM) Extension validation via OAuthBearerExtensionsValidatorCallback.
    // Why: If handler doesn't support extension validation, ALL extensions are silently
    // accepted without validation for backward compatibility (pre-KIP-368 handlers).
    // Exploit: Malicious client sends crafted extensions that bypass validation entirely.
    // Improvement: Log a WARNING when extension validation is skipped.
    private Map<String, String> processExtensions(OAuthBearerToken token, SaslExtensions extensions) throws SaslException {
        OAuthBearerExtensionsValidatorCallback extensionsCallback = new OAuthBearerExtensionsValidatorCallback(token, extensions);
        try {
            callbackHandler.handle(new Callback[] {extensionsCallback});
        } catch (UnsupportedCallbackException e) {
            // backwards compatibility - no extensions will be added
        } catch (IOException e) {
            handleCallbackError(e);
        }
        if (!extensionsCallback.invalidExtensions().isEmpty()) {
            String errorMessage = String.format("Authentication failed: %d extensions are invalid! They are: %s",
                    extensionsCallback.invalidExtensions().size(),
                    Utils.mkString(extensionsCallback.invalidExtensions(), "", "", ": ", "; "));
            log.debug(errorMessage);
            throw new SaslAuthenticationException(errorMessage);
        }

        return extensionsCallback.validatedExtensions();
    }

    // SECURITY: SEC-OAUTH-065 (MEDIUM) Error response sent to client as JSON.
    // Why: errorStatus, errorScope, errorOpenIDConfiguration are NOT sanitized.
    // Exploit: Attacker triggers validation errors to extract internal server
    // configuration (URLs, paths) leaked through error details to the client.
    // Improvement: Sanitize error fields to prevent information leakage.
    private static String jsonErrorResponse(String errorStatus, String errorScope, String errorOpenIDConfiguration) {
        String jsonErrorResponse = String.format("{\"status\":\"%s\"", errorStatus);
        if (errorScope != null)
            jsonErrorResponse = String.format("%s, \"scope\":\"%s\"", jsonErrorResponse, errorScope);
        if (errorOpenIDConfiguration != null)
            jsonErrorResponse = String.format("%s, \"openid-configuration\":\"%s\"", jsonErrorResponse,
                    errorOpenIDConfiguration);
        jsonErrorResponse = String.format("%s}", jsonErrorResponse);
        return jsonErrorResponse;
    }

    // SECURITY: SEC-OAUTH-066 (MEDIUM) Internal error wrapping — original exception message is
    // included in SaslException which may be sent to the client.
    // Why: Generic prefix appends e.getMessage() which could contain stack details.
    // Exploit: Triggering internal error reveals server-side class names and paths.
    // Improvement: Return only generic prefix to client; log full exception server-side.
    private void handleCallbackError(Exception e) throws SaslException {
        String msg = String.format("%s: %s", INTERNAL_ERROR_ON_SERVER, e.getMessage());
        log.debug(msg, e);
        throw new SaslException(msg);
    }

    // CROSS-CUTTING: Shared by both OAuthBearerSaslServer and OAuthBearerSaslClient
    // (via OAuthBearerSaslClientFactory delegation). Implements SASL NOPLAINTEXT policy
    // — returns empty array if policy requires no plaintext mechanisms.
    public static String[] mechanismNamesCompatibleWithPolicy(Map<String, ?> props) {
        return props != null && "true".equals(String.valueOf(props.get(Sasl.POLICY_NOPLAINTEXT))) ? new String[] {}
                : new String[] {OAuthBearerLoginModule.OAUTHBEARER_MECHANISM};
    }

    public static class OAuthBearerSaslServerFactory implements SaslServerFactory {
        @Override
        public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props,
                CallbackHandler callbackHandler) {
            String[] mechanismNamesCompatibleWithPolicy = getMechanismNames(props);
            for (String name : mechanismNamesCompatibleWithPolicy) {
                if (name.equals(mechanism)) {
                    return new OAuthBearerSaslServer(callbackHandler);
                }
            }
            return null;
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> props) {
            return OAuthBearerSaslServer.mechanismNamesCompatibleWithPolicy(props);
        }
    }
}
