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
package org.apache.kafka.common.security.oauthbearer;

import java.util.Objects;

import javax.security.auth.callback.Callback;

/**
 * A {@code Callback} for use by the {@code SaslServer} implementation when it
 * needs to provide an OAuth 2 bearer token compact serialization for
 * validation. Callback handlers should use the
 * {@link #error(String, String, String)} method to communicate errors back to
 * the SASL Client as per
 * <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC 6749: The OAuth
 * 2.0 Authorization Framework</a> and the <a href=
 * "https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error">IANA
 * OAuth Extensions Error Registry</a>. Callback handlers should communicate
 * other problems by raising an {@code IOException}.
 */
// SECURITY: (MEDIUM) Broker-side validation callback — carries the raw JWT token value
// from the SASL exchange to the callback handler for validation. The tokenValue field
// contains the full bearer token in cleartext. Care must be taken to avoid logging
// this value or exposing it in error messages.
// Exploit: If tokenValue is included in exception messages or debug logs, an attacker
// with log access could capture valid tokens for replay attacks.
// Improvement: Consider wrapping tokenValue in a Password-like type that masks toString().
//
// CROSS-CUTTING: Used by internals/OAuthBearerSaslServer (creates callback with tokenValue
// from client, passes to handler), OAuthBearerValidatorCallbackHandler (validates token,
// sets result), and internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler (dev).
// Contract: SaslServer creates with tokenValue, handler sets token() or error().
// Depends on: OAuthBearerToken. Implements javax.security.auth.callback.Callback.
public class OAuthBearerValidatorCallback implements Callback {
    private final String tokenValue;
    private OAuthBearerToken token = null;
    // DECISION: Three-part error model (status, scope, openIDConfiguration) matching RFC 6749
    // Section 5.2 and RFC 6750 Section 3.1 error response format. Alternative: Single error
    // message string. Rationale: Structured error enables the SASL server to construct a
    // spec-compliant error response to the client, including WWW-Authenticate header fields.
    private String errorStatus = null;
    private String errorScope = null;
    private String errorOpenIDConfiguration = null;

    /**
     * Constructor
     * 
     * @param tokenValue
     *            the mandatory/non-blank token value
     */
    public OAuthBearerValidatorCallback(String tokenValue) {
        if (Objects.requireNonNull(tokenValue).isEmpty())
            throw new IllegalArgumentException("token value must not be empty");
        this.tokenValue = tokenValue;
    }

    /**
     * Return the (always non-null) token value
     * 
     * @return the (always non-null) token value
     */
    public String tokenValue() {
        return tokenValue;
    }

    /**
     * Return the (potentially null) token
     * 
     * @return the (potentially null) token
     */
    public OAuthBearerToken token() {
        return token;
    }

    /**
     * Return the (potentially null) error status value as per
     * <a href="https://tools.ietf.org/html/rfc7628#section-3.2.2">RFC 7628: A Set
     * of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth</a>
     * and the <a href=
     * "https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error">IANA
     * OAuth Extensions Error Registry</a>.
     * 
     * @return the (potentially null) error status value
     */
    public String errorStatus() {
        return errorStatus;
    }

    /**
     * Return the (potentially null) error scope value as per
     * <a href="https://tools.ietf.org/html/rfc7628#section-3.2.2">RFC 7628: A Set
     * of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth</a>.
     * 
     * @return the (potentially null) error scope value
     */
    public String errorScope() {
        return errorScope;
    }

    /**
     * Return the (potentially null) error openid-configuration value as per
     * <a href="https://tools.ietf.org/html/rfc7628#section-3.2.2">RFC 7628: A Set
     * of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth</a>.
     * 
     * @return the (potentially null) error openid-configuration value
     */
    public String errorOpenIDConfiguration() {
        return errorOpenIDConfiguration;
    }

    // DECISION: Same mutual exclusion pattern as OAuthBearerTokenCallback — token() clears
    // errors, error() clears token. Maintains single-outcome invariant.
    /**
     * Set the token. The token value is unchanged and is expected to match the
     * provided token's value. All error values are cleared.
     * 
     * @param token
     *            the mandatory token to set
     */
    public void token(OAuthBearerToken token) {
        this.token = Objects.requireNonNull(token);
        this.errorStatus = null;
        this.errorScope = null;
        this.errorOpenIDConfiguration = null;
    }

    /**
     * Set the error values as per
     * <a href="https://tools.ietf.org/html/rfc7628#section-3.2.2">RFC 7628: A Set
     * of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth</a>.
     * Any token is cleared.
     * 
     * @param errorStatus
     *            the mandatory error status value from the <a href=
     *            "https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error">IANA
     *            OAuth Extensions Error Registry</a> to set
     * @param errorScope
     *            the optional error scope value to set
     * @param errorOpenIDConfiguration
     *            the optional error openid-configuration value to set
     */
    public void error(String errorStatus, String errorScope, String errorOpenIDConfiguration) {
        if (Objects.requireNonNull(errorStatus).isEmpty())
            throw new IllegalArgumentException("error status must not be empty");
        this.errorStatus = errorStatus;
        this.errorScope = errorScope;
        this.errorOpenIDConfiguration = errorOpenIDConfiguration;
        this.token = null;
    }
}
