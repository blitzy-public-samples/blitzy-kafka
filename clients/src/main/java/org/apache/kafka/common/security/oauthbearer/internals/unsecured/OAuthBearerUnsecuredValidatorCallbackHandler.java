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
package org.apache.kafka.common.security.oauthbearer.internals.unsecured;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerExtensionsValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.utils.Time;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

/**
 * A {@code CallbackHandler} that recognizes
 * {@link OAuthBearerValidatorCallback} and validates an unsecured OAuth 2
 * bearer token. It requires there to be an <code>"exp" (Expiration Time)</code>
 * claim of type Number. If <code>"iat" (Issued At)</code> or
 * <code>"nbf" (Not Before)</code> claims are present each must be a number that
 * precedes the Expiration Time claim, and if both are present the Not Before
 * claim must not precede the Issued At claim. It also accepts the following
 * options, none of which are required:
 * <ul>
 * <li>{@code unsecuredValidatorPrincipalClaimName} set to a non-empty value if
 * you wish a particular String claim holding a principal name to be checked for
 * existence; the default is to check for the existence of the '{@code sub}'
 * claim</li>
 * <li>{@code unsecuredValidatorScopeClaimName} set to a custom claim name if
 * you wish the name of the String or String List claim holding any token scope
 * to be something other than '{@code scope}'</li>
 * <li>{@code unsecuredValidatorRequiredScope} set to a space-delimited list of
 * scope values if you wish the String/String List claim holding the token scope
 * to be checked to make sure it contains certain values</li>
 * <li>{@code unsecuredValidatorAllowableClockSkewMs} set to a positive integer
 * value if you wish to allow up to some number of positive milliseconds of
 * clock skew (the default is 0)</li>
 * <ul>
 * For example:
 *
 * <pre>
 * KafkaServer {
 *      org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule Required
 *      unsecuredLoginStringClaim_sub="thePrincipalName"
 *      unsecuredLoginListClaim_scope=",KAFKA_BROKER,LOGIN_TO_KAFKA"
 *      unsecuredValidatorRequiredScope="LOGIN_TO_KAFKA"
 *      unsecuredValidatorAllowableClockSkewMs="3000";
 * };
 * </pre>
 * It also recognizes {@link OAuthBearerExtensionsValidatorCallback} and validates every extension passed to it.
 *
 * This class is the default when the SASL mechanism is OAUTHBEARER and no value
 * is explicitly set via the
 * {@code listener.name.sasl_[plaintext|ssl].oauthbearer.sasl.server.callback.handler.class}
 * broker configuration property.
 * It is worth noting that this class is not suitable for production use due to the use of unsecured JWT tokens and
 * validation of every given extension.
 */
// SECURITY: (CRITICAL) DEVELOPMENT ONLY -- NO PRODUCTION USE.
// This unsecured implementation accepts tokens without signature verification.
// A bad actor can forge any token with arbitrary claims (scope, subject, expiry).
// Using this in production allows complete authentication bypass.
// Improvement: Add a runtime check that logs CRITICAL-level warning when
// unsecured OAUTHBEARER is used in non-test contexts. Consider adding a
// system property or config flag to explicitly enable unsecured mode.
//
// CROSS-CUTTING: Depends on OAuthBearerUnsecuredJws (token parsing, same package),
// OAuthBearerValidationUtils (claim validation, same package),
// OAuthBearerValidationResult (validation result type, same package),
// OAuthBearerScopeUtils (scope parsing, same package),
// OAuthBearerLoginModule.OAUTHBEARER_MECHANISM (mechanism name constant).
// Used by: authenticator/SaslServerAuthenticator via SASL callback handler SPI.
// This is the default server-side validator when no custom
// sasl.server.callback.handler.class is configured for OAUTHBEARER.
// Contract: configure() -> handle() lifecycle. Single-threaded per SASL exchange.
// Impact: Replacing this handler with a secured implementation (e.g.,
// OAuthBearerValidatorCallbackHandler using JWKS) is the REQUIRED step for production.
// Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
public class OAuthBearerUnsecuredValidatorCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger log = LoggerFactory.getLogger(OAuthBearerUnsecuredValidatorCallbackHandler.class);
    private static final String OPTION_PREFIX = "unsecuredValidator";
    private static final String PRINCIPAL_CLAIM_NAME_OPTION = OPTION_PREFIX + "PrincipalClaimName";
    private static final String SCOPE_CLAIM_NAME_OPTION = OPTION_PREFIX + "ScopeClaimName";
    private static final String REQUIRED_SCOPE_OPTION = OPTION_PREFIX + "RequiredScope";
    private static final String ALLOWABLE_CLOCK_SKEW_MILLIS_OPTION = OPTION_PREFIX + "AllowableClockSkewMs";
    private Time time = Time.SYSTEM;
    private Map<String, String> moduleOptions = null;
    private boolean configured = false;

    /**
     * For testing
     *
     * @param time
     *            the mandatory time to set
     */
    void time(Time time) {
        this.time = Objects.requireNonNull(time);
    }

    /**
     * Return true if this instance has been configured, otherwise false
     *
     * @return true if this instance has been configured, otherwise false
     */
    public boolean configured() {
        return configured;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        if (Objects.requireNonNull(jaasConfigEntries).size() != 1 || jaasConfigEntries.get(0) == null)
            throw new IllegalArgumentException(
                    String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)",
                            jaasConfigEntries.size()));
        this.moduleOptions = Collections
                .unmodifiableMap((Map<String, String>) jaasConfigEntries.get(0).getOptions());
        configured = true;
        // SECURITY: (MEDIUM) Configuration captured from JAAS options without sanitization.
        // moduleOptions may contain attacker-controlled values if the JAAS config file is
        // writable. No validation is performed on option values until handle() is called.
        // Exploit: A malformed JAAS configuration could disable authentication or load a malicious login module.
        // Improvement: Validate JAAS configurations at startup and restrict login module classes to an allowlist.
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        if (!configured())
            throw new IllegalStateException("Callback handler not configured");
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerValidatorCallback) {
                OAuthBearerValidatorCallback validationCallback = (OAuthBearerValidatorCallback) callback;
                try {
                    handleCallback(validationCallback);
                } catch (OAuthBearerIllegalTokenException e) {
                    OAuthBearerValidationResult failureReason = e.reason();
                    String failureScope = failureReason.failureScope();
                    validationCallback.error(failureScope != null ? "insufficient_scope" : "invalid_token",
                            failureScope, failureReason.failureOpenIdConfig());
                }
            // SECURITY: (MEDIUM) All extensions are accepted unconditionally:
            // extensionsCallback.valid(extensionName) for every extension. In a production
            // validator, extensions should be validated against an allowlist.
            // Exploit: A malicious client can inject arbitrary SASL extensions that
            // downstream code (custom authorizers, audit loggers) may process unsafely.
            // Improvement: At minimum, log accepted extensions at DEBUG level for audit.
            } else if (callback instanceof OAuthBearerExtensionsValidatorCallback) {
                OAuthBearerExtensionsValidatorCallback extensionsCallback = (OAuthBearerExtensionsValidatorCallback) callback;
                extensionsCallback.inputExtensions().map().forEach((extensionName, v) -> extensionsCallback.valid(extensionName));
            } else
                throw new UnsupportedCallbackException(callback);
        }
    }

    @Override
    public void close() {
        // empty
    }

    // SECURITY: (CRITICAL) Validates unsecured tokens -- constructs OAuthBearerUnsecuredJws
    // and runs claim checks. Since tokens have NO cryptographic signature, validation only
    // checks structural validity (3-part JWS format, alg=none, non-empty signature segment)
    // and claim semantics (expiry, not-before, scope, principal existence). None of these
    // checks require cryptographic verification.
    // Exploit: An attacker can forge a token by: (1) Base64URL-encoding {"alg":"none"} as
    // header, (2) Base64URL-encoding any claims payload (e.g., {"sub":"admin",
    // "exp":999999999999,"scope":"cluster-admin"}), (3) concatenating header.payload.
    // (empty signature). This passes all validations because no signature is checked.
    // Improvement: Log principal name and token claims at WARN level when unsecured
    // validation is used, to create an audit trail. Reject tokens in production entirely.
    private void handleCallback(OAuthBearerValidatorCallback callback) {
        String tokenValue = callback.tokenValue();
        if (tokenValue == null)
            throw new IllegalArgumentException("Callback missing required token value");
        String principalClaimName = principalClaimName();
        String scopeClaimName = scopeClaimName();
        List<String> requiredScope = requiredScope();
        int allowableClockSkewMs = allowableClockSkewMs();
        OAuthBearerUnsecuredJws unsecuredJwt = new OAuthBearerUnsecuredJws(tokenValue, principalClaimName,
                scopeClaimName);
        long now = time.milliseconds();
        // DECISION: Validation checks are ordered: (1) principal claim existence,
        // (2) issued-at time, (3) expiration time, (4) time consistency (iat < exp),
        // (5) scope membership. Alternative: Validate all claims and collect all
        // failures before throwing. Rationale: Fail-fast approach -- first validation
        // failure throws immediately via throwExceptionIfFailed(). This is simpler but
        // means the client receives only the first error, not all errors. For
        // development/test use, fast failure is acceptable.
        OAuthBearerValidationUtils
                .validateClaimForExistenceAndType(unsecuredJwt, true, principalClaimName, String.class)
                .throwExceptionIfFailed();
        OAuthBearerValidationUtils.validateIssuedAt(unsecuredJwt, false, now, allowableClockSkewMs)
                .throwExceptionIfFailed();
        OAuthBearerValidationUtils.validateExpirationTime(unsecuredJwt, now, allowableClockSkewMs)
                .throwExceptionIfFailed();
        OAuthBearerValidationUtils.validateTimeConsistency(unsecuredJwt).throwExceptionIfFailed();
        OAuthBearerValidationUtils.validateScope(unsecuredJwt, requiredScope).throwExceptionIfFailed();
        log.info("Successfully validated token with principal {}: {}", unsecuredJwt.principalName(),
                unsecuredJwt.claims());
        callback.token(unsecuredJwt);
    }

    // DECISION: Default principal claim is "sub" and scope claim is "scope", matching
    // standard JWT/OIDC conventions. Alternatives: Custom claim names only (no defaults).
    // Rationale: Using "sub" and "scope" as defaults reduces configuration burden for
    // standard-compliant tokens. Custom overrides are available via JAAS options.
    private String principalClaimName() {
        String principalClaimNameValue = option(PRINCIPAL_CLAIM_NAME_OPTION);
        return Utils.isBlank(principalClaimNameValue) ? "sub" : principalClaimNameValue.trim();
    }

    private String scopeClaimName() {
        String scopeClaimNameValue = option(SCOPE_CLAIM_NAME_OPTION);
        return Utils.isBlank(scopeClaimNameValue) ? "scope" : scopeClaimNameValue.trim();
    }

    private List<String> requiredScope() {
        String requiredSpaceDelimitedScope = option(REQUIRED_SCOPE_OPTION);
        return Utils.isBlank(requiredSpaceDelimitedScope) ? Collections.emptyList() : OAuthBearerScopeUtils.parseScope(requiredSpaceDelimitedScope.trim());
    }

    // DECISION: Default clock skew is 0 ms (strict temporal validation). Alternative:
    // Default to a small tolerance (e.g., 5000 ms) to handle clock drift between token
    // issuer and Kafka broker. Rationale: Zero tolerance is the safest default for a
    // development/test validator -- it surfaces timing issues early during development.
    private int allowableClockSkewMs() {
        String allowableClockSkewMsValue = option(ALLOWABLE_CLOCK_SKEW_MILLIS_OPTION);
        int allowableClockSkewMs;
        try {
            allowableClockSkewMs = Utils.isBlank(allowableClockSkewMsValue) ? 0 : Integer.parseInt(allowableClockSkewMsValue.trim());
        } catch (NumberFormatException e) {
            throw new OAuthBearerConfigException(e.getMessage(), e);
        }
        if (allowableClockSkewMs < 0) {
            throw new OAuthBearerConfigException(
                    String.format("Allowable clock skew millis must not be negative: %s", allowableClockSkewMsValue));
        }
        return allowableClockSkewMs;
    }

    private String option(String key) {
        if (!configured)
            throw new IllegalStateException("Callback handler not configured");
        return moduleOptions.get(Objects.requireNonNull(key));
    }
}
