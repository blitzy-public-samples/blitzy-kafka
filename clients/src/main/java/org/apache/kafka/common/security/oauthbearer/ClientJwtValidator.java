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

import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.internals.secured.ClaimValidationUtils;
import org.apache.kafka.common.security.oauthbearer.internals.secured.ConfigurationUtils;
import org.apache.kafka.common.security.oauthbearer.internals.secured.SerializedJwt;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerIllegalTokenException;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerUnsecuredJws;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.login.AppConfigurationEntry;

import static org.apache.kafka.common.config.SaslConfigs.DEFAULT_SASL_OAUTHBEARER_SCOPE_CLAIM_NAME;
import static org.apache.kafka.common.config.SaslConfigs.DEFAULT_SASL_OAUTHBEARER_SUB_CLAIM_NAME;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_SCOPE_CLAIM_NAME;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_SUB_CLAIM_NAME;

/**
 * {@code ClientJwtValidator} is an implementation of {@link JwtValidator} that is used
 * by the client to perform some rudimentary validation of the JWT access token that is received
 * as part of the response from posting the client credentials to the OAuth/OIDC provider's
 * token endpoint.
 *
 * The validation steps performed are:
 *
 * <ol>
 *     <li>
 *         Basic structural validation of the <code>b64token</code> value as defined in
 *         <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750 Section 2.1</a>
 *     </li>
 *     <li>Basic conversion of the token into an in-memory map</li>
 *     <li>Presence of <code>scope</code>, <code>exp</code>, <code>subject</code>, and <code>iat</code> claims</li>
 * </ol>
 *
 * @implNote DECISION: Uses OAuthBearerUnsecuredJws.toMap() for token parsing rather
 * than jose4j. Alternatives: (1) Use jose4j JwtConsumer with signature verification
 * disabled, (2) Use Jackson ObjectMapper directly. Rationale: The client does not
 * need jose4j's heavyweight JWKS integration. OAuthBearerUnsecuredJws provides a
 * minimal, already-available Base64+JSON parser. Risk: Couples client validation to
 * the "unsecured" code path which could be confusing — the client IS doing unsecured
 * parsing even in production, by design.
 */

// SECURITY: (HIGH) Client-side JWT parsing — performs ONLY structural validation,
// NOT cryptographic signature verification. This is by design (broker does full
// verification).
// Why: Client-side validation is a lightweight sanity check before sending the
// token to the broker. No JWKS resolution occurs on the client side.
// Exploit: Token tampering — if a MITM intercepts the token between the OAuth
// provider and the client, they could modify claims (e.g., elevate scope, change
// subject) before the token reaches the broker. Since the client does not verify
// the signature, the tampered token would pass client-side validation. The
// broker's BrokerJwtValidator will catch this IF JWKS-based validation is
// properly configured.
// Improvement: Client should optionally validate token signature locally before
// sending, using a configurable JWKS endpoint. This provides defense-in-depth
// against token tampering in transit.

// CROSS-CUTTING: Depends on internals/secured/BasicOAuthBearerToken (token DTO),
// internals/secured/ClaimValidationUtils (claim validation),
// internals/secured/ConfigurationUtils (config resolution),
// internals/secured/SerializedJwt (JWT parsing),
// internals/unsecured/OAuthBearerUnsecuredJws (Base64+JSON map conversion).
// Used by OAuthBearerLoginCallbackHandler on the client side.
// Contract: Stateless after configure(). Thread-safe for concurrent validate()
// calls.

public class ClientJwtValidator implements JwtValidator {

    private static final Logger log = LoggerFactory.getLogger(ClientJwtValidator.class);

    // DECISION: Uses string constants for claim names rather than jose4j's
    // ReservedClaimNames. Alternative: Import jose4j constants. Rationale:
    // Client-side code should not depend on jose4j which is a broker-only
    // dependency. Using string constants avoids the dependency.
    public static final String EXPIRATION_CLAIM_NAME = "exp";

    public static final String ISSUED_AT_CLAIM_NAME = "iat";

    private String scopeClaimName;

    private String subClaimName;

    // DECISION: Claim name overrides (scope, sub) validated via
    // ClaimValidationUtils to ensure non-empty. This allows OAuth providers
    // using non-standard claim names (e.g., "scp" for scope, "email" for
    // subject) to work with Kafka without code changes.
    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        ConfigurationUtils cu = new ConfigurationUtils(configs, saslMechanism);
        this.scopeClaimName = ClaimValidationUtils.validateClaimNameOverride(
            DEFAULT_SASL_OAUTHBEARER_SCOPE_CLAIM_NAME,
            cu.get(SASL_OAUTHBEARER_SCOPE_CLAIM_NAME)
        );
        this.subClaimName = ClaimValidationUtils.validateClaimNameOverride(
            DEFAULT_SASL_OAUTHBEARER_SUB_CLAIM_NAME,
            cu.get(SASL_OAUTHBEARER_SUB_CLAIM_NAME)
        );
    }

    /**
     * Accepts an OAuth JWT access token in base-64 encoded format, validates, and returns an
     * OAuthBearerToken.
     *
     * @param accessToken Non-<code>null</code> JWT access token
     * @return {@link OAuthBearerToken}
     * @throws JwtValidatorException Thrown on errors performing validation of given token
     */

    // COMPLEXITY: 37 lines — Multi-phase claim extraction and validation
    // pipeline.
    // Structure: (1) Parse SerializedJwt, (2) Deserialize payload via
    // toMap(), (3) Extract scopeRaw with type dispatch
    // (String|Collection|empty), (4) Extract exp/sub/iat as Number/String,
    // (5) Validate via ClaimValidationUtils, (6) Convert epoch-seconds to
    // millis, (7) Construct BasicOAuthBearerToken.
    // Key branches: scopeRaw type dispatch (3 paths), null checks on
    // exp/iat for millis conversion.
    // Error path: OAuthBearerIllegalTokenException → JwtValidatorException.
    @SuppressWarnings("unchecked")
    public OAuthBearerToken validate(String accessToken) throws JwtValidatorException {
        SerializedJwt serializedJwt = new SerializedJwt(accessToken);
        Map<String, Object> payload;

        // SECURITY: (HIGH) Uses OAuthBearerUnsecuredJws.toMap() which performs
        // Base64 decoding and JSON deserialization WITHOUT signature
        // verification. This means the token payload is parsed from
        // potentially untrusted data — malformed JSON or oversized payloads
        // could cause excessive memory allocation. The
        // OAuthBearerIllegalTokenException catches structural issues but not
        // resource exhaustion.
        // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
        // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
        try {
            payload = OAuthBearerUnsecuredJws.toMap(serializedJwt.getPayload());
        } catch (OAuthBearerIllegalTokenException e) {
            throw new JwtValidatorException(String.format("Could not validate the access token: %s", e.getMessage()), e);
        }

        Object scopeRaw = getClaim(payload, scopeClaimName);
        Collection<String> scopeRawCollection;

        // SECURITY: (MEDIUM) Scope type coercion — same fail-closed pattern
        // as BrokerJwtValidator. Unexpected types default to empty set
        // (no scopes = restricted access).
        // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
        // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
        if (scopeRaw instanceof String)
            scopeRawCollection = Collections.singletonList((String) scopeRaw);
        else if (scopeRaw instanceof Collection)
            scopeRawCollection = (Collection<String>) scopeRaw;
        else
            scopeRawCollection = Collections.emptySet();

        Number expirationRaw = (Number) getClaim(payload, EXPIRATION_CLAIM_NAME);
        String subRaw = (String) getClaim(payload, subClaimName);
        Number issuedAtRaw = (Number) getClaim(payload, ISSUED_AT_CLAIM_NAME);

        Set<String> scopes = ClaimValidationUtils.validateScopes(scopeClaimName, scopeRawCollection);
        // SECURITY: (LOW) Numeric claim values are multiplied by 1000L to
        // convert epoch seconds to milliseconds. Integer overflow is
        // theoretically possible for timestamps far in the future
        // (~year 292278994) but practically irrelevant for token lifetimes.
        // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
        // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
        long expiration = ClaimValidationUtils.validateExpiration(EXPIRATION_CLAIM_NAME,
            expirationRaw != null ? expirationRaw.longValue() * 1000L : null);
        String subject = ClaimValidationUtils.validateSubject(subClaimName, subRaw);
        Long issuedAt = ClaimValidationUtils.validateIssuedAt(ISSUED_AT_CLAIM_NAME,
            issuedAtRaw != null ? issuedAtRaw.longValue() * 1000L : null);

        return new BasicOAuthBearerToken(accessToken,
            scopes,
            expiration,
            subject,
            issuedAt);
    }

    private Object getClaim(Map<String, Object> payload, String claimName) {
        Object value = payload.get(claimName);
        log.debug("getClaim - {}: {}", claimName, value);
        return value;
    }

}
