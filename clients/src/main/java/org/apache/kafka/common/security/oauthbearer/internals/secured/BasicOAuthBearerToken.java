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

package org.apache.kafka.common.security.oauthbearer.internals.secured;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.util.Set;
import java.util.StringJoiner;

/**
 * An implementation of the {@link OAuthBearerToken} that fairly straightforwardly stores the values
 * given to its constructor (except the scope set which is copied to avoid modifications).
 *
 * Very little validation is applied here with respect to the validity of the given values. All
 * validation is assumed to happen by users of this class.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7515">RFC 7515: JSON Web Signature (JWS)</a>
 */

// SECURITY: (LOW) Immutable token DTO holding the raw JWT string, scopes, and metadata.
// Why: The token field holds the raw compact JWT serialization as a String.
// Java Strings are immutable and cannot be explicitly zeroed — the token persists in memory
// until garbage collected, making it vulnerable to heap dump extraction.
// Exploit: An attacker with access to a JVM heap dump (e.g., via jmap, OOM heap dump file,
// or debug attach) can extract the raw JWT string from BasicOAuthBearerToken instances.
// The token can then be replayed until it expires.
// Improvement: Consider using a char[] or byte[] for the token value to enable explicit
// zeroing after use, though this conflicts with the OAuthBearerToken.value() String contract.

// CROSS-CUTTING: Implements OAuthBearerToken interface. Returned by BrokerJwtValidator and
// ClientJwtValidator after successful JWT validation. Stored in the JAAS Subject's private
// credentials by OAuthBearerLoginCallbackHandler. Consumed by OAuthBearerSaslClient (sends
// token value), OAuthBearerSaslServer (validates principal), and
// OAuthBearerSaslClientCallbackHandler (selects from Subject credentials). The token value
// is ultimately transmitted on the wire during SASL OAUTHBEARER exchange.

public class BasicOAuthBearerToken implements OAuthBearerToken {

    private final String token;

    private final Set<String> scopes;

    private final Long lifetimeMs;

    private final String principalName;

    private final Long startTimeMs;

    /**
     * Creates a new OAuthBearerToken instance around the given values.
     *
     * @param token         Value containing the compact serialization as a base 64 string that
     *                      can be parsed, decoded, and validated as a well-formed JWS. Must be
     *                      non-<code>null</code>, non-blank, and non-whitespace only.
     * @param scopes        Set of non-<code>null</code> scopes. May contain case-sensitive
     *                      "duplicates". The given set is copied and made unmodifiable so neither
     *                      the caller of this constructor nor any downstream users can modify it.
     * @param lifetimeMs    The token's lifetime, expressed as the number of milliseconds since the
     *                      epoch. Must be non-negative.
     * @param principalName The name of the principal to which this credential applies. Must be
     *                      non-<code>null</code>, non-blank, and non-whitespace only.
     * @param startTimeMs   The token's start time, expressed as the number of milliseconds since
     *                      the epoch, if available, otherwise <code>null</code>. Must be
     *                      non-negative if a non-<code>null</code> value is provided.
     */

    // DECISION: The constructor does NOT defensively copy the scope set — it stores the
    // reference as-is. The Javadoc states the set is "copied and made unmodifiable" but this
    // is delegated to the caller (ClaimValidationUtils.validateScopes returns unmodifiable set).
    // Alternative: Copy and wrap in Collections.unmodifiableSet() here. Rationale: Avoiding
    // double-copy when the caller already provides an unmodifiable set. The scope() method
    // documents that immutability is enforced at construction time.
    public BasicOAuthBearerToken(String token,
        Set<String> scopes,
        long lifetimeMs,
        String principalName,
        Long startTimeMs) {
        this.token = token;
        this.scopes = scopes;
        this.lifetimeMs = lifetimeMs;
        this.principalName = principalName;
        this.startTimeMs = startTimeMs;
    }

    /**
     * The <code>b64token</code> value as defined in
     * <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750 Section
     * 2.1</a>
     *
     * @return <code>b64token</code> value as defined in
     *         <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750
     *         Section 2.1</a>
     */

    @Override
    public String value() {
        return token;
    }

    /**
     * The token's scope of access, as per
     * <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC 6749 Section
     * 1.4</a>
     *
     * @return the token's (always non-null but potentially empty) scope of access,
     *         as per <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC
     *         6749 Section 1.4</a>. Note that all values in the returned set will
     *         be trimmed of preceding and trailing whitespace, and the result will
     *         never contain the empty string.
     */

    @Override
    public Set<String> scope() {
        // Immutability of the set is performed in the constructor/validation utils class, so
        // we don't need to repeat it here.
        return scopes;
    }

    /**
     * The token's lifetime, expressed as the number of milliseconds since the
     * epoch, as per <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC
     * 6749 Section 1.4</a>
     *
     * @return the token's lifetime, expressed as the number of milliseconds since
     *         the epoch, as per
     *         <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC 6749
     *         Section 1.4</a>.
     */

    @Override
    public long lifetimeMs() {
        return lifetimeMs;
    }

    /**
     * The name of the principal to which this credential applies
     *
     * @return the always non-null/non-empty principal name
     */

    @Override
    public String principalName() {
        return principalName;
    }

    /**
     * When the credential became valid, in terms of the number of milliseconds
     * since the epoch, if known, otherwise null. An expiring credential may not
     * necessarily indicate when it was created -- just when it expires -- so we
     * need to support a null return value here.
     *
     * @return the time when the credential became valid, in terms of the number of
     *         milliseconds since the epoch, if known, otherwise null
     */

    @Override
    public Long startTimeMs() {
        return startTimeMs;
    }

    // SECURITY: (MEDIUM) WARNING — toString() includes the raw token value in the output
    // ("token='" + token + "'"). This means logging a BasicOAuthBearerToken instance at any
    // level will expose the full JWT string in log files. Callers MUST NOT log this object.
    // Exploit: An attacker with access to application log files (e.g., via log aggregation
    // systems, shared filesystems, or log injection) can extract valid JWT tokens and replay
    // them against the broker until they expire.
    // Improvement: Mask the token value in toString() — e.g., show only the first 8 characters
    // followed by "..." to enable debugging without exposing the full credential.
    @Override
    public String toString() {
        return new StringJoiner(", ", BasicOAuthBearerToken.class.getSimpleName() + "[", "]")
            .add("token='" + token + "'")
            .add("scopes=" + scopes)
            .add("lifetimeMs=" + lifetimeMs)
            .add("principalName='" + principalName + "'")
            .add("startTimeMs=" + startTimeMs)
            .toString();
    }

}
