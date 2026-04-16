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

import java.util.Set;

/**
 * The <code>b64token</code> value as defined in
 * <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750 Section
 * 2.1</a> along with the token's specific scope and lifetime and principal
 * name.
 * <p>
 * A network request would be required to re-hydrate an opaque token, and that
 * could result in (for example) an {@code IOException}, but retrievers for
 * various attributes ({@link #scope()}, {@link #lifetimeMs()}, etc.) declare no
 * exceptions. Therefore, if a network request is required for any of these
 * retriever methods, that request could be performed at construction time so
 * that the various attributes can be reliably provided thereafter. For example,
 * a constructor might declare {@code throws IOException} in such a case.
 * Alternatively, the retrievers could throw unchecked exceptions.
 * <p>
 * 
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC 6749
 *      Section 1.4</a> and
 *      <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750
 *      Section 2.1</a>
 */
// SECURITY: SEC-OAUTH-035 (MEDIUM) Token interface exposing the raw b64token value via value().
// Why: The value() method returns the complete bearer token string — anyone with a
// reference to an OAuthBearerToken instance can extract and reuse the raw token.
// Exploit: If OAuthBearerToken instances are logged, serialized, or exposed via JMX,
// the raw token value becomes available to attackers for replay attacks.
// Improvement: Consider a token type that redacts value() in toString() and prevents
// accidental serialization (mark as transient or implement custom serialization).
//
// CROSS-CUTTING: Core token contract consumed by the entire OAUTHBEARER stack:
// - OAuthBearerLoginModule (stores in Subject's private credentials)
// - OAuthBearerSaslClient (sends value() to broker during SASL exchange)
// - OAuthBearerSaslServer (validates and exposes via negotiated properties)
// - OAuthBearerValidatorCallback/OAuthBearerTokenCallback (callback transport)
// - ExpiringCredential (refresh scheduling based on lifetimeMs/startTimeMs)
// Implementations: internals/secured/BasicOAuthBearerToken, internals/unsecured/
// OAuthBearerUnsecuredJws. Changes to this interface affect all OAUTHBEARER auth paths.
public interface OAuthBearerToken {
    /**
     * The <code>b64token</code> value as defined in
     * <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750 Section
     * 2.1</a>
     * 
     * @return <code>b64token</code> value as defined in
     *         <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750
     *         Section 2.1</a>
     */
    String value();

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
    // DECISION: scope() returns non-null Set (potentially empty). Alternative: Nullable set.
    // Rationale: Non-null contract simplifies caller code — no null checks needed. Empty set
    // semantics = no scopes granted, which is the restrictive default.
    Set<String> scope();

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
    // DECISION: Named "lifetimeMs" (absolute timestamp) rather than "expiresIn" (relative
    // duration). Alternative: Relative duration from creation. Rationale: Absolute timestamp
    // avoids ambiguity about the reference point (creation time vs current time) and is
    // directly comparable with System.currentTimeMillis() for expiration checks.
    long lifetimeMs();

    /**
     * The name of the principal to which this credential applies
     * 
     * @return the always non-null/non-empty principal name
     */
    String principalName();

    /**
     * When the credential became valid, in terms of the number of milliseconds
     * since the epoch, if known, otherwise null. An expiring credential may not
     * necessarily indicate when it was created -- just when it expires -- so we
     * need to support a null return value here.
     * 
     * @return the time when the credential became valid, in terms of the number of
     *         milliseconds since the epoch, if known, otherwise null
     */
    // DECISION: startTimeMs() returns nullable Long. Alternative: Default to 0 or throw
    // UnsupportedOperationException. Rationale: OAuth tokens may not include an "iat" claim
    // (though Kafka's validators require it) — the nullable contract supports interop with
    // external token implementations that don't provide issuance time.
    Long startTimeMs();
}
