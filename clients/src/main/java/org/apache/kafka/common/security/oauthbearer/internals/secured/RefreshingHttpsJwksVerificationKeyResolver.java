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

import org.apache.kafka.common.KafkaException;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.Key;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;

/**
 * <code>RefreshingHttpsJwksVerificationKeyResolver</code> is a
 * {@link VerificationKeyResolver} implementation that will periodically refresh the
 * JWKS using its {@link HttpsJwks} instance.
 *
 * A <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5">JWKS (JSON Web Key Set)</a>
 * is a JSON document provided by the OAuth/OIDC provider that lists the keys used to sign the JWTs
 * it issues.
 *
 * Here is a sample JWKS JSON document:
 *
 * <pre>
 * {
 *   "keys": [
 *     {
 *       "kty": "RSA",
 *       "alg": "RS256",
 *       "kid": "abc123",
 *       "use": "sig",
 *       "e": "AQAB",
 *       "n": "..."
 *     },
 *     {
 *       "kty": "RSA",
 *       "alg": "RS256",
 *       "kid": "def456",
 *       "use": "sig",
 *       "e": "AQAB",
 *       "n": "..."
 *     }
 *   ]
 * }
 * </pre>
 *
 * Without going into too much detail, the array of keys enumerates the key data that the provider
 * is using to sign the JWT. The key ID (<code>kid</code>) is referenced by the JWT's header in
 * order to match up the JWT's signing key with the key in the JWKS. During the validation step of
 * the broker, the jose4j OAuth library will use the contents of the appropriate key in the JWKS
 * to validate the signature.
 *
 * Given that the JWKS is referenced by the JWT, the JWKS must be made available by the
 * OAuth/OIDC provider so that a JWT can be validated.
 *
 * @see CloseableVerificationKeyResolver
 * @see VerificationKeyResolver
 * @see RefreshingHttpsJwks
 * @see HttpsJwks
 */
// SECURITY: (HIGH) JWKS refresh window creates a staleness exploit surface.
// Why: This resolver delegates to RefreshingHttpsJwks which caches JWKS with a periodic refresh.
// Between refreshes, the cache may contain stale keys. After an OAuth provider rotates keys,
// tokens signed with the NEW key will fail validation until the cache refreshes, while tokens
// signed with the OLD (potentially compromised) key continue to be accepted.
// Exploit: After JWKS key rotation at the provider, an attacker with a token signed by the old
// key has a window of up to refreshMs (default: 1 hour) to replay the token. Conversely, a
// provider-side emergency key revocation will not take effect until the next refresh cycle.
// Improvement: Configurable refresh intervals with jitter to prevent thundering herd on the
// JWKS endpoint. Consider an on-demand refresh when signature verification fails with a
// known key ID but invalid signature (possible indicator of key rotation in progress).
//
// DECISION: Delegates to RefreshingHttpsJwks for JWKS management rather than embedding HTTP
// refresh logic directly. Alternatives: (1) Direct JWKS fetch on every resolveKey() call,
// (2) jose4j's built-in HttpsJwksVerificationKeyResolver. Rationale: Separation of concerns --
// this class handles key selection via VerificationJwkSelector, while RefreshingHttpsJwks
// handles the refresh lifecycle, caching, and concurrency. jose4j's built-in resolver uses
// blocking HTTP in the hot path; this design avoids that by pre-caching JWKS.
//
// CROSS-CUTTING: Depends on RefreshingHttpsJwks (JWKS cache + refresh lifecycle),
// jose4j VerificationJwkSelector (JWK-to-JWS matching), jose4j HttpsJwks (HTTP client).
// Used by: VerificationKeyResolverFactory.create() which instantiates this resolver when
// the JWKS endpoint URL uses https:// or http:// protocol (not file://).
// Consumed by: BrokerJwtValidator and DefaultJwtValidator via jose4j's JwtConsumer which
// uses this as the VerificationKeyResolver for JWT signature validation.
// Contract: configure() must be called before resolveKey(). close() stops the refresh thread.
// Impact: Changes to RefreshingHttpsJwks cache/refresh logic directly affect JWT validation
// latency and availability for all OAUTHBEARER broker-side authentication.
public class RefreshingHttpsJwksVerificationKeyResolver implements CloseableVerificationKeyResolver {

    private static final Logger log = LoggerFactory.getLogger(RefreshingHttpsJwksVerificationKeyResolver.class);

    private final RefreshingHttpsJwks refreshingHttpsJwks;

    // DECISION: Uses jose4j's VerificationJwkSelector for JWK-to-JWS matching rather than manual
    // kid lookup. Rationale: VerificationJwkSelector handles algorithm matching, key use filtering,
    // and multi-key scenarios (e.g., multiple RSA keys with different kid values) per the JOSE spec.
    private final VerificationJwkSelector verificationJwkSelector;

    private boolean isInitialized;

    public RefreshingHttpsJwksVerificationKeyResolver(RefreshingHttpsJwks refreshingHttpsJwks) {
        this.refreshingHttpsJwks = refreshingHttpsJwks;
        this.verificationJwkSelector = new VerificationJwkSelector();
    }

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        try {
            log.debug("configure started");
            refreshingHttpsJwks.init();
        } catch (IOException e) {
            throw new KafkaException(e);
        } finally {
            // DECISION: isInitialized set in finally block -- even if init() throws IOException,
            // the resolver is marked initialized. This prevents repeated init() attempts on
            // transient failures. The exception is re-thrown as KafkaException, so the caller
            // still sees the failure. Alternative: Only set isInitialized on success. Risk:
            // Repeated init() calls could cause resource leaks (duplicate
            // ScheduledExecutorService instances in RefreshingHttpsJwks).
            isInitialized = true;
        }
    }

    @Override
    public void close() {
        try {
            log.debug("close started");

            refreshingHttpsJwks.close();
        } finally {
            log.debug("close completed");
        }
    }

    // SECURITY: (HIGH) Key resolution from cached JWKS. If no matching key is found, an expedited
    // refresh is triggered via maybeExpediteRefresh(keyId). This means an unknown keyId triggers
    // network I/O to the JWKS endpoint. A malicious client sending JWTs with random kid values
    // could trigger excessive JWKS endpoint requests (cache-busting DoS). The missingKeyIds cache
    // in RefreshingHttpsJwks mitigates this by rate-limiting refresh attempts per keyId, but the
    // cache has a fixed size (16 entries) which could be exhausted by rotating keyIds.
    // Improvement: Add a global rate limiter on expedited refresh attempts (e.g., max N per minute).
    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        // SECURITY: (MEDIUM) Fail-fast if configure() hasn't been called. This prevents resolveKey()
        // from operating on uninitialized state. Note: isInitialized is not volatile -- in a
        // multi-threaded environment, there's a theoretical visibility issue if resolveKey() is
        // called from a different thread than configure(). In practice, Kafka's authentication
        // path ensures ordering.
        if (!isInitialized)
            throw new IllegalStateException("Please call configure() first");

        try {
            List<JsonWebKey> jwks = refreshingHttpsJwks.getJsonWebKeys();
            JsonWebKey jwk = verificationJwkSelector.select(jws, jwks);

            if (jwk != null)
                return jwk.getKey();

            String keyId = jws.getKeyIdHeaderValue();

            if (refreshingHttpsJwks.maybeExpediteRefresh(keyId))
                log.debug("Refreshing JWKs from {} as no suitable verification key for JWS w/ header {} was found in {}", refreshingHttpsJwks.getLocation(), jws.getHeaders().getFullHeaderAsJsonString(), jwks);

            String sb = "Unable to find a suitable verification key for JWS w/ header " + jws.getHeaders().getFullHeaderAsJsonString() +
                    " from JWKs " + jwks + " obtained from " +
                    refreshingHttpsJwks.getLocation();
            throw new UnresolvableKeyException(sb);
        } catch (JoseException | IOException e) {
            String sb = "Unable to find a suitable verification key for JWS w/ header " + jws.getHeaders().getFullHeaderAsJsonString() +
                    " due to an unexpected exception (" + e + ") while obtaining or using keys from JWKS endpoint at " +
                    refreshingHttpsJwks.getLocation();
            throw new UnresolvableKeyException(sb, e);
        }
    }
}
