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

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.utils.Time;

import org.jose4j.http.Get;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.UnresolvableKeyException;

import java.io.IOException;
import java.net.URL;
import java.security.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.login.AppConfigurationEntry;

import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_JWKS_ENDPOINT_REFRESH_MS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_JWKS_ENDPOINT_RETRY_BACKOFF_MAX_MS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_JWKS_ENDPOINT_RETRY_BACKOFF_MS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_JWKS_ENDPOINT_URL;

/**
 * Because a {@link CloseableVerificationKeyResolver} instance can spawn threads and issue
 * HTTP(S) calls ({@link RefreshingHttpsJwksVerificationKeyResolver}), we only want to create
 * a new instance for each particular set of configuration. Because each set of configuration
 * may have multiple instances, we want to reuse the single instance.
 */
// CROSS-CUTTING: Depends on ConfigurationUtils (URL validation), JaasOptionsUtils (SSL config),
// RefreshingHttpsJwks (HTTPS JWKS refresh), RefreshingHttpsJwksVerificationKeyResolver,
// JwksFileVerificationKeyResolver, jose4j HttpsJwks and Get (HTTP client).
// Used by: OAuthBearerValidatorCallbackHandler which calls get() during configure() to
// obtain a shared CloseableVerificationKeyResolver for JWT signature validation.
// Contract: get() returns a configured, ref-counted resolver. Callers must call close()
// when done. Thread-safe via synchronized get() method.
// Impact: This factory is the single entry point for all JWKS resolver creation in the
// OAUTHBEARER stack. Changes here affect all broker-side JWT validation.
//
// DECISION: Factory pattern with static HashMap cache keyed by (configs, saslMechanism,
// moduleOptions). Alternatives: (1) Create new resolver per callback handler, (2) Dependency
// injection container. Rationale: JWKS resolvers spawn background threads and HTTP connections
// -- creating one per handler would waste resources. The cache ensures a single resolver per
// unique configuration. The RefCountingVerificationKeyResolver wraps the delegate to manage
// lifecycle across multiple consumers -- configure() only runs once, close() only runs when
// the last consumer disconnects. Risk: Static cache means resolvers live for the JVM lifetime
// unless explicitly closed. Memory leak if configs change frequently (unlikely in practice).
public class VerificationKeyResolverFactory {

    // SECURITY: (MEDIUM) Global static cache of resolver instances keyed by config. This means
    // all OAuthBearerValidatorCallbackHandler instances sharing the same config share a single
    // resolver (and its JWKS cache). A compromised handler could poison the shared resolver's
    // state, affecting all other handlers using the same config.
    // Exploit: In a multi-listener broker with shared OAUTHBEARER config, a vulnerability in
    // one listener's authentication path could corrupt the shared resolver, causing all
    // listeners to accept forged tokens or reject legitimate ones.
    // Improvement: Consider per-listener resolver isolation or immutable resolver instances.
    private static final Map<VerificationKeyResolverKey, CloseableVerificationKeyResolver> CACHE = new HashMap<>();

    // SECURITY: (LOW) Synchronized on class -- serializes resolver creation/retrieval.
    // Prevents race conditions during concurrent callback handler initialization.
    public static synchronized CloseableVerificationKeyResolver get(Map<String, ?> configs,
                                                                    String saslMechanism,
                                                                    List<AppConfigurationEntry> jaasConfigEntries) {
        VerificationKeyResolverKey key = new VerificationKeyResolverKey(configs, saslMechanism, jaasConfigEntries);

        return CACHE.computeIfAbsent(key, k ->
            new RefCountingVerificationKeyResolver(
                create(
                    configs,
                    saslMechanism,
                    jaasConfigEntries
                )
            )
        );
    }

    // SECURITY: (MEDIUM) Resolver type determined by JWKS URL protocol: file:// -> JwksFile,
    // https:// or http:// -> RefreshingHttpsJwks. No validation that https:// is preferred
    // over http:// -- an http:// JWKS endpoint sends keys in cleartext, vulnerable to MITM.
    // Exploit: Attacker intercepts cleartext http:// JWKS response, injects forged signing keys.
    // Improvement: Log a WARN when JWKS endpoint uses http:// (not https://) protocol.
    static CloseableVerificationKeyResolver create(Map<String, ?> configs,
                                                   String saslMechanism,
                                                   List<AppConfigurationEntry> jaasConfigEntries) {
        ConfigurationUtils cu = new ConfigurationUtils(configs, saslMechanism);
        URL jwksEndpointUrl = cu.validateUrl(SASL_OAUTHBEARER_JWKS_ENDPOINT_URL);
        CloseableVerificationKeyResolver resolver;

        if (jwksEndpointUrl.getProtocol().toLowerCase(Locale.ROOT).equals("file")) {
            resolver = new JwksFileVerificationKeyResolver();
        } else {
            long refreshIntervalMs = cu.validateLong(SASL_OAUTHBEARER_JWKS_ENDPOINT_REFRESH_MS, true, 0L);
            JaasOptionsUtils jou = new JaasOptionsUtils(saslMechanism, jaasConfigEntries);
            SSLSocketFactory sslSocketFactory = null;

            if (jou.shouldCreateSSLSocketFactory(jwksEndpointUrl))
                sslSocketFactory = jou.createSSLSocketFactory();

            HttpsJwks httpsJwks = new HttpsJwks(jwksEndpointUrl.toString());
            httpsJwks.setDefaultCacheDuration(refreshIntervalMs);

            if (sslSocketFactory != null) {
                Get get = new Get();
                get.setSslSocketFactory(sslSocketFactory);
                httpsJwks.setSimpleHttpGet(get);
            }

            RefreshingHttpsJwks refreshingHttpsJwks = new RefreshingHttpsJwks(Time.SYSTEM,
                httpsJwks,
                refreshIntervalMs,
                cu.validateLong(SASL_OAUTHBEARER_JWKS_ENDPOINT_RETRY_BACKOFF_MS),
                cu.validateLong(SASL_OAUTHBEARER_JWKS_ENDPOINT_RETRY_BACKOFF_MAX_MS));
            resolver = new RefreshingHttpsJwksVerificationKeyResolver(refreshingHttpsJwks);
        }

        resolver.configure(configs, saslMechanism, jaasConfigEntries);
        return resolver;
    }

    /**
     * <code>VkrKey</code> is a simple structure which encapsulates the criteria for different
     * sets of configuration. This will allow us to use this object as a key in a {@link Map}
     * to keep a single instance per key.
     */

    // DECISION: Cache key uses (configs, saslMechanism, moduleOptions) tuple. Alternatives:
    // (1) Just saslMechanism, (2) Config hash. Rationale: Full config equality ensures
    // different JWKS endpoints or SSL configurations get separate resolvers. moduleOptions
    // are extracted from JAAS config entries via JaasOptionsUtils.getOptions() for stable
    // comparison. Note: configs Map equality uses Map.equals() which compares all entries
    // -- expensive for large config maps but only called during resolver creation (not in
    // the hot path).
    private static class VerificationKeyResolverKey {

        private final Map<String, ?> configs;

        private final String saslMechanism;

        private final Map<String, Object> moduleOptions;

        public VerificationKeyResolverKey(Map<String, ?> configs,
                                          String saslMechanism,
                                          List<AppConfigurationEntry> jaasConfigEntries) {
            this.configs = configs;
            this.saslMechanism = saslMechanism;
            this.moduleOptions = JaasOptionsUtils.getOptions(saslMechanism, jaasConfigEntries);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }

            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            VerificationKeyResolverKey that = (VerificationKeyResolverKey) o;
            return configs.equals(that.configs) && saslMechanism.equals(that.saslMechanism) && moduleOptions.equals(that.moduleOptions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(configs, saslMechanism, moduleOptions);
        }
    }

    /**
     * <code>RefCountingVerificationKeyResolver</code> allows us to share a single
     * {@link CloseableVerificationKeyResolver} instance between multiple
     * {@link AuthenticateCallbackHandler} instances and perform the lifecycle methods the
     * appropriate number of times.
     */

    // DECISION: Reference-counting wrapper for shared resolver lifecycle management.
    // configure() increments count -- only first configure() initializes the delegate.
    // close() decrements count -- only last close() tears down the delegate.
    // Alternative: Use AtomicReference with lazy init. Rationale: Explicit reference counting
    // is simple and deterministic. Risk: If a consumer skips close(), the count never reaches
    // zero and the delegate leaks (background threads continue running).
    private static class RefCountingVerificationKeyResolver implements CloseableVerificationKeyResolver {

        private final CloseableVerificationKeyResolver delegate;

        private final AtomicInteger count = new AtomicInteger(0);

        public RefCountingVerificationKeyResolver(CloseableVerificationKeyResolver delegate) {
            this.delegate = delegate;
        }

        @Override
        public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
            return delegate.resolveKey(jws, nestingContext);
        }

        @Override
        public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
            if (count.incrementAndGet() == 1)
                delegate.configure(configs, saslMechanism, jaasConfigEntries);
        }

        @Override
        public void close() throws IOException {
            if (count.decrementAndGet() == 0)
                delegate.close();
        }
    }
}