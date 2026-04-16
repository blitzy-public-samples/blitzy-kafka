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

package org.apache.kafka.common.security.token.delegation.internals;

import org.apache.kafka.common.security.authenticator.CredentialCache;
import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.internals.ScramCredentialUtils;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;
import org.apache.kafka.common.security.token.delegation.DelegationToken;
import org.apache.kafka.common.security.token.delegation.TokenInformation;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DelegationTokenCache {

    // SECURITY: (MEDIUM) Thread-safe in-memory cache for active delegation tokens.
    // Stores tokenId->TokenInformation, hmac->tokenId, and tokenId->hmac mappings using
    // ConcurrentHashMap for lock-free reads. However, multi-map updates in updateCache()
    // and removeToken() are NOT atomic -- a concurrent reader may observe a partially-updated
    // state (e.g., token info present but hmac mapping absent, or vice versa).
    // Exploit: If token revocation (removeToken) races with authentication lookup
    // (tokenForHmac), a revoked token's HMAC could still resolve to a valid TokenInformation
    // in the window between the tokenCache.remove() and hmacTokenIdCache.remove() calls.
    // Improvement: Consider wrapping multi-map mutations in a synchronized block or using
    // a versioned/CAS-based approach to ensure atomic token lifecycle transitions.
    //
    // DECISION: Uses three separate ConcurrentHashMaps rather than a single composite map
    // to optimize for the common read path (HMAC->token lookup during SCRAM authentication)
    // at the cost of non-atomic multi-map mutations. Lock-free reads provide better
    // throughput under high-concurrency authentication workloads.
    //
    // CROSS-CUTTING: Consumed by authenticator/CredentialCache for SCRAM credential storage,
    // core/DelegationTokenManager for broker-side token lifecycle, and
    // ScramServerCallbackHandler for delegation token authentication during SASL/SCRAM
    // handshake.

    private final CredentialCache credentialCache = new CredentialCache();

    //Cache to hold all the tokens
    private final Map<String, TokenInformation> tokenCache = new ConcurrentHashMap<>();

    //Cache to hold hmac->tokenId mapping. This is required for renew, expire requests
    private final Map<String, String> hmacTokenIdCache = new ConcurrentHashMap<>();

    //Cache to hold tokenId->hmac mapping. This is required for removing entry from hmacTokenIdCache using tokenId.
    private final Map<String, String> tokenIdHmacCache = new ConcurrentHashMap<>();

    public DelegationTokenCache(Collection<String> scramMechanisms) {
        //Create caches for scramMechanisms
        ScramCredentialUtils.createCache(credentialCache, scramMechanisms);
    }

    public ScramCredential credential(String mechanism, String tokenId) {
        CredentialCache.Cache<ScramCredential> cache = credentialCache.cache(mechanism, ScramCredential.class);
        return cache == null ? null : cache.get(tokenId);
    }

    public String owner(String tokenId) {
        TokenInformation tokenInfo = tokenCache.get(tokenId);
        return tokenInfo == null ? null : tokenInfo.owner().getName();
    }

    // SECURITY: (MEDIUM) Non-atomic multi-map update -- adds token info, SCRAM credentials,
    // and HMAC mappings in sequence. A concurrent authentication attempt during this window
    // may find partial state (token info without SCRAM credentials, or vice versa).
    // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
    // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
    public void updateCache(DelegationToken token, Map<String, ScramCredential> scramCredentialMap) {
        //Update TokenCache
        String tokenId =  token.tokenInfo().tokenId();
        addToken(tokenId, token.tokenInfo());
        String hmac = token.hmacAsBase64String();
        //Update Scram Credentials
        updateCredentials(tokenId, scramCredentialMap);
        //Update hmac-id cache
        hmacTokenIdCache.put(hmac, tokenId);
        tokenIdHmacCache.put(tokenId, hmac);
    }

    // SECURITY: (MEDIUM) Token revocation -- removes token info and clears SCRAM credentials.
    // The removeToken->updateCredentials sequence is not atomic; a concurrent SCRAM auth
    // may still find valid credentials after token info has been removed.
    // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
    // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
    public void removeCache(String tokenId) {
        removeToken(tokenId);
        updateCredentials(tokenId, new HashMap<>());
    }

    public String tokenIdForHmac(String base64hmac) {
        return hmacTokenIdCache.get(base64hmac);
    }

    public TokenInformation tokenForHmac(String base64hmac) {
        String tokenId = hmacTokenIdCache.get(base64hmac);
        return tokenId == null ? null : tokenCache.get(tokenId);
    }

    public TokenInformation addToken(String tokenId, TokenInformation tokenInfo) {
        return tokenCache.put(tokenId, tokenInfo);
    }

    // DECISION: Removes from tokenCache first, then cascades to hmac maps.
    // This ordering ensures that tokenId-based lookups fail first, reducing the
    // window for stale HMAC-based lookups. However, the multi-step removal is
    // still non-atomic across the three ConcurrentHashMaps.
    public void removeToken(String tokenId) {
        TokenInformation tokenInfo = tokenCache.remove(tokenId);
        if (tokenInfo != null) {
            String hmac = tokenIdHmacCache.remove(tokenInfo.tokenId());
            if (hmac != null) {
                hmacTokenIdCache.remove(hmac);
            }
        }
    }

    public Collection<TokenInformation> tokens() {
        return tokenCache.values();
    }

    public TokenInformation token(String tokenId) {
        return tokenCache.get(tokenId);
    }

    public CredentialCache.Cache<ScramCredential> credentialCache(String mechanism) {
        return credentialCache.cache(mechanism, ScramCredential.class);
    }

    // CROSS-CUTTING: Integrates with ScramMechanism.mechanismNames() to update per-mechanism
    // SCRAM credential caches. Each SCRAM mechanism (SCRAM-SHA-256, SCRAM-SHA-512) maintains
    // an independent credential cache keyed by tokenId.
    private void updateCredentials(String tokenId, Map<String, ScramCredential> scramCredentialMap) {
        for (String mechanism : ScramMechanism.mechanismNames()) {
            CredentialCache.Cache<ScramCredential> cache = credentialCache.cache(mechanism, ScramCredential.class);
            if (cache != null) {
                ScramCredential credential = scramCredentialMap.get(mechanism);
                if (credential == null) {
                    cache.remove(tokenId);
                } else {
                    cache.put(tokenId, credential);
                }
            }
        }
    }
}