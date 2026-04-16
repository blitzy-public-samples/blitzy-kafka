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

import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe, typed in-memory credential registry for SASL mechanism credentials.
 *
 * @implSpec SECURITY: (MEDIUM) In-memory credential storage using ConcurrentHashMap.
 * Why: Stores SCRAM/token credentials keyed by username. Credentials include SCRAM
 * salted password hashes (ScramCredential) and delegation token HMAC secrets.
 * Exploit: (1) Cache poisoning -- if a concurrent credential update races with
 * authentication lookup, a client could authenticate with a stale credential that
 * should have been revoked. ConcurrentHashMap provides atomic put/get but does NOT
 * provide atomic check-then-update across multiple operations.
 * (2) No eviction -- credentials persist until explicitly removed. If credential
 * revocation fails (e.g., ZooKeeper write fails but cache is not updated), revoked
 * credentials remain valid for authentication.
 * (3) Memory exposure -- credential objects (ScramCredential containing salt, server
 * key, stored key) remain in heap memory and are accessible via heap dump.
 * Improvement: Consider adding cache-level TTL or periodic refresh from the metadata
 * log to detect stale entries. Consider using ByteBuffer-backed storage with explicit
 * clearing on removal rather than relying on garbage collection.
 */
// DECISION: ConcurrentHashMap per mechanism type for credential isolation.
// Alternatives: (1) Synchronized HashMap for stronger consistency, (2) Guava Cache
// with TTL, (3) ReadWriteLock-protected TreeMap. Rationale: ConcurrentHashMap provides
// good throughput under high read concurrency (many authenticating connections checking
// credentials simultaneously) without full synchronization overhead. The tradeoff is
// weaker consistency for compound operations (check-then-update).
//
// CROSS-CUTTING: Created by broker startup (BrokerServer/ControllerServer) and
// populated by the SCRAM credential management layer (ScramCredentialUtils).
// Read by: ScramSaslServer (scram/internals/) during SCRAM authentication to
// retrieve stored server keys for credential verification.
// Read by: DelegationTokenCache (token/delegation/internals/) for delegation token
// HMAC verification. Consumed by all server-side SASL mechanism implementations
// that perform server-side credential lookup.
// Contract: Cache instances are created at broker startup and persist for broker
// lifetime. Callers manage credential lifecycle (put on create, remove on revoke).
public class CredentialCache {

    private final ConcurrentHashMap<String, Cache<?>> cacheMap = new ConcurrentHashMap<>();

    // SECURITY: (LOW) putIfAbsent ensures only one Cache instance per mechanism,
    // preventing mechanism confusion where credentials for SCRAM-SHA-256 are
    // accidentally accessible via the SCRAM-SHA-512 mechanism name.
    // Exploit: Unauthorized access to the credential cache could expose authentication material.
    // Improvement: Limit cache access to authenticated callers and consider cache entry encryption at rest.
    public <C> Cache<C> createCache(String mechanism, Class<C> credentialClass) {
        Cache<C> cache = new Cache<>(credentialClass);
        @SuppressWarnings("unchecked")
        Cache<C> oldCache = (Cache<C>) cacheMap.putIfAbsent(mechanism, cache);
        return oldCache == null ? cache : oldCache;
    }

    // SECURITY: (LOW) Runtime type validation prevents type confusion where a
    // Cache<ScramCredential> could be retrieved as Cache<DelegationTokenData>.
    // This ensures mechanism-level credential isolation at the type system level.
    // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
    // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
    @SuppressWarnings("unchecked")
    public <C> Cache<C> cache(String mechanism, Class<C> credentialClass) {
        Cache<?> cache = cacheMap.get(mechanism);
        if (cache != null) {
            if (cache.credentialClass() != credentialClass)
                throw new IllegalArgumentException("Invalid credential class " + credentialClass + ", expected " + cache.credentialClass());
            return (Cache<C>) cache;
        } else
            return null;
    }

    // SECURITY: (MEDIUM) Per-mechanism credential storage. The ConcurrentHashMap
    // provides thread-safe read/write but individual operations are NOT transactional.
    // A put() followed by a separate authorization check is NOT atomic -- credentials
    // could be read between update and authorization, creating a TOCTOU race.
    //
    // DECISION: Generic typed Cache<C> with credentialClass field for runtime type
    // validation. Alternative: Separate classes per credential type. Rationale:
    // Generics enable a single cache implementation for all SASL mechanisms while
    // the credentialClass field enables safe downcasting in cache() method.
    // Exploit: Unauthorized access to the credential cache could expose authentication material.
    // Improvement: Limit cache access to authenticated callers and consider cache entry encryption at rest.
    public static class Cache<C> {
        private final Class<C> credentialClass;
        private final ConcurrentHashMap<String, C> credentials;

        public Cache(Class<C> credentialClass) {
            this.credentialClass = credentialClass;
            this.credentials = new ConcurrentHashMap<>();
        }

        public C get(String username) {
            return credentials.get(username);
        }

        public C put(String username, C credential) {
            return credentials.put(username, credential);
        }

        public C remove(String username) {
            return credentials.remove(username);
        }

        public Class<C> credentialClass() {
            return credentialClass;
        }
    }
}
