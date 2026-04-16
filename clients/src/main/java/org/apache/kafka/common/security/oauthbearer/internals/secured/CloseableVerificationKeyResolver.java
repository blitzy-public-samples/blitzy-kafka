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

import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler;

import org.jose4j.keys.resolvers.VerificationKeyResolver;

/**
 * The {@link OAuthBearerValidatorCallbackHandler} uses a {@link VerificationKeyResolver} as
 * part of its validation of the incoming JWT. Some of the <code>VerificationKeyResolver</code>
 * implementations use resources like threads, connections, etc. that should be properly closed
 * when no longer needed. Since the <code>VerificationKeyResolver</code> interface itself doesn't
 * define a <code>close</code> method, we provide a means to do that here.
 */

// SECURITY: (MEDIUM) Combined lifecycle contract for OAUTHBEARER key resolvers.
// Why: Implementations manage cryptographic key material and potentially long-lived HTTP
// connections. Improper lifecycle management (missing close()) can leak threads and connections.
// Exploit: If close() is not called, RefreshingHttpsJwks's ScheduledExecutorService continues
// running, maintaining HTTP connections to the JWKS endpoint. In a dynamic listener
// reconfiguration scenario, leaked resolvers continue validating tokens with stale keys.
// Improvement: Add a finalizer or Cleaner-based safety net to detect unclosed resolvers.

// DECISION: Combines jose4j VerificationKeyResolver + OAuthBearerConfigurable (configure +
// Closeable) into a single interface. Alternative: (1) Separate Configurable and Closeable
// wrappers, (2) Extend VerificationKeyResolver directly with configure/close methods.
// Rationale: Single interface simplifies the VerificationKeyResolverFactory return type and
// enables reference-counting lifecycle management (RefCountingVerificationKeyResolver).
// The composition avoids modifying jose4j's VerificationKeyResolver interface.

// CROSS-CUTTING: Implemented by RefreshingHttpsJwksVerificationKeyResolver (HTTPS JWKS),
// JwksFileVerificationKeyResolver (file JWKS), and VerificationKeyResolverFactory's
// RefCountingVerificationKeyResolver (ref-counting wrapper). Used by VerificationKeyResolverFactory
// (factory return type), OAuthBearerValidatorCallbackHandler (resolver lifecycle management),
// BrokerJwtValidator and DefaultJwtValidator (key resolution during JWT validation).
// Extends: jose4j VerificationKeyResolver (resolveKey), OAuthBearerConfigurable (configure + close).
public interface CloseableVerificationKeyResolver extends OAuthBearerConfigurable, VerificationKeyResolver {

}
