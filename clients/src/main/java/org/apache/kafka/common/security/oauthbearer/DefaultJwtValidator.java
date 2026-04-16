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

import org.apache.kafka.common.security.oauthbearer.internals.secured.CloseableVerificationKeyResolver;
import org.apache.kafka.common.utils.Utils;

import org.jose4j.keys.resolvers.VerificationKeyResolver;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.security.auth.login.AppConfigurationEntry;

/**
 * This {@link JwtValidator} uses the delegation approach, instantiating and delegating calls to a
 * more concrete implementation. The underlying implementation is determined by the presence/absence
 * of the {@link VerificationKeyResolver}: if it's present, a {@link BrokerJwtValidator} is
 * created, otherwise a {@link ClientJwtValidator} is created.
 *
 * @implNote DECISION: Uses Optional-based delegation rather than subclassing. Alternative:
 * Abstract base class with BrokerJwtValidator and ClientJwtValidator as subclasses. Rationale:
 * Delegation allows runtime selection based on configuration rather than compile-time type
 * hierarchy. The validator type is determined by whether the operator configures a JWKS endpoint.
 */
// SECURITY: (MEDIUM) Default validator selection — routes to BrokerJwtValidator (JWKS-based
// signature verification) when a VerificationKeyResolver is present, or ClientJwtValidator
// (structural-only parsing without signature verification) when absent.
// Why: The presence/absence of the key resolver determines whether the broker performs
// cryptographic token verification — a critical security boundary.
// Exploit: If the VerificationKeyResolver is not properly configured (e.g., JWKS endpoint
// URL is missing), this validator silently falls back to ClientJwtValidator which does NOT
// verify token signatures. An attacker could forge tokens with arbitrary claims.
// Improvement: Log a WARNING when falling back to ClientJwtValidator on the broker side,
// as this indicates no signature verification is occurring. Consider refusing to start
// the broker if JWKS is not configured for OAUTHBEARER.
//
// CROSS-CUTTING: Depends on BrokerJwtValidator (broker-side validation), ClientJwtValidator
// (client-side validation), internals/secured/CloseableVerificationKeyResolver (JWKS resolver).
// Used by OAuthBearerValidatorCallbackHandler as the default JwtValidator implementation.
// Contract: configure() must be called before validate(). Thread-safe after configure().
public class DefaultJwtValidator implements JwtValidator {

    private final Optional<CloseableVerificationKeyResolver> verificationKeyResolver;

    private JwtValidator delegate;

    public DefaultJwtValidator() {
        this.verificationKeyResolver = Optional.empty();
    }

    public DefaultJwtValidator(CloseableVerificationKeyResolver verificationKeyResolver) {
        this.verificationKeyResolver = Optional.of(verificationKeyResolver);
    }

    // DECISION: Delegate creation deferred to configure() rather than constructor. This allows
    // the VerificationKeyResolver to be fully configured before deciding which validator to use.
    // The resolver is Optional — empty means client-side (no JWKS), present means broker-side.
    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (verificationKeyResolver.isPresent()) {
            delegate = new BrokerJwtValidator(verificationKeyResolver.get());
        } else {
            delegate = new ClientJwtValidator();
        }

        delegate.configure(configs, saslMechanism, jaasConfigEntries);
    }

    @Override
    public OAuthBearerToken validate(String accessToken) throws JwtValidatorException {
        if (delegate == null)
            throw new IllegalStateException("JWT validator delegate is null; please call configure() first");

        return delegate.validate(accessToken);
    }

    @Override
    public void close() throws IOException {
        Utils.closeQuietly(delegate, "JWT validator delegate");
    }

    JwtValidator delegate() {
        return delegate;
    }
}
