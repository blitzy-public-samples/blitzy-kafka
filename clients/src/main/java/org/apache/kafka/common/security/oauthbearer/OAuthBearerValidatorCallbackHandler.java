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

import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.internals.secured.CloseableVerificationKeyResolver;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import static org.apache.kafka.common.security.oauthbearer.internals.secured.ConfigurationUtils.getConfiguredInstance;

/**
 * <p>
 * <code>OAuthBearerValidatorCallbackHandler</code> is an {@link AuthenticateCallbackHandler} that
 * accepts {@link OAuthBearerValidatorCallback} and {@link OAuthBearerExtensionsValidatorCallback}
 * callbacks to implement OAuth/OIDC validation. This callback handler is intended only to be used
 * on the Kafka broker side as it will receive a {@link OAuthBearerValidatorCallback} that includes
 * the JWT provided by the Kafka client. That JWT is validated in terms of format, expiration,
 * signature, and audience and issuer (if desired). This callback handler is the broker side of the
 * OAuth functionality, whereas {@link OAuthBearerLoginCallbackHandler} is used by clients.
 * </p>
 *
 * <p>
 * This {@link AuthenticateCallbackHandler} is enabled in the broker configuration by setting the
 * {@link org.apache.kafka.common.config.internals.BrokerSecurityConfigs#SASL_SERVER_CALLBACK_HANDLER_CLASS_CONFIG}
 * like so:
 *
 * <code>
 * listener.name.<listener name>.oauthbearer.sasl.server.callback.handler.class=org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler
 * </code>
 * </p>
 *
 * <p>
 * The JAAS configuration for OAuth is also needed. If using OAuth for inter-broker communication,
 * the options are those specified in {@link OAuthBearerLoginCallbackHandler}.
 * </p>
 *
 * <p>
 * The configuration option
 * {@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_JWKS_ENDPOINT_URL}
 * is also required in order to contact the OAuth/OIDC provider to retrieve the JWKS for use in
 * JWT signature validation. For example:
 *
 * <code>
 * listener.name.<listener name>.oauthbearer.sasl.oauthbearer.jwks.endpoint.url=https://example.com/oauth2/v1/keys
 * </code>
 *
 * Please see the OAuth/OIDC providers documentation for the JWKS endpoint URL.
 * </p>
 *
 * <p>
 * The following is a list of all the configuration options that are available for the broker
 * validation callback handler:
 *
 * <ul>
 *   <li>{@link org.apache.kafka.common.config.internals.BrokerSecurityConfigs#SASL_SERVER_CALLBACK_HANDLER_CLASS_CONFIG}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_JAAS_CONFIG}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_CLOCK_SKEW_SECONDS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_EXPECTED_AUDIENCE}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_EXPECTED_ISSUER}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_JWKS_ENDPOINT_REFRESH_MS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_JWKS_ENDPOINT_RETRY_BACKOFF_MAX_MS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_JWKS_ENDPOINT_RETRY_BACKOFF_MS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_JWKS_ENDPOINT_URL}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_SCOPE_CLAIM_NAME}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_SUB_CLAIM_NAME}</li>
 * </ul>
 * </p>
 *
 * @implNote DECISION: Separates validation (this handler) from login
 * (OAuthBearerLoginCallbackHandler) rather than combining both in a single
 * handler. Alternatives: (1) Single unified handler for both client and
 * broker, (2) Validation logic inline in SaslServerAuthenticator. Rationale:
 * Separation allows broker-side validation to use heavyweight JWKS-based
 * verification (jose4j) while client-side login uses lightweight token
 * retrieval, enabling independent evolution of each concern.
 */

// SECURITY: (CRITICAL) Broker-side JWT validation entry point — validates
// token signature, claims, expiry for every OAUTHBEARER authentication
// request. Why: This handler receives raw JWT tokens from untrusted clients
// and delegates to JwtValidator for cryptographic verification. Failure
// here = auth bypass. Exploit: Clock skew exploitation — if
// SASL_OAUTHBEARER_CLOCK_SKEW_SECONDS tolerance is too generous, expired
// tokens can be replayed within the window. An attacker who captures an
// expired token (from logs, network sniffing, or memory dump) has a time
// window equal to the clock skew tolerance to reuse it. Improvement:
// Consider making clock skew tolerance configurable with a strict default
// (e.g., 30 seconds rather than unbounded), and log a WARNING when clock
// skew exceeds a recommended threshold during configure().
//
// CROSS-CUTTING: Depends on auth/AuthenticateCallbackHandler (contract
// interface), internals/secured/CloseableVerificationKeyResolver (JWKS key
// management), internals/secured/ConfigurationUtils (config resolution),
// and JwtValidator (validation SPI). Consumed by:
// authenticator/SaslServerAuthenticator which invokes handle() during
// the SASL authentication handshake for OAUTHBEARER mechanism. Contract:
// Must be configured before handle() is called; not thread-safe for
// configure(). Impact: Changes to JwtValidator contract or
// CloseableVerificationKeyResolver lifecycle affect broker auth
// availability.
public class OAuthBearerValidatorCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthBearerValidatorCallbackHandler.class);

    // CROSS-CUTTING: Optional JWKS key resolver — when present, enables
    // cryptographic signature verification. Sourced from
    // VerificationKeyResolverFactory which manages JWKS endpoint
    // connectivity and key rotation. Lifecycle: configured in configure(),
    // closed in close(). Null when using test-injection path.
    private CloseableVerificationKeyResolver verificationKeyResolver;

    private JwtValidator jwtValidator;

    // SECURITY: JwtValidator is instantiated via reflection using the
    // configured class name. The class must implement JwtValidator and be
    // on the classpath. Malicious configuration could point to an
    // attacker-controlled class if config write access is compromised.
    //
    // DECISION: JwtValidator is loaded via getConfiguredInstance() rather
    // than directly instantiating BrokerJwtValidator. This enables users
    // to provide custom JWT validation implementations (e.g., for custom
    // claim validation or opaque token introspection). Alternative:
    // Hard-code BrokerJwtValidator. Rationale: Pluggability supports
    // diverse OAuth provider requirements without code changes.
    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        jwtValidator = getConfiguredInstance(
            configs,
            saslMechanism,
            jaasConfigEntries,
            SaslConfigs.SASL_OAUTHBEARER_JWT_VALIDATOR_CLASS,
            JwtValidator.class
        );
    }

    // DECISION: Package-visible overload accepting explicit
    // verificationKeyResolver and jwtValidator for testability.
    // Alternative: Use reflection or PowerMock. Rationale: Direct
    // dependency injection is simpler, less fragile, and avoids
    // reflection overhead.
    /*
     * Package-visible for testing.
     */
    void configure(Map<String, ?> configs,
                   String saslMechanism,
                   List<AppConfigurationEntry> jaasConfigEntries,
                   CloseableVerificationKeyResolver verificationKeyResolver,
                   JwtValidator jwtValidator) {
        this.verificationKeyResolver = verificationKeyResolver;
        this.verificationKeyResolver.configure(configs, saslMechanism, jaasConfigEntries);

        this.jwtValidator = jwtValidator;
        this.jwtValidator.configure(configs, saslMechanism, jaasConfigEntries);
    }

    // SECURITY: Uses Utils.closeQuietly to suppress close() exceptions,
    // preventing resource cleanup failures from leaking internal state
    // through exception messages.
    @Override
    public void close() {
        Utils.closeQuietly(jwtValidator, "JWT validator");
        Utils.closeQuietly(verificationKeyResolver, "JWT verification key resolver");
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        checkConfigured();

        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerValidatorCallback) {
                handleValidatorCallback((OAuthBearerValidatorCallback) callback);
            } else if (callback instanceof OAuthBearerExtensionsValidatorCallback) {
                handleExtensionsValidatorCallback((OAuthBearerExtensionsValidatorCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    // SECURITY: (CRITICAL) Token validation path — delegates to
    // JwtValidator.validate(). On validation failure, returns generic
    // "invalid_token" error without exposing the specific failure reason
    // to the client (defense against information leakage). The exception
    // is logged server-side at WARN level for audit trail.
    // Exploit: If the error message were returned to the client, an
    // attacker could iteratively probe token construction (e.g., learning
    // which claims are required, what audience values are accepted) to
    // forge a valid token. Improvement: Consider rate-limiting failed
    // validation attempts per client IP to mitigate brute-force token
    // probing.
    private void handleValidatorCallback(OAuthBearerValidatorCallback callback) {
        checkConfigured();

        OAuthBearerToken token;

        try {
            token = jwtValidator.validate(callback.tokenValue());
            callback.token(token);
        } catch (JwtValidatorException e) {
            log.warn(e.getMessage(), e);
            callback.error("invalid_token", null, null);
        }
    }

    // SECURITY: (MEDIUM) Marks all client-provided SASL extensions as
    // valid without checking their content. Per RFC 7628, unknown
    // extensions should be ignored. Why: Extensions are inherently
    // untrusted — they are sent by the client and can contain arbitrary
    // key-value pairs. Blindly marking all as "valid" is the correct
    // default per the RFC but could be a concern if custom authorizers
    // depend on extension values for access decisions.
    // Exploit: A malicious client could inject crafted extensions that
    // downstream components (custom authorizers, audit loggers) trust
    // without validation. Improvement: Consider providing a hook for
    // custom extension validation logic via a configurable
    // ExtensionValidator interface.
    private void handleExtensionsValidatorCallback(OAuthBearerExtensionsValidatorCallback extensionsValidatorCallback) {
        checkConfigured();

        extensionsValidatorCallback.inputExtensions().map().forEach((extensionName, v) -> extensionsValidatorCallback.valid(extensionName));
    }

    private void checkConfigured() {
        if (jwtValidator == null)
            throw new IllegalStateException(String.format("To use %s, first call the configure method", getClass().getSimpleName()));
    }
}
