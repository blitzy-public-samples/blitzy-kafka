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

import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.auth.SaslExtensionsCallback;
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerClientInitialResponse;
import org.apache.kafka.common.security.oauthbearer.internals.secured.JaasOptionsUtils;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.SaslException;

import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL;
import static org.apache.kafka.common.security.oauthbearer.internals.secured.ConfigurationUtils.getConfiguredInstance;

/**
 * <p>
 * <code>OAuthBearerLoginCallbackHandler</code> is an {@link AuthenticateCallbackHandler} that
 * accepts {@link OAuthBearerTokenCallback} and {@link SaslExtensionsCallback} callbacks to
 * perform the steps to request a JWT from an OAuth/OIDC provider using the
 * <code>client_credentials</code>. This grant type is commonly used for non-interactive
 * "service accounts" where there is no user available to interactively supply credentials.
 * </p>
 *
 * <p>
 * The <code>OAuthBearerLoginCallbackHandler</code> is used on the client side to retrieve a JWT
 * and the {@link OAuthBearerValidatorCallbackHandler} is used on the broker to validate the JWT
 * that was sent to it by the client to allow access. Both the brokers and clients will need to
 * be configured with their appropriate callback handlers and respective configuration for OAuth
 * functionality to work.
 * </p>
 *
 * <p>
 * Note that while this callback handler class must be specified for a Kafka client that wants to
 * use OAuth functionality, in the case of OAuth-based inter-broker communication, the callback
 * handler must be used on the Kafka broker side as well.
 * </p>
 *
 * <p>
 * This {@link AuthenticateCallbackHandler} is enabled by specifying its class name in the Kafka
 * configuration. For client use, specify the class name in the
 * {@link org.apache.kafka.common.config.SaslConfigs#SASL_LOGIN_CALLBACK_HANDLER_CLASS}
 * configuration like so:
 *
 * <code>
 * sasl.login.callback.handler.class=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginCallbackHandler
 * </code>
 * </p>
 *
 * <p>
 * If using OAuth login on the broker side (for inter-broker communication), the callback handler
 * class will be specified with a listener-based property:
 * <code>listener.name.<listener name>.oauthbearer.sasl.login.callback.handler.class</code> like so:
 *
 * <code>
 * listener.name.<listener name>.oauthbearer.sasl.login.callback.handler.class=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginCallbackHandler
 * </code>
 * </p>
 *
 * <p>
 * The Kafka configuration must also include JAAS configuration which includes the following
 * OAuth-specific options:
 *
 * <ul>
 *     <li><code>clientId</code>OAuth client ID (required)</li>
 *     <li><code>clientSecret</code>OAuth client secret (required)</li>
 *     <li><code>scope</code>OAuth scope (optional)</li>
 * </ul>
 * </p>
 *
 * <p>
 * The JAAS configuration can also include any SSL options that are needed. The configuration
 * options are the same as those specified by the configuration in
 * {@link org.apache.kafka.common.config.SslConfigs#addClientSslSupport(ConfigDef)}.
 * </p>
 *
 * <p>
 * Here's an example of the JAAS configuration for a Kafka client:
 *
 * <code>
 * sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required \
 *   clientId="foo" \
 *   clientSecret="bar" \
 *   scope="baz" \
 *   ssl.protocol="SSL" ;
 * </code>
 * </p>
 *
 * <p>
 * The configuration option
 * {@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL}
 * is also required in order for the client to contact the OAuth/OIDC provider. For example:
 *
 * <code>
 * sasl.oauthbearer.token.endpoint.url=https://example.com/oauth2/v1/token
 * </code>
 *
 * Please see the OAuth/OIDC providers documentation for the token endpoint URL.
 * </p>
 *
 * <p>
 * The following is a list of all the configuration options that are available for the login
 * callback handler:
 *
 * <ul>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_LOGIN_CALLBACK_HANDLER_CLASS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_LOGIN_CONNECT_TIMEOUT_MS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_LOGIN_READ_TIMEOUT_MS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_LOGIN_RETRY_BACKOFF_MS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_LOGIN_RETRY_BACKOFF_MAX_MS}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_JAAS_CONFIG}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_SCOPE_CLAIM_NAME}</li>
 *   <li>{@link org.apache.kafka.common.config.SaslConfigs#SASL_OAUTHBEARER_SUB_CLAIM_NAME}</li>
 * </ul>
 * </p>
 *
 * @implNote DECISION: Uses pluggable JwtRetriever + JwtValidator pattern (loaded via
 * getConfiguredInstance) rather than hard-coding HTTP client credentials flow. Alternatives:
 * (1) Hard-code ClientCredentialsJwtRetriever + ClientJwtValidator, (2) Single monolithic
 * handler. Rationale: The pluggable pattern supports multiple OAuth grant types
 * (client_credentials, jwt-bearer, file-based) and custom implementations without modifying
 * this handler. Risk: Misconfiguration can lead to ClassNotFoundException at runtime during
 * SASL handshake.
 */

// SECURITY: (HIGH) Client-side OAuth login handler -- retrieves JWT tokens from OAuth provider
// and validates them before caching in the JAAS Subject's private credentials.
// Why: This handler manages the full token lifecycle: retrieval -> validation -> caching.
// The retrieved token (containing client_id, client_secret in the request) passes through
// potentially untrusted networks.
// Exploit: Credential caching risk -- tokens are stored in the Subject's private credentials
// (via OAuthBearerLoginModule.commit()). If the Subject is not properly scoped or if tokens
// are not cleared on logout/expiry, stale tokens could be reused by other components sharing
// the same Subject. An attacker with access to heap dumps or JMX could extract cached tokens.
// Improvement: Ensure token cache has TTL aligned with token expiry and is cleared on
// Subject logout. Consider using SealedObject or similar for in-memory token protection.

// CROSS-CUTTING: Depends on auth/AuthenticateCallbackHandler (contract interface),
// JwtRetriever (token retrieval SPI), JwtValidator (token validation SPI),
// internals/secured/JaasOptionsUtils (JAAS option extraction),
// internals/OAuthBearerClientInitialResponse (extension validation).
// Consumed by: OAuthBearerLoginModule (via CallbackHandler.handle()), which is invoked
// by LoginManager during SASL authentication setup on the client side.
// Also used broker-side for inter-broker OAUTHBEARER communication.

public class OAuthBearerLoginCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthBearerLoginCallbackHandler.class);

    // SECURITY: (HIGH) Client credentials (clientId, clientSecret) defined as JAAS module
    // options. These are sensitive values that appear in sasl.jaas.config. The config value
    // is of type Password which masks toString(), but JAAS option values are plain strings
    // stored in memory.
    // Exploit: An attacker with access to JVM heap dumps or JAAS debug logging could
    // extract plaintext client secrets from memory or log files.
    // Improvement: Ensure JAAS config is not logged at DEBUG level. Consider using a
    // credential provider abstraction to avoid plaintext secrets in memory.
    public static final String CLIENT_ID_CONFIG = "clientId";
    public static final String CLIENT_SECRET_CONFIG = "clientSecret";
    public static final String SCOPE_CONFIG = "scope";

    public static final String CLIENT_ID_DOC = "The OAuth/OIDC identity provider-issued " +
        "client ID to uniquely identify the service account to use for authentication for " +
        "this client. The value must be paired with a corresponding " + CLIENT_SECRET_CONFIG + " " +
        "value and is provided to the OAuth provider using the OAuth " +
        "clientcredentials grant type.";

    public static final String CLIENT_SECRET_DOC = "The OAuth/OIDC identity provider-issued " +
        "client secret serves a similar function as a password to the " + CLIENT_ID_CONFIG + " " +
        "account and identifies the service account to use for authentication for " +
        "this client. The value must be paired with a corresponding " + CLIENT_ID_CONFIG + " " +
        "value and is provided to the OAuth provider using the OAuth " +
        "clientcredentials grant type.";

    public static final String SCOPE_DOC = "The (optional) HTTP/HTTPS login request to the " +
        "token endpoint (" + SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL + ") may need to specify an " +
        "OAuth \"scope\". If so, the " + SCOPE_CONFIG + " is used to provide the value to " +
        "include with the login request.";

    // DECISION: Extensions prefixed with "extension_" in JAAS options rather than a separate
    // config namespace. Alternative: Dedicated sasl.oauthbearer.extensions.* config keys.
    // Rationale: Reuses existing JAAS option mechanism without new config infrastructure.
    // Extensions are rarely used and don't warrant dedicated config keys.
    private static final String EXTENSION_PREFIX = "extension_";

    private Map<String, Object> moduleOptions;

    private JwtRetriever jwtRetriever;

    private JwtValidator jwtValidator;

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        moduleOptions = JaasOptionsUtils.getOptions(saslMechanism, jaasConfigEntries);
        jwtRetriever = getConfiguredInstance(
            configs,
            saslMechanism,
            jaasConfigEntries,
            SaslConfigs.SASL_OAUTHBEARER_JWT_RETRIEVER_CLASS,
            JwtRetriever.class
        );

        jwtValidator = getConfiguredInstance(
            configs,
            saslMechanism,
            jaasConfigEntries,
            SaslConfigs.SASL_OAUTHBEARER_JWT_VALIDATOR_CLASS,
            JwtValidator.class
        );
    }

    /*
     * Package-visible for testing.
     */
    // DECISION: Test-injectable configure() overload -- same pattern as
    // OAuthBearerValidatorCallbackHandler. Enables unit testing without
    // needing real OAuth provider connectivity.
    void configure(Map<String, ?> configs,
                   String saslMechanism,
                   List<AppConfigurationEntry> jaasConfigEntries,
                   JwtRetriever jwtRetriever,
                   JwtValidator jwtValidator) {
        this.moduleOptions = JaasOptionsUtils.getOptions(saslMechanism, jaasConfigEntries);

        this.jwtRetriever = jwtRetriever;
        this.jwtRetriever.configure(configs, saslMechanism, jaasConfigEntries);

        this.jwtValidator = jwtValidator;
        this.jwtValidator.configure(configs, saslMechanism, jaasConfigEntries);
    }

    @Override
    public void close() {
        Utils.closeQuietly(jwtRetriever, "JWT retriever");
        Utils.closeQuietly(jwtValidator, "JWT validator");
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        checkConfigured();

        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback) {
                handleTokenCallback((OAuthBearerTokenCallback) callback);
            } else if (callback instanceof SaslExtensionsCallback) {
                handleExtensionsCallback((SaslExtensionsCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    // SECURITY: (HIGH) Token retrieval and validation in sequence. The accessToken string
    // may contain sensitive data (the JWT itself). It is passed to jwtValidator.validate()
    // which performs at minimum structural validation. On failure, "invalid_token" error
    // is set on callback with the exception message -- this message should NOT contain
    // secrets but may contain claim names that aid token probing.
    // Exploit: If jwtRetriever.retrieve() throws and the exception message contains the
    // client_secret (from HTTP request logging), it could be logged at WARN level.
    // Improvement: Sanitize exception messages from retrieve() before logging.
    private void handleTokenCallback(OAuthBearerTokenCallback callback) throws IOException {
        checkConfigured();
        String accessToken = jwtRetriever.retrieve();

        try {
            OAuthBearerToken token = jwtValidator.validate(accessToken);
            callback.token(token);
        } catch (JwtValidatorException e) {
            log.warn(e.getMessage(), e);
            callback.error("invalid_token", e.getMessage(), null);
        }
    }

    // SECURITY: (MEDIUM) SASL extensions extracted from JAAS moduleOptions with "extension_"
    // prefix. Extension keys/values are validated via OAuthBearerClientInitialResponse.
    // validateExtensions() which enforces RFC 7628 patterns.
    // Exploit: If moduleOptions are sourced from untrusted config (e.g., dynamic per-user
    // JAAS config), malicious extension values could be injected into the SASL handshake,
    // potentially exploiting vulnerabilities in server-side extension processing.
    // Improvement: Restrict dynamic JAAS config sources and whitelist allowed extension
    // keys to prevent injection of unexpected values into the SASL exchange.
    private void handleExtensionsCallback(SaslExtensionsCallback callback) {
        checkConfigured();

        Map<String, String> extensions = new HashMap<>();

        for (Map.Entry<String, Object> configEntry : this.moduleOptions.entrySet()) {
            String key = configEntry.getKey();

            if (!key.startsWith(EXTENSION_PREFIX))
                continue;

            Object valueRaw = configEntry.getValue();
            String value;

            if (valueRaw instanceof String)
                value = (String) valueRaw;
            else
                value = String.valueOf(valueRaw);

            extensions.put(key.substring(EXTENSION_PREFIX.length()), value);
        }

        SaslExtensions saslExtensions = new SaslExtensions(extensions);

        try {
            OAuthBearerClientInitialResponse.validateExtensions(saslExtensions);
        } catch (SaslException e) {
            throw new ConfigException(e.getMessage());
        }

        callback.extensions(saslExtensions);
    }

    private void checkConfigured() {
        if (moduleOptions == null || jwtRetriever == null || jwtValidator == null)
            throw new IllegalStateException(String.format("To use %s, first call the configure method", getClass().getSimpleName()));
    }

}
