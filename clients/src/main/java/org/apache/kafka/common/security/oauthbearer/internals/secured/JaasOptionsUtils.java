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

import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.common.network.ConnectionMode;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.ssl.DefaultSslEngineFactory;
import org.apache.kafka.common.security.ssl.SslFactory;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.login.AppConfigurationEntry;

/**
 * <code>JaasOptionsUtils</code> is a utility class to perform logic for the JAAS options and
 * is separated out here for easier, more direct testing.
 */

// SECURITY: SEC-OAUTH-098 (MEDIUM) JAAS option extraction utility — reads SASL/SSL configuration from
// JAAS login module options. These options may contain sensitive material (passwords, key
// store paths, trust store configurations).
// Why: JAAS options are the primary mechanism for passing SSL client configuration to the
// OAUTHBEARER HTTP components (token endpoint, JWKS endpoint). Misconfigured SSL options
// (e.g., trust-all trust manager) weaken the TLS security of OAuth token retrieval.
// Exploit: A malicious JAAS configuration could specify a custom SSLSocketFactory that
// disables certificate verification, enabling MITM attacks on the token/JWKS endpoints.
// The createSSLSocketFactory() method creates the factory from JAAS options without
// additional validation of the resulting SSL context's trust configuration.
// Improvement: Validate that the created SSLContext has a non-empty trust store and uses
// TLS 1.2+ protocol. Log a WARNING if the trust store is empty or uses weak protocols.

// DECISION: Centralized JAAS option parsing rather than per-class extraction. Alternatives:
// (1) Each class reads JAAS options directly, (2) Inject options via constructor. Rationale:
// Centralization ensures consistent mechanism validation, option extraction, and SSL factory
// creation. Reduces code duplication across HttpJwtRetriever, ClientCredentialsJwtRetriever,
// and VerificationKeyResolverFactory.

// CROSS-CUTTING: Used by HttpJwtRetriever (SSL for token endpoint),
// VerificationKeyResolverFactory (SSL for JWKS endpoint), ClientCredentialsJwtRetriever,
// and JwtBearerJwtRetriever.
// Depends on: SslFactory (SSL context creation), DefaultSslEngineFactory (SSLContext
// access), OAuthBearerLoginModule (mechanism name constant), ConfigDef (SSL config
// definitions).
// Contract: Constructor validates mechanism and extracts options. createSSLSocketFactory()
// creates a configured SSLSocketFactory. Thread-safe for read-only access.
public class JaasOptionsUtils {

    private static final Logger log = LoggerFactory.getLogger(JaasOptionsUtils.class);

    private final Map<String, Object> options;

    public JaasOptionsUtils(Map<String, Object> options) {
        this.options = options;
    }

    public JaasOptionsUtils(String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        this.options = getOptions(saslMechanism, jaasConfigEntries);
    }

    // SECURITY: SEC-OAUTH-099 (LOW) Extracts options map from JAAS config entry. Validates mechanism
    // Why: JAAS option extraction handles sensitive configuration
    // values including client secrets and credentials.
    // name matches OAUTHBEARER and exactly 1 config entry exists. The returned map is
    // unmodifiable (Collections.unmodifiableMap) to prevent downstream modification of
    // JAAS state.
    // Exploit: Sensitive JAAS options (client secrets, passwords) could
    // leak through option value extraction if not properly secured.
    // Improvement: Mask sensitive JAAS option values in log output
    // and clear them from memory after extraction.
    public static Map<String, Object> getOptions(String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));

        if (Objects.requireNonNull(jaasConfigEntries).size() != 1 || jaasConfigEntries.get(0) == null)
            throw new IllegalArgumentException(String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)", jaasConfigEntries.size()));

        return Collections.unmodifiableMap(jaasConfigEntries.get(0).getOptions());
    }

    public boolean containsKey(String name) {
        return options.containsKey(name);
    }

    // DECISION: Only creates SSLSocketFactory when URL protocol is HTTPS. For HTTP URLs,
    // no custom SSL is needed (and would be ignored by HttpURLConnection). For file://
    // URLs, SSL is not applicable. Rationale: Avoids unnecessary SSL context
    // initialization overhead.
    public boolean shouldCreateSSLSocketFactory(URL url) {
        return url.getProtocol().equalsIgnoreCase("https");
    }

    // DECISION: Creates a temporary ConfigDef with SSL client support, then wraps JAAS
    // options in an AbstractConfig to extract typed SSL config values. Alternative:
    // Manual option extraction by key name. Rationale: Reuses Kafka's SSL config parsing
    // logic (ConfigDef validation, type coercion, default values) for consistency with
    // broker SSL configuration.
    public Map<String, ?> getSslClientConfig() {
        ConfigDef sslConfigDef = new ConfigDef();
        sslConfigDef.withClientSslSupport();
        AbstractConfig sslClientConfig = new AbstractConfig(sslConfigDef, options);
        return sslClientConfig.values();
    }

    // SECURITY: SEC-OAUTH-100 (MEDIUM) Creates SSLSocketFactory from JAAS SSL options via SslFactory.
    // Why: JAAS option extraction handles sensitive configuration
    // values including client secrets and credentials.
    // The factory is used for HTTPS connections to the token endpoint and JWKS endpoint.
    // The SslFactory is configured in CLIENT mode — it will verify server certificates
    // using the trust store specified in JAAS options (or JVM default if not specified).
    // Note: The SSL config values are logged at DEBUG level — ensure DEBUG logging is
    // not enabled in production as it may reveal trust/key store paths.
    // Exploit: Sensitive JAAS options (client secrets, passwords) could
    // leak through option value extraction if not properly secured.
    // Improvement: Mask sensitive JAAS option values in log output
    // and clear them from memory after extraction.
    public SSLSocketFactory createSSLSocketFactory() {
        Map<String, ?> sslClientConfig = getSslClientConfig();
        SslFactory sslFactory = new SslFactory(ConnectionMode.CLIENT);
        sslFactory.configure(sslClientConfig);
        SSLSocketFactory socketFactory = ((DefaultSslEngineFactory) sslFactory.sslEngineFactory()).sslContext().getSocketFactory();
        log.debug("Created SSLSocketFactory: {}", sslClientConfig);
        return socketFactory;
    }

    public String validatePassword(String name) {
        Password value = (Password) options.get(name);

        if (value == null || Utils.isBlank(value.value()))
            throw new ConfigException(String.format("The OAuth configuration option %s value is required", name));

        return value.value().trim();
    }

    public String validateString(String name) {
        return validateString(name, true);
    }

    public String validateString(String name, boolean isRequired) {
        String value = (String) options.get(name);

        if (Utils.isBlank(value)) {
            if (isRequired)
                throw new ConfigException(String.format("The OAuth configuration option %s value is required", name));
            else
                return null;
        }

        return value.trim();
    }
}
