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
package org.apache.kafka.common.security;

import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.common.network.ListenerName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import static org.apache.kafka.common.security.JaasUtils.ALLOWED_LOGIN_MODULES_CONFIG;
import static org.apache.kafka.common.security.JaasUtils.DISALLOWED_LOGIN_MODULES_CONFIG;
import static org.apache.kafka.common.security.JaasUtils.DISALLOWED_LOGIN_MODULES_DEFAULT;

/**
 * JAAS context for Kafka's SASL authentication, supporting dynamic per-listener
 * and static file-based configuration resolution.
 *
 * @implSpec SECURITY: SEC-JAAS-005 (MEDIUM) Login module allowlist/denylist enforcement.
 * Why: JAAS context resolution determines which login modules
 * are trusted and loaded for authentication.
 * JaasContext controls which login modules can be loaded via SASL_JAAS_CONFIG.
 * Exploit: A malicious admin injects "JndiLoginModule REQUIRED" into sasl.jaas.config,
 * triggering JNDI lookups to attacker-controlled LDAP (CVE-2023-25194 pattern).
 * Improvement: Restrict dynamic JAAS config to well-known Kafka login modules by default.
 *
 * @implNote DECISION: Separate server/client loading paths (loadServerContext vs
 * loadClientContext) rather than a unified method. Server contexts require listener-name
 * and mechanism-specific config resolution; client contexts use flat global config.
 * Separate methods prevent cross-contamination of credential resolution strategies.
 */
// CROSS-CUTTING: Consumed by authenticator/LoginManager, SaslServerAuthenticator,
// SaslClientAuthenticator, and all SASL mechanism implementations for context resolution.
// Contract: Immutable after construction; thread-safe for concurrent reads.
// Depends on: JaasConfig, JaasUtils, SaslConfigs (common/config), ListenerName (common/network).
public class JaasContext {

    private static final Logger LOG = LoggerFactory.getLogger(JaasContext.class);

    private static final String GLOBAL_CONTEXT_NAME_SERVER = "KafkaServer";
    private static final String GLOBAL_CONTEXT_NAME_CLIENT = "KafkaClient";

    /**
     * Returns an instance of this class.
     *
     * The context will contain the configuration specified by the JAAS configuration property
     * {@link SaslConfigs#SASL_JAAS_CONFIG} with prefix `listener.name.{listenerName}.{mechanism}.`
     * with listenerName and mechanism in lower case. The context `KafkaServer` will be returned
     * with a single login context entry loaded from the property.
     * <p>
     * If the property is not defined, the context will contain the default Configuration and
     * the context name will be one of:
     * <ol>
     *   <li>Lowercased listener name followed by a period and the string `KafkaServer`</li>
     *   <li>The string `KafkaServer`</li>
     *  </ol>
     * If both are valid entries in the default JAAS configuration, the first option is chosen.
     * </p>
     *
     * @throws IllegalArgumentException if listenerName or mechanism is not defined.
     */
    // SECURITY: SEC-JAAS-006 (MEDIUM) Server-side JAAS context loading uses mechanism-prefixed config keys
    // Why: JAAS context resolution determines which login modules
    // are trusted and loaded for authentication.
    // to isolate per-mechanism credentials. Misconfigured prefix resolution could expose one
    // mechanism's credentials to another.
    // Exploit: A malformed JAAS configuration could disable authentication or load a malicious login module.
    // Improvement: Validate JAAS configurations at startup and restrict login module classes to an allowlist.
    public static JaasContext loadServerContext(ListenerName listenerName, String mechanism, Map<String, ?> configs) {
        if (listenerName == null)
            throw new IllegalArgumentException("listenerName should not be null for SERVER");
        if (mechanism == null)
            throw new IllegalArgumentException("mechanism should not be null for SERVER");
        String listenerContextName = listenerName.value().toLowerCase(Locale.ROOT) + "." + GLOBAL_CONTEXT_NAME_SERVER;
        // SECURITY: SEC-JAAS-007 (MEDIUM) Dynamic JAAS config from Password type -- value is in-memory only, not
        // Why: JAAS context resolution determines which login modules
        // are trusted and loaded for authentication.
        // persisted to disk. May appear in config dumps unless explicitly masked.
        // The log.warn below correctly avoids logging the config value itself.
        // Exploit: A malformed JAAS configuration could disable authentication or load a malicious login module.
        // Improvement: Validate JAAS configurations at startup and restrict login module classes to an allowlist.
        Password dynamicJaasConfig = (Password) configs.get(mechanism.toLowerCase(Locale.ROOT) + "." + SaslConfigs.SASL_JAAS_CONFIG);
        if (dynamicJaasConfig == null && configs.get(SaslConfigs.SASL_JAAS_CONFIG) != null)
            LOG.warn("Server config {} should be prefixed with SASL mechanism name, ignoring config", SaslConfigs.SASL_JAAS_CONFIG);
        return load(Type.SERVER, listenerContextName, GLOBAL_CONTEXT_NAME_SERVER, dynamicJaasConfig);
    }

    /**
     * Returns an instance of this class.
     *
     * If JAAS configuration property {@link SaslConfigs#SASL_JAAS_CONFIG} is specified,
     * the configuration object is created by parsing the property value. Otherwise, the default Configuration
     * is returned. The context name is always `KafkaClient`.
     *
     */
    public static JaasContext loadClientContext(Map<String, ?> configs) {
        Password dynamicJaasConfig = (Password) configs.get(SaslConfigs.SASL_JAAS_CONFIG);
        return load(JaasContext.Type.CLIENT, null, GLOBAL_CONTEXT_NAME_CLIENT, dynamicJaasConfig);
    }

    // DECISION: Enforces exactly 1 login module for dynamic configs but allows multiple for
    // file-based JAAS. Rationale: Dynamic per-listener configs target a single mechanism;
    // allowing multiple modules would create ambiguity about which handles authentication.
    static JaasContext load(JaasContext.Type contextType, String listenerContextName,
                            String globalContextName, Password dynamicJaasConfig) {
        if (dynamicJaasConfig != null) {
            JaasConfig jaasConfig = new JaasConfig(globalContextName, dynamicJaasConfig.value());
            AppConfigurationEntry[] contextModules = jaasConfig.getAppConfigurationEntry(globalContextName);
            if (contextModules == null || contextModules.length == 0)
                throw new IllegalArgumentException("JAAS config property does not contain any login modules");
            else if (contextModules.length != 1)
                throw new IllegalArgumentException("JAAS config property contains " + contextModules.length + " login modules, should be 1 module");

            throwIfLoginModuleIsNotAllowed(contextModules[0]);
            return new JaasContext(globalContextName, contextType, jaasConfig, dynamicJaasConfig);
        } else
            return defaultContext(contextType, listenerContextName, globalContextName);
    }

    // SECURITY: SEC-JAAS-008 (HIGH) Login module validation -- last line of defense against arbitrary class
    // Why: JAAS context resolution determines which login modules
    // are trusted and loaded for authentication.
    // instantiation via JAAS config injection. Without this check, any class on the classpath
    // could be loaded as a login module via dynamic SASL_JAAS_CONFIG.
    // Exploit: If bypassed, attacker-specified login modules execute in the broker's JVM.
    // Improvement: Validate at JaasConfig.getAppConfigurationEntry() as defense-in-depth.
    //
    // COMPLEXITY: ~30 lines -- dual-path validation with allowlist/denylist precedence.
    // Control flow: (1) Check deprecated DISALLOWED property, log warning; (2) If ALLOWED
    // property set, check membership -> return or throw; (3) If no ALLOWED, fall back to
    // DISALLOWED with default denylist -> throw if disallowed.
    // Exit paths: normal return, IllegalArgumentException.
    @SuppressWarnings("deprecation")
    // Visible for testing
     static void throwIfLoginModuleIsNotAllowed(AppConfigurationEntry appConfigurationEntry) {
        String disallowedProperty = System.getProperty(DISALLOWED_LOGIN_MODULES_CONFIG);
        if (disallowedProperty != null) {
            LOG.warn("System property '{}' is deprecated and will be removed in a future release. Use '{}' instead.",
                    DISALLOWED_LOGIN_MODULES_CONFIG, ALLOWED_LOGIN_MODULES_CONFIG);
        }
        String loginModuleName = appConfigurationEntry.getLoginModuleName().trim();
        String allowedProperty = System.getProperty(ALLOWED_LOGIN_MODULES_CONFIG);
        if (allowedProperty != null) {
            Set<String> allowedLoginModuleList = Arrays.stream(allowedProperty.split(","))
                    .map(String::trim)
                    .collect(Collectors.toSet());
            if (!allowedLoginModuleList.contains(loginModuleName)) {
                throw new IllegalArgumentException(loginModuleName + " is not allowed. Update System property '"
                        + ALLOWED_LOGIN_MODULES_CONFIG + "' to allow " + loginModuleName);
            }
            return;
        }
        if (disallowedProperty == null) {
            disallowedProperty = DISALLOWED_LOGIN_MODULES_DEFAULT;
        }
        Set<String> disallowedLoginModuleList = Arrays.stream(disallowedProperty.split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
        if (disallowedLoginModuleList.contains(loginModuleName)) {
            throw new IllegalArgumentException(loginModuleName + " is not allowed. "
                + "The system property '" + DISALLOWED_LOGIN_MODULES_CONFIG + "' is deprecated. "
                + "Use the " + ALLOWED_LOGIN_MODULES_CONFIG + " to allow this module. e.g.,"
                + "-D" + ALLOWED_LOGIN_MODULES_CONFIG + "=" + loginModuleName);
        }
    }

    // DECISION: Falls back from listener-specific context name to global "KafkaServer" context.
    // This two-tier lookup enables backward compatibility with pre-KIP-103 JAAS files that
    // only define "KafkaServer".
    //
    // COMPLEXITY: ~40 lines -- multi-step JAAS context resolution with fallback.
    // Structure: (1) Check system property for JAAS config file; (2) Get default Configuration;
    // (3) Try listener-specific context name; (4) Fall back to global context name;
    // (5) Validate all modules; (6) Construct JaasContext.
    // Key paths: listener name found, global fallback, no config file. Each validates modules.
    private static JaasContext defaultContext(JaasContext.Type contextType, String listenerContextName,
                                              String globalContextName) {
        String jaasConfigFile = System.getProperty(JaasUtils.JAVA_LOGIN_CONFIG_PARAM);
        if (jaasConfigFile == null) {
            if (contextType == Type.CLIENT) {
                LOG.debug("System property '" + JaasUtils.JAVA_LOGIN_CONFIG_PARAM + "' and Kafka SASL property '" +
                        SaslConfigs.SASL_JAAS_CONFIG + "' are not set, using default JAAS configuration.");
            } else {
                LOG.debug("System property '" + JaasUtils.JAVA_LOGIN_CONFIG_PARAM + "' is not set, using default JAAS " +
                        "configuration.");
            }
        }

        Configuration jaasConfig = Configuration.getConfiguration();

        AppConfigurationEntry[] configEntries = null;
        String contextName = globalContextName;

        if (listenerContextName != null) {
            configEntries = jaasConfig.getAppConfigurationEntry(listenerContextName);
            if (configEntries != null)
                contextName = listenerContextName;
        }

        if (configEntries == null)
            configEntries = jaasConfig.getAppConfigurationEntry(globalContextName);

        if (configEntries == null) {
            String listenerNameText = listenerContextName == null ? "" : " or '" + listenerContextName + "'";
            String errorMessage = "Could not find a '" + globalContextName + "'" + listenerNameText + " entry in the JAAS " +
                    "configuration. System property '" + JaasUtils.JAVA_LOGIN_CONFIG_PARAM + "' is " +
                    (jaasConfigFile == null ? "not set" : jaasConfigFile);
            throw new IllegalArgumentException(errorMessage);
        }

        for (AppConfigurationEntry appConfigurationEntry : configEntries) {
            throwIfLoginModuleIsNotAllowed(appConfigurationEntry);
        }
        return new JaasContext(contextName, contextType, jaasConfig, null);
    }

    /**
     * The type of the SASL login context, it should be SERVER for the broker and CLIENT for the clients (consumer, producer,
     * etc.). This is used to validate behaviour (e.g. some functionality is only available in the broker or clients).
     */
    // DECISION: Simple CLIENT/SERVER enum rather than more granular types (INTER_BROKER,
    // CONTROLLER, etc.). JAAS configuration is only differentiated at the client/server
    // boundary; listener-based differentiation is handled by the context name, not type.
    public enum Type { CLIENT, SERVER }

    private final String name;
    private final Type type;
    private final Configuration configuration;
    private final List<AppConfigurationEntry> configurationEntries;
    private final Password dynamicJaasConfig;

    public JaasContext(String name, Type type, Configuration configuration, Password dynamicJaasConfig) {
        this.name = name;
        this.type = type;
        this.configuration = configuration;
        AppConfigurationEntry[] entries = configuration.getAppConfigurationEntry(name);
        if (entries == null)
            throw new IllegalArgumentException("Could not find a '" + name + "' entry in this JAAS configuration.");
        this.configurationEntries = List.of(entries);
        this.dynamicJaasConfig = dynamicJaasConfig;
    }

    public String name() {
        return name;
    }

    public Type type() {
        return type;
    }

    public Configuration configuration() {
        return configuration;
    }

    public List<AppConfigurationEntry> configurationEntries() {
        return configurationEntries;
    }

    public Password dynamicJaasConfig() {
        return dynamicJaasConfig;
    }

    /**
     * Returns the configuration option for <code>key</code> from this context.
     * If login module name is specified, return option value only from that module.
     */
    // CROSS-CUTTING: Called by KerberosLogin, ScramLoginModule, and OAUTHBEARER handlers
    // to extract mechanism-specific options (e.g., serviceName, tokenEndpointUrl)
    // from the JAAS configuration entries.
    public static String configEntryOption(List<AppConfigurationEntry> configurationEntries, String key, String loginModuleName) {
        for (AppConfigurationEntry entry : configurationEntries) {
            if (loginModuleName != null && !loginModuleName.equals(entry.getLoginModuleName()))
                continue;
            Object val = entry.getOptions().get(key);
            if (val != null)
                return (String) val;
        }
        return null;
    }

}
