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

import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.common.network.ListenerName;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.Login;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerUnsecuredLoginCallbackHandler;
import org.apache.kafka.common.utils.SecurityUtils;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import static java.util.Arrays.asList;

// CROSS-CUTTING: Central lifecycle manager consumed by all SASL mechanism handlers.
// Depends on: auth/Login, auth/AuthenticateCallbackHandler, JaasContext,
// oauthbearer/OAuthBearerLoginModule. Consumed by: SaslChannelBuilder.
// Contract: acquireLoginManager() returns a Login; callers MUST call release() when done.
/**
 * Centralized, reference-counted lifecycle manager for {@link Login} and
 * {@link AuthenticateCallbackHandler} instances.
 *
 * @implSpec SECURITY: (HIGH) Reference-counted login lifecycle management.
 * Caches Login instances (with authenticated JAAS Subjects) in static maps.
 * Exploit: A double-release would decrement refCount below zero; a subsequent
 * acquire/release could close the Login while another holder still uses it --
 * a use-after-close exposing the JAAS Subject in an inconsistent state.
 * Mitigation: refCount==0 check in release() throws IllegalStateException.
 * Improvement: Use AtomicInteger with CAS; validate refCount &gt; 0 before decrement.
 */
public class LoginManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginManager.class);

    // DECISION: Two separate cache maps (static vs. dynamic) rather than a unified cache.
    // Rationale: Static JAAS configs identified by context name; dynamic configs by Password
    // value, enabling hot-reload when config changes. Risk: static instances persist until
    // JVM exit unless explicitly cleared via closeAll().
    // SECURITY: (HIGH) Caches hold Login instances with authenticated JAAS Subjects.
    // Exploit: If Password.hashCode/equals leaks timing info (DYNAMIC_INSTANCES keyed by
    // Password), side-channel attacks could reveal config values. Password.equals() uses
    // constant-time comparison. Improvement: Consider non-sensitive hash as cache key.
    // static configs (broker or client)
    private static final Map<LoginMetadata<String>, LoginManager> STATIC_INSTANCES = new HashMap<>();

    // dynamic configs (broker or client)
    private static final Map<LoginMetadata<Password>, LoginManager> DYNAMIC_INSTANCES = new HashMap<>();

    private final Login login;
    private final LoginMetadata<?> loginMetadata;
    private final AuthenticateCallbackHandler loginCallbackHandler;
    private int refCount;

    // SECURITY: (MEDIUM) Constructor performs login immediately via reflection-created
    // Login/CallbackHandler instances (Utils.newInstance). If login fails, closeResources()
    // cleans up partial state. Exploit: Any class on the classpath matching the Login or
    // AuthenticateCallbackHandler type could be instantiated via reflection.
    // Improvement: Add explicit type allowlisting beyond the upstream JAAS module check.
    private LoginManager(JaasContext jaasContext, String saslMechanism, Map<String, ?> configs,
                 LoginMetadata<?> loginMetadata) throws LoginException {
        this.loginMetadata = loginMetadata;
        this.login = Utils.newInstance(loginMetadata.loginClass);
        loginCallbackHandler = Utils.newInstance(loginMetadata.loginCallbackClass);
        try {
            loginCallbackHandler.configure(configs, saslMechanism, jaasContext.configurationEntries());
            login.configure(configs, jaasContext.name(), jaasContext.configuration(), loginCallbackHandler);
            login.login();
        } catch (Exception e) {
            closeResources();
            throw e;
        }
    }

    /**
     * Returns an instance of `LoginManager` and increases its reference count.
     *
     * `release()` should be invoked when the `LoginManager` is no longer needed. This method will try to reuse an
     * existing `LoginManager` for the provided context type. If `jaasContext` was loaded from a dynamic config,
     * login managers are reused for the same dynamic config value. For `jaasContext` loaded from static JAAS
     * configuration, login managers are reused for static contexts with the same login context name.
     *
     * This is a bit ugly and it would be nicer if we could pass the `LoginManager` to `ChannelBuilders.create` and
     * shut it down when the broker or clients are closed. It's straightforward to do the former, but it's more
     * complicated to do the latter without making the consumer API more complex.
     *
     * @param jaasContext Static or dynamic JAAS context. `jaasContext.dynamicJaasConfig()` is non-null for dynamic context.
     *                    For static contexts, this may contain multiple login modules if the context type is SERVER.
     *                    For CLIENT static contexts and dynamic contexts of CLIENT and SERVER, `jaasContext` contains
     *                    only one login module.
     * @param saslMechanism SASL mechanism for which login manager is being acquired. For dynamic contexts, the single
     *                      login module in `jaasContext` corresponds to this SASL mechanism. Hence `Login` class is
     *                      chosen based on this mechanism.
     * @param defaultLoginClass Default login class to use if an override is not specified in `configs`
     * @param configs Config options used to configure `Login` if a new login manager is created.
     *
     */
    // COMPLEXITY: ~32 lines -- Login instance acquisition with class resolution and
    // caching. Structure: (1) Resolve loginClass from config or default, (2) Resolve
    // loginCallbackClass with OAUTHBEARER special-casing, (3) Synchronized block:
    // branch on dynamic vs static JAAS config, (4) Check cache / create LoginManager
    // on miss, (5) Add security providers, (6) Return acquired instance.
    // Key paths: dynamic -> DYNAMIC_INSTANCES cache; static -> STATIC_INSTANCES cache.
    public static LoginManager acquireLoginManager(JaasContext jaasContext, String saslMechanism,
                                                   Class<? extends Login> defaultLoginClass,
                                                   Map<String, ?> configs) throws LoginException {
        Class<? extends Login> loginClass = configuredClassOrDefault(configs, jaasContext,
                saslMechanism, SaslConfigs.SASL_LOGIN_CLASS, defaultLoginClass);
        Class<? extends AuthenticateCallbackHandler> defaultLoginCallbackHandlerClass = OAuthBearerLoginModule.OAUTHBEARER_MECHANISM
                .equals(saslMechanism) ? OAuthBearerUnsecuredLoginCallbackHandler.class
                        : AbstractLogin.DefaultLoginCallbackHandler.class;
        Class<? extends AuthenticateCallbackHandler> loginCallbackClass = configuredClassOrDefault(configs, jaasContext,
                saslMechanism, SaslConfigs.SASL_LOGIN_CALLBACK_HANDLER_CLASS, defaultLoginCallbackHandlerClass);
        // DECISION: Class-level synchronization rather than per-mechanism or per-cache
        // locking. Alternative: ConcurrentHashMap.computeIfAbsent. Rationale: Login
        // creation has side effects (JAAS login, Kerberos TGT) that must not execute
        // concurrently for the same key. Tradeoff: all mechanisms contend on one lock.
        synchronized (LoginManager.class) {
            LoginManager loginManager;
            Password jaasConfigValue = jaasContext.dynamicJaasConfig();
            if (jaasConfigValue != null) {
                LoginMetadata<Password> loginMetadata = new LoginMetadata<>(jaasConfigValue, loginClass, loginCallbackClass, configs);
                loginManager = DYNAMIC_INSTANCES.get(loginMetadata);
                if (loginManager == null) {
                    loginManager = new LoginManager(jaasContext, saslMechanism, configs, loginMetadata);
                    DYNAMIC_INSTANCES.put(loginMetadata, loginManager);
                }
            } else {
                LoginMetadata<String> loginMetadata = new LoginMetadata<>(jaasContext.name(), loginClass, loginCallbackClass, configs);
                loginManager = STATIC_INSTANCES.get(loginMetadata);
                if (loginManager == null) {
                    loginManager = new LoginManager(jaasContext, saslMechanism, configs, loginMetadata);
                    STATIC_INSTANCES.put(loginMetadata, loginManager);
                }
            }
            // CROSS-CUTTING: Registers JDK security providers (e.g., BouncyCastle)
            // configured via security.providers -- affects the global JVM provider list.
            SecurityUtils.addConfiguredSecurityProviders(configs);
            return loginManager.acquire();
        }
    }

    public Subject subject() {
        return login.subject();
    }

    public String serviceName() {
        return login.serviceName();
    }

    // Only for testing
    Object cacheKey() {
        return loginMetadata.configInfo;
    }

    private LoginManager acquire() {
        ++refCount;
        LOGGER.trace("{} acquired", this);
        return this;
    }

    /**
     * Decrease the reference count for this instance and release resources if it reaches 0.
     */
    // SECURITY: (HIGH) Reference-counted lifecycle with synchronized(LoginManager.class).
    // Why: Last release (refCount==1) closes Login and removes from cache atomically.
    // Exploit: Without synchronization, a thread could find a cached instance between
    // the cache removal and login.close(), obtaining a closing/closed Login.
    // Improvement: Consider ReadWriteLock for concurrent reads with exclusive releases.
    public void release() {
        synchronized (LoginManager.class) {
            if (refCount == 0)
                throw new IllegalStateException("release() called on disposed " + this);
            else if (refCount == 1) {
                if (loginMetadata.configInfo instanceof Password) {
                    DYNAMIC_INSTANCES.remove(loginMetadata);
                } else {
                    STATIC_INSTANCES.remove(loginMetadata);
                }
                login.close();
                loginCallbackHandler.close();
            }
            --refCount;
            LOGGER.trace("{} released", this);
        }
    }

    // SECURITY: (MEDIUM) toString() avoids Subject.toString() which exposes private
    // credentials. Exploit: If Subject.toString() were used, passwords/tokens would
    // appear in log files accessible to operators. Improvement: Consider redaction util.
    @Override
    public String toString() {
        return "LoginManager(serviceName=" + serviceName() +
                // subject.toString() exposes private credentials, so we can't use it
                ", publicCredentials=" + subject().getPublicCredentials() +
                ", refCount=" + refCount + ')';
    }

    /**
     * Closes Login and AuthenticateCallbackHandler quietly.
     * The function logs exceptions that are thrown during closing.
     */
    private void closeResources() {
        try {
            List<Callable<Void>> tasks = asList(
                    () -> {
                        login.close();
                        return null;
                    },
                    () -> {
                        loginCallbackHandler.close();
                        return null;
                    }
            );
            Utils.tryAll(tasks);
        } catch (Throwable t) {
            LOGGER.info("Exception thrown during closing", t);
        }
    }

    /* Should only be used in tests. */
    public static void closeAll() {
        synchronized (LoginManager.class) {
            for (LoginMetadata<String> key : new ArrayList<>(STATIC_INSTANCES.keySet()))
                STATIC_INSTANCES.remove(key).login.close();
            for (LoginMetadata<Password> key : new ArrayList<>(DYNAMIC_INSTANCES.keySet()))
                DYNAMIC_INSTANCES.remove(key).login.close();
        }
    }

    // DECISION: Listener-name prefix (e.g., "sasl_ssl.sasl.") applied only for SERVER
    // type, not CLIENT. This enables per-listener mechanism configuration on the broker
    // while keeping client config flat. The multi-module check prevents ambiguity when
    // overriding classes in multi-entry JAAS configs.
    private static <T> Class<? extends T> configuredClassOrDefault(Map<String, ?> configs,
                                                     JaasContext jaasContext,
                                                     String saslMechanism,
                                                     String configName,
                                                     Class<? extends T> defaultClass) {
        String prefix  = jaasContext.type() == JaasContext.Type.SERVER ? ListenerName.saslMechanismPrefix(saslMechanism) : "";
        @SuppressWarnings("unchecked")
        Class<? extends T> clazz = (Class<? extends T>) configs.get(prefix + configName);
        if (clazz != null && jaasContext.configurationEntries().size() != 1) {
            String errorMessage = configName + " cannot be specified with multiple login modules in the JAAS context. " +
                    SaslConfigs.SASL_JAAS_CONFIG + " must be configured to override mechanism-specific configs.";
            throw new ConfigException(errorMessage);
        }
        if (clazz == null)
            clazz = defaultClass;
        return clazz;
    }

    // DECISION: Cache key includes loginClass + loginCallbackClass + saslConfigs (filtered
    // to sasl.* keys only). Changing ANY sasl.* config creates a new cache entry and Login.
    // Alternative: key only on configInfo. Rationale: different SASL configs may require
    // different Login behavior (e.g., different OAuth token endpoints).
    private static class LoginMetadata<T> {
        final T configInfo;
        final Class<? extends Login> loginClass;
        final Class<? extends AuthenticateCallbackHandler> loginCallbackClass;
        final Map<String, Object> saslConfigs;

        LoginMetadata(T configInfo, Class<? extends Login> loginClass,
                      Class<? extends AuthenticateCallbackHandler> loginCallbackClass,
                      Map<String, ?> configs) {
            this.configInfo = configInfo;
            this.loginClass = loginClass;
            this.loginCallbackClass = loginCallbackClass;
            this.saslConfigs = new HashMap<>();
            configs.entrySet().stream()
                    .filter(e -> e.getKey().startsWith("sasl."))
                    .forEach(e -> saslConfigs.put(e.getKey(), e.getValue())); // value may be null
        }

        @Override
        public int hashCode() {
            return Objects.hash(configInfo, loginClass, loginCallbackClass, saslConfigs);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            LoginMetadata<?> loginMetadata = (LoginMetadata<?>) o;
            return Objects.equals(configInfo, loginMetadata.configInfo) &&
                   Objects.equals(loginClass, loginMetadata.loginClass) &&
                   Objects.equals(loginCallbackClass, loginMetadata.loginCallbackClass) &&
                   Objects.equals(saslConfigs, loginMetadata.saslConfigs);
        }
    }
}
