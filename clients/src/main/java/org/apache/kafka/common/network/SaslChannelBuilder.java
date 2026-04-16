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
package org.apache.kafka.common.network;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.config.internals.BrokerSecurityConfigs;
import org.apache.kafka.common.memory.MemoryPool;
import org.apache.kafka.common.requests.ApiVersionsResponse;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.Login;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.common.security.authenticator.CredentialCache;
import org.apache.kafka.common.security.authenticator.DefaultLogin;
import org.apache.kafka.common.security.authenticator.LoginManager;
import org.apache.kafka.common.security.authenticator.SaslClientAuthenticator;
import org.apache.kafka.common.security.authenticator.SaslClientCallbackHandler;
import org.apache.kafka.common.security.authenticator.SaslServerAuthenticator;
import org.apache.kafka.common.security.authenticator.SaslServerCallbackHandler;
import org.apache.kafka.common.security.kerberos.KerberosClientCallbackHandler;
import org.apache.kafka.common.security.kerberos.KerberosLogin;
import org.apache.kafka.common.security.kerberos.KerberosName;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerRefreshingLogin;
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerSaslClientCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerUnsecuredValidatorCallbackHandler;
import org.apache.kafka.common.security.plain.internals.PlainSaslServer;
import org.apache.kafka.common.security.plain.internals.PlainServerCallbackHandler;
import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;
import org.apache.kafka.common.security.scram.internals.ScramServerCallbackHandler;
import org.apache.kafka.common.security.ssl.SslFactory;
import org.apache.kafka.common.security.token.delegation.internals.DelegationTokenCache;
import org.apache.kafka.common.utils.LogContext;
import org.apache.kafka.common.utils.Time;
import org.apache.kafka.common.utils.Utils;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.Socket;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

// SECURITY: (HIGH) SaslChannelBuilder constructs authenticated SASL channels
// for both SASL_PLAINTEXT and SASL_SSL security protocols. This builder
// orchestrates the JAAS configuration, LoginManager lifecycle, per-mechanism
// callback handler instantiation, and SASL authenticator creation.
// Why: This class is the entry point for all SASL authentication
// configuration — a misconfiguration here (wrong JAAS config, missing
// callback handler, incorrect mechanism list) can silently disable
// authentication or weaken the security posture.
// Risk: If the LoginManager is shared across mechanisms without proper
// isolation, a compromise of one mechanism's credentials could affect
// others. The reflective instantiation of callback handlers (via
// Utils.newInstance) could load malicious classes if the classpath is
// compromised.
// Improvement: Consider validating callback handler class names against
// an allowlist before reflective instantiation to prevent classloading
// attacks.
//
// CROSS-CUTTING: Depends on security/authenticator/ (SaslServerAuthenticator,
// SaslClientAuthenticator, LoginManager, CredentialCache),
// security/kerberos/ (KerberosLogin, KerberosShortNamer),
// security/oauthbearer/ (OAuthBearerSaslClientCallbackHandler),
// security/scram/ (ScramMechanism, ScramServerCallbackHandler),
// security/plain/ (PlainSaslServer, PlainServerCallbackHandler),
// and security/token/delegation/ (DelegationTokenCache).
// Contract: LoginManager must be successfully created before
// buildChannel() is called.
// Impact: Changes to any SASL mechanism's callback handler interface
// break this builder.
// Exploit: A malicious client could send crafted packets to manipulate state transitions and bypass authentication.
public class SaslChannelBuilder implements ChannelBuilder, ListenerReconfigurable {
    static final String GSS_NATIVE_PROP = "sun.security.jgss.native";

    private final SecurityProtocol securityProtocol;
    private final ListenerName listenerName;
    private final boolean isInterBrokerListener;
    private final String clientSaslMechanism;
    private final ConnectionMode connectionMode;
    private final Map<String, JaasContext> jaasContexts;
    private final CredentialCache credentialCache;
    private final DelegationTokenCache tokenCache;
    private final Map<String, LoginManager> loginManagers;
    private final Map<String, Subject> subjects;
    private final Function<Short, ApiVersionsResponse> apiVersionSupplier;
    private final String sslClientAuthOverride;
    private final Map<String, AuthenticateCallbackHandler> saslCallbackHandlers;
    private final Map<String, Long> connectionsMaxReauthMsByMechanism;
    private final Time time;
    private final LogContext logContext;
    private final Logger log;

    private SslFactory sslFactory;
    private Map<String, ?> configs;
    private KerberosShortNamer kerberosShortNamer;

    public SaslChannelBuilder(ConnectionMode connectionMode,
                              Map<String, JaasContext> jaasContexts,
                              SecurityProtocol securityProtocol,
                              ListenerName listenerName,
                              boolean isInterBrokerListener,
                              String clientSaslMechanism,
                              CredentialCache credentialCache,
                              DelegationTokenCache tokenCache,
                              String sslClientAuthOverride,
                              Time time,
                              LogContext logContext,
                              Function<Short, ApiVersionsResponse> apiVersionSupplier) {
        this.connectionMode = connectionMode;
        this.jaasContexts = jaasContexts;
        this.loginManagers = new HashMap<>(jaasContexts.size());
        this.subjects = new HashMap<>(jaasContexts.size());
        this.securityProtocol = securityProtocol;
        this.listenerName = listenerName;
        this.isInterBrokerListener = isInterBrokerListener;
        this.clientSaslMechanism = clientSaslMechanism;
        this.credentialCache = credentialCache;
        this.tokenCache = tokenCache;
        this.sslClientAuthOverride = sslClientAuthOverride;
        this.saslCallbackHandlers = new HashMap<>();
        this.connectionsMaxReauthMsByMechanism = new HashMap<>();
        this.time = time;
        this.logContext = logContext;
        this.log = logContext.logger(getClass());
        this.apiVersionSupplier = apiVersionSupplier;

        if (connectionMode == ConnectionMode.SERVER && apiVersionSupplier == null) {
            throw new IllegalArgumentException("Server channel builder must provide an ApiVersionResponse supplier");
        }
    }

    // COMPLEXITY: Method size ~45 lines — multi-phase SASL configuration
    // covering server/client callback handler creation, Kerberos realm
    // resolution, LoginManager acquisition per mechanism, and optional
    // SSL factory setup.
    // Structure: (1) Server/client branch for callback handler creation,
    // (2) Kerberos short-namer initialization if GSSAPI is configured,
    // (3) LoginManager loop per JAAS context with native GSS credential
    // injection, (4) SASL_SSL SslFactory initialization.
    // Key paths: Happy path completes all four phases; any exception in
    // phases 1-4 triggers close() cleanup and re-throws as KafkaException.
    @SuppressWarnings("unchecked")
    @Override
    public void configure(Map<String, ?> configs) throws KafkaException {
        try {
            this.configs = configs;
            if (connectionMode == ConnectionMode.SERVER) {
                createServerCallbackHandlers(configs);
                createConnectionsMaxReauthMsMap(configs);
            } else
                createClientCallbackHandler(configs);
            for (Map.Entry<String, AuthenticateCallbackHandler> entry : saslCallbackHandlers.entrySet()) {
                String mechanism = entry.getKey();
                entry.getValue().configure(configs, mechanism, jaasContexts.get(mechanism).configurationEntries());
            }

            Class<? extends Login> defaultLoginClass = defaultLoginClass();
            if (connectionMode == ConnectionMode.SERVER && jaasContexts.containsKey(SaslConfigs.GSSAPI_MECHANISM)) {
                String defaultRealm;
                try {
                    defaultRealm = defaultKerberosRealm();
                } catch (Exception ke) {
                    defaultRealm = "";
                }
                List<String> principalToLocalRules = (List<String>) configs.get(BrokerSecurityConfigs.SASL_KERBEROS_PRINCIPAL_TO_LOCAL_RULES_CONFIG);
                if (principalToLocalRules != null)
                    kerberosShortNamer = KerberosShortNamer.fromUnparsedRules(defaultRealm, principalToLocalRules);
            }
            // SECURITY: (HIGH) LoginManager instances are reference-counted
            // singletons per mechanism. Sharing LoginManagers across
            // connections for the same mechanism improves performance
            // (avoids repeated Kerberos TGT acquisition) but means a
            // credential compromise affects all connections. The
            // DelegationTokenCache and CredentialCache parameters inject
            // server-side token/credential stores that the authenticator
            // uses for validation.
            // Risk: A single compromised LoginManager allows an attacker
            // to hijack all connections using that mechanism.
            // Improvement: Consider per-connection LoginManager isolation
            // for high-security deployments at the cost of performance.
            // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
            for (Map.Entry<String, JaasContext> entry : jaasContexts.entrySet()) {
                String mechanism = entry.getKey();
                // With static JAAS configuration, use KerberosLogin if Kerberos is enabled. With dynamic JAAS configuration,
                // use KerberosLogin only for the LoginContext corresponding to GSSAPI
                LoginManager loginManager = LoginManager.acquireLoginManager(entry.getValue(), mechanism, defaultLoginClass, configs);
                loginManagers.put(mechanism, loginManager);
                Subject subject = loginManager.subject();
                subjects.put(mechanism, subject);
                if (connectionMode == ConnectionMode.SERVER && mechanism.equals(SaslConfigs.GSSAPI_MECHANISM))
                    maybeAddNativeGssapiCredentials(subject);
            }
            if (this.securityProtocol == SecurityProtocol.SASL_SSL) {
                // Disable SSL client authentication as we are using SASL authentication
                this.sslFactory = new SslFactory(connectionMode, sslClientAuthOverride, isInterBrokerListener);
                this.sslFactory.configure(configs);
            }
        } catch (Throwable e) {
            close();
            throw new KafkaException(e);
        }
    }

    @Override
    public Set<String> reconfigurableConfigs() {
        return securityProtocol == SecurityProtocol.SASL_SSL ? SslConfigs.RECONFIGURABLE_CONFIGS : Collections.emptySet();
    }

    @Override
    public void validateReconfiguration(Map<String, ?> configs) throws ConfigException {
        if (this.securityProtocol == SecurityProtocol.SASL_SSL)
            try {
                sslFactory.validateReconfiguration(configs);
            } catch (IllegalStateException e) {
                throw new ConfigException("SASL reconfiguration failed due to " + e);
            }
    }

    @Override
    public void reconfigure(Map<String, ?> configs) {
        if (this.securityProtocol == SecurityProtocol.SASL_SSL)
            sslFactory.reconfigure(configs);
    }

    @Override
    public ListenerName listenerName() {
        return listenerName;
    }

    // DECISION: Channel construction creates a Supplier<Authenticator>
    // (lazy authenticator creation) rather than an Authenticator instance
    // directly. This supports re-authentication — when a channel needs
    // to re-authenticate, KafkaChannel
    // .swapAuthenticatorsAndBeginReauthentication() invokes the supplier
    // to create a fresh authenticator while the old one handles cleanup.
    // Alternative: Eager authenticator creation — rejected because
    // re-authentication requires fresh state (new SASL handshake) that
    // cannot be achieved by resetting an existing authenticator.
    //
    // COMPLEXITY: Method size ~35 lines — builds transport layer, then
    // branches on server/client mode to create authenticator supplier,
    // finally constructs KafkaChannel. Error path closes transport layer
    // if KafkaChannel creation fails.
    @Override
    public KafkaChannel buildChannel(String id, SelectionKey key, int maxReceiveSize,
                                     MemoryPool memoryPool, ChannelMetadataRegistry metadataRegistry) throws KafkaException {
        TransportLayer transportLayer = null;
        try {
            SocketChannel socketChannel = (SocketChannel) key.channel();
            Socket socket = socketChannel.socket();
            transportLayer = buildTransportLayer(id, key, socketChannel, metadataRegistry);
            final TransportLayer finalTransportLayer = transportLayer;
            Supplier<Authenticator> authenticatorCreator;
            if (connectionMode == ConnectionMode.SERVER) {
                authenticatorCreator = () -> buildServerAuthenticator(configs,
                        Collections.unmodifiableMap(saslCallbackHandlers),
                        id,
                        finalTransportLayer,
                        Collections.unmodifiableMap(subjects),
                        Collections.unmodifiableMap(connectionsMaxReauthMsByMechanism),
                        metadataRegistry);
            } else {
                LoginManager loginManager = loginManagers.get(clientSaslMechanism);
                authenticatorCreator = () -> buildClientAuthenticator(configs,
                        saslCallbackHandlers.get(clientSaslMechanism),
                        id,
                        socket.getInetAddress().getHostName(),
                        loginManager.serviceName(),
                        finalTransportLayer,
                        subjects.get(clientSaslMechanism));
            }
            return new KafkaChannel(id, transportLayer, authenticatorCreator, maxReceiveSize,
                memoryPool != null ? memoryPool : MemoryPool.NONE, metadataRegistry);
        } catch (Exception e) {
            // Ideally these resources are closed by the KafkaChannel but this builder should close the resources instead
            // if an error occurs due to which KafkaChannel is not created.
            Utils.closeQuietly(transportLayer, "transport layer for channel Id: " + id);
            throw new KafkaException(e);
        }
    }

    @Override
    public void close()  {
        for (LoginManager loginManager : loginManagers.values())
            loginManager.release();
        loginManagers.clear();
        for (AuthenticateCallbackHandler handler : saslCallbackHandlers.values())
            handler.close();
        if (sslFactory != null) sslFactory.close();
    }

    // DECISION: SASL_SSL wraps an SslTransportLayer for encryption before
    // SASL authentication. SASL_PLAINTEXT uses PlaintextTransportLayer —
    // SASL credentials are sent without encryption. The SecurityProtocol
    // enum determines which transport is used. For SASL_PLAINTEXT, the
    // SASL mechanism itself must provide credential protection (e.g.,
    // SCRAM uses challenge-response). PLAIN over SASL_PLAINTEXT sends
    // credentials in cleartext — see PlainSaslServer SECURITY warning.
    //
    // Visible to override for testing
    protected TransportLayer buildTransportLayer(String id, SelectionKey key, SocketChannel socketChannel,
                                                 ChannelMetadataRegistry metadataRegistry) throws IOException {
        if (this.securityProtocol == SecurityProtocol.SASL_SSL) {
            return SslTransportLayer.create(id, key,
                sslFactory.createSslEngine(socketChannel.socket()),
                metadataRegistry);
        } else {
            return new PlaintextTransportLayer(key);
        }
    }

    // Visible to override for testing
    protected SaslServerAuthenticator buildServerAuthenticator(Map<String, ?> configs,
                                                               Map<String, AuthenticateCallbackHandler> callbackHandlers,
                                                               String id,
                                                               TransportLayer transportLayer,
                                                               Map<String, Subject> subjects,
                                                               Map<String, Long> connectionsMaxReauthMsByMechanism,
                                                               ChannelMetadataRegistry metadataRegistry) {
        return new SaslServerAuthenticator(configs, callbackHandlers, id, subjects,
                kerberosShortNamer, listenerName, securityProtocol, transportLayer,
                connectionsMaxReauthMsByMechanism, metadataRegistry, time, apiVersionSupplier);
    }

    // Visible to override for testing
    protected SaslClientAuthenticator buildClientAuthenticator(Map<String, ?> configs,
                                                               AuthenticateCallbackHandler callbackHandler,
                                                               String id,
                                                               String serverHost,
                                                               String servicePrincipal,
                                                               TransportLayer transportLayer, Subject subject) {
        return new SaslClientAuthenticator(configs, callbackHandler, id, subject, servicePrincipal,
                serverHost, clientSaslMechanism, transportLayer, time, logContext);
    }

    // Package private for testing
    Map<String, LoginManager> loginManagers() {
        return loginManagers;
    }

    private static String defaultKerberosRealm() {
        // see https://issues.apache.org/jira/browse/HADOOP-10848 for details
        return new KerberosPrincipal("tmp", 1).getRealm();
    }

    // SECURITY: (MEDIUM) Client callback handler is loaded via reflection
    // from the SASL_CLIENT_CALLBACK_HANDLER_CLASS config. If not set,
    // a default handler is selected based on the mechanism. Reflective
    // class loading from user-provided config means a misconfigured or
    // malicious class name could execute arbitrary code at instantiation.
    // Risk: An attacker who can modify client configuration could inject
    // a malicious AuthenticateCallbackHandler implementation.
    // Improvement: Validate that the configured class implements
    // AuthenticateCallbackHandler before instantiation, and consider
    // restricting class loading to trusted packages.
    // Exploit: A malicious client could send crafted packets to manipulate state transitions and bypass authentication.
    private void createClientCallbackHandler(Map<String, ?> configs) {
        @SuppressWarnings("unchecked")
        Class<? extends AuthenticateCallbackHandler> clazz = (Class<? extends AuthenticateCallbackHandler>) configs.get(SaslConfigs.SASL_CLIENT_CALLBACK_HANDLER_CLASS);
        if (clazz == null)
            clazz = clientCallbackHandlerClass();
        AuthenticateCallbackHandler callbackHandler = Utils.newInstance(clazz);
        saslCallbackHandlers.put(clientSaslMechanism, callbackHandler);
    }

    // SECURITY: (MEDIUM) Callback handlers are instantiated via reflection from
    // class names specified in SASL configuration. For PLAIN mechanism,
    // PlainServerCallbackHandler is used by default on the server side.
    // For SCRAM, ScramServerCallbackHandler retrieves stored credentials
    // from CredentialCache. For OAUTHBEARER,
    // OAuthBearerUnsecuredValidatorCallbackHandler handles JWT
    // validation (WARNING: unsecured validator — development only).
    // Each handler class has different security properties and trust
    // assumptions.
    // Risk: Custom handler classes loaded via config could bypass
    // standard authentication checks if not properly validated.
    // Improvement: Log a warning when a custom (non-default) callback
    // handler is loaded, and consider a security audit hook.
    // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
    private void createServerCallbackHandlers(Map<String, ?> configs) {
        for (String mechanism : jaasContexts.keySet()) {
            AuthenticateCallbackHandler callbackHandler;
            String prefix = ListenerName.saslMechanismPrefix(mechanism);
            @SuppressWarnings("unchecked")
            Class<? extends AuthenticateCallbackHandler> clazz =
                    (Class<? extends AuthenticateCallbackHandler>) configs.get(prefix + BrokerSecurityConfigs.SASL_SERVER_CALLBACK_HANDLER_CLASS_CONFIG);
            if (clazz != null)
                callbackHandler = Utils.newInstance(clazz);
            else if (mechanism.equals(PlainSaslServer.PLAIN_MECHANISM))
                callbackHandler = new PlainServerCallbackHandler();
            else if (ScramMechanism.isScram(mechanism))
                callbackHandler = new ScramServerCallbackHandler(credentialCache.cache(mechanism, ScramCredential.class), tokenCache);
            else if (mechanism.equals(OAuthBearerLoginModule.OAUTHBEARER_MECHANISM))
                callbackHandler = new OAuthBearerUnsecuredValidatorCallbackHandler();
            else
                callbackHandler = new SaslServerCallbackHandler();
            saslCallbackHandlers.put(mechanism, callbackHandler);
        }
    }

    private void createConnectionsMaxReauthMsMap(Map<String, ?> configs) {
        for (String mechanism : jaasContexts.keySet()) {
            String prefix = ListenerName.saslMechanismPrefix(mechanism);
            Long connectionsMaxReauthMs = (Long) configs.get(prefix + BrokerSecurityConfigs.CONNECTIONS_MAX_REAUTH_MS_CONFIG);
            if (connectionsMaxReauthMs == null)
                connectionsMaxReauthMs = (Long) configs.get(BrokerSecurityConfigs.CONNECTIONS_MAX_REAUTH_MS_CONFIG);
            if (connectionsMaxReauthMs != null)
                connectionsMaxReauthMsByMechanism.put(mechanism, connectionsMaxReauthMs);
        }
    }

    // DECISION: Login class selection follows a priority chain:
    // (1) If GSSAPI is configured, use KerberosLogin — which manages TGT
    // renewal via a background thread and Subject re-login.
    // (2) If OAUTHBEARER is the client mechanism, use
    // OAuthBearerRefreshingLogin — which handles OAuth token refresh.
    // (3) Otherwise, use DefaultLogin — a minimal login that performs a
    // single JAAS login without renewal.
    // Alternative: A unified login class with pluggable refresh — rejected
    // because Kerberos and OAuth have fundamentally different renewal
    // lifecycles (TGT ticket granting vs. token refresh grant).
    protected Class<? extends Login> defaultLoginClass() {
        if (jaasContexts.containsKey(SaslConfigs.GSSAPI_MECHANISM))
            return KerberosLogin.class;
        if (OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(clientSaslMechanism))
            return OAuthBearerRefreshingLogin.class;
        return DefaultLogin.class;
    }

    // DECISION: Default client callback handler is selected by SASL
    // mechanism: GSSAPI uses KerberosClientCallbackHandler (handles
    // Kerberos-specific callbacks), OAUTHBEARER uses
    // OAuthBearerSaslClientCallbackHandler (handles OAuth token
    // retrieval), and all other mechanisms fall back to the generic
    // SaslClientCallbackHandler.
    // Alternative: A single polymorphic handler — rejected because each
    // mechanism has unique callback types requiring specialized logic.
    private Class<? extends AuthenticateCallbackHandler> clientCallbackHandlerClass() {
        switch (clientSaslMechanism) {
            case SaslConfigs.GSSAPI_MECHANISM:
                return KerberosClientCallbackHandler.class;
            case OAuthBearerLoginModule.OAUTHBEARER_MECHANISM:
                return OAuthBearerSaslClientCallbackHandler.class;
            default:
                return SaslClientCallbackHandler.class;
        }
    }

    // SECURITY: (MEDIUM) Native GSSCredential is acquired for Kerberos
    // (GSSAPI) server-mode operation. The GSSCredential is stored as a
    // private credential in the Subject and shared across all connections
    // using the same Kerberos principal. If GSSCredential expires and
    // renewal fails, all new connections will fail authentication until
    // the credential is refreshed by LoginManager.
    // Risk: Stale GSSCredential can cause cascading authentication
    // failures. Additionally, the GSSCredential stored in the Subject's
    // private credential set could be extracted by code running in the
    // same JVM with access to the Subject.
    // Improvement: Monitor GSSCredential remaining lifetime and trigger
    // proactive renewal before expiry to avoid authentication outages.
    //
    // As described in http://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/jgss-features.html:
    // "To enable Java GSS to delegate to the native GSS library and its list of native mechanisms,
    // set the system property "sun.security.jgss.native" to true"
    // "In addition, when performing operations as a particular Subject, for example, Subject.doAs(...)
    // or Subject.doAsPrivileged(...), the to-be-used GSSCredential should be added to Subject's
    // private credential set. Otherwise, the GSS operations will fail since no credential is found."
    // Exploit: A misconfigured auth_to_local rule could map an attacker principal to a privileged local identity.
    private void maybeAddNativeGssapiCredentials(Subject subject) {
        boolean usingNativeJgss = Boolean.getBoolean(GSS_NATIVE_PROP);
        if (usingNativeJgss && subject.getPrivateCredentials(GSSCredential.class).isEmpty()) {

            final String servicePrincipal = SaslClientAuthenticator.firstPrincipal(subject);
            KerberosName kerberosName;
            try {
                kerberosName = KerberosName.parse(servicePrincipal);
            } catch (IllegalArgumentException e) {
                throw new KafkaException("Principal has name with unexpected format " + servicePrincipal);
            }
            final String servicePrincipalName = kerberosName.serviceName();
            final String serviceHostname = kerberosName.hostName();

            try {
                GSSManager manager = gssManager();
                // This Oid is used to represent the Kerberos version 5 GSS-API mechanism. It is defined in
                // RFC 1964.
                Oid krb5Mechanism = new Oid("1.2.840.113554.1.2.2");
                GSSName gssName = manager.createName(servicePrincipalName + "@" + serviceHostname, GSSName.NT_HOSTBASED_SERVICE);
                GSSCredential cred = manager.createCredential(gssName,
                        GSSContext.INDEFINITE_LIFETIME, krb5Mechanism, GSSCredential.ACCEPT_ONLY);
                subject.getPrivateCredentials().add(cred);
                log.info("Configured native GSSAPI private credentials for {}@{}", serviceHostname, serviceHostname);
            } catch (GSSException ex) {
                log.warn("Cannot add private credential to subject; clients authentication may fail", ex);
            }
        }
    }

    // Visibility to override for testing
    protected GSSManager gssManager() {
        return GSSManager.getInstance();
    }

    // Visibility for testing
    protected Subject subject(String saslMechanism) {
        return subjects.get(saslMechanism);
    }
}
