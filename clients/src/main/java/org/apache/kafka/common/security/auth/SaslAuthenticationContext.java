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
package org.apache.kafka.common.security.auth;

import java.net.InetAddress;
import java.util.Optional;

import javax.net.ssl.SSLSession;
import javax.security.sasl.SaslServer;

// SECURITY: SEC-AUTH-006 (LOW) SaslAuthenticationContext carries the javax.security.sasl.SaslServer
// instance for SASL-authenticated connections. The SaslServer.getAuthorizationID()
// provides the authenticated identity used for ACL evaluation.
// Why: This context bridges the SASL authentication result to the authorization layer.
// The SaslServer instance encapsulates the completed SASL exchange state.
// Exploit: If the SaslServer instance is replaced or its authorizationID is tampered
// with after authentication completes, a different identity could be used for
// authorization decisions. The immutable field storage mitigates this.
// Improvement: Consider making the server field's type a read-only wrapper that only
// exposes getAuthorizationID() and getMechanismName(), preventing access to
// mutable SaslServer methods like unwrap()/wrap() post-authentication.
//
// CROSS-CUTTING: Created by authenticator/SaslServerAuthenticator after successful
// SASL authentication. Passed to KafkaPrincipalBuilder.build() for principal construction.
// The SaslServer instance provides mechanism-specific auth context (e.g., SCRAM server
// state, OAUTHBEARER token data, GSSAPI context). Also carries optional SSLSession for
// SASL_SSL protocol -- used when both SASL and mTLS identity are needed.
// Depends on: auth/AuthenticationContext, auth/SecurityProtocol (this package).
public class SaslAuthenticationContext implements AuthenticationContext {
    private final SaslServer server;
    private final SecurityProtocol securityProtocol;
    private final InetAddress clientAddress;
    private final String listenerName;
    private final Optional<SSLSession> sslSession;

    // DECISION: Two constructors -- convenience (without sslSession) and full (with Optional).
    // Alternative: Single constructor with nullable SSLSession. Rationale: The Optional pattern
    // makes the SASL_PLAINTEXT vs SASL_SSL distinction explicit at construction time.
    // The convenience constructor delegates to the full constructor with Optional.empty().
    public SaslAuthenticationContext(SaslServer server, SecurityProtocol securityProtocol, InetAddress clientAddress, String listenerName) {
        this(server, securityProtocol, clientAddress, listenerName, Optional.empty());
    }

    public SaslAuthenticationContext(SaslServer server, SecurityProtocol securityProtocol,
                                     InetAddress clientAddress,
                                     String listenerName,
                                     Optional<SSLSession> sslSession) {
        this.server = server;
        this.securityProtocol = securityProtocol;
        this.clientAddress = clientAddress;
        this.listenerName = listenerName;
        this.sslSession = sslSession;
    }

    // DECISION: Exposes raw SaslServer rather than just authorizationID string.
    // Rationale: Custom KafkaPrincipalBuilder implementations may need mechanism-specific
    // attributes from the SaslServer (e.g., negotiated QoP, SASL properties).
    public SaslServer server() {
        return server;
    }

    /**
     * Returns SSL session for the connection if security protocol is SASL_SSL. If SSL
     * mutual client authentication is enabled for the listener, peer principal can be
     * determined using {@link SSLSession#getPeerPrincipal()}.
     */
    public Optional<SSLSession> sslSession() {
        return sslSession;
    }

    @Override
    public SecurityProtocol securityProtocol() {
        return securityProtocol;
    }

    @Override
    public InetAddress clientAddress() {
        return clientAddress;
    }

    @Override
    public String listenerName() {
        return listenerName;
    }
}
