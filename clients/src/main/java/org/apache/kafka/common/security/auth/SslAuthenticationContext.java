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

import javax.net.ssl.SSLSession;

// SECURITY: (LOW) SslAuthenticationContext carries the javax.net.ssl.SSLSession for
// SSL-authenticated connections. The SSLSession provides the peer certificate chain
// via getPeerCertificates(), enabling certificate-based principal extraction.
// Why: The SSLSession is the primary source of client identity for SSL listeners. If
// mutual TLS (mTLS) is enabled, the peer certificate is used by KafkaPrincipalBuilder
// to construct the KafkaPrincipal.
// Exploit: If the SSLSession's peer certificate chain is not properly validated (e.g.,
// hostname verification disabled, or trust store too permissive), a client with any
// valid CA-signed cert could authenticate as a different principal.
// Improvement: Consider adding a validation check in this context that verifies the
// SSLSession has completed the handshake before exposing it for principal extraction.

// CROSS-CUTTING: Created by common/network/SslChannelBuilder after TLS handshake
// completion. Passed to authenticator/DefaultKafkaPrincipalBuilder.build() which
// extracts the peer certificate DN for principal construction via SslPrincipalMapper.
// Depends on: auth/AuthenticationContext, auth/SecurityProtocol (this package).
public class SslAuthenticationContext implements AuthenticationContext {
    private final SSLSession session;
    private final InetAddress clientAddress;
    private final String listenerName;

    public SslAuthenticationContext(SSLSession session, InetAddress clientAddress, String listenerName) {
        this.session = session;
        this.clientAddress = clientAddress;
        this.listenerName = listenerName;
    }

    // DECISION: Exposes raw SSLSession rather than extracted certificate or principal.
    // Alternative: Extract and store only the peer principal at construction time.
    // Rationale: Exposing the full SSLSession allows KafkaPrincipalBuilder implementations
    // to access any session attribute (cipher suite, protocol version, cert chain) for
    // custom principal construction logic. Extracting only the principal would limit
    // extensibility for custom builders.
    public SSLSession session() {
        return session;
    }

    @Override
    public SecurityProtocol securityProtocol() {
        return SecurityProtocol.SSL;
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
