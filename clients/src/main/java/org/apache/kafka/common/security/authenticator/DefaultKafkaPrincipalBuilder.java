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

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.message.DefaultPrincipalData;
import org.apache.kafka.common.protocol.ByteBufferAccessor;
import org.apache.kafka.common.protocol.MessageUtil;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.PlaintextAuthenticationContext;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.apache.kafka.common.security.kerberos.KerberosName;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.apache.kafka.common.security.ssl.SslPrincipalMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Principal;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.SaslServer;

/**
 * Default implementation of {@link KafkaPrincipalBuilder} which provides basic support for
 * SSL authentication and SASL authentication. In the latter case, when GSSAPI is used, this
 * class applies {@link org.apache.kafka.common.security.kerberos.KerberosShortNamer} to transform
 * the name.
 *
 * NOTE: This is an internal class and can change without notice.
 *
 * @implSpec SECURITY: (HIGH) Principal spoofing risk in SSL/SASL context extraction.
 * This class constructs KafkaPrincipal from auth contexts (SSL DN, SASL ID, ANONYMOUS).
 * Exploit: (1) SSL: Crafted certificate DN mapping to admin via SslPrincipalMapper rules.
 * (2) SASL/GSSAPI: Permissive KerberosShortNamer rules map distinct principals to same
 * name. (3) Plaintext: Returns ANONYMOUS unconditionally with no authentication.
 * Improvement: Add audit logging on ANONYMOUS fallback; validate mapper rules cannot
 * produce privileged principal names by default.
 */
// CROSS-CUTTING: Depends on auth/KafkaPrincipal, auth/KafkaPrincipalBuilder (interface),
// kerberos/KerberosName + KerberosShortNamer (GSSAPI), ssl/SslPrincipalMapper (X.500 DN).
// Instantiated by network/ChannelBuilders.createPrincipalBuilder(), consumed by
// SaslServerAuthenticator.principal(). Contract: build() returns non-null KafkaPrincipal.
// Impact: Principal mapping changes affect all downstream authorization decisions in
// StandardAuthorizer and AclCache (metadata/authorizer/).
public class DefaultKafkaPrincipalBuilder implements KafkaPrincipalBuilder {
    private final KerberosShortNamer kerberosShortNamer;
    private final SslPrincipalMapper sslPrincipalMapper;

    /**
     * Construct a new instance.
     *
     * @param kerberosShortNamer Kerberos name rewrite rules or null if none have been configured
     * @param sslPrincipalMapper SSL Principal mapper or null if none have been configured
     */
    // DECISION: kerberosShortNamer and sslPrincipalMapper may be null ("not configured").
    // Alternative: Use identity-function implementations. Rationale: Null is simpler;
    // null checks are deferred to usage sites in build().
    public DefaultKafkaPrincipalBuilder(KerberosShortNamer kerberosShortNamer, SslPrincipalMapper sslPrincipalMapper) {
        this.kerberosShortNamer = kerberosShortNamer;
        this.sslPrincipalMapper = sslPrincipalMapper;
    }

    // SECURITY: (HIGH) Principal resolution: Plaintext -> ANONYMOUS, SSL -> peer cert DN
    // (mapped), SASL/GSSAPI -> Kerberos short name, SASL/other -> raw authorizationID.
    // SSL falls back to ANONYMOUS if peer cert is unverified (mutual TLS not enforced here).
    // A broker without ssl.client.auth=required grants ANONYMOUS to SSL clients.
    //
    // DECISION: Uses instanceof chain rather than polymorphic dispatch on AuthenticationContext.
    // Alternatives: (1) Visitor pattern, (2) Map<Class, Function>. Rationale: Auth context
    // types are a closed set (3 types); instanceof is simpler. IllegalArgumentException
    // on unknown types forces explicit handling of future context additions.
    // Exploit: An attacker could exploit weak cipher suites or certificate validation gaps for MITM attacks.
    // Improvement: Enforce strong cipher suite selection and certificate pinning where feasible.
    @Override
    public KafkaPrincipal build(AuthenticationContext context) {
        if (context instanceof PlaintextAuthenticationContext) {
            return KafkaPrincipal.ANONYMOUS;
        } else if (context instanceof SslAuthenticationContext) {
            SSLSession sslSession = ((SslAuthenticationContext) context).session();
            try {
                return applySslPrincipalMapper(sslSession.getPeerPrincipal());
            } catch (SSLPeerUnverifiedException se) {
                return KafkaPrincipal.ANONYMOUS;
            }
        } else if (context instanceof SaslAuthenticationContext) {
            SaslServer saslServer = ((SaslAuthenticationContext) context).server();
            if (SaslConfigs.GSSAPI_MECHANISM.equals(saslServer.getMechanismName()))
                return applyKerberosShortNamer(saslServer.getAuthorizationID());
            else
                return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, saslServer.getAuthorizationID());
        } else {
            throw new IllegalArgumentException("Unhandled authentication context type: " + context.getClass().getName());
        }
    }

    // SECURITY: (MEDIUM) Kerberos principal name is parsed and transformed via
    // auth_to_local rules (KerberosShortNamer). Misconfigured regex rules could map
    // all principals to one short name, breaking identity isolation.
    // Improvement: Log the full Kerberos principal alongside the short name for audit.
    // Exploit: A misconfigured auth_to_local rule could map an attacker principal to a privileged local identity.
    private KafkaPrincipal applyKerberosShortNamer(String authorizationId) {
        KerberosName kerberosName = KerberosName.parse(authorizationId);
        try {
            String shortName = kerberosShortNamer.shortName(kerberosName);
            return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, shortName);
        } catch (IOException e) {
            throw new KafkaException("Failed to set name for '" + kerberosName +
                    "' based on Kerberos authentication rules.", e);
        }
    }

    // SECURITY: (MEDIUM) SSL principal mapping applies regex rules to X.500 DNs.
    // Non-X500 principals bypass the mapper and use principal.getName() directly.
    // Exploit: A custom TrustManager producing a non-X500Principal with a crafted
    // getName() value could inject an arbitrary identity string.
    // Improvement: Consider validating principal names against an allowlist.
    private KafkaPrincipal applySslPrincipalMapper(Principal principal) {
        try {
            if (!(principal instanceof X500Principal) || principal == KafkaPrincipal.ANONYMOUS) {
                return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, principal.getName());
            } else {
                return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, sslPrincipalMapper.getName(principal.getName()));
            }
        } catch (IOException e) {
            throw new KafkaException("Failed to map name for '" + principal.getName() +
                    "' based on SSL principal mapping rules.", e);
        }
    }

    // DECISION: Serializes with HIGHEST_SUPPORTED_VERSION for forward compatibility.
    // Alternative: Fixed version. Chosen approach auto-includes new schema fields.
    // SECURITY: (MEDIUM) Version-prefixed format; deserialize validates version bounds
    // to reject principals from unknown schema versions with different security semantics.
    // Exploit: A misconfigured auth_to_local rule could map an attacker principal to a privileged local identity.
    // Improvement: Audit auth_to_local rules regularly and use strict realm-based principal validation.
    @Override
    public byte[] serialize(KafkaPrincipal principal) {
        DefaultPrincipalData data = new DefaultPrincipalData()
                                        .setType(principal.getPrincipalType())
                                        .setName(principal.getName())
                                        .setTokenAuthenticated(principal.tokenAuthenticated());
        return MessageUtil.toVersionPrefixedBytes(DefaultPrincipalData.HIGHEST_SUPPORTED_VERSION, data);
    }

    // SECURITY: (MEDIUM) Version check prevents deserialization of principals from
    // unknown schema versions. Improvement: Consider adding integrity verification
    // (e.g., checksum) to detect byte-level tampering in serialized principal data.
    // Exploit: A misconfigured auth_to_local rule could map an attacker principal to a privileged local identity.
    @Override
    public KafkaPrincipal deserialize(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        short version = buffer.getShort();
        if (version < DefaultPrincipalData.LOWEST_SUPPORTED_VERSION || version > DefaultPrincipalData.HIGHEST_SUPPORTED_VERSION) {
            throw new SerializationException("Invalid principal data version " + version);
        }

        DefaultPrincipalData data = new DefaultPrincipalData(new ByteBufferAccessor(buffer), version);
        return new KafkaPrincipal(data.type(), data.name(), data.tokenAuthenticated());
    }
}
