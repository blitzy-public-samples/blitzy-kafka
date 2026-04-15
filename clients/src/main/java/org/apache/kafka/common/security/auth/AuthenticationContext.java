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


/**
 * An object representing contextual information from the authentication session. See
 * {@link PlaintextAuthenticationContext}, {@link SaslAuthenticationContext}
 * and {@link SslAuthenticationContext}. This class is only used in the broker.
 */
// DECISION: Marker interface with securityProtocol(), clientAddress(), and listenerName()
// for protocol-agnostic authentication context. Sealed hierarchy (by convention, not Java
// sealed classes): PlaintextAuthenticationContext, SslAuthenticationContext,
// SaslAuthenticationContext. Alternative: Use a single class with optional fields for
// SSLSession and SaslServer. Rationale: Separate implementations ensure type safety —
// KafkaPrincipalBuilder.build() can use instanceof to determine the authentication
// mechanism and safely downcast to access mechanism-specific context (e.g., SSLSession
// for certificate extraction, SaslServer for authorization ID).
//
// CROSS-CUTTING: Created by common/network/ channel builders (PlaintextChannelBuilder,
// SslChannelBuilder, SaslChannelBuilder) during connection establishment. Passed to
// auth/KafkaPrincipalBuilder.build() for principal construction. Also used by broker-side
// interceptors and audit logging for connection metadata.
// Depends on: auth/SecurityProtocol (this package). Depended on by: all KafkaPrincipalBuilder
// implementations and all authentication-aware broker components.
// Contract: Implementations must be immutable after construction. This interface is only
// used in the broker (per existing Javadoc); clients construct context internally.
public interface AuthenticationContext {
    /**
     * Underlying security protocol of the authentication session.
     */
    SecurityProtocol securityProtocol();

    /**
     * Address of the authenticated client
     */
    InetAddress clientAddress();

    /**
     * Name of the listener used for the connection
     */
    String listenerName();
}
