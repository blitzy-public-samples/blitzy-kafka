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

// SECURITY: (LOW) PlaintextAuthenticationContext represents connections with NO authentication
// and NO encryption. Used for PLAINTEXT listeners and for pre-SASL phase of SASL_PLAINTEXT.
// Why: No identity verification occurs — any client can connect and the principal defaults to
// KafkaPrincipal.ANONYMOUS unless SASL authentication follows (for SASL_PLAINTEXT).
// Exploit: On a PLAINTEXT listener, any network-reachable client can impersonate any producer
// or consumer. Traffic is also visible to network sniffers (cleartext wire protocol).
// Improvement: In production, always use SSL or SASL_SSL. PLAINTEXT should only be used in
// isolated development environments. Consider logging a warning when PLAINTEXT is configured.
//
// CROSS-CUTTING: Created by common/network/PlaintextChannelBuilder and passed to
// KafkaPrincipalBuilder.build() for principal construction. Also used by broker-side
// SocketServer when a new PLAINTEXT connection is accepted.
// Depends on: auth/AuthenticationContext (this package), auth/SecurityProtocol.
public class PlaintextAuthenticationContext implements AuthenticationContext {
    private final InetAddress clientAddress;
    private final String listenerName;

    // DECISION: Immutable context with only clientAddress and listenerName — no session
    // or credentials. Alternative: Include a "reason" field for why plaintext was chosen.
    // Rationale: Plaintext connections carry no authentication metadata by definition;
    // keeping this class minimal reflects the absence of security context.
    public PlaintextAuthenticationContext(InetAddress clientAddress, String listenerName) {
        this.clientAddress = clientAddress;
        this.listenerName = listenerName;
    }

    @Override
    public SecurityProtocol securityProtocol() {
        return SecurityProtocol.PLAINTEXT;
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
