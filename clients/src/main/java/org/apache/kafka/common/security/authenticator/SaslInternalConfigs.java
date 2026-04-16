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

import org.apache.kafka.common.config.internals.BrokerSecurityConfigs;

// SECURITY: (LOW) Internal SASL configuration constants used for inter-component
// credential lifetime communication. The CREDENTIAL_LIFETIME_MS property is passed
// via SaslServer.getNegotiatedProperty() -- a SASL framework API that allows server
// and client to exchange metadata after authentication. A compromised SaslServer
// implementation could set an artificially long credential lifetime, preventing
// session expiration and re-authentication. The broker-configured
// CONNECTIONS_MAX_REAUTH_MS provides an upper bound that mitigates this risk.
//
// CROSS-CUTTING: This constant bridges the SASL mechanism layer and the connection
// management layer. Written by: SCRAM mechanism (ScramSaslServer sets credential
// lifetime from SCRAM credential expiry), OAUTHBEARER mechanism (sets JWT token
// expiry time). Read by: SaslServerAuthenticator.ReauthInfo.calcCompletionTimesAndReturn-
// SessionLifetimeMs() to compute session expiration. Also read by SaslClientAuthenticator
// via SaslAuthenticateResponse.sessionLifetimeMs (the broker forwards this value).
// Depends on: BrokerSecurityConfigs.CONNECTIONS_MAX_REAUTH_MS_CONFIG (upper bound).
// Exploit: A malicious client could send crafted packets to manipulate state transitions and bypass authentication.
// Improvement: Add state transition validation to reject unexpected state changes.
public class SaslInternalConfigs {
    /**
     * The server (broker) specifies a positive session length in milliseconds to a
     * SASL client when {@link BrokerSecurityConfigs#CONNECTIONS_MAX_REAUTH_MS_CONFIG} is
     * positive as per <a href=
     * "https://cwiki.apache.org/confluence/display/KAFKA/KIP-368%3A+Allow+SASL+Connections+to+Periodically+Re-Authenticate">KIP
     * 368: Allow SASL Connections to Periodically Re-Authenticate</a>. The session
     * length is the minimum of the configured value and any session length implied
     * by the credential presented during authentication. The lifetime defined by
     * the credential, in terms of milliseconds since the epoch, is available via a
     * negotiated property on the SASL Server instance, and that value can be
     * converted to a session length by subtracting the time at which authentication
     * occurred. This variable defines the negotiated property key that is used to
     * communicate the credential lifetime in milliseconds since the epoch.
     */
    // DECISION: Uses SaslServer.getNegotiatedProperty() as the transport for credential
    // lifetime rather than a custom response field or out-of-band channel. Alternative:
    // Embed lifetime in the SaslAuthenticateResponse. Rationale: getNegotiatedProperty()
    // is a standard SASL API that works across all SASL mechanisms without requiring
    // mechanism-specific response modifications. The property key is a String constant
    // rather than an enum to match the SASL negotiated property API contract (Map<String,?>).
    public static final String CREDENTIAL_LIFETIME_MS_SASL_NEGOTIATED_PROPERTY_KEY = "CREDENTIAL.LIFETIME.MS";

    private SaslInternalConfigs() {
        // empty
    }
}
