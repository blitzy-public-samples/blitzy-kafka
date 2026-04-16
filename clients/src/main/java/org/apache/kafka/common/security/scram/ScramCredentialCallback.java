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
package org.apache.kafka.common.security.scram;

import javax.security.auth.callback.Callback;

/**
 * Callback used for SCRAM mechanisms.
 */
// SECURITY: (LOW) JAAS Callback for transferring ScramCredential instances between
// CallbackHandler implementations and SASL mechanism code during SCRAM authentication.
// Why: This callback carries the server-side SCRAM credential (salt, storedKey, serverKey,
// iterations) through the JAAS CallbackHandler pipeline. The credential contains derived
// cryptographic material -- not the original password -- but exposure of storedKey and
// serverKey would allow offline attacks against the user's password.
// Exploit: If a malicious CallbackHandler implementation intercepts this callback, it
// could extract the ScramCredential fields (storedKey, serverKey) and use them for
// offline dictionary attacks. The storedKey is H(ClientKey), and recovering ClientKey
// from storedKey is computationally equivalent to a hash inversion -- but serverKey
// directly enables server-signature computation, allowing impersonation of the server.
// Improvement: Consider making ScramCredential fields accessible only through a
// security-manager-protected accessor, or zeroize the credential data after use.
//
// CROSS-CUTTING: Used by scram/internals/ScramServerCallbackHandler to pass
// credentials from authenticator/CredentialCache into ScramSaslServer during
// server-side SCRAM authentication. Also handled by custom AuthenticateCallbackHandler
// implementations that integrate with external credential stores.
// Contract: CallbackHandler MUST set scramCredential before returning from handle().
// Impact: If the callback is not handled (credential not set), ScramSaslServer will
// fail authentication with a SaslException -- this is a correct security-fail-closed behavior.
public class ScramCredentialCallback implements Callback {
    private ScramCredential scramCredential;

    /**
     * Sets the SCRAM credential for this instance.
     */
    // SECURITY: (MEDIUM) No validation on the credential being set -- a null or malformed credential
    // would cause NullPointerException downstream in ScramSaslServer.evaluateResponse().
    // Exploit: Unauthorized access to the credential cache could expose authentication material.
    // Improvement: Limit cache access to authenticated callers and consider cache entry encryption at rest.
    public void scramCredential(ScramCredential scramCredential) {
        this.scramCredential = scramCredential;
    }

    /**
     * Returns the SCRAM credential if set on this instance.
     */
    public ScramCredential scramCredential() {
        return scramCredential;
    }
}
