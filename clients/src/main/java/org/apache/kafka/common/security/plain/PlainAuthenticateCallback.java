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

package org.apache.kafka.common.security.plain;

import javax.security.auth.callback.Callback;

/*
 * Authentication callback for SASL/PLAIN authentication. Callback handler must
 * set authenticated flag to true if the client provided password in the callback
 * matches the expected password.
 */
// SECURITY: SEC-PLAIN-001 (MEDIUM) Carries plaintext username/password during SASL/PLAIN authentication.
// Why: This callback transports raw credentials (char[] password) between the SaslServer
// and the CallbackHandler. The password field is a final reference but its contents are
// mutable and never zeroed after use.
// Exploit: If this callback object is inadvertently logged, serialized, or retained beyond
// the authentication exchange, the plaintext password is exposed. A malicious or buggy
// callback handler could store the reference, leaking credentials to unauthorized code paths.
// Improvement: Implement Destroyable interface to enable explicit credential zeroing
// (Arrays.fill(password, '\0')) after authentication completes. Add @SensitiveData annotation
// or override toString() to prevent accidental logging of password contents.
//
// CROSS-CUTTING: Consumed by plain/internals/PlainSaslServer (creates callback in
// evaluateResponse()) and plain/internals/PlainServerCallbackHandler (reads password()
// and sets authenticated() result).
// Contract: CallbackHandler MUST call authenticated(true/false) after validation.
// Impact: If callback is not handled, authentication silently fails (authenticated=false).
// Also consumed by authenticator/SaslServerAuthenticator via PLAIN mechanism delegation.
public class PlainAuthenticateCallback implements Callback {
    // SECURITY: SEC-PLAIN-002 (MEDIUM) Raw credential storage -- char[] chosen over String to allow zeroing,
    // Why: PLAIN mechanism handles cleartext credentials that have
    // no cryptographic protection.
    // but this class does not implement zeroing. Callers must manage credential lifecycle.
    // Exploit: The authenticated flag and cleartext password in the
    // callback could be intercepted by a malicious callback handler.
    // Improvement: Clear the password char[] after authentication
    // completes to minimize credential exposure in memory.
    private final char[] password;
    private boolean authenticated;

    /**
     * Creates a callback with the password provided by the client
     * @param password The password provided by the client during SASL/PLAIN authentication
     */
    public PlainAuthenticateCallback(char[] password) {
        this.password = password;
    }

    // DECISION: Exposes raw char[] reference rather than a defensive copy.
    // Alternatives: (1) Return Arrays.copyOf(password) for immutability, (2) Wrap in
    // ReadOnlyCharBuffer.
    // Rationale: Defensive copy would create additional copies of sensitive material in memory.
    // Direct reference allows the CallbackHandler to read and validate without extra allocations.
    // Risk: Caller could modify array contents, corrupting the credential mid-validation.
    /**
     * Returns the password provided by the client during SASL/PLAIN authentication
     */
    public char[] password() {
        return password;
    }

    /**
     * Returns true if client password matches expected password, false otherwise.
     * This state is set the server-side callback handler.
     */
    public boolean authenticated() {
        return this.authenticated;
    }

    /**
     * Sets the authenticated state. This is set by the server-side callback handler
     * by matching the client provided password with the expected password.
     *
     * @param authenticated true indicates successful authentication
     */
    public void authenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }
}
