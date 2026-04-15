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
package org.apache.kafka.common.security.scram.internals;

import org.apache.kafka.common.errors.AuthenticationException;
import org.apache.kafka.common.errors.IllegalSaslStateException;
import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.apache.kafka.common.security.authenticator.SaslInternalConfigs;
import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.ScramCredentialCallback;
import org.apache.kafka.common.security.scram.ScramLoginModule;
import org.apache.kafka.common.security.scram.internals.ScramMessages.ClientFinalMessage;
import org.apache.kafka.common.security.scram.internals.ScramMessages.ClientFirstMessage;
import org.apache.kafka.common.security.scram.internals.ScramMessages.ServerFinalMessage;
import org.apache.kafka.common.security.scram.internals.ScramMessages.ServerFirstMessage;
import org.apache.kafka.common.security.token.delegation.internals.DelegationTokenCredentialCallback;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

/**
 * SaslServer implementation for SASL/SCRAM. This server is configured with a callback
 * handler for integration with a credential manager. Kafka brokers provide callbacks
 * based on a Zookeeper-based password store.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5802">RFC 5802</a>
 */
// SECURITY: (CRITICAL) Server-side SCRAM challenge-response handler implementing RFC 5802.
// Why: This class handles raw SASL tokens from untrusted clients, performs cryptographic
// proof verification, and manages the server-side SCRAM state machine. Incorrect state
// transitions, timing leaks, or proof verification flaws would allow authentication bypass.
// Exploit: A malicious client could send a crafted SASL token targeting a specific state
// to trigger an IllegalSaslStateException or skip the proof verification step. Additionally,
// if HMAC comparison in verifyClientProof() did NOT use constant-time MessageDigest.isEqual(),
// an attacker could determine the correct storedKey byte-by-byte via timing analysis across
// thousands of authentication attempts (even 10ns differences are exploitable with statistics).
// Improvement: (1) Verify ALL comparison paths use MessageDigest.isEqual() -- String.equals()
// or Arrays.equals() MUST NOT be used for cryptographic material. (2) Add input length
// validation before state machine transition to reject malformed tokens early. (3) Consider
// adding rate limiting for failed authentication attempts per client IP.
//
// CROSS-CUTTING: Depends on ScramFormatter for all cryptographic operations (HMAC, hash,
// key derivation, nonce generation). Depends on ScramMessages for RFC 5802 message parsing.
// Depends on ScramMechanism for algorithm selection (SHA-256/SHA-512).
// Consumed by authenticator/SaslServerAuthenticator via Java SASL Provider SPI -- the
// ScramSaslServerFactory nested class is registered by ScramSaslServerProvider.
// Contract: CallbackHandler MUST handle ScramCredentialCallback or DelegationTokenCredentialCallback.
// Impact: Changes to ScramFormatter's cryptographic methods break proof verification.
public class ScramSaslServer implements SaslServer {

    private static final Logger log = LoggerFactory.getLogger(ScramSaslServer.class);
    // SECURITY: Allowlist of supported SCRAM extensions. Only TOKEN_AUTH_CONFIG ("tokenauth")
    // is permitted. Unsupported extensions are logged and ignored (not rejected), which is a
    // deliberate lenient policy to avoid breaking forward compatibility.
    private static final Set<String> SUPPORTED_EXTENSIONS = Set.of(ScramLoginModule.TOKEN_AUTH_CONFIG);

    // DECISION: Explicit enum state machine rather than if-else chains or boolean flags.
    // States: RECEIVE_CLIENT_FIRST_MESSAGE -> RECEIVE_CLIENT_FINAL_MESSAGE -> COMPLETE (or FAILED).
    // Alternatives: (1) Single evaluateResponse with message-type detection, (2) Coroutine-style
    // continuation passing. Rationale: Enum states directly map to RFC 5802 protocol phases,
    // making the state machine verifiable against the specification. The FAILED terminal state
    // ensures no further processing after an error, preventing partial authentication.
    enum State {
        RECEIVE_CLIENT_FIRST_MESSAGE,
        RECEIVE_CLIENT_FINAL_MESSAGE,
        COMPLETE,
        FAILED
    }

    private final ScramMechanism mechanism;
    private final ScramFormatter formatter;
    private final CallbackHandler callbackHandler;
    private State state;
    private ClientFirstMessage clientFirstMessage;
    private ServerFirstMessage serverFirstMessage;
    private ScramExtensions scramExtensions;
    private ScramCredential scramCredential;
    private String authorizationId;
    private Long tokenExpiryTimestamp;

    // DECISION: ScramFormatter created per-connection rather than shared across connections.
    // This avoids thread-safety issues since MessageDigest and Mac are stateful and not
    // thread-safe. The performance cost is acceptable because SCRAM auth is low-frequency.
    public ScramSaslServer(ScramMechanism mechanism, Map<String, ?> props, CallbackHandler callbackHandler) throws NoSuchAlgorithmException {
        this.mechanism = mechanism;
        this.formatter = new ScramFormatter(mechanism);
        this.callbackHandler = callbackHandler;
        setState(State.RECEIVE_CLIENT_FIRST_MESSAGE);
    }

    /**
     * @throws SaslAuthenticationException if the requested authorization id is not the same as username.
     * <p>
     * <b>Note:</b> This method may throw {@link SaslAuthenticationException} to provide custom error messages
     * to clients. But care should be taken to avoid including any information in the exception message that
     * should not be leaked to unauthenticated clients. It may be safer to throw {@link SaslException} in
     * most cases so that a standard error message is returned to clients.
     * </p>
     */
    // COMPLEXITY: ~76 lines -- multi-state SCRAM challenge-response handler.
    // Structure: switch on state enum with two primary cases:
    //   1. RECEIVE_CLIENT_FIRST_MESSAGE: Parse client-first, extract extensions,
    //      resolve credentials via CallbackHandler, validate iteration count, generate
    //      server-first. Branch points: tokenAuthenticated check, null credential,
    //      authzid mismatch, iteration bounds.
    //   2. RECEIVE_CLIENT_FINAL_MESSAGE: Parse client-final, verify nonce match,
    //      verify client proof, compute server signature, clear credentials.
    // Exit paths: normal return (server message bytes), SaslException,
    //   SaslAuthenticationException, IllegalSaslStateException (default case).
    //   All exceptions trigger clearCredentials() and state transition to FAILED.
    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException, SaslAuthenticationException {
        try {
            switch (state) {
                case RECEIVE_CLIENT_FIRST_MESSAGE:
                    this.clientFirstMessage = new ClientFirstMessage(response);
                    this.scramExtensions = clientFirstMessage.extensions();
                    if (!SUPPORTED_EXTENSIONS.containsAll(scramExtensions.map().keySet())) {
                        log.debug("Unsupported extensions will be ignored, supported {}, provided {}",
                                SUPPORTED_EXTENSIONS, scramExtensions.map().keySet());
                    }
                    String serverNonce = formatter.secureRandomString();
                    try {
                        String saslName = clientFirstMessage.saslName();
                        String username = ScramFormatter.username(saslName);
                        NameCallback nameCallback = new NameCallback("username", username);
                        ScramCredentialCallback credentialCallback;
                        // SECURITY: (HIGH) Delegation token auth path -- branches on
                        // client extension. If tokenAuthenticated() is true, uses
                        // DelegationTokenCredentialCallback instead of ScramCredentialCallback.
                        // Risk: If dispatch logic is flawed, a regular SCRAM auth could be
                        // routed to token lookup, bypassing token expiry checks.
                        if (scramExtensions.tokenAuthenticated()) {
                            DelegationTokenCredentialCallback tokenCallback = new DelegationTokenCredentialCallback();
                            credentialCallback = tokenCallback;
                            callbackHandler.handle(new Callback[]{nameCallback, tokenCallback});
                            if (tokenCallback.tokenOwner() == null)
                                throw new SaslException("Token Authentication failed: Invalid tokenId : " + username);
                            this.authorizationId = tokenCallback.tokenOwner();
                            this.tokenExpiryTimestamp = tokenCallback.tokenExpiryTimestamp();
                        } else {
                            credentialCallback = new ScramCredentialCallback();
                            callbackHandler.handle(new Callback[]{nameCallback, credentialCallback});
                            this.authorizationId = username;
                            this.tokenExpiryTimestamp = null;
                        }
                        this.scramCredential = credentialCallback.scramCredential();
                        // SECURITY: Fail-closed -- null credential causes immediate
                        // SaslException, preventing auth with non-existent users.
                        if (scramCredential == null)
                            throw new SaslException("Authentication failed: Invalid user credentials");
                        String authorizationIdFromClient = clientFirstMessage.authorizationId();
                        if (!authorizationIdFromClient.isEmpty() && !authorizationIdFromClient.equals(username))
                            throw new SaslAuthenticationException("Authentication failed: Client requested an authorization id that is different from username");

                        if (scramCredential.iterations() < mechanism.minIterations())
                            throw new SaslException("Iterations " + scramCredential.iterations() +  " is less than the minimum " + mechanism.minIterations() + " for " + mechanism);
                        this.serverFirstMessage = new ServerFirstMessage(clientFirstMessage.nonce(),
                                serverNonce,
                                scramCredential.salt(),
                                scramCredential.iterations());
                        setState(State.RECEIVE_CLIENT_FINAL_MESSAGE);
                        return serverFirstMessage.toBytes();
                    } catch (SaslException | AuthenticationException e) {
                        throw e;
                    } catch (Throwable e) {
                        throw new SaslException("Authentication failed: Credentials could not be obtained", e);
                    }

                case RECEIVE_CLIENT_FINAL_MESSAGE:
                    try {
                        ClientFinalMessage clientFinalMessage = new ClientFinalMessage(response);
                        if (!clientFinalMessage.nonce().equals(serverFirstMessage.nonce())) {
                            throw new SaslException("Invalid client nonce in the final client message.");
                        }
                        verifyClientProof(clientFinalMessage);
                        byte[] serverKey = scramCredential.serverKey();
                        byte[] serverSignature = formatter.serverSignature(serverKey, clientFirstMessage, serverFirstMessage, clientFinalMessage);
                        ServerFinalMessage serverFinalMessage = new ServerFinalMessage(null, serverSignature);
                        clearCredentials();
                        setState(State.COMPLETE);
                        return serverFinalMessage.toBytes();
                    } catch (InvalidKeyException e) {
                        throw new SaslException("Authentication failed: Invalid client final message", e);
                    }

                default:
                    throw new IllegalSaslStateException("Unexpected challenge in Sasl server state " + state);
            }
        } catch (SaslException | AuthenticationException e) {
            clearCredentials();
            setState(State.FAILED);
            throw e;
        }
    }

    @Override
    public String getAuthorizationID() {
        if (!isComplete())
            throw new IllegalStateException("Authentication exchange has not completed");
        return authorizationId;
    }

    @Override
    public String getMechanismName() {
        return mechanism.mechanismName();
    }

    // DECISION: Returns tokenExpiryTimestamp as a negotiated SASL property, enabling the
    // authenticator layer to enforce credential lifetime without coupling to SCRAM internals.
    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!isComplete())
            throw new IllegalStateException("Authentication exchange has not completed");
        if (SaslInternalConfigs.CREDENTIAL_LIFETIME_MS_SASL_NEGOTIATED_PROPERTY_KEY.equals(propName))
            return tokenExpiryTimestamp; // will be null if token not used
        if (SUPPORTED_EXTENSIONS.contains(propName))
            return scramExtensions.map().get(propName);
        else
            return null;
    }

    @Override
    public boolean isComplete() {
        return state == State.COMPLETE;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
        if (!isComplete())
            throw new IllegalStateException("Authentication exchange has not completed");
        throw new IllegalStateException("SCRAM supports neither integrity nor privacy");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
        if (!isComplete())
            throw new IllegalStateException("Authentication exchange has not completed");
        throw new IllegalStateException("SCRAM supports neither integrity nor privacy");
    }

    @Override
    public void dispose() {
    }

    private void setState(State state) {
        log.debug("Setting SASL/{} server state to {}", mechanism, state);
        this.state = state;
    }

    // SECURITY: (CRITICAL) Constant-time proof verification using MessageDigest.isEqual().
    // This method reconstructs StoredKey from the client's proof and compares it against
    // the expected StoredKey using a constant-time comparison to prevent timing attacks.
    // Why: Non-constant-time comparison (e.g., Arrays.equals()) would allow an attacker to
    // determine the correct StoredKey one byte at a time by measuring response time.
    // Computation: computedStoredKey = H(clientSignature XOR clientProof) must equal
    // expectedStoredKey. If they match, the client has proven knowledge of ClientKey.
    // Visible for testing
    void verifyClientProof(ClientFinalMessage clientFinalMessage) throws SaslException {
        try {
            byte[] expectedStoredKey = scramCredential.storedKey();
            byte[] clientSignature = formatter.clientSignature(expectedStoredKey, clientFirstMessage, serverFirstMessage, clientFinalMessage);
            byte[] computedStoredKey = formatter.storedKey(clientSignature, clientFinalMessage.proof());
            if (!MessageDigest.isEqual(computedStoredKey, expectedStoredKey))
                throw new SaslException("Invalid client credentials");
        } catch (InvalidKeyException e) {
            throw new SaslException("Sasl client verification failed", e);
        }
    }

    // SECURITY: (MEDIUM) Credential clearing after authentication completes or fails.
    // Sets references to null but does NOT zero the underlying byte arrays (salt,
    // storedKey, serverKey). Contents remain in memory until garbage collected.
    // Improvement: Zero byte arrays explicitly before nulling references to reduce
    // the window for heap dump credential extraction.
    private void clearCredentials() {
        scramCredential = null;
        clientFirstMessage = null;
        serverFirstMessage = null;
    }

    // CROSS-CUTTING: Factory registered via ScramSaslServerProvider into JCA Provider
    // framework. Consumed by javax.security.sasl.Sasl.createSaslServer() during SASL
    // negotiation in SaslServerAuthenticator. Validates mechanism name against ScramMechanism.
    public static class ScramSaslServerFactory implements SaslServerFactory {

        @Override
        public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh)
            throws SaslException {

            if (!ScramMechanism.isScram(mechanism)) {
                throw new SaslException(String.format("Requested mechanism '%s' is not supported. Supported mechanisms are '%s'.",
                        mechanism, ScramMechanism.mechanismNames()));
            }
            try {
                return new ScramSaslServer(ScramMechanism.forMechanismName(mechanism), props, cbh);
            } catch (NoSuchAlgorithmException e) {
                throw new SaslException("Hash algorithm not supported for mechanism " + mechanism, e);
            }
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> props) {
            Collection<String> mechanisms = ScramMechanism.mechanismNames();
            return mechanisms.toArray(new String[0]);
        }
    }
}
