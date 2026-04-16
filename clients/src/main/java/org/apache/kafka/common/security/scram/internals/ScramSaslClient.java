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

import org.apache.kafka.common.errors.IllegalSaslStateException;
import org.apache.kafka.common.security.scram.ScramExtensionsCallback;
import org.apache.kafka.common.security.scram.internals.ScramMessages.ClientFinalMessage;
import org.apache.kafka.common.security.scram.internals.ScramMessages.ServerFinalMessage;
import org.apache.kafka.common.security.scram.internals.ScramMessages.ServerFirstMessage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

/**
 * SaslClient implementation for SASL/SCRAM.
 * <p>
 * This implementation expects a login module that populates username as
 * the Subject's public credential and password as the private credential.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5802">RFC 5802</a>
 *
 */
// SECURITY: (HIGH) Client-side SCRAM SASL implementation per RFC 5802.
// Why: Computes client proof (ClientKey XOR ClientSignature) and verifies server signature.
// Handles the client's password in memory during key derivation (saltedPassword field).
// Nonce generation uses SecureRandom via ScramFormatter.secureRandomString().
// Exploit: If client nonce were predictable (e.g., weak RNG like java.util.Random instead of
// SecureRandom), the server's combined nonce could be pre-computed, enabling an offline
// dictionary attack without observing the full SCRAM exchange. Also, if ClientKey leaks
// (e.g., via memory dump of saltedPassword), an attacker can authenticate as the user.
// Improvement: (1) Zero saltedPassword byte array after computing clientProof and serverKey
// in handleServerFirstMessage(). (2) Validate that nonce generation uses SecureRandom.
// (3) Consider char[] instead of byte[] for intermediate password material to enable zeroing.
//
// CROSS-CUTTING: Depends on ScramFormatter for cryptographic operations (PBKDF2, HMAC, hash).
// Depends on ScramMessages for RFC 5802 message construction and parsing.
// Depends on ScramMechanism for algorithm selection and iteration bounds.
// Uses ScramExtensionsCallback (from scram/ parent) for optional SCRAM extensions (tokenauth).
// Consumed by authenticator/SaslClientAuthenticator via Java SASL Provider SPI -- the nested
// ScramSaslClientFactory is registered by ScramSaslClientProvider.
// Impact: Changes to ScramFormatter's key derivation (hi method) would break proof computation.
public class ScramSaslClient implements SaslClient {

    private static final Logger log = LoggerFactory.getLogger(ScramSaslClient.class);

    // DECISION: Client-side state machine: SEND_CLIENT_FIRST_MESSAGE ->
    // RECEIVE_SERVER_FIRST_MESSAGE -> RECEIVE_SERVER_FINAL_MESSAGE -> COMPLETE (or FAILED).
    // Mirrors the RFC 5802 client flow.
    // Alternatives: (1) Stateless message-type dispatch, (2) Promise/callback chain.
    // Rationale: Enum states map directly to RFC 5802 Section 5 steps, making compliance
    // verifiable by inspection.
    enum State {
        SEND_CLIENT_FIRST_MESSAGE,
        RECEIVE_SERVER_FIRST_MESSAGE,
        RECEIVE_SERVER_FINAL_MESSAGE,
        COMPLETE,
        FAILED
    }

    private final ScramMechanism mechanism;
    private final CallbackHandler callbackHandler;
    private final ScramFormatter formatter;
    private String clientNonce;
    private State state;
    private byte[] saltedPassword;
    private ScramMessages.ClientFirstMessage clientFirstMessage;
    private ScramMessages.ServerFirstMessage serverFirstMessage;
    private ScramMessages.ClientFinalMessage clientFinalMessage;

    public ScramSaslClient(ScramMechanism mechanism, CallbackHandler cbh) throws NoSuchAlgorithmException {
        this.mechanism = mechanism;
        this.callbackHandler = cbh;
        this.formatter = new ScramFormatter(mechanism);
        setState(State.SEND_CLIENT_FIRST_MESSAGE);
    }

    @Override
    public String getMechanismName() {
        return mechanism.mechanismName();
    }

    // DECISION: Returns true -- SCRAM client sends the first message (client-first-message)
    // before receiving any server challenge. This is required by RFC 5802 and the SASL SCRAM
    // profile (the client initiates the exchange, not the server).
    @Override
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        try {
            switch (state) {
                // DECISION: ScramExtensionsCallback is requested separately and
                // UnsupportedCallbackException is caught. This allows SCRAM to work even if
                // the CallbackHandler does not support extensions -- graceful degradation
                // rather than hard failure.
                case SEND_CLIENT_FIRST_MESSAGE:
                    if (challenge != null && challenge.length != 0)
                        throw new SaslException("Expected empty challenge");
                    clientNonce = formatter.secureRandomString();
                    NameCallback nameCallback = new NameCallback("Name:");
                    ScramExtensionsCallback extensionsCallback = new ScramExtensionsCallback();

                    try {
                        callbackHandler.handle(new Callback[]{nameCallback});
                        try {
                            callbackHandler.handle(new Callback[]{extensionsCallback});
                        } catch (UnsupportedCallbackException e) {
                            log.debug("Extensions callback is not supported by client callback handler {}, no extensions will be added",
                                    callbackHandler);
                        }
                    } catch (Throwable e) {
                        throw new SaslException("User name or extensions could not be obtained", e);
                    }

                    String username = nameCallback.getName();
                    String saslName = ScramFormatter.saslName(username);
                    Map<String, String> extensions = extensionsCallback.extensions();
                    this.clientFirstMessage = new ScramMessages.ClientFirstMessage(saslName, clientNonce, extensions);
                    setState(State.RECEIVE_SERVER_FIRST_MESSAGE);
                    return clientFirstMessage.toBytes();

                case RECEIVE_SERVER_FIRST_MESSAGE:
                    this.serverFirstMessage = new ServerFirstMessage(challenge);
                    // SECURITY: (HIGH) Verifies server nonce starts with client nonce per RFC 5802
                    // Section 5. Prevents server nonce substitution attacks where a MITM
                    // replaces the server's nonce.
                    // Exploit: Predictable nonce or salt values would allow precomputation attacks against the
                    // challenge-response.
                    // Improvement: Verify SecureRandom is seeded from a strong entropy source on the deployment
                    // platform.
                    if (!serverFirstMessage.nonce().startsWith(clientNonce))
                        throw new SaslException("Invalid server nonce: does not start with client nonce");
                    // SECURITY: (HIGH) Enforces minimum iteration count from the mechanism
                    // definition (4096 for both SHA-256 and SHA-512). Prevents a compromised
                    // server from requesting trivially low iterations, which would weaken the
                    // key derivation and make the salted password easier to brute-force.
                    // Exploit: An attacker could brute-force weak passwords if the iteration count is set below the
                    // recommended minimum.
                    // Improvement: Enforce a minimum iteration count floor and consider periodic increases as hardware
                    // improves.
                    if (serverFirstMessage.iterations() < mechanism.minIterations())
                        throw new SaslException("Requested iterations " + serverFirstMessage.iterations() +  " is less than the minimum " + mechanism.minIterations() + " for " + mechanism);
                    PasswordCallback passwordCallback = new PasswordCallback("Password:", false);
                    try {
                        callbackHandler.handle(new Callback[]{passwordCallback});
                    } catch (Throwable e) {
                        throw new SaslException("User name could not be obtained", e);
                    }
                    this.clientFinalMessage = handleServerFirstMessage(passwordCallback.getPassword());
                    setState(State.RECEIVE_SERVER_FINAL_MESSAGE);
                    return clientFinalMessage.toBytes();

                case RECEIVE_SERVER_FINAL_MESSAGE:
                    ServerFinalMessage serverFinalMessage = new ServerFinalMessage(challenge);
                    if (serverFinalMessage.error() != null)
                        throw new SaslException("Sasl authentication using " + mechanism + " failed with error: " + serverFinalMessage.error());
                    handleServerFinalMessage(serverFinalMessage.serverSignature());
                    setState(State.COMPLETE);
                    return null;

                default:
                    throw new IllegalSaslStateException("Unexpected challenge in Sasl client state " + state);
            }
        } catch (SaslException e) {
            setState(State.FAILED);
            throw e;
        }
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
    public Object getNegotiatedProperty(String propName) {
        if (!isComplete())
            throw new IllegalStateException("Authentication exchange has not completed");
        return null;
    }

    @Override
    public void dispose() {
    }

    private void setState(State state) {
        log.debug("Setting SASL/{} client state to {}", mechanism, state);
        this.state = state;
    }

    // SECURITY: (HIGH) Derives SaltedPassword from user's password using PBKDF2
    // (ScramFormatter.hi). The saltedPassword is stored in an instance field and persists
    // until GC.
    // Risk: Heap dump or memory scanner could extract the salted password, which, combined
    // with the known salt, allows an attacker to impersonate the client without knowing the
    // original password. The char[] password from PasswordCallback is also converted to
    // byte[] via normalize() -- the char[] is managed by the CallbackHandler but the byte[]
    // copy (passwordBytes) persists on the heap until GC.
    // Exploit: An attacker could brute-force weak passwords if the iteration count is set below the recommended
    // minimum.
    // Improvement: Enforce a minimum iteration count floor and consider periodic increases as hardware improves.
    private ClientFinalMessage handleServerFirstMessage(char[] password) throws SaslException {
        try {
            byte[] passwordBytes = ScramFormatter.normalize(new String(password));
            this.saltedPassword = formatter.hi(passwordBytes, serverFirstMessage.salt(), serverFirstMessage.iterations());

            ClientFinalMessage clientFinalMessage = new ClientFinalMessage("n,,".getBytes(StandardCharsets.UTF_8), serverFirstMessage.nonce());
            byte[] clientProof = formatter.clientProof(saltedPassword, clientFirstMessage, serverFirstMessage, clientFinalMessage);
            clientFinalMessage.proof(clientProof);
            return clientFinalMessage;
        } catch (InvalidKeyException e) {
            throw new SaslException("Client final message could not be created", e);
        }
    }

    // SECURITY: (HIGH) Server signature verification using constant-time MessageDigest.isEqual().
    // This prevents a malicious server from detecting partial signature match via timing
    // analysis. The verification ensures mutual authentication -- the server proves it
    // knows the ServerKey.
    // Exploit: An attacker could use response timing differences to incrementally reconstruct the secret.
    // Improvement: Ensure all cryptographic comparisons use constant-time algorithms like MessageDigest.isEqual().
    private void handleServerFinalMessage(byte[] signature) throws SaslException {
        try {
            byte[] serverKey = formatter.serverKey(saltedPassword);
            byte[] serverSignature = formatter.serverSignature(serverKey, clientFirstMessage, serverFirstMessage, clientFinalMessage);
            if (!MessageDigest.isEqual(signature, serverSignature))
                throw new SaslException("Invalid server signature in server final message");
        } catch (InvalidKeyException e) {
            throw new SaslException("Sasl server signature verification failed", e);
        }
    }

    // CROSS-CUTTING: Factory registered by ScramSaslClientProvider into JCA Provider framework.
    // Consumed by javax.security.sasl.Sasl.createSaslClient() during SASL negotiation in
    // SaslClientAuthenticator. First matching ScramMechanism from the offered list is selected.
    public static class ScramSaslClientFactory implements SaslClientFactory {

        @Override
        public SaslClient createSaslClient(String[] mechanisms,
                String authorizationId,
                String protocol,
                String serverName,
                Map<String, ?> props,
                CallbackHandler cbh) throws SaslException {

            ScramMechanism mechanism = null;
            for (String mech : mechanisms) {
                mechanism = ScramMechanism.forMechanismName(mech);
                if (mechanism != null)
                    break;
            }
            if (mechanism == null)
                throw new SaslException(String.format("Requested mechanisms '%s' not supported. Supported mechanisms are '%s'.",
                        Arrays.asList(mechanisms), ScramMechanism.mechanismNames()));

            try {
                return new ScramSaslClient(mechanism, cbh);
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
