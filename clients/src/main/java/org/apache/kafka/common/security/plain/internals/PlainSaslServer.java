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
package org.apache.kafka.common.security.plain.internals;

import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

/**
 * Simple SaslServer implementation for SASL/PLAIN. In order to make this implementation
 * fully pluggable, authentication of username/password is fully contained within the
 * server implementation.
 * <p>
 * Valid users with passwords are specified in the Jaas configuration file. Each user
 * is specified with user_<username> as key and <password> as value. This is consistent
 * with Zookeeper Digest-MD5 implementation.
 * <p>
 * To avoid storing clear passwords on disk or to integrate with external authentication
 * servers in production systems, this module can be replaced with a different implementation.
 *
 */
// SECURITY: SEC-PLAIN-005 (CRITICAL) SASL/PLAIN transmits credentials in CLEARTEXT at the SASL layer.
// Why: PLAIN mechanism sends username and password as Base64-encoded bytes with no encryption
// at the SASL layer itself. Authentication relies entirely on transport layer (TLS) for
// confidentiality. Per RFC 4616, PLAIN MUST NOT be used without adequate data security.
// Exploit: If TLS is not configured (SASL_PLAINTEXT listener), a network sniffer can capture
// credentials in plaintext. Even with TLS, if certificate validation is disabled
// (ssl.endpoint.identification.algorithm=none), a MITM attacker can intercept credentials.
// Improvement: Consider deprecating SASL_PLAINTEXT and requiring SASL_SSL for PLAIN mechanism.
// Add runtime warning when PLAIN is used without TLS. Enforce ssl.endpoint.identification
// to prevent MITM attacks on credential exchange.
//
// CROSS-CUTTING: Depends on plain/PlainAuthenticateCallback (credential carrier passed to
// CallbackHandler). Consumed by authenticator/SaslServerAuthenticator when PLAIN mechanism
// is negotiated via Sasl.createSaslServer().
// Contract: CallbackHandler must handle NameCallback and PlainAuthenticateCallback.
// Impact: If PlainSaslServerFactory is not registered via PlainSaslServerProvider, SASL
// mechanism negotiation fails -- Sasl.createSaslServer("PLAIN",...) returns null.
public class PlainSaslServer implements SaslServer {

    public static final String PLAIN_MECHANISM = "PLAIN";

    private final CallbackHandler callbackHandler;
    private boolean complete;
    private String authorizationId;

    public PlainSaslServer(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    /**
     * @throws SaslAuthenticationException if username/password combination is invalid or if the requested
     *         authorization id is not the same as username.
     * <p>
     * <b>Note:</b> This method may throw {@link SaslAuthenticationException} to provide custom error messages
     * to clients. But care should be taken to avoid including any information in the exception message that
     * should not be leaked to unauthenticated clients. It may be safer to throw {@link SaslException} in
     * some cases so that a standard error message is returned to clients.
     * </p>
     */
    // COMPLEXITY: 44 lines -- RFC 4616 token parsing, callback-based validation, authz ID check.
    // Structure: (1) Parse NUL-delimited message into 3 tokens via extractTokens(), (2) Validate
    // non-empty username/password, (3) Dispatch to CallbackHandler for credential verification,
    // (4) Verify authorization ID matches authentication ID if provided.
    // Key paths: Success -> sets authorizationId and complete=true, returns empty byte[];
    // Failure -> throws SaslAuthenticationException at 4 distinct validation points.
    //
    // SECURITY: SEC-PLAIN-006 (HIGH) Parses raw bytes from untrusted client into credential tokens.
    // Why: The NUL-delimited format (authzid NUL authcid NUL passwd per RFC 4616) is parsed from
    // raw bytes. Malformed messages could cause unexpected token extraction.
    // Exploit: A client could send a message with extra NUL bytes to attempt unexpected parsing.
    // The extractTokens() method mitigates this by validating exactly 3 tokens.
    // Improvement: Consider adding maximum token length validation (RFC 4616 specifies 255 octets
    // max per field) to prevent memory abuse from oversized credentials.
    //
    // DECISION: Uses simple NUL-delimited format per RFC 4616 rather than challenge-response.
    // Alternatives: (1) Challenge-response protocol like SCRAM, (2) Token-based like OAUTHBEARER.
    // Rationale: PLAIN is intentionally simple for environments where TLS provides transport
    // security and a lightweight auth mechanism is sufficient. The single-round-trip design
    // minimizes authentication latency.
    @Override
    public byte[] evaluateResponse(byte[] responseBytes) throws SaslAuthenticationException {
        /*
         * Message format (from https://tools.ietf.org/html/rfc4616):
         *
         * message   = [authzid] UTF8NUL authcid UTF8NUL passwd
         * authcid   = 1*SAFE ; MUST accept up to 255 octets
         * authzid   = 1*SAFE ; MUST accept up to 255 octets
         * passwd    = 1*SAFE ; MUST accept up to 255 octets
         * UTF8NUL   = %x00 ; UTF-8 encoded NUL character
         *
         * SAFE      = UTF1 / UTF2 / UTF3 / UTF4
         *                ;; any UTF-8 encoded Unicode character except NUL
         */

        String response = new String(responseBytes, StandardCharsets.UTF_8);
        List<String> tokens = extractTokens(response);
        String authorizationIdFromClient = tokens.get(0);
        String username = tokens.get(1);
        String password = tokens.get(2);

        if (username.isEmpty()) {
            throw new SaslAuthenticationException("Authentication failed: username not specified");
        }
        if (password.isEmpty()) {
            throw new SaslAuthenticationException("Authentication failed: password not specified");
        }

        NameCallback nameCallback = new NameCallback("username", username);
        PlainAuthenticateCallback authenticateCallback = new PlainAuthenticateCallback(password.toCharArray());
        try {
            callbackHandler.handle(new Callback[]{nameCallback, authenticateCallback});
        } catch (Throwable e) {
            throw new SaslAuthenticationException("Authentication failed: credentials for user could not be verified", e);
        }
        if (!authenticateCallback.authenticated())
            throw new SaslAuthenticationException("Authentication failed: Invalid username or password");
        if (!authorizationIdFromClient.isEmpty() && !authorizationIdFromClient.equals(username))
            throw new SaslAuthenticationException("Authentication failed: Client requested an authorization id that is different from username");

        this.authorizationId = username;

        complete = true;
        return new byte[0];
    }

    // SECURITY: SEC-PLAIN-007 (MEDIUM) Input validation for NUL-delimited SASL/PLAIN message format.
    // Why: Parses untrusted client input -- malformed NUL sequences could yield wrong token count.
    // The method enforces exactly 3 tokens, rejecting messages with fewer or more segments.
    // Exploit: Without the token-count check, extra NUL bytes could cause index confusion.
    // Improvement: Add per-token length cap (255 octets per RFC 4616 Section 4) to bound memory.
    private List<String> extractTokens(String string) {
        List<String> tokens = new ArrayList<>();
        int startIndex = 0;
        for (int i = 0; i < 4; ++i) {
            int endIndex = string.indexOf("\u0000", startIndex);
            if (endIndex == -1) {
                tokens.add(string.substring(startIndex));
                break;
            }
            tokens.add(string.substring(startIndex, endIndex));
            startIndex = endIndex + 1;
        }

        if (tokens.size() != 3)
            throw new SaslAuthenticationException("Invalid SASL/PLAIN response: expected 3 tokens, got " +
                tokens.size());

        return tokens;
    }

    @Override
    public String getAuthorizationID() {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return authorizationId;
    }

    @Override
    public String getMechanismName() {
        return PLAIN_MECHANISM;
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return null;
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    // DECISION: Explicitly throws IllegalStateException for wrap/unwrap because PLAIN provides no
    // security layer (no integrity or privacy). This is per SASL spec -- mechanisms declare QoP
    // (Quality of Protection) support, and PLAIN offers none.
    // Alternatives: Return input unchanged (pass-through). Rationale: Throwing is more correct
    // because it prevents callers from incorrectly assuming a security layer exists.
    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        throw new IllegalStateException("PLAIN supports neither integrity nor privacy");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        throw new IllegalStateException("PLAIN supports neither integrity nor privacy");
    }

    @Override
    public void dispose() {
    }

    // SECURITY: SEC-PLAIN-008 (LOW) Factory respects Sasl.POLICY_NOPLAINTEXT property to suppress PLAIN in
    // Why: PLAIN mechanism handles cleartext credentials that have
    // no cryptographic protection.
    // policy-restricted environments. getMechanismNames() returns empty array when NOPLAINTEXT
    // is set, preventing PLAIN from being offered during SASL mechanism negotiation.
    // Exploit: An attacker on the network can intercept all data including credentials in transit.
    // Improvement: Use TLS-encrypted transports (SSL or SASL_SSL) in production environments.
    public static class PlainSaslServerFactory implements SaslServerFactory {

        @Override
        public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh)
            throws SaslException {

            if (!PLAIN_MECHANISM.equals(mechanism))
                throw new SaslException(String.format("Mechanism \'%s\' is not supported. Only PLAIN is supported.", mechanism));

            return new PlainSaslServer(cbh);
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> props) {
            if (props == null) return new String[]{PLAIN_MECHANISM};
            String noPlainText = (String) props.get(Sasl.POLICY_NOPLAINTEXT);
            if ("true".equals(noPlainText))
                return new String[]{};
            else
                return new String[]{PLAIN_MECHANISM};
        }
    }
}
