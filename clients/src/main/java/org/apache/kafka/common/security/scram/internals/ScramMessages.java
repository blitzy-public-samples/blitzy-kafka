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

import org.apache.kafka.common.utils.Utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.sasl.SaslException;

/**
 * SCRAM request/response message creation and parsing based on
 * <a href="https://tools.ietf.org/html/rfc5802">RFC 5802</a>
 *
 */
// SECURITY: (HIGH) RFC 5802 SASL SCRAM message parsing and construction.
// Why: This class parses untrusted network data into structured SCRAM protocol messages.
// Malformed messages from a malicious client or MITM could cause parsing errors, regex
// backtracking, or injection of crafted attribute values.
// Exploit: An attacker could craft a SCRAM message where attribute values contain unescaped
// reserved characters (comma ',' is the attribute separator per RFC 5802). While the regex
// patterns restrict the character set (VALUE_SAFE excludes '=' and ','; PRINTABLE excludes
// ','), a message that passes regex validation but contains semantically invalid content
// (e.g., extremely long nonce, malformed Base64 in salt/proof) could cause downstream
// parsing errors or excessive memory allocation.
// Improvement: (1) Add length limits on parsed fields (nonce, saslName, Base64 values) to
// prevent memory exhaustion attacks. (2) Add regex timeout or use possessive quantifiers to
// prevent ReDoS. (3) Validate Base64 field lengths match expected hash output sizes.
//
// CROSS-CUTTING: Used by ScramSaslServer and ScramSaslClient for SCRAM protocol message
// construction, parsing, and wire format conversion. Each nested message class corresponds
// to one step in the RFC 5802 four-message exchange:
//   ClientFirstMessage -> ServerFirstMessage -> ClientFinalMessage -> ServerFinalMessage.
// Depends on ScramExtensions for protocol extension parsing in ClientFirstMessage.
// Depends on Utils.mkString() for extension serialization.
// Impact: Changes to message format, regex patterns, or field accessors would break both
// client and server SCRAM authentication paths simultaneously.
public class ScramMessages {

    // DECISION: Regex-based message parsing per RFC 5802 ABNF grammar rather than a
    // hand-written character-by-character parser. Alternatives: (1) ANTLR grammar for formal
    // parsing, (2) Manual StringTokenizer/split parsing, (3) State machine character parser.
    // Rationale: Precompiled regex Pattern objects (PATTERN constants in each message class)
    // directly express the RFC 5802 ABNF rules, making compliance verifiable by inspection.
    // The patterns are compiled once (static final) and reused across all message instances.
    // Risk: Complex regex patterns may be vulnerable to catastrophic backtracking (ReDoS).
    abstract static class AbstractScramMessage {

        // SECURITY: (MEDIUM) Regex character classes define allowed character sets per RFC 5802 ABNF.
        // VALUE_SAFE: Excludes '=' and ',' -- prevents attribute boundary confusion.
        // PRINTABLE: Excludes only ',' -- used for nonce values which must be unique/random.
        // SASLNAME: Allows '=2C' and '=3D' escape sequences per RFC 5802 Section 5.1.
        // Exploit: Predictable nonce or salt values would allow precomputation attacks against the challenge-response.
        // Improvement: Verify SecureRandom is seeded from a strong entropy source on the deployment platform.
        static final String ALPHA = "[A-Za-z]+";
        static final String VALUE_SAFE = "[\\x01-\\x7F&&[^=,]]+";
        static final String VALUE = "[\\x01-\\x7F&&[^,]]+";
        static final String PRINTABLE = "[\\x21-\\x7E&&[^,]]+";
        static final String SASLNAME = "(?:[\\x01-\\x7F&&[^=,]]|=2C|=3D)+";
        static final String BASE64_CHAR = "[a-zA-Z0-9/+]";
        static final String BASE64 = String.format("(?:%s{4})*(?:%s{3}=|%s{2}==)?", BASE64_CHAR, BASE64_CHAR, BASE64_CHAR);
        static final String RESERVED = String.format("(m=%s,)?", VALUE);
        static final String EXTENSIONS = String.format("(,%s=%s)*", ALPHA, VALUE);

        abstract String toMessage();

        public byte[] toBytes() {
            return toMessage().getBytes(StandardCharsets.UTF_8);
        }

        protected String toMessage(byte[] messageBytes) {
            return new String(messageBytes, StandardCharsets.UTF_8);
        }
    }

    /**
     * Format:
     *     gs2-header [reserved-mext ","] username "," nonce ["," extensions]
     * Limitations:
     *     Only gs2-header "n" is supported.
     *     Extensions are ignored.
     *
     */
    public static class ClientFirstMessage extends AbstractScramMessage {
        private static final Pattern PATTERN = Pattern.compile(String.format(
                "n,(a=(?<authzid>%s))?,%sn=(?<saslname>%s),r=(?<nonce>%s)(?<extensions>%s)",
                SASLNAME,
                RESERVED,
                SASLNAME,
                PRINTABLE,
                EXTENSIONS));


        private final String saslName;
        private final String nonce;
        private final String authorizationId;
        private final ScramExtensions extensions;
        // SECURITY: (HIGH) Parsing client-first message from untrusted network data. The regex
        // PATTERN validates the overall structure, but individual field content is not
        // bounds-checked. The saslName field undergoes =2C/=3D unescaping in
        // ScramFormatter.username() -- crafted saslNames with unexpected escape sequences
        // could cause IllegalArgumentException.
        // Improvement: Add bounds-checking on saslName length after regex extraction.
        // Exploit: Malformed serialized data could trigger parsing exceptions or inject unexpected values.
        public ClientFirstMessage(byte[] messageBytes) throws SaslException {
            String message = toMessage(messageBytes);
            Matcher matcher = PATTERN.matcher(message);
            if (!matcher.matches())
                throw new SaslException("Invalid SCRAM client first message format: " + message);
            String authzid = matcher.group("authzid");
            this.authorizationId = authzid != null ? authzid : "";
            this.saslName = matcher.group("saslname");
            this.nonce = matcher.group("nonce");
            String extString = matcher.group("extensions");

            this.extensions = extString.startsWith(",") ? new ScramExtensions(extString.substring(1)) : new ScramExtensions();
        }
        // DECISION: Separate constructors for parsing (from bytes) and construction (from
        // fields). The byte constructor validates via regex; the field constructor trusts
        // its callers. This asymmetry is intentional -- server-originated messages trust
        // internal data.
        public ClientFirstMessage(String saslName, String nonce, Map<String, String> extensions) {
            this.saslName = saslName;
            this.nonce = nonce;
            this.extensions = new ScramExtensions(extensions);
            this.authorizationId = ""; // Optional authzid not specified in gs2-header
        }
        public String saslName() {
            return saslName;
        }
        public String nonce() {
            return nonce;
        }
        public String authorizationId() {
            return authorizationId;
        }
        public String gs2Header() {
            return "n," + authorizationId + ",";
        }
        public ScramExtensions extensions() {
            return extensions;
        }

        public String clientFirstMessageBare() {
            String extensionStr = Utils.mkString(extensions.map(), "", "", "=", ",");

            if (extensionStr.isEmpty())
                return String.format("n=%s,r=%s", saslName, nonce);
            else
                return String.format("n=%s,r=%s,%s", saslName, nonce, extensionStr);
        }
        String toMessage() {
            return gs2Header() + clientFirstMessageBare();
        }
    }

    /**
     * Format:
     *     [reserved-mext ","] nonce "," salt "," iteration-count ["," extensions]
     * Limitations:
     *     Extensions are ignored.
     *
     */
    public static class ServerFirstMessage extends AbstractScramMessage {
        private static final Pattern PATTERN = Pattern.compile(String.format(
                "%sr=(?<nonce>%s),s=(?<salt>%s),i=(?<iterations>[0-9]+)%s",
                RESERVED,
                PRINTABLE,
                BASE64,
                EXTENSIONS));

        private final String nonce;
        private final byte[] salt;
        private final int iterations;
        public ServerFirstMessage(byte[] messageBytes) throws SaslException {
            String message = toMessage(messageBytes);
            Matcher matcher = PATTERN.matcher(message);
            if (!matcher.matches())
                throw new SaslException("Invalid SCRAM server first message format: " + message);
            // SECURITY: (MEDIUM) Iteration count parsed from server message. A compromised server
            // could send extremely high iterations (e.g., Integer.MAX_VALUE) causing CPU
            // exhaustion during PBKDF2 key derivation on the client. ScramSaslClient checks
            // minimum but not maximum. Improvement: Enforce ScramMechanism.maxIterations()
            // (16384) here to reject excessive iteration counts before PBKDF2 begins.
            // Exploit: An attacker could brute-force weak passwords if the iteration count is set below the recommended
            // minimum.
            try {
                this.iterations = Integer.parseInt(matcher.group("iterations"));
                if (this.iterations <= 0)
                    throw new SaslException("Invalid SCRAM server first message format: invalid iterations " + iterations);
            } catch (NumberFormatException e) {
                throw new SaslException("Invalid SCRAM server first message format: invalid iterations", e);
            }
            this.nonce = matcher.group("nonce");
            String salt = matcher.group("salt");
            this.salt = Base64.getDecoder().decode(salt);
        }
        public ServerFirstMessage(String clientNonce, String serverNonce, byte[] salt, int iterations) {
            this.nonce = clientNonce + serverNonce;
            this.salt = salt;
            this.iterations = iterations;
        }
        public String nonce() {
            return nonce;
        }
        public byte[] salt() {
            return salt;
        }
        public int iterations() {
            return iterations;
        }
        String toMessage() {
            return String.format("r=%s,s=%s,i=%d", nonce, Base64.getEncoder().encodeToString(salt), iterations);
        }
    }
    /**
     * Format:
     *     channel-binding "," nonce ["," extensions]"," proof
     * Limitations:
     *     Extensions are ignored.
     *
     */
    public static class ClientFinalMessage extends AbstractScramMessage {
        private static final Pattern PATTERN = Pattern.compile(String.format(
                "c=(?<channel>%s),r=(?<nonce>%s)%s,p=(?<proof>%s)",
                BASE64,
                PRINTABLE,
                EXTENSIONS,
                BASE64));

        private final byte[] channelBinding;
        private final String nonce;
        private byte[] proof;
        public ClientFinalMessage(byte[] messageBytes) throws SaslException {
            String message = toMessage(messageBytes);
            Matcher matcher = PATTERN.matcher(message);
            if (!matcher.matches())
                throw new SaslException("Invalid SCRAM client final message format: " + message);

            this.channelBinding = Base64.getDecoder().decode(matcher.group("channel"));
            this.nonce = matcher.group("nonce");
            // SECURITY: (HIGH) Client proof is the core authentication token -- ClientProof =
            // ClientKey XOR ClientSignature. This field is Base64-decoded from untrusted
            // client data. No length validation is performed -- an incorrect-length proof
            // would cause comparison failure in ScramSaslServer.verifyClientProof() but not
            // before crypto operations are performed.
            // Improvement: Validate decoded proof length matches expected hash output size.
            // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
            this.proof = Base64.getDecoder().decode(matcher.group("proof"));
        }
        public ClientFinalMessage(byte[] channelBinding, String nonce) {
            this.channelBinding = channelBinding;
            this.nonce = nonce;
        }
        public byte[] channelBinding() {
            return channelBinding;
        }
        public String nonce() {
            return nonce;
        }
        public byte[] proof() {
            return proof;
        }
        public void proof(byte[] proof) {
            this.proof = proof;
        }
        public String clientFinalMessageWithoutProof() {
            return String.format("c=%s,r=%s",
                    Base64.getEncoder().encodeToString(channelBinding),
                    nonce);
        }
        String toMessage() {
            return String.format("%s,p=%s",
                    clientFinalMessageWithoutProof(),
                    Base64.getEncoder().encodeToString(proof));
        }
    }
    /**
     * Format:
     *     ("e=" server-error-value | "v=" base64_server_signature) ["," extensions]
     * Limitations:
     *     Extensions are ignored.
     *
     */
    public static class ServerFinalMessage extends AbstractScramMessage {
        private static final Pattern PATTERN = Pattern.compile(String.format(
                "(?:e=(?<error>%s))|(?:v=(?<signature>%s))%s",
                VALUE_SAFE,
                BASE64,
                EXTENSIONS));

        private final String error;
        private final byte[] serverSignature;
        public ServerFinalMessage(byte[] messageBytes) throws SaslException {
            String message = toMessage(messageBytes);
            Matcher matcher = PATTERN.matcher(message);
            if (!matcher.matches())
                throw new SaslException("Invalid SCRAM server final message format: " + message);
            // DECISION: Error and server-signature are mutually exclusive per RFC 5802
            // Section 7. The try-catch on matcher.group("error") handles regex groups that
            // may not participate in the match. If error is present, serverSignature is null
            // and vice versa.
            String error = null;
            try {
                error = matcher.group("error");
            } catch (IllegalArgumentException e) {
                // ignore
            }
            if (error == null) {
                this.serverSignature = Base64.getDecoder().decode(matcher.group("signature"));
                this.error = null;
            } else {
                this.serverSignature = null;
                this.error = error;
            }
        }
        public ServerFinalMessage(String error, byte[] serverSignature) {
            this.error = error;
            this.serverSignature = serverSignature;
        }
        public String error() {
            return error;
        }
        public byte[] serverSignature() {
            return serverSignature;
        }
        String toMessage() {
            if (error != null)
                return "e=" + error;
            else
                return "v=" + Base64.getEncoder().encodeToString(serverSignature);
        }
    }
}
