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
package org.apache.kafka.common.security.oauthbearer.internals;

import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.utils.Utils;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.sasl.SaslException;

// SECURITY: SEC-OAUTH-042 (MEDIUM) Parses and constructs the SASL OAUTHBEARER client-first message
// per RFC 7628. The message embeds the raw bearer token in the "auth=Bearer <token>" field.
// Why: This class handles untrusted input (byte[] from the network on the server side)
// and constructs cleartext token-bearing messages (on the client side). Malformed input
// can trigger SaslException but malicious extensions bypass structural validation.
// Exploit: Extension injection -- a malicious client could craft extensions with values
// that pass EXTENSION_VALUE_PATTERN but contain semantically dangerous content (e.g.,
// control characters within the allowed range 0x21-0x7E, tab, CR, LF). Downstream
// consumers of these extensions (custom authorizers, audit loggers) may not expect
// or properly handle such content, enabling log injection or authorization bypass.
// Improvement: Consider a stricter extension value pattern that excludes CR/LF/tab,
// or sanitize extension values before passing to downstream consumers.
//
// CROSS-CUTTING: Used by OAuthBearerSaslClient (constructs and sends client-first message),
// OAuthBearerSaslServer (parses received client-first message), and
// OAuthBearerLoginCallbackHandler / OAuthBearerUnsecuredLoginCallbackHandler (extension
// validation via validateExtensions() static method).
// Depends on: auth/SaslExtensions (extension DTO), Utils.parseMap/mkString (parsing/formatting).
// Contract: After construction, tokenValue(), authorizationId(), and extensions() are
// non-null and validated. toBytes() produces a wire-compatible message.
// Impact: Changes to regex patterns or validation logic affect ALL OAUTHBEARER authentication
// on both client and server sides.
public class OAuthBearerClientInitialResponse {
    // DECISION: Uses U+0001 (control-A) as the field separator per RFC 7628. Alternative:
    // Use a visible delimiter like "|" or ",". Rationale: RFC 7628 specifies U+0001 as the
    // GS2 header separator. This character is unlikely to appear in extension values,
    // preventing delimiter confusion. OAuthBearerSaslClient uses BYTE_CONTROL_A (0x01) for
    // the error acknowledgment -- same byte value, different semantic context.
    static final String SEPARATOR = "\u0001";

    // DECISION: Uses compiled regex patterns for message parsing rather than manual string
    // splitting. Alternatives: (1) Manual parsing with indexOf/substring, (2) StreamTokenizer.
    // Rationale: Regex patterns provide RFC-compliance validation and field extraction in a
    // single pass. The patterns are compiled once (static finals) and reused for all instances.
    // Risk: Complex regex can be vulnerable to ReDoS -- the patterns here are bounded by
    // the input structure (fixed delimiters) which limits backtracking.
    private static final String SASLNAME = "(?:[\\x01-\\x7F&&[^=,]]|=2C|=3D)+";
    private static final String KEY = "[A-Za-z]+";
    private static final String VALUE = "[\\x21-\\x7E \t\r\n]+";

    private static final String KVPAIRS = String.format("(%s=%s%s)*", KEY, VALUE, SEPARATOR);
    private static final Pattern AUTH_PATTERN = Pattern.compile("(?<scheme>[\\w]+)[ ]+(?<token>[-_~+/\\.a-zA-Z0-9]+([=]*))");
    private static final Pattern CLIENT_INITIAL_RESPONSE_PATTERN = Pattern.compile(
            String.format("n,(a=(?<authzid>%s))?,%s(?<kvpairs>%s)%s", SASLNAME, SEPARATOR, KVPAIRS, SEPARATOR));
    public static final String AUTH_KEY = "auth";

    private final String tokenValue;
    private final String authorizationId;
    private final SaslExtensions saslExtensions;

    // SECURITY: SEC-OAUTH-043 (MEDIUM) Extension validation regex patterns per RFC 7628 Section 3.1.
    // Why: The initial SASL response contains the bearer token and
    // extensions that must be parsed securely.
    // KEY: [A-Za-z]+ -- letters only, preventing injection via special characters in keys.
    // VALUE: [\x21-\x7E \t\r\n]+ -- printable ASCII plus whitespace. Note: \r\n
    // are included per the RFC but could enable header injection in downstream HTTP
    // components if extensions are forwarded without sanitization.
    // Exploit: Malicious extensions or callback values could inject unexpected behavior into the auth flow.
    // Improvement: Validate all extension keys and values against an allowlist before processing.
    public static final Pattern EXTENSION_KEY_PATTERN = Pattern.compile(KEY);
    public static final Pattern EXTENSION_VALUE_PATTERN = Pattern.compile(VALUE);

    // SECURITY: SEC-OAUTH-044 (MEDIUM) Parses untrusted client input. CLIENT_INITIAL_RESPONSE_PATTERN
    // Why: The initial SASL response contains the bearer token and
    // extensions that must be parsed securely.
    // regex validates the overall structure, AUTH_PATTERN validates the "Bearer <token>"
    // format. If the regex doesn't match, SaslException is thrown (fail-closed). The token
    // value is extracted via named capture group "token" which restricts to [-_~+/.a-zA-Z0-9=].
    // This character set covers Base64URL encoding used by JWTs.
    //
    // DECISION: Three constructor overloads -- (1) byte[] parser for server-side deserialization,
    // (2) token+extensions for client-side construction, (3) token+authzId+extensions for
    // full specification. Alternative: Single builder pattern. Rationale: Three constructors
    // cover the two primary use cases cleanly (server parsing, client construction) without
    // the overhead of a builder for this simple data carrier.
    // Exploit: A malformed initial SASL response could exploit parsing to inject unauthorized authentication paramet...
    // Improvement: Add strict format validation for the initial SASL response fields before processing.
    public OAuthBearerClientInitialResponse(byte[] response) throws SaslException {
        String responseMsg = new String(response, StandardCharsets.UTF_8);
        Matcher matcher = CLIENT_INITIAL_RESPONSE_PATTERN.matcher(responseMsg);
        if (!matcher.matches())
            throw new SaslException("Invalid OAUTHBEARER client first message");
        String authzid = matcher.group("authzid");
        this.authorizationId = authzid == null ? "" : authzid;
        String kvPairs = matcher.group("kvpairs");
        Map<String, String> properties = Utils.parseMap(kvPairs, "=", SEPARATOR);
        String auth = properties.get(AUTH_KEY);
        if (auth == null)
            throw new SaslException("Invalid OAUTHBEARER client first message: 'auth' not specified");
        properties.remove(AUTH_KEY);
        SaslExtensions extensions = new SaslExtensions(properties);
        validateExtensions(extensions);
        this.saslExtensions = extensions;

        Matcher authMatcher = AUTH_PATTERN.matcher(auth);
        if (!authMatcher.matches())
            throw new SaslException("Invalid OAUTHBEARER client first message: invalid 'auth' format");
        if (!"bearer".equalsIgnoreCase(authMatcher.group("scheme"))) {
            String msg = String.format("Invalid scheme in OAUTHBEARER client first message: %s",
                    matcher.group("scheme"));
            throw new SaslException(msg);
        }
        this.tokenValue = authMatcher.group("token");
    }

    /**
     * Constructor
     * 
     * @param tokenValue
     *            the mandatory token value
     * @param extensions
     *            the optional extensions
     * @throws SaslException
     *             if any extension name or value fails to conform to the required
     *             regular expression as defined by the specification, or if the
     *             reserved {@code auth} appears as a key
     */
    public OAuthBearerClientInitialResponse(String tokenValue, SaslExtensions extensions) throws SaslException {
        this(tokenValue, "", extensions);
    }

    /**
     * Constructor
     * 
     * @param tokenValue
     *            the mandatory token value
     * @param authorizationId
     *            the optional authorization ID
     * @param extensions
     *            the optional extensions
     * @throws SaslException
     *             if any extension name or value fails to conform to the required
     *             regular expression as defined by the specification, or if the
     *             reserved {@code auth} appears as a key
     */
    public OAuthBearerClientInitialResponse(String tokenValue, String authorizationId, SaslExtensions extensions) throws SaslException {
        this.tokenValue = Objects.requireNonNull(tokenValue, "token value must not be null");
        this.authorizationId = authorizationId == null ? "" : authorizationId;
        validateExtensions(extensions);
        this.saslExtensions = extensions != null ? extensions : SaslExtensions.empty();
    }

    /**
     * Return the always non-null extensions
     * 
     * @return the always non-null extensions
     */
    public SaslExtensions extensions() {
        return saslExtensions;
    }

    // SECURITY: SEC-OAUTH-045 (LOW) Constructs the wire-format message. The token value is embedded
    // Why: The initial SASL response contains the bearer token and
    // extensions that must be parsed securely.
    // directly -- no encoding or escaping is applied beyond what was validated at
    // construction time. The SEPARATOR (U+0001) is used as a field delimiter.
    // Exploit: A malformed initial client response could exploit SASL
    // parsing to inject unauthorized authentication parameters.
    // Improvement: Add defense-in-depth OAuth token validation with
    // token binding and strict claim verification.
    public byte[] toBytes() {
        String authzid = authorizationId.isEmpty() ? "" : "a=" + authorizationId;
        String extensions = extensionsMessage();
        if (!extensions.isEmpty())
            extensions = SEPARATOR + extensions;

        String message = String.format("n,%s,%sauth=Bearer %s%s%s%s", authzid,
                SEPARATOR, tokenValue, extensions, SEPARATOR, SEPARATOR);

        return message.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Return the always non-null token value
     * 
     * @return the always non-null token value
     */
    public String tokenValue() {
        return tokenValue;
    }

    /**
     * Return the always non-null authorization ID
     * 
     * @return the always non-null authorization ID
     */
    public String authorizationId() {
        return authorizationId;
    }

    /**
     * Validates that the given extensions conform to the standard. They should also not contain the reserve key name {@link OAuthBearerClientInitialResponse#AUTH_KEY}
     *
     * @param extensions
     *            optional extensions to validate
     * @throws SaslException
     *             if any extension name or value fails to conform to the required
     *             regular expression as defined by the specification, or if the
     *             reserved {@code auth} appears as a key
     *
     * @see <a href="https://tools.ietf.org/html/rfc7628#section-3.1">RFC 7628,
     *  Section 3.1</a>
     */
    // SECURITY: SEC-OAUTH-046 (MEDIUM) Validates all extensions against patterns and checks for reserved
    // Why: The initial SASL response contains the bearer token and
    // extensions that must be parsed securely.
    // key "auth". This prevents a client from injecting a second "auth" key to override
    // the legitimate token. The iteration over all entries ensures no key or value escapes
    // validation. Extension validation is called from both constructors.
    // Exploit: Injecting control characters in SASL extensions could
    // manipulate the authentication exchange or bypass parsing.
    // Improvement: Add defense-in-depth OAuth token validation with
    // token binding and strict claim verification.
    public static void validateExtensions(SaslExtensions extensions) throws SaslException {
        if (extensions == null)
            return;
        if (extensions.map().containsKey(OAuthBearerClientInitialResponse.AUTH_KEY))
            throw new SaslException("Extension name " + OAuthBearerClientInitialResponse.AUTH_KEY + " is invalid");

        for (Map.Entry<String, String> entry : extensions.map().entrySet()) {
            String extensionName = entry.getKey();
            String extensionValue = entry.getValue();

            if (!EXTENSION_KEY_PATTERN.matcher(extensionName).matches())
                throw new SaslException("Extension name " + extensionName + " is invalid");
            if (!EXTENSION_VALUE_PATTERN.matcher(extensionValue).matches())
                throw new SaslException("Extension value (" + extensionValue + ") for extension " + extensionName + " is invalid");
        }
    }

    /**
     * Converts the SASLExtensions to an OAuth protocol-friendly string
     */
    private String extensionsMessage() {
        return Utils.mkString(saslExtensions.map(), "", "", "=", SEPARATOR);
    }
}
