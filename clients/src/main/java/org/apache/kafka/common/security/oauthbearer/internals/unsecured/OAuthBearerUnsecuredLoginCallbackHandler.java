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
package org.apache.kafka.common.security.oauthbearer.internals.unsecured;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.auth.SaslExtensionsCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerClientInitialResponse;
import org.apache.kafka.common.utils.Time;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.SaslException;

/**
 * A {@code CallbackHandler} that recognizes {@link OAuthBearerTokenCallback}
 * to return an unsecured OAuth 2 bearer token and {@link SaslExtensionsCallback} to return SASL extensions
 * <p>
 * Claims and their values on the returned token can be specified using
 * {@code unsecuredLoginStringClaim_<claimname>},
 * {@code unsecuredLoginNumberClaim_<claimname>}, and
 * {@code unsecuredLoginListClaim_<claimname>} options. The first character of
 * the value is taken as the delimiter for list claims. You may define any claim
 * name and value except '{@code iat}' and '{@code exp}', both of which are
 * calculated automatically.
 * <p>
 * <p>
 * You can also add custom unsecured SASL extensions using
 * {@code unsecuredLoginExtension_<extensionname>}. Extension keys and values are subject to regex validation.
 * The extension key must also not be equal to the reserved key {@link OAuthBearerClientInitialResponse#AUTH_KEY}
 * <p>
 * This implementation also accepts the following options:
 * <ul>
 * <li>{@code unsecuredLoginPrincipalClaimName} set to a custom claim name if
 * you wish the name of the String claim holding the principal name to be
 * something other than '{@code sub}'.</li>
 * <li>{@code unsecuredLoginLifetimeSeconds} set to an integer value if the
 * token expiration is to be set to something other than the default value of
 * 3600 seconds (which is 1 hour). The '{@code exp}' claim reflects the
 * expiration time.</li>
 * <li>{@code unsecuredLoginScopeClaimName} set to a custom claim name if you
 * wish the name of the String or String List claim holding any token scope to
 * be something other than '{@code scope}'</li>
 * </ul>
 * For example:
 *
 * <pre>
 * KafkaClient {
 *      org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule Required
 *      unsecuredLoginStringClaim_sub="thePrincipalName"
 *      unsecuredLoginListClaim_scope="|scopeValue1|scopeValue2"
 *      unsecuredLoginLifetimeSeconds="60"
 *      unsecuredLoginExtension_traceId="123";
 * };
 * </pre>
 *
 * This class is the default when the SASL mechanism is OAUTHBEARER and no value
 * is explicitly set via either the {@code sasl.login.callback.handler.class}
 * client configuration property or the
 * {@code listener.name.sasl_[plaintext|ssl].oauthbearer.sasl.login.callback.handler.class}
 * broker configuration property.
 */
// SECURITY: SEC-OAUTH-140 (CRITICAL) DEVELOPMENT ONLY — NO PRODUCTION USE.
// Why: Unsecured token handling has ZERO cryptographic protection
// and must never be used in production.
// This unsecured implementation accepts tokens without signature verification.
// A bad actor can forge any token with arbitrary claims (scope, subject, expiry).
// Using this in production allows complete authentication bypass.
// Improvement: Add a runtime check that logs CRITICAL-level warning when
// unsecured OAUTHBEARER is used in non-test contexts. Consider adding a
// system property or config flag to explicitly enable unsecured mode.
//
// CROSS-CUTTING: Depends on OAuthBearerUnsecuredJws (token representation, same package),
// OAuthBearerClientInitialResponse.validateExtensions() (extension validation,
// org.apache.kafka.common.security.oauthbearer.internals package),
// OAuthBearerTokenCallback (callback contract, oauthbearer package),
// SaslExtensionsCallback / SaslExtensions (auth package),
// OAuthBearerLoginModule.OAUTHBEARER_MECHANISM (mechanism name constant).
// Used by: authenticator/LoginManager as the default login callback handler when
// sasl.login.callback.handler.class is not configured for OAUTHBEARER mechanism.
// Contract: configure() -> handle() lifecycle. Not thread-safe.
// Impact: Tokens created here are consumed by OAuthBearerSaslClient for client-first
// message construction, then validated by OAuthBearerUnsecuredValidatorCallbackHandler
// (or a production validator) on the broker side.
// Exploit: Unsigned tokens from this handler can be forged by any party; production use enables trivial impersonation.
public class OAuthBearerUnsecuredLoginCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger log = LoggerFactory.getLogger(OAuthBearerUnsecuredLoginCallbackHandler.class);
    private static final String OPTION_PREFIX = "unsecuredLogin";
    private static final String PRINCIPAL_CLAIM_NAME_OPTION = OPTION_PREFIX + "PrincipalClaimName";
    private static final String LIFETIME_SECONDS_OPTION = OPTION_PREFIX + "LifetimeSeconds";
    private static final String SCOPE_CLAIM_NAME_OPTION = OPTION_PREFIX + "ScopeClaimName";
    // DECISION: Only "iat" and "exp" are reserved (auto-calculated). Alternative: Reserve
    // additional standard JWT claims ("nbf", "iss", "aud", "jti"). Rationale: Minimal
    // reservation — users may need to set custom "iss"/"aud" for testing. "iat" and "exp"
    // MUST be auto-calculated for temporal consistency with the system clock.
    private static final Set<String> RESERVED_CLAIMS = Set.of("iat", "exp");
    private static final String DEFAULT_PRINCIPAL_CLAIM_NAME = "sub";
    // DECISION: Default token lifetime is 3600 seconds (1 hour). Alternative: Shorter
    // default (e.g., 300s) for tighter security-by-default. Rationale: 1 hour balances
    // convenience for development (less frequent token refresh) with reasonable token
    // validity window.
    private static final String DEFAULT_LIFETIME_SECONDS_ONE_HOUR = "3600";
    private static final String DEFAULT_SCOPE_CLAIM_NAME = "scope";
    private static final String STRING_CLAIM_PREFIX = OPTION_PREFIX + "StringClaim_";
    // DECISION: Three claim prefix patterns (unsecuredLoginStringClaim_,
    // unsecuredLoginNumberClaim_, unsecuredLoginListClaim_) for type-safe claim
    // specification via JAAS options. Alternative: Single prefix with JSON value
    // parsing. Rationale: Separate prefixes avoid ambiguity in value parsing (e.g.,
    // "123" as string vs number) and make JAAS config more readable. List claims use
    // a delimiter-prefixed format (first char = delimiter).
    // Risk: The delimiter convention for list claims is unusual and error-prone.
    private static final String NUMBER_CLAIM_PREFIX = OPTION_PREFIX + "NumberClaim_";
    private static final String LIST_CLAIM_PREFIX = OPTION_PREFIX + "ListClaim_";
    private static final String EXTENSION_PREFIX = OPTION_PREFIX + "Extension_";
    private static final String QUOTE = "\"";
    private Time time = Time.SYSTEM;
    private Map<String, String> moduleOptions = null;
    private boolean configured = false;

    private static final Pattern DOUBLEQUOTE = Pattern.compile("\"", Pattern.LITERAL);

    private static final Pattern BACKSLASH = Pattern.compile("\\", Pattern.LITERAL);

    /**
     * For testing
     *
     * @param time
     *            the mandatory time to set
     */
    void time(Time time) {
        this.time = Objects.requireNonNull(time);
    }

    /**
     * Return true if this instance has been configured, otherwise false
     *
     * @return true if this instance has been configured, otherwise false
     */
    public boolean configured() {
        return configured;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        if (Objects.requireNonNull(jaasConfigEntries).size() != 1 || jaasConfigEntries.get(0) == null)
            throw new IllegalArgumentException(
                    String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)",
                            jaasConfigEntries.size()));
        this.moduleOptions = Collections.unmodifiableMap((Map<String, String>) jaasConfigEntries.get(0).getOptions());
        configured = true;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (!configured())
            throw new IllegalStateException("Callback handler not configured");
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback)
                try {
                    handleTokenCallback((OAuthBearerTokenCallback) callback);
                } catch (KafkaException e) {
                    throw new IOException(e.getMessage(), e);
                }
            else if (callback instanceof SaslExtensionsCallback)
                try {
                    handleExtensionsCallback((SaslExtensionsCallback) callback);
                } catch (KafkaException e) {
                    throw new IOException(e.getMessage(), e);
                }
            else
                throw new UnsupportedCallbackException(callback);
        }
    }

    @Override
    public void close() {
        // empty
    }

    // SECURITY: SEC-OAUTH-141 (CRITICAL) Creates tokens from JAAS options without any OAuth provider
    // interaction — no token endpoint call, no client credentials, no authorization code.
    // Why: Any JAAS configuration can specify arbitrary claims via option prefixes
    // (unsecuredLoginStringClaim_, unsecuredLoginNumberClaim_, unsecuredLoginListClaim_).
    // Exploit: An attacker with access to the JAAS config file (or who can influence JAAS
    // options programmatically) can specify: unsecuredLoginStringClaim_sub=admin,
    // unsecuredLoginListClaim_scope="|cluster-admin|topic-admin" to create a token
    // granting full administrative access. The token is self-issued with no external
    // validation.
    // Improvement: Log all claim values at WARN level when creating unsecured tokens.
    // Consider requiring explicit opt-in via a system property like
    // -Dkafka.oauthbearer.unsecured.enabled=true before allowing token creation.
    //
    // COMPLEXITY: 38 lines — Token construction pipeline.
    // Structure: (1) Guard: callback.token() must be null, (2) Guard: moduleOptions not
    // empty, (3) Guard: not extension-only options, (4) Extract principal/scope claim
    // names with defaults, (5) Build JSON header {"alg":"none"}, (6) Build claims JSON
    // with exp, iat, and custom string/number/list claims, (7) Base64URL-encode header
    // and claims without padding, (8) Construct OAuthBearerUnsecuredJws from encoded
    // string, (9) Set callback token.
    // Key branches: empty moduleOptions -> null token, extension-only -> exception,
    // NumberFormatException -> config exception.
    // Exit paths: return via callback.token(null), throw OAuthBearerConfigException
    // (3 locations), normal return via callback.token(jws).
    private void handleTokenCallback(OAuthBearerTokenCallback callback) {
        if (callback.token() != null)
            throw new IllegalArgumentException("Callback had a token already");
        if (moduleOptions.isEmpty()) {
            log.debug("Token not provided, this login cannot be used to establish client connections");
            callback.token(null);
            return;
        }
        if (moduleOptions.keySet().stream().allMatch(name -> name.startsWith(EXTENSION_PREFIX))) {
            throw new OAuthBearerConfigException("Extensions provided in login context without a token");
        }
        String principalClaimNameValue = optionValue(PRINCIPAL_CLAIM_NAME_OPTION);
        String principalClaimName = Utils.isBlank(principalClaimNameValue) ? DEFAULT_PRINCIPAL_CLAIM_NAME : principalClaimNameValue.trim();
        String scopeClaimNameValue = optionValue(SCOPE_CLAIM_NAME_OPTION);
        String scopeClaimName = Utils.isBlank(scopeClaimNameValue) ? DEFAULT_SCOPE_CLAIM_NAME : scopeClaimNameValue.trim();
        // DECISION: Constructs JSON manually via string concatenation with escape()
        // helper rather than using Jackson ObjectMapper serialization. Alternative:
        // Use ObjectMapper.writeValueAsString(). Rationale: Avoids Jackson dependency
        // for token creation (Jackson is only used in OAuthBearerUnsecuredJws for
        // parsing). Manual construction is simpler for the fixed header format
        // {"alg":"none"} and avoids ObjectMapper instantiation overhead.
        // Risk: Manual JSON escaping in escape() may miss edge cases. However, claim
        // names come from JAAS config keys (alphanumeric) and values are
        // user-controlled strings.
        String headerJson = "{" + claimOrHeaderJsonText("alg", "none") + "}";
        String lifetimeSecondsValueToUse = optionValue(LIFETIME_SECONDS_OPTION, DEFAULT_LIFETIME_SECONDS_ONE_HOUR);
        String claimsJson;
        try {
            claimsJson = String.format("{%s,%s%s}", expClaimText(Long.parseLong(lifetimeSecondsValueToUse)),
                    claimOrHeaderJsonText("iat", time.milliseconds() / 1000.0),
                    commaPrependedStringNumberAndListClaimsJsonText());
        } catch (NumberFormatException e) {
            throw new OAuthBearerConfigException(e.getMessage());
        }
        try {
            Encoder urlEncoderNoPadding = Base64.getUrlEncoder().withoutPadding();
            // SECURITY: SEC-OAUTH-142 (CRITICAL) Constructs an unsigned JWS:
            // Why: Unsecured token handling has ZERO cryptographic protection
            // and must never be used in production.
            // Base64URL(header).Base64URL(claims).(empty signature). The header
            // is always {"alg":"none"}. The claims contain iat, exp, and all custom
            // claims from JAAS options. No cryptographic signing occurs. The
            // resulting token is a valid JWT compact serialization that any JWT
            // parser can decode — an attacker can trivially read all claims.
            // Exploit: CRITICAL — unsecured JWS tokens have no signature;
            // any attacker can forge tokens with arbitrary claims.
            // Improvement: Add a runtime guard that prevents unsecured login
            // handlers from being used outside development environments.
            OAuthBearerUnsecuredJws jws = new OAuthBearerUnsecuredJws(
                    String.format("%s.%s.",
                            urlEncoderNoPadding.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)),
                            urlEncoderNoPadding.encodeToString(claimsJson.getBytes(StandardCharsets.UTF_8))),
                    principalClaimName, scopeClaimName);
            log.info("Retrieved token with principal {}", jws.principalName());
            callback.token(jws);
        } catch (OAuthBearerIllegalTokenException e) {
            // occurs if the principal claim doesn't exist or has an empty value
            throw new OAuthBearerConfigException(e.getMessage(), e);
        }
    }

    // SECURITY: SEC-OAUTH-143 (MEDIUM) SASL extensions are sourced from JAAS options prefixed with
    // Why: Unsecured token handling has ZERO cryptographic protection
    // and must never be used in production.
    // unsecuredLoginExtension_. Extensions are validated via
    // OAuthBearerClientInitialResponse.validateExtensions() which checks key/value
    // regex patterns and rejects the reserved "auth" key. However, extension VALUES
    // can contain any printable ASCII content that passes the regex.
    // Exploit: A malicious JAAS config can inject extensions that downstream consumers
    // (custom authorizers, audit systems) may process unsafely — e.g., log injection.
    // Improvement: Sanitize extension values or restrict to a strict allowlist pattern.
    /**
     *  Add and validate all the configured extensions.
     *  Token keys, apart from passing regex validation, must not be equal to the reserved key {@link OAuthBearerClientInitialResponse#AUTH_KEY}
     */
    private void handleExtensionsCallback(SaslExtensionsCallback callback) {
        Map<String, String> extensions = new HashMap<>();
        for (Map.Entry<String, String> configEntry : this.moduleOptions.entrySet()) {
            String key = configEntry.getKey();
            if (!key.startsWith(EXTENSION_PREFIX))
                continue;

            extensions.put(key.substring(EXTENSION_PREFIX.length()), configEntry.getValue());
        }

        SaslExtensions saslExtensions = new SaslExtensions(extensions);
        try {
            OAuthBearerClientInitialResponse.validateExtensions(saslExtensions);
        } catch (SaslException e) {
            throw new ConfigException(e.getMessage());
        }

        callback.extensions(saslExtensions);
    }

    // COMPLEXITY: 18 lines — Iterates all moduleOptions keys, matching against three
    // prefixes (STRING_CLAIM_PREFIX, NUMBER_CLAIM_PREFIX, LIST_CLAIM_PREFIX). Each
    // matching key strips the prefix, validates it is not a reserved claim, retrieves
    // the value, and appends comma-prepended JSON text. Number claims are parsed as
    // Double. List claims delegate to listJsonText() for delimiter-aware array
    // construction.
    private String commaPrependedStringNumberAndListClaimsJsonText() throws OAuthBearerConfigException {
        StringBuilder sb = new StringBuilder();
        for (String key : moduleOptions.keySet()) {
            if (key.startsWith(STRING_CLAIM_PREFIX) && key.length() > STRING_CLAIM_PREFIX.length())
                sb.append(',').append(claimOrHeaderJsonText(
                        confirmNotReservedClaimName(key.substring(STRING_CLAIM_PREFIX.length())), optionValue(key)));
            else if (key.startsWith(NUMBER_CLAIM_PREFIX) && key.length() > NUMBER_CLAIM_PREFIX.length())
                sb.append(',')
                        .append(claimOrHeaderJsonText(
                                confirmNotReservedClaimName(key.substring(NUMBER_CLAIM_PREFIX.length())),
                                Double.valueOf(optionValue(key))));
            else if (key.startsWith(LIST_CLAIM_PREFIX) && key.length() > LIST_CLAIM_PREFIX.length())
                sb.append(',')
                        .append(claimOrHeaderJsonArrayText(
                                confirmNotReservedClaimName(key.substring(LIST_CLAIM_PREFIX.length())),
                                listJsonText(optionValue(key))));
        }
        return sb.toString();
    }

    private String confirmNotReservedClaimName(String claimName) throws OAuthBearerConfigException {
        if (RESERVED_CLAIMS.contains(claimName))
            throw new OAuthBearerConfigException(String.format("Cannot explicitly set the '%s' claim", claimName));
        return claimName;
    }

    // COMPLEXITY: 32 lines — Delimiter-aware list parsing.
    // Structure: First character of value is the delimiter (e.g., "|" in
    // "|scope1|scope2"). Special regex characters (\\, ., [, (, {, |, ^, $) are
    // escaped with backslash for String.split(). Remaining text is split on the
    // delimiter, each element is quoted and escaped. Edge case handling: leading
    // delimiter, trailing delimiter, or consecutive delimiters produce empty string
    // elements appended as trailing "".
    private String listJsonText(String value) {
        if (value.length() <= 1)
            return "[]";
        String delimiter;
        String unescapedDelimiterChar = value.substring(0, 1);
        switch (unescapedDelimiterChar) {
            case "\\":
            case ".":
            case "[":
            case "(":
            case "{":
            case "|":
            case "^":
            case "$":
                delimiter = "\\" + unescapedDelimiterChar;
                break;
            default:
                delimiter = unescapedDelimiterChar;
                break;
        }
        String listText = value.substring(1);
        String[] elements = listText.split(delimiter);
        StringBuilder sb = new StringBuilder();
        for (String element : elements) {
            sb.append(sb.length() == 0 ? '[' : ',');
            sb.append('"').append(escape(element)).append('"');
        }
        if (listText.startsWith(unescapedDelimiterChar) || listText.endsWith(unescapedDelimiterChar)
                || listText.contains(unescapedDelimiterChar + unescapedDelimiterChar))
            sb.append(",\"\"");
        return sb.append(']').toString();
    }

    private String optionValue(String key) {
        return optionValue(key, null);
    }

    private String optionValue(String key, String defaultValue) {
        String explicitValue = option(key);
        return explicitValue != null ? explicitValue : defaultValue;
    }

    private String option(String key) {
        if (!configured)
            throw new IllegalStateException("Callback handler not configured");
        return moduleOptions.get(Objects.requireNonNull(key));
    }

    private String claimOrHeaderJsonText(String claimName, Number claimValue) {
        return QUOTE + escape(claimName) + QUOTE + ":" + claimValue;
    }

    private String claimOrHeaderJsonText(String claimName, String claimValue) {
        return QUOTE + escape(claimName) + QUOTE + ":" + QUOTE + escape(claimValue) + QUOTE;
    }

    private String claimOrHeaderJsonArrayText(String claimName, String escapedClaimValue) {
        if (!escapedClaimValue.startsWith("[") || !escapedClaimValue.endsWith("]"))
            throw new IllegalArgumentException(String.format("Illegal JSON array: %s", escapedClaimValue));
        return QUOTE + escape(claimName) + QUOTE + ":" + escapedClaimValue;
    }

    private String escape(String jsonStringValue) {
        String replace1 = DOUBLEQUOTE.matcher(jsonStringValue).replaceAll(Matcher.quoteReplacement("\\\""));
        return BACKSLASH.matcher(replace1).replaceAll(Matcher.quoteReplacement("\\\\"));
    }

    private String expClaimText(long lifetimeSeconds) {
        return claimOrHeaderJsonText("exp", time.milliseconds() / 1000.0 + lifetimeSeconds);
    }
}
