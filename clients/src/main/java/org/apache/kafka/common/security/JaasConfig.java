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
package org.apache.kafka.common.security;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.SaslConfigs;

import java.io.IOException;
import java.io.StreamTokenizer;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;

/**
 * JAAS configuration parser that constructs a JAAS configuration object with a single
 * login context from the Kafka configuration option {@link SaslConfigs#SASL_JAAS_CONFIG}.
 * <p/>
 * JAAS configuration file format is described <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/tutorials/LoginConfigFile.html">here</a>.
 * The format of the property value is:
 * <pre>
 * {@code
 *   <loginModuleClass> <controlFlag> (<optionName>=<optionValue>)*;
 * }
 * </pre>
 *
 * @implSpec SECURITY: (MEDIUM) This class parses untrusted JAAS configuration strings
 * (from sasl.jaas.config) using java.io.StreamTokenizer, which has complex tokenization
 * rules. Malformed or crafted config strings could cause unexpected parsing behavior.
 * Exploit: An attacker with config write access could inject a malicious login module
 * class name by exploiting StreamTokenizer word-character rules (e.g., '$' for inner
 * classes of dangerous modules), potentially bypassing the post-parse allowlist check
 * in {@link JaasContext}. Improvement: Consider a pre-parse validation step that checks
 * the login module class name against an allowlist BEFORE constructing the
 * AppConfigurationEntry, and consider using a stricter parser with well-defined grammar.
 *
 * @implNote DECISION: Uses java.io.StreamTokenizer for JAAS config parsing rather than
 * a regex or hand-written parser. Alternatives: (1) Regex-based parser, (2) ANTLR/javacc
 * grammar, (3) Direct javax.security Configuration.getConfiguration(). Rationale:
 * StreamTokenizer naturally handles quoted strings, C-style comments, and whitespace
 * matching the JAAS file format spec. Tradeoff: reduced control over error messages and
 * tokenization edge cases compared to a hand-written parser.
 */
// CROSS-CUTTING: Instantiated by JaasContext.load() when dynamic SASL_JAAS_CONFIG is
// provided. The parsed AppConfigurationEntry[] is consumed by JAAS LoginContext for
// creating login module instances. Depends on: SaslConfigs (common/config) for config
// key definition. Depended on by: JaasContext (this package), which passes parsed
// entries to LoginManager -> AbstractLogin -> mechanism-specific LoginModules.
class JaasConfig extends Configuration {

    private final String loginContextName;
    private final List<AppConfigurationEntry> configEntries;

    public JaasConfig(String loginContextName, String jaasConfigParams) {
        // SECURITY: (MEDIUM) StreamTokenizer configured with slashSlash and slashStar comments
        // enabled — comment sequences (//, /* */) inside JAAS config values will be
        // silently consumed, potentially hiding injected content from human review.
        // Characters '-', '_', '$' are added as word chars to support Java class names
        // with inner classes and hyphens in option keys.
        // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
        // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
        StreamTokenizer tokenizer = new StreamTokenizer(new StringReader(jaasConfigParams));
        tokenizer.slashSlashComments(true);
        tokenizer.slashStarComments(true);
        tokenizer.wordChars('-', '-');
        tokenizer.wordChars('_', '_');
        tokenizer.wordChars('$', '$');

        try {
            // DECISION: Mutable ArrayList during parsing, exposed as array via
            // getAppConfigurationEntry(). Multiple login modules per context are
            // supported (semicolon-separated) matching standard JAAS file format.
            configEntries = new ArrayList<>();
            while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
                configEntries.add(parseAppConfigurationEntry(tokenizer));
            }
            if (configEntries.isEmpty())
                throw new IllegalArgumentException("Login module not specified in JAAS config");

            this.loginContextName = loginContextName;

        } catch (IOException e) {
            throw new KafkaException("Unexpected exception while parsing JAAS config");
        }
    }

    // DECISION: Returns null (not empty array) when name doesn't match, per
    // javax.security.auth.login.Configuration contract. Callers must handle null
    // return — this is a JAAS framework requirement, not a design choice.
    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        if (this.loginContextName.equals(name))
            return configEntries.toArray(new AppConfigurationEntry[0]);
        else
            return  null;
    }

    // DECISION: Case-insensitive control flag matching using Locale.ROOT (not default
    // locale). Alternative: Exact case match per JAAS spec. Rationale: Lenient parsing
    // reduces misconfiguration errors; JAAS spec allows case-insensitive matching.
    // Uses Locale.ROOT to avoid the Turkish-I locale-sensitivity problem.
    private LoginModuleControlFlag loginModuleControlFlag(String flag) {
        if (flag == null)
            throw new IllegalArgumentException("Login module control flag is not available in the JAAS config");

        LoginModuleControlFlag controlFlag;
        switch (flag.toUpperCase(Locale.ROOT)) {
            case "REQUIRED":
                controlFlag = LoginModuleControlFlag.REQUIRED;
                break;
            case "REQUISITE":
                controlFlag = LoginModuleControlFlag.REQUISITE;
                break;
            case "SUFFICIENT":
                controlFlag = LoginModuleControlFlag.SUFFICIENT;
                break;
            case "OPTIONAL":
                controlFlag = LoginModuleControlFlag.OPTIONAL;
                break;
            default:
                throw new IllegalArgumentException("Invalid login module control flag '" + flag + "' in JAAS config");
        }
        return controlFlag;
    }

    // SECURITY: (MEDIUM) Parses one login module entry from the token stream. The login
    // module class name (tokenizer.sval at entry) comes directly from the config string
    // without class-name validation — class loading is deferred to JAAS runtime. A crafted
    // class name could reference any class on the classpath. Post-parse validation occurs
    // in JaasContext.throwIfLoginModuleIsNotAllowed().
    //
    // COMPLEXITY: ~17 lines — Linear token consumption with 3 phases: (1) Read login
    // module class name (current token), (2) Read control flag (next token), (3) Loop
    // reading key=value pairs until ';' or EOF. Error paths: EOF before control flag,
    // missing '=' in options, EOF before option value, missing terminating ';'. All
    // errors throw IllegalArgumentException with descriptive messages.
    // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
    // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
    private AppConfigurationEntry parseAppConfigurationEntry(StreamTokenizer tokenizer) throws IOException {
        String loginModule = tokenizer.sval;
        if (tokenizer.nextToken() == StreamTokenizer.TT_EOF)
            throw new IllegalArgumentException("Login module control flag not specified in JAAS config");
        LoginModuleControlFlag controlFlag = loginModuleControlFlag(tokenizer.sval);
        Map<String, String> options = new HashMap<>();
        // SECURITY: (MEDIUM) Key=value option parsing. Option values are read as raw
        // StreamTokenizer tokens. Values containing special characters ('=', ';')
        // must be quoted per JAAS syntax. Unquoted values terminate at whitespace,
        // which could cause option value truncation if not properly quoted.
        // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
        // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
        while (tokenizer.nextToken() != StreamTokenizer.TT_EOF && tokenizer.ttype != ';') {
            String key = tokenizer.sval;
            if (tokenizer.nextToken() != '=' || tokenizer.nextToken() == StreamTokenizer.TT_EOF || tokenizer.sval == null)
                throw new IllegalArgumentException("Value not specified for key '" + key + "' in JAAS config");
            String value = tokenizer.sval;
            options.put(key, value);
        }
        if (tokenizer.ttype != ';')
            throw new IllegalArgumentException("JAAS config entry not terminated by semi-colon");
        return new AppConfigurationEntry(loginModule, controlFlag, options);
    }
}
