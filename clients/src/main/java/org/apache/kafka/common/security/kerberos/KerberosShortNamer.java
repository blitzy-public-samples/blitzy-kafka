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
package org.apache.kafka.common.security.kerberos;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class implements parsing and handling of Kerberos principal names. In
 * particular, it splits them apart and translates them down into local
 * operating system names.
 */
// SECURITY (MEDIUM): Applies auth_to_local rules (similar to Hadoop's) to map Kerberos principals
// to short names used for authorization. Rules are regex-based.
// Exploit: A malicious user with a carefully crafted Kerberos principal could exploit regex
// substitution rules to map their principal to an admin user's short name, gaining elevated privileges.
// Improvement: Disallow regex backreferences in replacement strings and log all principal-to-shortname
// mappings at INFO level for audit.
// CROSS-CUTTING: Consumed by DefaultKafkaPrincipalBuilder (authenticator/) for GSSAPI principal
// resolution. Changes to rule evaluation order affect all Kerberos-authenticated identities.
public class KerberosShortNamer {

    /**
     * A pattern for parsing a auth_to_local rule.
     */
    // DECISION: Uses a single complex regex to parse auth_to_local rules in the format
    // DEFAULT or RULE:[n:template](match)s/from/to/g/L|U. This follows Hadoop's auth_to_local
    // convention for compatibility with existing Kerberos infrastructure.
    // Alternative: Recursive descent parser -- rejected for simplicity and Hadoop compatibility.
    // Risk: Complex regex is hard to maintain; any parsing bug could silently mismap principals.
    private static final Pattern RULE_PARSER = Pattern.compile("((DEFAULT)|((RULE:\\[(\\d*):([^\\]]*)](\\(([^)]*)\\))?(s/([^/]*)/([^/]*)/(g)?)?/?(L|U)?)))");

    /* Rules for the translation of the principal name into an operating system name */
    private final List<KerberosRule> principalToLocalRules;

    public KerberosShortNamer(List<KerberosRule> principalToLocalRules) {
        this.principalToLocalRules = principalToLocalRules;
    }

    public static KerberosShortNamer fromUnparsedRules(String defaultRealm, List<String> principalToLocalRules) {
        List<String> rules = principalToLocalRules == null ? Collections.singletonList("DEFAULT") : principalToLocalRules;
        return new KerberosShortNamer(parseRules(defaultRealm, rules));
    }

    // SECURITY (MEDIUM): Parses user-configured auth_to_local rules into KerberosRule objects.
    // Rules containing regex patterns are compiled here. Malformed rules with catastrophic
    // backtracking patterns could cause ReDoS. Input validation is limited to regex match against
    // RULE_PARSER; the inner substitution regex (group 10/11) is not complexity-checked.
    // Improvement: Add regex complexity checks (e.g., reject nested quantifiers) on inner groups.
    private static List<KerberosRule> parseRules(String defaultRealm, List<String> rules) {
        List<KerberosRule> result = new ArrayList<>();
        for (String rule : rules) {
            Matcher matcher = RULE_PARSER.matcher(rule);
            if (!matcher.lookingAt()) {
                throw new IllegalArgumentException("Invalid rule: " + rule);
            }
            if (rule.length() != matcher.end())
                throw new IllegalArgumentException("Invalid rule: `" + rule + "`, unmatched substring: `" + rule.substring(matcher.end()) + "`");
            if (matcher.group(2) != null) {
                result.add(new KerberosRule(defaultRealm));
            } else {
                result.add(new KerberosRule(defaultRealm,
                        Integer.parseInt(matcher.group(5)),
                        matcher.group(6),
                        matcher.group(8),
                        matcher.group(10),
                        matcher.group(11),
                        "g".equals(matcher.group(12)),
                        "L".equals(matcher.group(13)),
                        "U".equals(matcher.group(13))));

            }
        }
        return result;
    }

    /**
     * Get the translation of the principal name into an operating system
     * user name.
     * @return the short name
     * @throws IOException
     */
    // SECURITY (MEDIUM): First-match-wins rule evaluation. If rules are misconfigured, an earlier
    // overly broad rule could match before a more specific restrictive rule, mapping unauthorized
    // principals to privileged short names. Always place DENY/restrictive rules before ALLOW rules.
    public String shortName(KerberosName kerberosName) throws IOException {
        String[] params;
        if (kerberosName.hostName() == null) {
            // DECISION: Fast-path for simple names (no realm, no host) -- returns serviceName directly
            // without applying any rules. This preserves identity for non-Kerberos principals.
            // if it is already simple, just return it
            if (kerberosName.realm() == null)
                return kerberosName.serviceName();
            params = new String[]{kerberosName.realm(), kerberosName.serviceName()};
        } else {
            params = new String[]{kerberosName.realm(), kerberosName.serviceName(), kerberosName.hostName()};
        }
        for (KerberosRule r : principalToLocalRules) {
            String result = r.apply(params);
            if (result != null)
                return result;
        }
        throw new NoMatchingRule("No rules apply to " + kerberosName + ", rules " + principalToLocalRules);
    }

    @Override
    public String toString() {
        return "KerberosShortNamer(principalToLocalRules = " + principalToLocalRules + ")";
    }

}
