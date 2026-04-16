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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

// SECURITY: SEC-KERB-010 (MEDIUM) Parses Kerberos principal names (user@REALM, user/host@REALM) into components.
// Why: Kerberos name parsing and auth_to_local mapping determine
// the authenticated principal identity.
// Malformed principals could cause incorrect identity mapping downstream in KerberosShortNamer.
// Exploit: A crafted principal with embedded special characters could manipulate the NAME_PARSER
// regex, producing an incorrect serviceName that maps to a different user's identity
// in the auth_to_local rules, potentially granting elevated privileges.
// Improvement: Strict validation of principal components against allowed character sets per RFC 4120
// (Section 5.2.1 — principal names should contain only alphanumeric, '.', '-', '_' characters).
// DECISION: Regex-based parsing (NAME_PARSER) vs structured tokenizer.
// Rationale: Regex is concise for the three Kerberos principal forms (bare, service@REALM,
// service/host@REALM). Alternative: recursive descent parser — rejected for simplicity.
// CROSS-CUTTING: Used by DefaultKafkaPrincipalBuilder (authenticator/) for GSSAPI principal
// resolution, and by KerberosShortNamer for auth_to_local rule application.
public class KerberosName {

    /**
     * A pattern that matches a Kerberos name with at most 3 components.
     */
    // SECURITY: SEC-KERB-011 (LOW) NAME_PARSER regex uses [^/@]* which accepts any characters except '/' and '@'.
    // Why: Kerberos name parsing and auth_to_local mapping determine
    // the authenticated principal identity.
    // This means principal components can contain spaces, control characters, or other unexpected chars.
    // Risk: Unusual characters in serviceName could confuse downstream authorization systems.
    // Exploit: A misconfigured auth_to_local rule could map an attacker principal to a privileged local identity.
    // Improvement: Audit auth_to_local rules regularly and use strict realm-based principal validation.
    private static final Pattern NAME_PARSER = Pattern.compile("([^/@]*)(/([^/@]*))?@([^/@]*)");

    /** The first component of the name */
    private final String serviceName;
    /** The second component of the name. It may be null. */
    private final String hostName;
    /** The realm of the name. */
    private final String realm;

    /**
     * Creates an instance of `KerberosName` with the provided parameters.
     */
    public KerberosName(String serviceName, String hostName, String realm) {
        if (serviceName == null)
            throw new IllegalArgumentException("serviceName must not be null");
        this.serviceName = serviceName;
        this.hostName = hostName;
        this.realm = realm;
    }

    // DECISION: parse() handles three principal forms: (1) service/host@REALM (full match against
    // NAME_PARSER), (2) bare name without '@' (fallback to simple name with null host/realm),
    // (3) malformed with '@' but not matching pattern (throws IllegalArgumentException).
    // This three-way classification ensures deterministic parsing with fail-fast on ambiguous input.
    /**
     * Create a name from the full Kerberos principal name.
     */
    public static KerberosName parse(String principalName) {
        Matcher match = NAME_PARSER.matcher(principalName);
        if (!match.matches()) {
            if (principalName.contains("@")) {
                throw new IllegalArgumentException("Malformed Kerberos name: " + principalName);
            } else {
                return new KerberosName(principalName, null, null);
            }
        } else {
            return new KerberosName(match.group(1), match.group(3), match.group(4));
        }
    }

    /**
     * Put the name back together from the parts.
     */
    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append(serviceName);
        if (hostName != null) {
            result.append('/');
            result.append(hostName);
        }
        if (realm != null) {
            result.append('@');
            result.append(realm);
        }
        return result.toString();
    }

    /**
     * Get the first component of the name.
     * @return the first section of the Kerberos principal name
     */
    public String serviceName() {
        return serviceName;
    }

    /**
     * Get the second component of the name.
     * @return the second section of the Kerberos principal name, and may be null
     */
    public String hostName() {
        return hostName;
    }

    /**
     * Get the realm of the name.
     * @return the realm of the name, may be null
     */
    public String realm() {
        return realm;
    }

}
