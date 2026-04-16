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

/**
 * Constants for JAAS configuration across the Kafka security package.
 *
 * @implNote DECISION: Constants centralized in a non-instantiable utility class
 * rather than distributed across JaasConfig and JaasContext. Alternative: Define
 * constants in their respective consuming classes. Rationale: These system property
 * names are used by both JaasConfig (for parsing) and JaasContext (for validation),
 * and may be referenced by operators configuring JVM args -- a single location makes
 * them discoverable and prevents drift between consumers.
 */
// CROSS-CUTTING: Constants consumed by JaasConfig (parsing), JaasContext
// (validation/loading), KerberosLogin (service name), and indirectly by
// all SASL mechanism implementations. Also referenced by operators setting
// JVM system properties (-Djava.security.auth.login.config, etc.).
// Impact: Changing any constant name here breaks system property contracts
// with existing deployment scripts and documentation.
public final class JaasUtils {
    // SECURITY: (MEDIUM) Points to the system-wide JAAS configuration file.
    // If this file is writable by unauthorized users, any login module can
    // be injected. Improvement: Document that this file should have restrictive
    // file permissions (e.g., 600) in production deployments.
    // Exploit: A malformed JAAS configuration could disable authentication or load a malicious login module.
    public static final String JAVA_LOGIN_CONFIG_PARAM = "java.security.auth.login.config";
    // SECURITY: (HIGH) Deprecated denylist approach -- dangerous because it
    // only blocks known-bad modules, allowing unknown/new dangerous modules
    // through. The allowlist (ALLOWED_LOGIN_MODULES_CONFIG) is preferred.
    // Exploit: Accepting unapproved values could expand the attack surface beyond intended boundaries.
    // Improvement: Maintain strict allowlists and log rejected values for security monitoring.
    @Deprecated(since = "4.2")
    public static final String DISALLOWED_LOGIN_MODULES_CONFIG = "org.apache.kafka.disallowed.login.modules";
    // SECURITY: (HIGH) Allowlist system property for login modules.
    // When set, ONLY listed modules can be loaded -- defense-in-depth
    // against arbitrary class loading via JAAS config injection.
    // Improvement: Consider making the allowlist a broker config
    // (not just system property) for easier management.
    // Exploit: A malformed JAAS configuration could disable authentication or load a malicious login module.
    public static final String ALLOWED_LOGIN_MODULES_CONFIG = "org.apache.kafka.allowed.login.modules";
    // SECURITY: (HIGH) Default denylist blocks JndiLoginModule and
    // LdapLoginModule which are known JNDI injection vectors (CVE-2023-25194).
    // These modules allow LDAP/RMI URL injection leading to remote code
    // execution. The denylist is not exhaustive -- other dangerous modules
    // may exist on the classpath. Prefer allowlist approach.
    // Exploit: A malformed JAAS configuration could disable authentication or load a malicious login module.
    // Improvement: Validate JAAS configurations at startup and restrict login module classes to an allowlist.
    @Deprecated(since = "4.2")
    public static final String DISALLOWED_LOGIN_MODULES_DEFAULT =
            "com.sun.security.auth.module.JndiLoginModule,com.sun.security.auth.module.LdapLoginModule";
    // DECISION: Kerberos service name key shared between JAAS config options
    // and SaslConfigs. Used by KerberosLogin to extract the service principal
    // component. Kept here rather than in kerberos/ package because it appears
    // in JAAS config entries which are parsed at this package level.
    public static final String SERVICE_NAME = "serviceName";

    private JaasUtils() {}

}
