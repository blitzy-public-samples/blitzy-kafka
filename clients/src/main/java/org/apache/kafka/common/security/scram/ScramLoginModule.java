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
package org.apache.kafka.common.security.scram;

import org.apache.kafka.common.security.scram.internals.ScramSaslClientProvider;
import org.apache.kafka.common.security.scram.internals.ScramSaslServerProvider;

import java.util.Collections;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

// SECURITY: (MEDIUM) JAAS LoginModule for SCRAM authentication (SCRAM-SHA-256 and SCRAM-SHA-512).
// Why: This module registers JCA security providers and injects credentials into the JAAS Subject.
// Credentials (username/password) are extracted from JAAS config options and stored in Subject
// public/private credential sets -- these remain in memory for the JVM lifetime unless explicitly cleared.
// Exploit: If an attacker gains access to the JAAS configuration (e.g., via dynamic config injection
// or file system access), they can set arbitrary username/password values. Additionally, the password
// stored via subject.getPrivateCredentials().add(password) is a plain String -- Strings are interned
// by the JVM and cannot be reliably zeroed from memory, making them vulnerable to heap dump extraction.
// Improvement: Consider using char[] instead of String for password handling to enable explicit
// zeroing after use. Validate that provider registration order matches expected SCRAM variants.
//
// CROSS-CUTTING: Depends on scram/internals/ScramSaslClientProvider and
// scram/internals/ScramSaslServerProvider for JCA provider registration.
// Contract: Provider registration MUST occur before any SASL negotiation.
// Depended on by: authenticator/LoginManager (creates LoginContext using this module),
// JaasContext (validates this module via allowlist/denylist check).
// Impact: If this class is not on the classpath or fails to load, SCRAM-SHA-256
// and SCRAM-SHA-512 mechanisms will not be available for SASL authentication.
public class ScramLoginModule implements LoginModule {

    private static final String USERNAME_CONFIG = "username";
    private static final String PASSWORD_CONFIG = "password";
    // CROSS-CUTTING: This constant is referenced by ScramSaslClient (internals/) to detect
    // token auth mode, and by ScramServerCallbackHandler (internals/) to dispatch between
    // regular SCRAM credentials and delegation token credentials.
    // Also referenced by: token/delegation/ package for DelegationToken authentication flow.
    public static final String TOKEN_AUTH_CONFIG = "tokenauth";

    // DECISION: Provider registration in static initializer rather than in initialize() method.
    // Alternatives: (1) Register in initialize() on first call, (2) Register via explicit
    // ScramSaslClientProvider.initialize()/ScramSaslServerProvider.initialize() calls from
    // broker startup. Rationale: Static initialization ensures providers are available as
    // soon as the class is loaded by JAAS, before any SASL negotiation begins. This avoids
    // race conditions where a SASL mechanism is requested before providers are registered.
    //
    // SECURITY: (MEDIUM) Static provider registration -- both SCRAM client and server providers
    // are registered on class load. This is global JVM state. If provider registration order is
    // manipulated (e.g., a malicious provider with the same mechanism name registered earlier),
    // a weaker or compromised SCRAM implementation could be selected during SASL negotiation.
    // Exploit: Improper handling could be exploited to bypass security controls or leak sensitive information.
    // Improvement: Add comprehensive logging for security-relevant operations and enforce fail-closed semantics.
    static {
        ScramSaslClientProvider.initialize();
        ScramSaslServerProvider.initialize();
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        // SECURITY: (MEDIUM) Username extracted via unchecked cast from options Map. A ClassCastException
        // here would prevent authentication but is not handled gracefully. The username is added
        // to public credentials -- visible to any code with access to the Subject.
        // Exploit: Unauthorized access to the credential cache could expose authentication material.
        // Improvement: Limit cache access to authenticated callers and consider cache entry encryption at rest.
        String username = (String) options.get(USERNAME_CONFIG);
        if (username != null)
            subject.getPublicCredentials().add(username);
        // SECURITY: (MEDIUM) Password added to Subject's private credentials as a String.
        // Strings are immutable and may be interned by the JVM, making them difficult to
        // erase from memory. A heap dump or memory scanner could extract the plaintext password.
        // Exploit: An attacker on the network can intercept all data including credentials in transit.
        // Improvement: Use TLS-encrypted transports (SSL or SASL_SSL) in production environments.
        String password = (String) options.get(PASSWORD_CONFIG);
        if (password != null)
            subject.getPrivateCredentials().add(password);

        // SECURITY: (LOW) Token authentication flag -- when tokenauth=true, a SCRAM extensions
        // map is injected into public credentials. This signals ScramSaslClient to include
        // the tokenauth extension in the client-first message, triggering delegation token
        // credential lookup on the server side instead of regular SCRAM credentials.
        // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
        // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
        boolean useTokenAuthentication = "true".equalsIgnoreCase((String) options.get(TOKEN_AUTH_CONFIG));
        if (useTokenAuthentication) {
            Map<String, String> scramExtensions = Collections.singletonMap(TOKEN_AUTH_CONFIG, "true");
            subject.getPublicCredentials().add(scramExtensions);
        }
    }

    // DECISION: login(), commit(), logout() return true (no-op), abort() returns false.
    // Rationale: All credential setup happens in initialize(). The LoginModule lifecycle
    // (login -> commit/abort -> logout) is not needed because SCRAM credentials are
    // managed externally by CredentialCache, not by this module's Subject lifecycle.
    // Returning true from logout() without clearing credentials is intentional -- credential
    // cleanup is the responsibility of the LoginManager/CredentialCache infrastructure.
    @Override
    public boolean login() {
        return true;
    }

    @Override
    public boolean logout() {
        return true;
    }

    @Override
    public boolean commit() {
        return true;
    }

    @Override
    public boolean abort() {
        return false;
    }
}
