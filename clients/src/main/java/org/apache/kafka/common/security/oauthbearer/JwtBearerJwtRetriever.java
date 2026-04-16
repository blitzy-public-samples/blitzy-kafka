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

package org.apache.kafka.common.security.oauthbearer;

import org.apache.kafka.common.security.oauthbearer.internals.secured.ConfigurationUtils;
import org.apache.kafka.common.security.oauthbearer.internals.secured.HttpJwtRetriever;
import org.apache.kafka.common.security.oauthbearer.internals.secured.HttpRequestFormatter;
import org.apache.kafka.common.security.oauthbearer.internals.secured.JwtBearerRequestFormatter;
import org.apache.kafka.common.security.oauthbearer.internals.secured.assertion.AssertionCreator;
import org.apache.kafka.common.security.oauthbearer.internals.secured.assertion.AssertionJwtTemplate;
import org.apache.kafka.common.security.oauthbearer.internals.secured.assertion.DefaultAssertionCreator;
import org.apache.kafka.common.security.oauthbearer.internals.secured.assertion.FileAssertionCreator;
import org.apache.kafka.common.security.oauthbearer.internals.secured.assertion.StaticAssertionJwtTemplate;
import org.apache.kafka.common.utils.Time;
import org.apache.kafka.common.utils.Utils;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import javax.security.auth.login.AppConfigurationEntry;

import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_ALGORITHM;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_FILE;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_PRIVATE_KEY_FILE;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_PRIVATE_KEY_PASSPHRASE;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_SCOPE;
import static org.apache.kafka.common.security.oauthbearer.internals.secured.assertion.AssertionUtils.layeredAssertionJwtTemplate;

/**
 * {@code JwtBearerJwtRetriever} is a {@link JwtRetriever} that performs the steps to request
 * a JWT from an OAuth/OIDC identity provider using the <code>urn:ietf:params:oauth:grant-type:jwt-bearer</code>
 * grant type. This grant type is used for machine-to-machine "service accounts".
 *
 * <p/>
 *
 * This {@code JwtRetriever} is enabled by specifying its class name in the Kafka configuration.
 * For client use, specify the class name in the <code>sasl.oauthbearer.jwt.retriever.class</code>
 * configuration like so:
 *
 * <pre>
 * sasl.oauthbearer.jwt.retriever.class=org.apache.kafka.common.security.oauthbearer.JwtBearerJwtRetriever
 * </pre>
 *
 * <p/>
 *
 * If using this {@code JwtRetriever} on the broker side (for inter-broker communication), the configuration
 * should be specified with a listener-based property:
 *
 * <pre>
 * listener.name.&lt;listener name&gt;.oauthbearer.sasl.oauthbearer.jwt.retriever.class=org.apache.kafka.common.security.oauthbearer.JwtBearerJwtRetriever
 * </pre>
 *
 * <p/>
 *
 * The {@code JwtBearerJwtRetriever} also uses the following configuration:
 *
 * <ul>
 *     <li><code>sasl.oauthbearer.assertion.algorithm</code></li>
 *     <li><code>sasl.oauthbearer.assertion.claim.aud</code></li>
 *     <li><code>sasl.oauthbearer.assertion.claim.exp.seconds</code></li>
 *     <li><code>sasl.oauthbearer.assertion.claim.iss</code></li>
 *     <li><code>sasl.oauthbearer.assertion.claim.jti.include</code></li>
 *     <li><code>sasl.oauthbearer.assertion.claim.nbf.seconds</code></li>
 *     <li><code>sasl.oauthbearer.assertion.claim.sub</code></li>
 *     <li><code>sasl.oauthbearer.assertion.file</code></li>
 *     <li><code>sasl.oauthbearer.assertion.private.key.file</code></li>
 *     <li><code>sasl.oauthbearer.assertion.private.key.passphrase</code></li>
 *     <li><code>sasl.oauthbearer.assertion.template.file</code></li>
 *     <li><code>sasl.oauthbearer.jwt.retriever.class</code></li>
 *     <li><code>sasl.oauthbearer.scope</code></li>
 *     <li><code>sasl.oauthbearer.token.endpoint.url</code></li>
 * </ul>
 *
 * Please refer to the official Apache Kafka documentation for more information on these, and related, configuration.
 *
 * <p/>
 *
 * Here's an example of the JAAS configuration for a Kafka client:
 *
 * <pre>
 * sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required ;
 *
 * sasl.oauthbearer.assertion.algorithm=RS256
 * sasl.oauthbearer.assertion.claim.aud=my-application-audience
 * sasl.oauthbearer.assertion.claim.exp.seconds=600
 * sasl.oauthbearer.assertion.claim.iss=my-oauth-issuer
 * sasl.oauthbearer.assertion.claim.jti.include=true
 * sasl.oauthbearer.assertion.claim.nbf.seconds=120
 * sasl.oauthbearer.assertion.claim.sub=kafka-app-1234
 * sasl.oauthbearer.assertion.private.key.file=/path/to/private.key
 * sasl.oauthbearer.assertion.private.key.passphrase=$3cr3+
 * sasl.oauthbearer.assertion.template.file=/path/to/assertion-template.json
 * sasl.oauthbearer.jwt.retriever.class=org.apache.kafka.common.security.oauthbearer.JwtBearerJwtRetriever
 * sasl.oauthbearer.scope=my-application-scope
 * sasl.oauthbearer.token.endpoint.url=https://example.com/oauth2/v1/token
 * </pre>
 *
 * @implNote DECISION: Supports two assertion creation modes: (1) file-based (pre-signed JWT
 * read from disk) and (2) dynamic (sign JWT at runtime using private key). Alternative: Only
 * support dynamic signing. Rationale: File-based assertions enable integration with external
 * secret managers or CI/CD pipelines that pre-generate assertions. Dynamic signing is more
 * common but requires private key access. The mode is selected by presence of
 * SASL_OAUTHBEARER_ASSERTION_FILE config.
 */
// SECURITY: (HIGH) JWT bearer assertion grant flow
// (urn:ietf:params:oauth:grant-type:jwt-bearer).
// Why: This retriever creates signed JWT assertions using a private key, then exchanges
// them for access tokens at the OAuth provider's token endpoint. The private key is the
// root of trust — compromise of this key allows unlimited token generation.
// Exploit: Assertion tampering — if the assertion is not properly signed (e.g., if the
// private key file has weak permissions and is replaced by an attacker), forged assertions
// will be accepted by the OAuth provider, granting the attacker access tokens with the
// original service account's privileges. Private key passphrase brute-forcing is also a
// risk if the passphrase is weak.
// Improvement: Consider validating private key file permissions at configure() time
// (e.g., warn if group/world readable). Consider supporting HSM-backed keys via PKCS#11.
//
// CROSS-CUTTING: Depends on internals/secured/HttpJwtRetriever (HTTP transport),
// internals/secured/JwtBearerRequestFormatter (request formatting), internals/secured/
// assertion/* (AssertionCreator, AssertionJwtTemplate implementations),
// internals/secured/ConfigurationUtils (config resolution).
// Used by: DefaultJwtRetriever does NOT use this — it defaults to
// ClientCredentialsJwtRetriever. Users must explicitly configure
// sasl.oauthbearer.jwt.retriever.class to this class.
// External deps: Time (kafka common/utils).
public class JwtBearerJwtRetriever implements JwtRetriever {

    private final Time time;
    private HttpJwtRetriever delegate;
    private AssertionJwtTemplate assertionJwtTemplate;
    private AssertionCreator assertionCreator;

    // DECISION: Time abstraction injected via constructor for testability. Alternative:
    // Use System.currentTimeMillis() directly. Rationale: Enables deterministic testing
    // of time-dependent assertion claims (iat, exp, nbf) without wall-clock dependency.
    public JwtBearerJwtRetriever() {
        this(Time.SYSTEM);
    }

    public JwtBearerJwtRetriever(Time time) {
        this.time = time;
    }

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        ConfigurationUtils cu = new ConfigurationUtils(configs, saslMechanism);

        String scope = cu.validateString(SASL_OAUTHBEARER_SCOPE, false);

        if (cu.validateString(SASL_OAUTHBEARER_ASSERTION_FILE, false) != null) {
            // SECURITY: (MEDIUM) File-based assertion — reads a pre-signed JWT assertion
            // from a file. If the file is writable by unauthorized users, they could
            // replace the assertion with one granting elevated privileges. Ensure
            // assertion file has restrictive permissions (600).
            // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
            // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
            File assertionFile = cu.validateFile(SASL_OAUTHBEARER_ASSERTION_FILE);
            assertionCreator = new FileAssertionCreator(assertionFile);
            assertionJwtTemplate = new StaticAssertionJwtTemplate();
        } else {
            // SECURITY: (HIGH) Private key loaded from filesystem via
            // cu.validateFile(). The passphrase (if present) is retrieved via
            // cu.validatePassword() which uses the Password type for masking. However,
            // the actual key material is held in memory as a java.security.PrivateKey
            // object which cannot be reliably zeroed in Java. After configure(), the
            // key persists for the lifetime of the AssertionCreator.
            // Exploit: An attacker could exhaust server resources by sending oversized or excessive requests.
            // Improvement: Enforce strict per-connection resource limits and implement connection rate limiting.
            String algorithm = cu.validateString(SASL_OAUTHBEARER_ASSERTION_ALGORITHM);
            File privateKeyFile = cu.validateFile(SASL_OAUTHBEARER_ASSERTION_PRIVATE_KEY_FILE);
            Optional<String> passphrase = cu.containsKey(SASL_OAUTHBEARER_ASSERTION_PRIVATE_KEY_PASSPHRASE) ?
                Optional.of(cu.validatePassword(SASL_OAUTHBEARER_ASSERTION_PRIVATE_KEY_PASSPHRASE)) :
                Optional.empty();

            assertionCreator = new DefaultAssertionCreator(algorithm, privateKeyFile, passphrase);
            // DECISION: Uses layered template pattern (StaticAssertionJwtTemplate +
            // DynamicAssertionJwtTemplate + FileAssertionJwtTemplate) for assertion JWT
            // construction. Alternative: Single template class. Rationale: Layering
            // allows static config-driven claims to be overridden by dynamic claims
            // (iat, exp, jti) and optionally by file-based template claims, supporting
            // flexible deployment.
            assertionJwtTemplate = layeredAssertionJwtTemplate(cu, time);
        }

        // SECURITY: (HIGH) Assertion created on every retrieve() call via
        // assertionCreator.create(). Each assertion gets fresh iat/exp claims
        // (via Time.SYSTEM). If assertion creation fails, JwtRetrieverException is
        // thrown — the exception message should not contain key material.
        // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
        // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
        Supplier<String> assertionSupplier = () -> {
            try {
                return assertionCreator.create(assertionJwtTemplate);
            } catch (Exception e) {
                throw new JwtRetrieverException(e);
            }
        };

        HttpRequestFormatter requestFormatter = new JwtBearerRequestFormatter(scope, assertionSupplier);

        delegate = new HttpJwtRetriever(requestFormatter);
        delegate.configure(configs, saslMechanism, jaasConfigEntries);
    }

    @Override
    public String retrieve() throws JwtRetrieverException {
        if (delegate == null)
            throw new IllegalStateException("JWT retriever delegate is null; please call configure() first");

        return delegate.retrieve();
    }

    @Override
    public void close() throws IOException {
        Utils.closeQuietly(assertionCreator, "JWT assertion creator");
        Utils.closeQuietly(assertionJwtTemplate, "JWT assertion template");
        Utils.closeQuietly(delegate, "JWT retriever delegate");
    }
}
