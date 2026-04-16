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
package org.apache.kafka.common.security.oauthbearer.internals.secured;


import org.apache.kafka.common.utils.Utils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

// SECURITY: SEC-OAUTH-104 (MEDIUM) Formats JWT bearer assertion grant request (RFC 7523 / urn:ietf:params:
// oauth:grant-type:jwt-bearer). The assertion value (a signed JWT) is included in the form body.
// Why: The assertion is a signed JWT that proves the client's identity — if intercepted, it can
// be replayed to obtain access tokens within its validity window (typically short, ~5 minutes).
// Exploit: If the token endpoint URL uses HTTP, the assertion JWT is sent in cleartext. An
// attacker capturing the assertion can replay it to the token endpoint to obtain access tokens.
// Unlike client_credentials, the assertion is a bearer credential — no additional secret needed.
// Improvement: Enforce HTTPS-only for jwt-bearer grant type. Add assertion nonce/jti tracking.

// CROSS-CUTTING: Implements HttpRequestFormatter — used by HttpJwtRetriever for the
// jwt-bearer grant flow. Created by JwtBearerJwtRetriever during configure(). The
// assertionSupplier wraps AssertionCreator.createAssertion() for on-demand JWT signing.
// Depends on: HttpRequestFormatter (interface contract), Utils (blank checking).
// Impact: Changes to body/header formatting affect all jwt-bearer OAuth authentication flows.
public class JwtBearerRequestFormatter implements HttpRequestFormatter {

    // DECISION: Uses the standard URN "urn:ietf:params:oauth:grant-type:jwt-bearer" per RFC 7523.
    // This is URL-encoded in formatBody() because it contains special characters (:).
    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private final String scope;
    // DECISION: Uses Supplier<String> for lazy assertion retrieval rather than a pre-computed
    // String. Rationale: The assertion JWT contains time-sensitive claims (iat, exp, jti) that
    // must be fresh at the time of each token request. A Supplier allows the AssertionCreator
    // to generate a new assertion with current timestamps on each formatBody() call.
    private final Supplier<String> assertionSupplier;

    public JwtBearerRequestFormatter(String scope, Supplier<String> assertionSupplier) {
        this.scope = scope;
        this.assertionSupplier = assertionSupplier;
    }

    @Override
    public String formatBody() {
        // SECURITY: SEC-OAUTH-105 (MEDIUM) The assertion is obtained from the assertionSupplier (Supplier<String>)
        // Why: OAuth token handling is a security dependency because
        // it controls authentication and authorization for connections.
        // at call time and URL-encoded before inclusion in the form body. URL encoding prevents body
        // parameter injection via crafted assertion values.
        // Exploit: Improper handling could be exploited to bypass security controls or leak sensitive information.
        // Improvement: Add comprehensive logging for security-relevant operations and enforce fail-closed semantics.
        String assertion = assertionSupplier.get();
        StringBuilder requestParameters = new StringBuilder();
        requestParameters.append("grant_type=").append(URLEncoder.encode(GRANT_TYPE, StandardCharsets.UTF_8));
        requestParameters.append("&assertion=").append(URLEncoder.encode(assertion, StandardCharsets.UTF_8));

        if (!Utils.isBlank(scope))
            requestParameters.append("&scope=").append(URLEncoder.encode(scope.trim(), StandardCharsets.UTF_8));

        return requestParameters.toString();
    }

    @Override
    public Map<String, String> formatHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Cache-Control", "no-cache");
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        return headers;
    }
}
