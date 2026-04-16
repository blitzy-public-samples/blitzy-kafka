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

import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.utils.Utils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_ID;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_SECRET;

// SECURITY: SEC-OAUTH-083 (MEDIUM) Formats client_credentials grant request body and Basic Authorization header.
// Why: Client secret is included in both the request body parameters and the Basic Authorization
// header (Base64-encoded clientId:clientSecret). These credentials must be transmitted over HTTPS.
// Exploit: (1) If the token endpoint URL uses HTTP instead of HTTPS, the client secret is sent
// in cleartext. (2) The Basic Authorization header uses non-URL-safe Base64 (per RFC 7617) --
// a misconfigured proxy that logs Authorization headers would capture the encoded credentials.
// (3) The client secret is held in a String field which cannot be zeroed -- it persists in
// memory until garbage collected, vulnerable to heap dump extraction.
// Improvement: Use char[] instead of String for clientSecret to enable explicit zeroing.
// Log a WARNING if the token endpoint URL protocol is not HTTPS.

// CROSS-CUTTING: Implements HttpRequestFormatter interface -- used by HttpJwtRetriever to
// format the HTTP request to the token endpoint. Created by ClientCredentialsJwtRetriever
// during configure(). The formatted request body and headers are passed to
// HttpJwtRetriever.post().
// Depends on: SaslConfigs (config key names), Utils (blank checking, UTF-8 encoding).
// Impact: Changes to header formatting or body encoding affect all client_credentials
// OAuth flows.
public class ClientCredentialsRequestFormatter implements HttpRequestFormatter {

    // DECISION: Static constant for "client_credentials" grant type. Ensures consistency
    // and enables grep/search across the codebase for this OAuth flow.
    public static final String GRANT_TYPE = "client_credentials";

    private final String clientId;

    private final String clientSecret;

    private final String scope;

    // DECISION: URL-encoding is configurable via the urlencode constructor parameter
    // rather than always applied. Alternative: Always URL-encode per RFC 6749 spec.
    // Rationale: Some OAuth providers may not correctly decode URL-encoded credentials
    // in the Basic header. The flag allows backward compatibility. In practice, urlencode
    // should always be true for spec compliance.
    // Risk: Setting urlencode=false violates RFC 6749 Section 2.3.1.
    public ClientCredentialsRequestFormatter(String clientId, String clientSecret, String scope, boolean urlencode) {
        if (Utils.isBlank(clientId))
            throw new ConfigException(SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_ID, clientId);

        if (Utils.isBlank(clientSecret))
            throw new ConfigException(SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_SECRET, clientId);

        clientId = clientId.trim();
        clientSecret = clientSecret.trim();
        scope = Utils.isBlank(scope) ? null : scope.trim();

        // SECURITY: SEC-OAUTH-084 (LOW) URL-encoding of clientId, clientSecret, and scope per
        // Why: Request formatting handles client secrets that must be
        // protected during transmission to the token endpoint.
        // RFC 6749 Section 2.3.1. This prevents injection of additional form parameters
        // via special characters in credentials. Without URL encoding, a clientId
        // containing "&scope=admin" could inject an admin scope.
        // according to RFC-6749 clientId & clientSecret must be urlencoded, see https://tools.ietf.org/html/rfc6749#section-2.3.1
        // Exploit: Client secret exposure in the HTTP request body could
        // occur if TLS is not enforced or if request logging is enabled.
        // Improvement: Clear client secret from memory immediately after
        // formatting the request to minimize secret exposure window.
        if (urlencode) {
            clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
            clientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

            if (scope != null)
                scope = URLEncoder.encode(scope, StandardCharsets.UTF_8);
        }

        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scope = scope;
    }

    @Override
    public Map<String, String> formatHeaders() {
        String s = String.format("%s:%s", clientId, clientSecret);
        // SECURITY: SEC-OAUTH-085 (MEDIUM) Per RFC 7617 / KAFKA-14496, uses non-URL-safe Base64
        // Why: Request formatting handles client secrets that must be
        // protected during transmission to the token endpoint.
        // encoder for the Basic Authorization header. The clientId:clientSecret string
        // is UTF-8 encoded then Base64 encoded. Note: Base64.getEncoder() (not
        // getUrlEncoder()) is used intentionally. The encoded string is prefixed with
        // "Basic " per HTTP Basic authentication standard.
        // Per RFC-7617, we need to use the *non-URL safe* base64 encoder. See KAFKA-14496.
        // Exploit: Malformed serialized data could trigger parsing exceptions or inject unexpected values.
        // Improvement: Apply strict input validation with size bounds and character allowlists before deserialization.
        String encoded = Base64.getEncoder().encodeToString(Utils.utf8(s));
        String authorizationHeader = String.format("Basic %s", encoded);

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Authorization", authorizationHeader);
        headers.put("Cache-Control", "no-cache");
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        return headers;
    }

    @Override
    public String formatBody() {
        StringBuilder requestParameters = new StringBuilder();
        requestParameters.append("grant_type=").append(GRANT_TYPE);

        if (scope != null)
            requestParameters.append("&scope=").append(scope);

        return requestParameters.toString();
    }
}
