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

import org.apache.kafka.common.security.oauthbearer.JwtRetrieverException;
import org.apache.kafka.common.utils.Utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

// SECURITY: SEC-OAUTH-106 (MEDIUM) Parses JSON response from OAuth token endpoint to extract JWT.
// Why: The token endpoint response is untrusted network input. A compromised token endpoint
// could return malicious JSON payloads designed to exploit the JSON parser or downstream
// token consumers.
// Exploit: (1) Malformed JSON from a compromised endpoint could cause Jackson parsing errors
// (IOException), which are wrapped in JwtRetrieverException — no information leakage. (2) A
// response containing a very large JSON document could cause OOM during parsing — the response
// body size is only limited by HttpJwtRetriever's stream copy buffer. (3) A response where
// /access_token contains a non-JWT string could bypass downstream validation if validators
// assume well-formed JWT input.
// Improvement: Add response body size limit before JSON parsing. Validate that the extracted
// token has the expected JWT structure (3 dot-separated segments) before returning.

// CROSS-CUTTING: Used by HttpJwtRetriever.retrieve() to parse the token endpoint JSON response.
// Depends on: Jackson ObjectMapper (JSON parsing), JwtRetrieverException (error reporting).
// No state — can be instantiated per-call (as HttpJwtRetriever does at line 173).
// Impact: Changes to JSON path extraction affect all OAuth token retrieval flows.
public class JwtResponseParser {

    // DECISION: Checks /access_token first, then /id_token as fallback. Rationale: OAuth 2.0
    // token responses typically use access_token; OIDC may additionally include id_token.
    // The first non-blank match is returned — in the rare case both exist, access_token wins.
    private static final String[] JSON_PATHS = new String[] {"/access_token", "/id_token"};
    // SECURITY: SEC-OAUTH-107 (LOW) Truncates response body to 1000 chars in error messages to prevent log
    // Why: Response parsing handles untrusted data from the
    // authorization server's token endpoint.
    // flooding from large malicious responses. The full response body is still parsed by Jackson
    // (no size limit on parsing) — this only affects the error message snippet.
    // Exploit: An attacker could exhaust server resources by sending oversized or excessive requests.
    // Improvement: Enforce strict per-connection resource limits and implement connection rate limiting.
    private static final int MAX_RESPONSE_BODY_LENGTH = 1000;

    public String parseJwt(String responseBody) throws JwtRetrieverException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode;

        try {
            rootNode = mapper.readTree(responseBody);
        } catch (IOException e) {
            throw new JwtRetrieverException(e);
        }

        for (String jsonPath : JSON_PATHS) {
            JsonNode node = rootNode.at(jsonPath);

            if (node != null && !node.isMissingNode()) {
                String value = node.textValue();

                if (!Utils.isBlank(value)) {
                    return value.trim();
                }
            }
        }

        // Only grab the first N characters so that if the response body is huge, we don't blow up.
        String snippet = responseBody;

        if (snippet.length() > MAX_RESPONSE_BODY_LENGTH) {
            int actualLength = responseBody.length();
            String s = responseBody.substring(0, MAX_RESPONSE_BODY_LENGTH);
            snippet = String.format("%s (trimmed to first %d characters out of %d total)", s, MAX_RESPONSE_BODY_LENGTH, actualLength);
        }

        throw new JwtRetrieverException(String.format("The token endpoint response did not contain a valid JWT. Response: (%s)", snippet));
    }
}
