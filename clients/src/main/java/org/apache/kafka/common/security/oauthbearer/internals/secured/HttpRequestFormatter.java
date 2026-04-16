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

import java.util.Map;

// SECURITY: SEC-OAUTH-097 (MEDIUM) HTTP request formatting interface for OAuth token endpoint requests.
// Why: Implementations construct HTTP headers and body containing sensitive credentials
// (client secrets in Basic Authorization, assertions in form body). The formatted output
// is passed directly to HttpJwtRetriever.post() without additional sanitization.
// Exploit: A malicious implementation could inject additional headers (e.g., X-Forwarded-For)
// or form parameters into the request, potentially exploiting the token endpoint. Header
// injection is possible if implementations return header values containing CRLF sequences.
// Improvement: HttpJwtRetriever should sanitize header values by rejecting CRLF characters
// before passing them to HttpURLConnection.setRequestProperty().

// DECISION: Separate interface for request formatting rather than embedding in HttpJwtRetriever.
// Alternatives: (1) Inline formatting in retrieve(), (2) Abstract base class with template
// method. Rationale: Strategy pattern enables different OAuth grant types (client_credentials
// vs jwt-bearer) to share the same HTTP transport logic in HttpJwtRetriever while varying
// only the request format. New grant types can be added by implementing this interface.

// CROSS-CUTTING: Implemented by ClientCredentialsRequestFormatter (client_credentials grant)
// and JwtBearerRequestFormatter (jwt-bearer grant). Used by HttpJwtRetriever which calls
// formatHeaders() and formatBody() during token retrieval.
// Contract: formatHeaders() returns a fresh Map per call. formatBody() returns URL-encoded
// body string. Both methods must be callable multiple times (for retry scenarios).
public interface HttpRequestFormatter {

    Map<String, String> formatHeaders();

    String formatBody();
}
