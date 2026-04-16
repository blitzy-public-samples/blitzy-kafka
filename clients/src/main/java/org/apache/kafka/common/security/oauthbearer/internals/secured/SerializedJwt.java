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

import org.apache.kafka.common.security.oauthbearer.JwtValidatorException;

/**
 * SerializedJwt provides a modicum of structure and validation around a JWT's serialized form by
 * splitting and making the three sections (header, payload, and signature) available to the user.
 */

// SECURITY: SEC-OAUTH-118 (MEDIUM) JWT structural parsing — splits compact serialization into header,
// payload, and signature sections at the "." delimiter.
// Why: This is the first parser to touch the raw JWT string. Malformed input is rejected
// here before reaching jose4j or any other validation logic.
// Exploit: (1) A JWT with extra dots (e.g., "a.b.c.d") passes the splits.length != 3 check
// and is rejected — correct. (2) A JWT with empty sections (e.g., "a..b") passes the split
// but validateSection() catches the empty section — correct. (3) String.split("\\.")
// discards trailing empty strings by default, so "a.b." would produce ["a","b"] (length 2)
// and be rejected — correct. However, "a.b.c " (trailing space in signature) is accepted
// after trim(). This is consistent with JWT compact serialization whitespace handling.
// Improvement: Consider using a strict regex that rejects any whitespace within sections,
// or validate Base64URL encoding of each section before accepting.

// CROSS-CUTTING: Used by CachedFile.STRING_JSON_VALIDATING_TRANSFORMER (JWT file validation),
// BrokerJwtValidator and ClientJwtValidator (JWT header extraction for algorithm detection).
// Depends on: JwtValidatorException (structural validation errors).
// Contract: Constructor validates and splits. Getters return immutable, trimmed sections.
// Impact: Structural validation changes affect all JWT parsing in the OAUTHBEARER stack.

public class SerializedJwt {

    private final String token;

    private final String header;

    private final String payload;

    private final String signature;

    // DECISION: Validates JWT structure eagerly in the constructor rather than lazily on access.
    // Alternative: Accept any string, validate on getHeader()/getPayload()/getSignature().
    // Rationale: Fail-fast — invalid JWTs are rejected immediately, preventing downstream code
    // from operating on malformed data. The token is immutable after construction.
    public SerializedJwt(String token) {
        // DECISION: Input token is trimmed before splitting, and each section is trimmed individually
        // by validateSection(). Alternative: Reject tokens with whitespace. Rationale: Whitespace
        // tolerance handles common copy-paste artifacts (trailing newline, leading space) without
        // weakening security, since Base64URL encoding doesn't use whitespace characters.
        if (token == null)
            token = "";
        else
            token = token.trim();

        if (token.isEmpty())
            throw new JwtValidatorException("Malformed JWT provided; expected three sections (header, payload, and signature)");

        // SECURITY: SEC-OAUTH-119 (MEDIUM) Exact 3-segment validation — rejects JWTs with wrong number of sections.
        // Why: JWT serialization parsing handles untrusted token strings
        // that could contain malformed or malicious content.
        // The dot delimiter is regex-escaped. Note: String.split("\\.") with no limit parameter
        // discards trailing empty strings — this means a token ending in "." would have fewer than
        // 3 segments and be rejected. This is the correct security behavior.
        // Exploit: A malformed serialized JWT with missing or extra dots could
        // bypass parsing validation and inject malicious claims.
        // Improvement: Add strict format validation for JWT structure
        // before attempting deserialization of the token parts.
        String[] splits = token.split("\\.");

        if (splits.length != 3)
            throw new JwtValidatorException("Malformed JWT provided; expected three sections (header, payload, and signature)");

        this.token = token.trim();
        this.header = validateSection(splits[0]);
        this.payload = validateSection(splits[1]);
        this.signature = validateSection(splits[2]);
    }

    /**
     * Returns the entire base 64-encoded JWT.
     *
     * @return JWT
     */

    public String getToken() {
        return token;
    }

    /**
     * Returns the first section--the JWT header--in its base 64-encoded form.
     *
     * @return Header section of the JWT
     */

    public String getHeader() {
        return header;
    }

    /**
     * Returns the second section--the JWT payload--in its base 64-encoded form.
     *
     * @return Payload section of the JWT
     */

    public String getPayload() {
        return payload;
    }

    /**
     * Returns the third section--the JWT signature--in its base 64-encoded form.
     *
     * @return Signature section of the JWT
     */

    public String getSignature() {
        return signature;
    }

    private String validateSection(String section) throws JwtValidatorException {
        section = section.trim();

        if (section.isEmpty())
            throw new JwtValidatorException("Malformed JWT provided; expected three sections (header, payload, and signature)");

        return section;
    }

}
