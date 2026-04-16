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
package org.apache.kafka.common.security.oauthbearer.internals.unsecured;

import org.apache.kafka.common.KafkaException;

import java.util.Objects;

/**
 * Exception thrown when token validation fails due to a problem with the token
 * itself (as opposed to a missing remote resource or a configuration problem)
 */
// DECISION: Wraps OAuthBearerValidationResult as the exception's reason — enables
// programmatic access to validation failure details (description, scope, openid config).
// Alternative: Standard exception with String message only. Rationale: Carrying the
// full OAuthBearerValidationResult allows catch-site code (e.g.,
// OAuthBearerUnsecuredValidatorCallbackHandler) to extract failureScope and
// failureOpenIdConfig for constructing the SASL error response with appropriate
// "insufficient_scope" or "invalid_token" error codes per RFC 7628.
// CROSS-CUTTING: Thrown by OAuthBearerUnsecuredJws constructor on structural/claim
// violations (malformed compact serialization, wrong alg, non-empty signature, missing
// principal, missing expiration). Thrown by OAuthBearerValidationResult.throwExceptionIfFailed()
// when a validation check fails. Caught by OAuthBearerUnsecuredValidatorCallbackHandler
// in handle() to extract failureScope and failureOpenIdConfig for SASL error response.
// Caught by OAuthBearerUnsecuredLoginCallbackHandler to wrap as OAuthBearerConfigException.
// Depends on: OAuthBearerValidationResult (reason field), KafkaException (superclass).
// Contract: Always carries a non-null OAuthBearerValidationResult indicating failure.
// Impact: The reason() accessor is the primary mechanism for error classification in
// SASL OAUTHBEARER exchanges — determines "invalid_token" vs "insufficient_scope".
public class OAuthBearerIllegalTokenException extends KafkaException {
    private static final long serialVersionUID = -5275276640051316350L;
    private final OAuthBearerValidationResult reason;

    /**
     * Constructor
     * 
     * @param reason
     *            the mandatory reason for the validation failure; it must indicate
     *            failure
     */
    // DECISION: Constructor enforces non-null, failure-only result via Objects.requireNonNull()
    // and an explicit success check that throws IllegalArgumentException. Alternative: Accept
    // any result and let callers check. Rationale: Fail-fast constructor prevents misuse —
    // an exception wrapping a "success" result would be semantically contradictory and could
    // mask bugs in validation logic. The message is derived from reason.failureDescription().
    public OAuthBearerIllegalTokenException(OAuthBearerValidationResult reason) {
        super(Objects.requireNonNull(reason).failureDescription());
        if (reason.success())
            throw new IllegalArgumentException("The reason indicates success; it must instead indicate failure");
        this.reason = reason;
    }

    /**
     * Return the (always non-null) reason for the validation failure
     * 
     * @return the reason for the validation failure
     */
    public OAuthBearerValidationResult reason() {
        return reason;
    }
}
