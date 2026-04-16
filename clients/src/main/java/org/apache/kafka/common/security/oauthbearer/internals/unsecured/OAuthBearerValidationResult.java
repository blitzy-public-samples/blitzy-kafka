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

import java.io.Serializable;

/**
 * The result of some kind of token validation
 */
// DECISION: Immutable value object with static factory methods newSuccess()/newFailure()
// rather than a mutable builder or enum-based result. Alternative: (1) Java enum with
// SUCCESS/FAILURE constants, (2) Mutable result object with setters. Rationale: Static
// factory methods enforce invariants at creation time — success cannot carry scope/openid
// info (line 70-71), and failure always has a description. Immutability ensures results
// cannot be tampered with after creation. Implements Serializable for potential JAAS
// subject credential transport across JVM boundaries.
// CROSS-CUTTING: Used by OAuthBearerValidationUtils (return type for all validation
// methods), OAuthBearerIllegalTokenException (wraps this as the failure reason),
// OAuthBearerUnsecuredJws (creates failure instances for structural validation errors),
// OAuthBearerUnsecuredValidatorCallbackHandler (checks results via throwExceptionIfFailed
// and extracts failureScope/failureOpenIdConfig for SASL error responses).
// Also used by OAuthBearerSaslServer (indirectly via OAuthBearerIllegalTokenException.reason()
// to construct JSON error responses with scope and openid-configuration fields).
// Depends on: OAuthBearerIllegalTokenException (thrown by throwExceptionIfFailed()).
// Contract: Immutable after construction. newSuccess() returns a result where success()==true
// and all failure fields are null. newFailure() returns success()==false with description.
// Impact: This is the core validation result type for the entire unsecured OAUTHBEARER
// package. Changes to its fields or semantics ripple through all validation and error paths.
public class OAuthBearerValidationResult implements Serializable {
    private static final long serialVersionUID = 5774669940899777373L;
    private final boolean success;
    private final String failureDescription;
    private final String failureScope;
    private final String failureOpenIdConfig;

    /**
     * Return an instance indicating success
     * 
     * @return an instance indicating success
     */
    public static OAuthBearerValidationResult newSuccess() {
        return new OAuthBearerValidationResult(true, null, null, null);
    }

    /**
     * Return a new validation failure instance
     * 
     * @param failureDescription
     *            optional description of the failure
     * @return a new validation failure instance
     */
    public static OAuthBearerValidationResult newFailure(String failureDescription) {
        return newFailure(failureDescription, null, null);
    }

    /**
     * Return a new validation failure instance
     * 
     * @param failureDescription
     *            optional description of the failure
     * @param failureScope
     *            optional scope to be reported with the failure
     * @param failureOpenIdConfig
     *            optional OpenID Connect configuration to be reported with the
     *            failure
     * @return a new validation failure instance
     */
    public static OAuthBearerValidationResult newFailure(String failureDescription, String failureScope,
            String failureOpenIdConfig) {
        return new OAuthBearerValidationResult(false, failureDescription, failureScope, failureOpenIdConfig);
    }

    private OAuthBearerValidationResult(boolean success, String failureDescription, String failureScope,
            String failureOpenIdConfig) {
        // DECISION: Success and failure are mutually exclusive — enforced by the constructor
        // invariant (line 70-71). A successful result CANNOT carry failureScope or
        // failureOpenIdConfig. Alternative: Allow success with warnings/metadata.
        // Rationale: Binary success/failure aligns with SASL authentication semantics — a
        // token is either valid or invalid, with no intermediate states. Failure metadata
        // (scope, openid config) is used to construct RFC 7628 error responses.
        if (success && (failureScope != null || failureOpenIdConfig != null))
            throw new IllegalArgumentException("success was indicated but failure scope/OpenIdConfig were provided");
        this.success = success;
        this.failureDescription = failureDescription;
        this.failureScope = failureScope;
        this.failureOpenIdConfig = failureOpenIdConfig;
    }

    /**
     * Return true if this instance indicates success, otherwise false
     * 
     * @return true if this instance indicates success, otherwise false
     */
    public boolean success() {
        return success;
    }

    /**
     * Return the (potentially null) descriptive message for the failure
     * 
     * @return the (potentially null) descriptive message for the failure
     */
    public String failureDescription() {
        return failureDescription;
    }

    /**
     * Return the (potentially null) scope to be reported with the failure
     * 
     * @return the (potentially null) scope to be reported with the failure
     */
    public String failureScope() {
        return failureScope;
    }

    /**
     * Return the (potentially null) OpenID Connect configuration to be reported
     * with the failure
     * 
     * @return the (potentially null) OpenID Connect configuration to be reported
     *         with the failure
     */
    public String failureOpenIdConfig() {
        return failureOpenIdConfig;
    }

    /**
     * Raise an exception if this instance indicates failure, otherwise do nothing
     * 
     * @throws OAuthBearerIllegalTokenException
     *             if this instance indicates failure
     */
    // DECISION: Convenience method that bridges the result-based pattern to exception-based
    // control flow. Alternative: Force callers to check success() manually.
    // Rationale: Enables fluent chaining in OAuthBearerUnsecuredValidatorCallbackHandler:
    //   validateXxx(...).throwExceptionIfFailed()
    // This pattern keeps the validation logic (in OAuthBearerValidationUtils) decoupled from
    // the error handling policy (in the callback handler). Each validator call returns a
    // result; the handler decides to throw immediately via this method.
    public void throwExceptionIfFailed() throws OAuthBearerIllegalTokenException {
        if (!success())
            throw new OAuthBearerIllegalTokenException(this);
    }
}
