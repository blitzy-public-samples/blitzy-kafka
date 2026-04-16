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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Simple utility class to perform basic cleaning and validation on input values so that they're
 * performed consistently throughout the code base.
 */

// SECURITY: (MEDIUM) Pure static validators for JWT claim values (scopes, expiration,
// subject, issuedAt, claim name overrides). These validators form the first line of defense
// against malformed or malicious JWT claims.
// Why: JWT claims are untrusted input from the OAuth token endpoint. Without validation,
// malicious claims could propagate through the system causing authorization bypass or
// injection.
// Exploit: (1) Scope injection -- if scope values contain special characters (e.g., spaces,
// semicolons) that are meaningful to downstream authorization logic, a crafted scope like
// "read;admin" could be interpreted as two scopes by a naive parser. The trim() + duplicate
// check mitigates this but does not restrict allowed characters within scope values. (2)
// Subject injection -- the subject claim (sub) is used as the principal name. A subject
// containing path separators or special characters could cause issues in ACL matching.
// Improvement: Consider restricting scope and subject values to a safe character set
// (e.g., alphanumeric + limited punctuation) rather than accepting any non-empty string.

// DECISION: All string claims are trimmed before validation. Scope values are additionally
// de-duplicated. Alternative: Reject values with leading/trailing whitespace rather than
// trimming. Rationale: Trimming is more forgiving of minor formatting differences in JWT
// claims across different OAuth providers. The unmodifiable return types ensure callers
// cannot modify the validated values.

// CROSS-CUTTING: Used by BrokerJwtValidator and ClientJwtValidator (claim extraction and
// validation), DefaultJwtValidator (scope/subject/expiration/issuedAt validation).
// The validated scope set is passed to BasicOAuthBearerToken constructor.
// Depends on: JwtValidatorException (validation error reporting).
// Contract: Pure static methods -- no state, fully thread-safe. All methods throw
// JwtValidatorException on invalid input. Valid input returns cleaned (trimmed) values.
// Impact: Validation changes affect what JWT claims are accepted across all OAUTHBEARER
// auth.
public class ClaimValidationUtils {

    /**
     * Validates that the scopes are valid, where <i>invalid</i> means <i>any</i> of
     * the following:
     *
     * <ul>
     *     <li>Collection is <code>null</code></li>
     *     <li>Collection has duplicates</li>
     *     <li>Any of the elements in the collection are <code>null</code></li>
     *     <li>Any of the elements in the collection are zero length</li>
     *     <li>Any of the elements in the collection are whitespace only</li>
     * </ul>
     *
     * @param scopeClaimName Name of the claim used for the scope values
     * @param scopes         Collection of String scopes
     *
     * @return Unmodifiable {@link Set} that includes the values of the original set, but with
     *         each value trimmed
     *
     * @throws JwtValidatorException Thrown if the value is <code>null</code>, contains duplicates, or
     *                           if any of the values in the set are <code>null</code>, empty,
     *                           or whitespace only
     */

    // SECURITY: (MEDIUM) Scope validation: non-null collection, each element trimmed, no
    // duplicates after trimming. Returns unmodifiable Set -- downstream code cannot add scopes.
    // Note: Does not validate scope VALUE format -- any non-empty, non-whitespace string is
    // accepted.
    // Exploit: Malformed serialized data could trigger parsing exceptions or inject unexpected values.
    // Improvement: Apply strict input validation with size bounds and character allowlists before deserialization.
    public static Set<String> validateScopes(String scopeClaimName, Collection<String> scopes) throws JwtValidatorException {
        if (scopes == null)
            throw new JwtValidatorException(String.format("%s value must be non-null", scopeClaimName));

        Set<String> copy = new HashSet<>();

        for (String scope : scopes) {
            scope = validateString(scopeClaimName, scope);

            if (copy.contains(scope))
                throw new JwtValidatorException(String.format("%s value must not contain duplicates - %s already present", scopeClaimName, scope));

            copy.add(scope);
        }

        return Collections.unmodifiableSet(copy);
    }

    /**
     * Validates that the given lifetime is valid, where <i>invalid</i> means <i>any</i> of
     * the following:
     *
     * <ul>
     *     <li><code>null</code></li>
     *     <li>Negative</li>
     * </ul>
     *
     * @param claimName  Name of the claim
     * @param claimValue Expiration time (in milliseconds)
     *
     * @return Input parameter, as provided
     *
     * @throws JwtValidatorException Thrown if the value is <code>null</code> or negative
     */

    // SECURITY: (LOW) Expiration validation: non-null, non-negative. The actual expiry check
    // (comparing against current time) is performed by the JWT validator, not here. This only
    // validates the structural integrity of the expiration claim value.
    // Exploit: An attacker could forge or replay tokens if validation is insufficient or tokens are leaked.
    // Improvement: Implement token binding or short-lived tokens with strict audience and issuer validation.
    public static long validateExpiration(String claimName, Long claimValue) throws JwtValidatorException {
        if (claimValue == null)
            throw new JwtValidatorException(String.format("%s value must be non-null", claimName));

        if (claimValue < 0)
            throw new JwtValidatorException(String.format("%s value must be non-negative; value given was \"%s\"", claimName, claimValue));

        return claimValue;
    }

    /**
     * Validates that the given claim value is valid, where <i>invalid</i> means <i>any</i> of
     * the following:
     *
     * <ul>
     *     <li><code>null</code></li>
     *     <li>Zero length</li>
     *     <li>Whitespace only</li>
     * </ul>
     *
     * @param claimName  Name of the claim
     * @param claimValue Name of the subject
     *
     * @return Trimmed version of the <code>claimValue</code> parameter
     *
     * @throws JwtValidatorException Thrown if the value is <code>null</code>, empty, or whitespace only
     */

    public static String validateSubject(String claimName, String claimValue) throws JwtValidatorException {
        return validateString(claimName, claimValue);
    }

    /**
     * Validates that the given issued at claim name is valid, where <i>invalid</i> means <i>any</i> of
     * the following:
     *
     * <ul>
     *     <li>Negative</li>
     * </ul>
     *
     * @param claimName  Name of the claim
     * @param claimValue Start time (in milliseconds) or <code>null</code> if not used
     *
     * @return Input parameter, as provided
     *
     * @throws JwtValidatorException Thrown if the value is negative
     */

    public static Long validateIssuedAt(String claimName, Long claimValue) throws JwtValidatorException {
        if (claimValue != null && claimValue < 0)
            throw new JwtValidatorException(String.format("%s value must be null or non-negative; value given was \"%s\"", claimName, claimValue));

        return claimValue;
    }

    /**
     * Validates that the given claim name override is valid, where <i>invalid</i> means
     * <i>any</i> of the following:
     *
     * <ul>
     *     <li><code>null</code></li>
     *     <li>Zero length</li>
     *     <li>Whitespace only</li>
     * </ul>
     *
     * @param name  "Standard" name of the claim, e.g. <code>sub</code>
     * @param value "Override" name of the claim, e.g. <code>email</code>
     *
     * @return Trimmed version of the <code>value</code> parameter
     *
     * @throws JwtValidatorException Thrown if the value is <code>null</code>, empty, or whitespace only
     */

    public static String validateClaimNameOverride(String name, String value) throws JwtValidatorException {
        return validateString(name, value);
    }

    // DECISION: Shared private validateString() used by validateSubject() and
    // validateClaimNameOverride(). Alternative: Inline validation in each public method.
    // Rationale: DRY -- consistent null, empty, and whitespace-only checks. Returns trimmed
    // value on success.
    private static String validateString(String name, String value) throws JwtValidatorException {
        if (value == null)
            throw new JwtValidatorException(String.format("%s value must be non-null", name));

        if (value.isEmpty())
            throw new JwtValidatorException(String.format("%s value must be non-empty", name));

        value = value.trim();

        if (value.isEmpty())
            throw new JwtValidatorException(String.format("%s value must not contain only whitespace", name));

        return value;
    }

}
