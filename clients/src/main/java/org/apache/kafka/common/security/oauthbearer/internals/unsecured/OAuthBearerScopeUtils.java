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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Utility class for help dealing with
 * <a href="https://tools.ietf.org/html/rfc6749#section-3.3">Access Token
 * Scopes</a>
 */
// DECISION: RFC 6749 Section 3.3 compliant scope parsing as a static utility class.
// Uses single-space split (String.split(" ")) rather than regex split (\\s+).
// Alternative: Regex-based whitespace split to handle tabs, multiple spaces.
// Rationale: RFC 6749 Section 3.3 explicitly defines scope as "one or more scope values
// separated by spaces" (SP = %x20). Using literal " " split is spec-compliant. Regex
// whitespace split would be more lenient but would accept non-compliant scope strings.
// Individual scope items are validated against INDIVIDUAL_SCOPE_ITEM_PATTERN regex.
//
// CROSS-CUTTING: Consumed by OAuthBearerValidationUtils.validateScope() (indirectly — the
// requiredScope list passed to validateScope is often produced by parseScope()),
// OAuthBearerUnsecuredValidatorCallbackHandler.requiredScope() (parses the
// unsecuredValidatorRequiredScope JAAS option via parseScope()),
// OAuthBearerUnsecuredLoginCallbackHandler (scope claim handling during token construction).
// Depends on: OAuthBearerConfigException (thrown for invalid scope items).
// Contract: parseScope() returns an unmodifiable list of validated scope items.
// isValidScopeItem() is a pure predicate. Both are thread-safe (stateless).
// Impact: Changes to the INDIVIDUAL_SCOPE_ITEM_PATTERN affect which scope values are
// accepted across all OAUTHBEARER authentication paths in the unsecured package.
public class OAuthBearerScopeUtils {
    private static final Pattern INDIVIDUAL_SCOPE_ITEM_PATTERN = Pattern.compile("[\\x23-\\x5B\\x5D-\\x7E\\x21]+");
    // DECISION: Pattern [\\x23-\\x5B\\x5D-\\x7E\\x21]+ covers NQCHAR + NQSCHAR per RFC 6749.
    // The range excludes \\x22 (double-quote) and \\x5C (backslash) from the printable ASCII
    // set, as these are special characters that could cause parsing issues in scope values.
    // Alternative: Use a more permissive pattern. Rationale: Strict RFC compliance prevents
    // scope values that could be misinterpreted by downstream consumers or injection targets.

    /**
     * Return true if the given value meets the definition of a valid scope item as
     * per <a href="https://tools.ietf.org/html/rfc6749#section-3.3">RFC 6749
     * Section 3.3</a>, otherwise false
     * 
     * @param scopeItem
     *            the mandatory scope item to check for validity
     * @return true if the given value meets the definition of a valid scope item,
     *         otherwise false
     */
    public static boolean isValidScopeItem(String scopeItem) {
        return INDIVIDUAL_SCOPE_ITEM_PATTERN.matcher(Objects.requireNonNull(scopeItem)).matches();
    }

    /**
     * Convert a space-delimited list of scope values (for example,
     * <code>"scope1 scope2"</code>) to a List containing the individual elements
     * (<code>"scope1"</code> and <code>"scope2"</code>)
     * 
     * @param spaceDelimitedScope
     *            the mandatory (but possibly empty) space-delimited scope values,
     *            each of which must be valid according to
     *            {@link #isValidScopeItem(String)}
     * @return the list of the given (possibly empty) space-delimited values
     * @throws OAuthBearerConfigException
     *             if any of the individual scope values are malformed/illegal
     */
    public static List<String> parseScope(String spaceDelimitedScope) throws OAuthBearerConfigException {
        List<String> retval = new ArrayList<>();
        for (String individualScopeItem : Objects.requireNonNull(spaceDelimitedScope).split(" ")) {
            if (!individualScopeItem.isEmpty()) {
                if (!isValidScopeItem(individualScopeItem))
                    throw new OAuthBearerConfigException(String.format("Invalid scope value: %s", individualScopeItem));
                retval.add(individualScopeItem);
            }
        }
        // DECISION: Returns Collections.unmodifiableList() to prevent callers from modifying the
        // parsed scope list. Alternative: Return mutable ArrayList. Rationale: Scope values are
        // treated as immutable configuration data. Wrapping in unmodifiable view prevents accidental
        // mutation by callers, consistent with OAuthBearerUnsecuredJws immutability convention.
        return Collections.unmodifiableList(retval);
    }

    private OAuthBearerScopeUtils() {
        // empty
    }
}
