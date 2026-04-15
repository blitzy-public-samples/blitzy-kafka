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
package org.apache.kafka.common.security.auth;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

import javax.security.auth.Subject;

/**
 * A simple immutable value object class holding customizable SASL extensions.
 *
 * <p/>
 *
 * <b>Note on object identity and equality</b>: <code>SaslExtensions</code> <em>intentionally</em>
 * overrides the standard {@link #equals(Object)} and {@link #hashCode()} methods calling their
 * respective {@link Object#equals(Object)} and {@link Object#hashCode()} implementations. In so
 * doing, it provides equality <em>only</em> via reference identity and will not base equality on
 * the underlying values of its {@link #extensionsMap extensions map}.
 *
 * <p/>
 *
 * The reason for this approach to equality is based off of the manner in which
 * credentials are stored in a {@link Subject}. <code>SaslExtensions</code> are added to and
 * removed from a {@link Subject} via its {@link Subject#getPublicCredentials() public credentials}.
 * The public credentials are stored in a {@link Set} in the {@link Subject}, so object equality
 * therefore becomes a concern. With shallow, reference-based equality, distinct
 * <code>SaslExtensions</code> instances with the same map values can be considered unique. This is
 * critical to operations like token refresh.
 *
 * See <a href="https://issues.apache.org/jira/browse/KAFKA-14062">KAFKA-14062</a> for more detail.
 */
// SECURITY: (MEDIUM) SASL extension key-value pairs carried alongside authentication.
// Why: Extensions are transmitted in the initial SASL client message and propagated through
// the auth pipeline. They can influence downstream behavior such as quota assignment,
// principal enrichment, or custom authorization decisions.
// Exploit: If extension keys/values are not validated by the callback handler or authenticator,
// a malicious client could inject unexpected keys (e.g., mimicking internal extension names)
// to influence quota assignments, bypass rate limits, or manipulate audit log entries.
// Improvement: Consider validating extension keys against an allowed set in the authenticator
// before propagating them. Also consider size limits on extension values to prevent
// memory exhaustion from oversized extension payloads in the SASL exchange.
public class SaslExtensions {
    // CROSS-CUTTING: Consumed by SaslExtensionsCallback (this package) for JAAS callback transport,
    // by authenticator/SaslServerAuthenticator for extracting client extensions post-auth,
    // by oauthbearer/OAuthBearerLoginCallbackHandler for attaching token extensions.
    // Stored in javax.security.auth.Subject.getPublicCredentials() during SASL login lifecycle.
    // Contract: Immutable after construction. Identity-based equality for Subject credential storage.
    private final Map<String, String> extensionsMap;

    // DECISION: Uses Map.copyOf() for defensive copy — ensures immutability after construction.
    // Alternative: Store reference directly (cheaper) or use Collections.unmodifiableMap(new HashMap<>(...)).
    // Rationale: Map.copyOf() rejects null keys/values and creates a truly unmodifiable snapshot,
    // preventing callers from modifying the extensions after construction via the original map reference.
    public SaslExtensions(Map<String, String> extensionsMap) {
        this.extensionsMap = Map.copyOf(extensionsMap);
    }

    /**
     * Returns an <strong>immutable</strong> map of the extension names and their values
     */
    public Map<String, String> map() {
        return extensionsMap;
    }

    /**
     * Creates an "empty" instance indicating no SASL extensions. <em>Do not cache the result of
     * this method call</em> for use by multiple {@link Subject}s as the references need to be
     * unique.
     *
     * <p/>
     *
     * See the class-level documentation for details.
     * @return Unique, but empty, <code>SaslExtensions</code> instance
     */
    @SuppressWarnings("unchecked")
    public static SaslExtensions empty() {
        // It's ok to re-use the EMPTY_MAP instance as the object equality is on the outer
        // SaslExtensions reference.
        return new SaslExtensions(Collections.EMPTY_MAP);
    }

    /**
     * Implements equals using the reference comparison implementation from
     * {@link Object#equals(Object)}.
     *
     * <p/>
     *
     * See the class-level documentation for details.
     *
     * @param o Other object to compare
     * @return True if <code>o == this</code>
     */
    // DECISION: Identity-based equals/hashCode (delegates to Object) rather than value-based.
    // This is critical for Subject.getPublicCredentials() Set storage — see KAFKA-14062.
    // Without identity semantics, token refresh would fail to add new SaslExtensions
    // instances to the Subject when the extension map values are identical.
    @Override
    public final boolean equals(Object o) {
        return super.equals(o);
    }

    /**
     * Implements <code>hashCode</code> using the native implementation from
     * {@link Object#hashCode()}.
     *
     * <p/>
     *
     * See the class-level documentation for details.
     *
     * @return Hash code of instance
     */
    @Override
    public final int hashCode() {
        return super.hashCode();
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", SaslExtensions.class.getSimpleName() + "[", "]")
            .add("extensionsMap=" + extensionsMap)
            .toString();
    }

}
