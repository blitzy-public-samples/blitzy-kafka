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

import java.security.Principal;

import static java.util.Objects.requireNonNull;

/**
 * <p>Principals in Kafka are defined by a type and a name. The principal type will always be <code>"User"</code>
 * for the simple authorizer that is enabled by default, but custom authorizers can leverage different
 * principal types (such as to enable group or role-based ACLs). The {@link KafkaPrincipalBuilder} interface
 * is used when you need to derive a different principal type from the authentication context, or when
 * you need to represent relations between different principals. For example, you could extend
 * {@link KafkaPrincipal} in order to link a user principal to one or more role principals.
 *
 * <p>For custom extensions of {@link KafkaPrincipal}, there two key points to keep in mind:
 * <ol>
 * <li>To be compatible with the ACL APIs provided by Kafka (including the command line tool), each ACL
 *    can only represent a permission granted to a single principal (consisting of a principal type and name).
 *    It is possible to use richer ACL semantics, but you must implement your own mechanisms for adding
 *    and removing ACLs.
 * <li>In general, {@link KafkaPrincipal} extensions are only useful when the corresponding Authorizer
 *    is also aware of the extension. If you have a {@link KafkaPrincipalBuilder} which derives user groups
 *    from the authentication context (e.g. from an SSL client certificate), then you need a custom
 *    authorizer which is capable of using the additional group information.
 * </ol>
 */
// SECURITY: SEC-AUTH-001 (MEDIUM) KafkaPrincipal is the canonical identity type for ALL Kafka
// authorization decisions. It wraps a principal type (e.g., "User") and name, with
// an optional tokenAuthenticated flag for delegation token users.
// Why: Every ACL evaluation, quota check, and audit log entry uses KafkaPrincipal
// to identify the acting entity. Corruption of the principal affects the entire
// security model.
// Exploit: If principal serialization/deserialization (via KafkaPrincipalSerde) is
// not properly validated, a crafted principal string could bypass ACL checks by
// manipulating the type or name fields. For example, injecting the ":" separator
// character in the principal name could cause incorrect parsing in
// toString()/deserialization, leading to misidentification during ACL evaluation.
// Improvement: Consider validating principal type and name against allowed character
// sets during construction (e.g., reject ":" in name to prevent parsing ambiguity).
//
// DECISION: Extends java.security.Principal for standard Java security integration.
// Alternative: A Kafka-specific identity class without Principal interface.
// Rationale: Implementing Principal allows KafkaPrincipal to integrate with standard
// Java security infrastructure (JAAS Subject, SecurityManager) without adaptation
// layers, and enables interoperability with javax.security.auth.Subject.
public class KafkaPrincipal implements Principal {
    // CROSS-CUTTING: Used by ALL authorization decisions in Kafka:
    // - metadata/authorizer/StandardAuthorizer and StandardAuthorizerData for KRaft ACL
    //   evaluation
    // - core/server/AuthHelper.scala for broker-side authorization checks
    // - server/authorizer/AclEntry for ACL matching and wildcard principal support
    // - clients/admin/KafkaAdminClient for ACL management operations
    // Also consumed by: quota management (ClientQuotaManager), audit logging, metrics
    // tagging, and request logging throughout the broker.
    // Constructed by KafkaPrincipalBuilder implementations.
    // Contract: Immutable identity (principalType + name); tokenAuthenticated is mutable
    // post-construction.

    public static final String USER_TYPE = "User";
    // SECURITY: SEC-AUTH-002 (LOW) ANONYMOUS principal used for unauthenticated PLAINTEXT connections.
    // Why: Represents the identity for unauthenticated sessions in ACL authorization.
    // Exploit: Reference equality (==) is NOT reliable -- equals() checks type+name, so
    // new KafkaPrincipal("User","ANONYMOUS") matches, potentially bypassing identity checks.
    // Improvement: Always use equals(); ensure ACL configs DENY ANONYMOUS in production.
    public static final KafkaPrincipal ANONYMOUS = new KafkaPrincipal(KafkaPrincipal.USER_TYPE, "ANONYMOUS");

    private final String principalType;
    private final String name;
    // SECURITY: SEC-AUTH-003 (MEDIUM) volatile boolean -- delegation token users have this flag set
    // to true. Authorization logic may apply different ACL evaluation for
    // token-authenticated principals (e.g., delegation tokens inherit the token owner's
    // permissions with possible restrictions).
    // Why: The volatile keyword ensures thread visibility when set post-construction
    // during re-authentication; incorrect flag state affects authorization decisions.
    // Exploit: If set incorrectly, a non-token user could gain token permissions, or a
    // token-authenticated user could bypass delegation token restrictions.
    // Improvement: Consider making this field immutable (set only via constructor) to
    // prevent post-construction mutation from untrusted callers.
    private volatile boolean tokenAuthenticated;

    public KafkaPrincipal(String principalType, String name) {
        this(principalType, name, false);
    }

    public KafkaPrincipal(String principalType, String name, boolean tokenAuthenticated) {
        this.principalType = requireNonNull(principalType, "Principal type cannot be null");
        this.name = requireNonNull(name, "Principal name cannot be null");
        this.tokenAuthenticated = tokenAuthenticated;
    }

    // DECISION: "type:name" serialization format used for logging, ACL display, and
    // some internal serialization paths. The ":" delimiter is a convention, not validated
    // in the constructor -- names containing ":" could cause ambiguous parsing.
    @Override
    public String toString() {
        return principalType + ":" + name;
    }

    // DECISION: equals/hashCode based ONLY on principalType and name, deliberately
    // excluding tokenAuthenticated. Alternative: Include tokenAuthenticated in equality.
    // Rationale: The same user identity (type+name) should be equal regardless of how
    // they authenticated (password vs delegation token). Token authentication is a
    // session-level property, not an identity property. This ensures ACL lookups match.
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (getClass() != o.getClass()) return false;

        KafkaPrincipal that = (KafkaPrincipal) o;
        return principalType.equals(that.principalType) && name.equals(that.name);
    }

    @Override
    public int hashCode() {
        int result = principalType != null ? principalType.hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }

    @Override
    public String getName() {
        return name;
    }

    public String getPrincipalType() {
        return principalType;
    }

    public void tokenAuthenticated(boolean tokenAuthenticated) {
        this.tokenAuthenticated = tokenAuthenticated;
    }

    public boolean tokenAuthenticated() {
        return tokenAuthenticated;
    }
}
