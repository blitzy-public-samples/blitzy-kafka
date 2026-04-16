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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

// DECISION: Four security protocols combining transport security (none/SSL) with
// authentication (none/SASL) as a 2x2 matrix with permanent numeric IDs (0-3).
// Alternative: Separate enums for transport and authentication, composed at runtime.
// Rationale: A single enum with wire-protocol IDs ensures atomic protocol selection and
// prevents invalid combinations (e.g., SSL transport without SSL authentication context).
// The numeric IDs are embedded in connection metadata and MUST remain stable across
// all Kafka versions for backward compatibility — IDs can never be reassigned.
public enum SecurityProtocol {
    // CROSS-CUTTING: Used across the entire Kafka ecosystem — client connection configuration
    // (CommonClientConfigs.SECURITY_PROTOCOL_CONFIG), broker listener configuration
    // (KafkaConfig.listeners), inter-broker communication (KafkaConfig.interBrokerSecurityProtocol),
    // Connect worker coordination, and AdminClient. Wire protocol ID (short) is embedded in
    // connection metadata headers. The id field MUST match kafka.cluster.SecurityProtocol
    // (see comment on line 51). Impact: Adding a new protocol requires coordinated changes
    // across clients, brokers, and all tools that parse listener configurations.

    // SECURITY: (MEDIUM) PLAINTEXT (id=0) provides NO encryption and NO authentication.
    // SASL_PLAINTEXT (id=2) provides authentication but NO encryption — credentials
    // traverse the network in cleartext. Both should be avoided in production environments
    // where network sniffing or MITM attacks are possible. SSL (id=1) and SASL_SSL (id=3)
    // are the recommended protocols for production deployments.
    // Exploit: An attacker could exploit weak cipher suites or certificate validation gaps for MITM attacks.
    // Improvement: Enforce strong cipher suite selection and certificate pinning where feasible.

    /** Un-authenticated, non-encrypted channel */
    PLAINTEXT(0, "PLAINTEXT"),
    /** SSL channel */
    SSL(1, "SSL"),
    /** SASL authenticated, non-encrypted channel */
    SASL_PLAINTEXT(2, "SASL_PLAINTEXT"),
    /** SASL authenticated, SSL channel */
    SASL_SSL(3, "SASL_SSL");

    private static final Map<Short, SecurityProtocol> CODE_TO_SECURITY_PROTOCOL;
    private static final List<String> NAMES;

    // DECISION: Eagerly builds unmodifiable lookup maps at class load time for O(1) lookups.
    // Alternative: Lazy initialization or values() iteration on each lookup.
    // Rationale: SecurityProtocol is looked up on every new connection and metadata request;
    // O(1) map lookup avoids repeated iteration over the enum constants.
    static {
        SecurityProtocol[] protocols = SecurityProtocol.values();
        List<String> names = new ArrayList<>(protocols.length);
        Map<Short, SecurityProtocol> codeToSecurityProtocol = new HashMap<>(protocols.length);
        for (SecurityProtocol proto : protocols) {
            codeToSecurityProtocol.put(proto.id, proto);
            names.add(proto.name);
        }
        CODE_TO_SECURITY_PROTOCOL = Collections.unmodifiableMap(codeToSecurityProtocol);
        NAMES = Collections.unmodifiableList(names);
    }

    /** The permanent and immutable id of a security protocol -- this can't change, and must match kafka.cluster.SecurityProtocol  */
    public final short id;

    /** Name of the security protocol. This may be used by client configuration. */
    public final String name;

    SecurityProtocol(int id, String name) {
        this.id = (short) id;
        this.name = name;
    }

    public static List<String> names() {
        return NAMES;
    }

    public static SecurityProtocol forId(short id) {
        return CODE_TO_SECURITY_PROTOCOL.get(id);
    }

    // DECISION: Case-insensitive lookup using Locale.ROOT (not default locale).
    // Rationale: Locale.ROOT prevents Turkish-I problem where "PLAINTEXT".toLowerCase()
    // could produce unexpected results in a Turkish locale. This ensures consistent
    // behavior regardless of JVM default locale settings.
    /** Case insensitive lookup by protocol name */
    public static SecurityProtocol forName(String name) {
        return SecurityProtocol.valueOf(name.toUpperCase(Locale.ROOT));
    }

}
