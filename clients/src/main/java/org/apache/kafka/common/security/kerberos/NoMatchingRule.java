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
package org.apache.kafka.common.security.kerberos;

import java.io.IOException;

// Package-private exception thrown when no auth_to_local rule matches a Kerberos principal name,
// or when a rule produces a non-simple name containing '/' or '@' characters.
// CROSS-CUTTING: Thrown by KerberosShortNamer.shortName() and KerberosRule.apply().
// Caught by DefaultKafkaPrincipalBuilder (authenticator/) which wraps it in KafkaException.
// SECURITY: SEC-KERB-018 (LOW) A NoMatchingRule exception means the principal cannot be mapped to a local
// Why: Kerberos authentication handles security-critical ticket
// exchange and principal resolution.
// identity. The caller should deny access for unmapped principals rather than using a default identity.
// Exploit: A misconfigured auth_to_local rule could map an attacker principal to a privileged local identity.
// Improvement: Audit auth_to_local rules regularly and use strict realm-based principal validation.
public class NoMatchingRule extends IOException {
    NoMatchingRule(String msg) {
        super(msg);
    }
}
