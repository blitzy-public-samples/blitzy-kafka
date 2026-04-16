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
package org.apache.kafka.common.security.scram;

import java.util.Collections;
import java.util.Map;

import javax.security.auth.callback.Callback;


/**
 * Optional callback used for SCRAM mechanisms if any extensions need to be set
 * in the SASL/SCRAM exchange.
 */
// SECURITY: (LOW) JAAS Callback for SCRAM protocol extensions (RFC 5802 extensions).
// Why: Extensions are included in the client-first SCRAM message and are visible to
// the server. Currently used for delegation token authentication signaling (tokenauth=true).
// Exploit: If an attacker can inject arbitrary extensions into the SCRAM client-first
// message (e.g., by controlling CallbackHandler configuration), they could set
// tokenauth=true to switch the server to delegation token credential lookup — potentially
// bypassing regular SCRAM authentication if a valid delegation token exists for the user.
// Improvement: Server-side validation should verify that the tokenauth extension is
// consistent with the authentication mechanism being used and the client's known identity.
//
// CROSS-CUTTING: Used by ScramSaslClient (internals/) to include extensions in the
// SCRAM client-first message. Populated by OAuthBearerLoginCallbackHandler or
// ScramLoginModule when tokenauth=true is configured.
// Contract: Extensions map MUST be set before ScramSaslClient.evaluateChallenge() is called.
// Depends on: ScramLoginModule.TOKEN_AUTH_CONFIG for the tokenauth extension key.
// Impact: If extensions are not set, the SCRAM exchange proceeds as a normal (non-token)
// authentication — this is the correct default behavior.
public class ScramExtensionsCallback implements Callback {
    // DECISION: Default to Collections.emptyMap() rather than null.
    // Alternatives: (1) null default with null-check in consumers, (2) empty HashMap.
    // Rationale: Empty immutable map avoids null checks in ScramSaslClient message
    // construction and ensures the extensions attribute is always safe to iterate.
    private Map<String, String> extensions = Collections.emptyMap();

    /**
     * Returns map of the extension names and values that are sent by the client to
     * the server in the initial client SCRAM authentication message.
     * Default is an empty unmodifiable map.
     */
    public Map<String, String> extensions() {
        return extensions;
    }

    /**
     * Sets the SCRAM extensions on this callback. Maps passed in should be unmodifiable
     */
    // SECURITY: (MEDIUM) No validation on extension keys or values. Javadoc states maps should be
    // unmodifiable, but this is not enforced — a mutable map could be modified after being
    // set, changing the SCRAM message content mid-authentication.
    // Exploit: Malicious extensions or callback values could inject unexpected behavior into the auth flow.
    // Improvement: Validate all extension keys and values against an allowlist before processing.
    public void extensions(Map<String, String> extensions) {
        this.extensions = extensions;
    }
}
