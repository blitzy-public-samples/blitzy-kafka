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
package org.apache.kafka.common.security.scram.internals;

import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.scram.ScramLoginModule;
import org.apache.kafka.common.utils.Utils;

import java.util.Collections;
import java.util.Map;

// SECURITY: SEC-SCRAM-021 (LOW) SCRAM protocol extensions wrapper for delegation token support.
// Why: Extensions are included in the SCRAM client-first message and are visible to the server.
// The primary extension is "tokenauth=true" which switches the server to delegation token
// credential lookup instead of regular SCRAM credentials.
// Exploit: If an attacker can inject the tokenauth=true extension (e.g., by controlling
// CallbackHandler configuration or manipulating the SCRAM client-first message in transit),
// the server switches to delegation token lookup. If a valid delegation token exists for the
// target user, the attacker could authenticate using the token credential instead of the
// user's SCRAM credential, potentially bypassing stronger password-based authentication.
// Improvement: Server should validate that tokenauth extension is only accepted from
// clients that have been configured for delegation token authentication.
//
// CROSS-CUTTING: Extends auth/SaslExtensions -- used by ScramSaslClient for client-first
// message construction and by ScramSaslServer for token auth detection.
// Depends on: ScramLoginModule.TOKEN_AUTH_CONFIG for the "tokenauth" extension key.
// Depends on: Utils.parseMap() for string-to-map conversion.
// Contract: Extension map is effectively immutable after construction (inherited from
// SaslExtensions). The map() accessor returns an unmodifiable view.
// Impact: Adding new extension keys requires updating ScramSaslServer.SUPPORTED_EXTENSIONS.
public class ScramExtensions extends SaslExtensions {

    public ScramExtensions() {
        this(Collections.emptyMap());
    }

    // SECURITY: SEC-SCRAM-022 (MEDIUM) Parses extension string using Utils.parseMap() with "=" key-value separator
    // Why: SCRAM extensions carry authentication metadata that could
    // influence the challenge-response exchange.
    // and "," pair separator. No validation on extension keys or values -- arbitrary extensions
    // can be passed through to the server.
    // Exploit: Malformed serialized data could trigger parsing exceptions or inject unexpected values.
    // Improvement: Apply strict input validation with size bounds and character allowlists before deserialization.
    public ScramExtensions(String extensions) {
        this(Utils.parseMap(extensions, "=", ","));
    }

    public ScramExtensions(Map<String, String> extensionMap) {
        super(extensionMap);
    }

    // SECURITY: SEC-SCRAM-023 (MEDIUM) Checks if the "tokenauth" extension is set to "true". This single boolean flag
    // Why: SCRAM extensions carry authentication metadata that could
    // influence the challenge-response exchange.
    // controls the entire credential dispatch path in ScramSaslServer (line 112 in that file).
    // The value is parsed from the extension map using Boolean.parseBoolean(), which returns
    // false for any value other than case-insensitive "true" -- this is safe default behavior.
    // Exploit: Injection of malicious SCRAM extensions could alter
    // authentication parameters or bypass server-side validation.
    // Improvement: Add strict validation of extension keys and values
    // to reject injection attempts in SCRAM extensions.
    public boolean tokenAuthenticated() {
        return Boolean.parseBoolean(map().get(ScramLoginModule.TOKEN_AUTH_CONFIG));
    }
}
