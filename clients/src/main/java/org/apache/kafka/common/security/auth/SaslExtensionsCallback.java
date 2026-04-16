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

import java.util.Objects;

import javax.security.auth.callback.Callback;

/**
 * Optional callback used for SASL mechanisms if any extensions need to be set
 * in the SASL exchange.
 */
// CROSS-CUTTING: Callback for passing SASL extensions between login modules and authenticators.
// Used by OAuthBearerLoginCallbackHandler to attach token extensions during login,
// and by SaslServerAuthenticator/SaslClientAuthenticator to extract extensions post-auth.
// Contract: Callback handlers MUST call extensions(SaslExtensions) to populate; authenticators
// read via extensions(). Depends on: auth/SaslExtensions (this package).
// Impact: If extensions are not populated, downstream components (e.g., quota managers reading
// principal extensions) will see empty extensions, not null -- safe but potentially incomplete.
public class SaslExtensionsCallback implements Callback {
    // DECISION: Default-initialized to SaslExtensions.empty() rather than null.
    // Alternative: Initialize to null and require explicit setting. Rationale: Non-null default
    // ensures unhandled callbacks produce a safe empty extensions object rather than NPE.
    // This follows the "null-safe by default" pattern used across Kafka's callback framework.
    private SaslExtensions extensions = SaslExtensions.empty();

    /**
     * Returns always non-null {@link SaslExtensions} consisting of the extension
     * names and values that are sent by the client to the server in the initial
     * client SASL authentication message. The default value is
     * {@link SaslExtensions#empty()} so that if this callback is
     * unhandled the client will see a non-null value.
     */
    public SaslExtensions extensions() {
        return extensions;
    }

    /**
     * Sets the SASL extensions on this callback.
     * 
     * @param extensions
     *            the mandatory extensions to set
     */
    // SECURITY: SEC-AUTH-008 (LOW) Extensions set here are carried through the SASL exchange and may
    // Why: SASL extensions carry authentication metadata that could
    // influence authorization decisions.
    // influence downstream behavior (e.g., quota assignment based on extension keys).
    // The Objects.requireNonNull guard prevents null injection but does not validate
    // individual extension keys or values against an allowlist.
    // Exploit: Malicious extensions or callback values could inject unexpected behavior into the auth flow.
    // Improvement: Validate all extension keys and values against an allowlist before processing.
    public void extensions(SaslExtensions extensions) {
        this.extensions = Objects.requireNonNull(extensions, "extensions must not be null");
    }
}
