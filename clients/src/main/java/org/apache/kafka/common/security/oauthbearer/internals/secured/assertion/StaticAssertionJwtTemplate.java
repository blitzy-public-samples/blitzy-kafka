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
package org.apache.kafka.common.security.oauthbearer.internals.secured.assertion;

import java.util.Collections;
import java.util.Map;

/**
 * This {@link AssertionJwtTemplate} uses a static set of headers and claims provided on initialization.
 * The values typically come from configuration, and it is often used in conjunction with other templates
 * such as {@link LayeredAssertionJwtTemplate}.
 */
// DECISION: Null object pattern: the no-arg constructor (line 33) creates a template with
// Map.of() (empty immutable maps) for both header and payload. This is always used as the base
// layer in LayeredAssertionJwtTemplate when no static config claims (aud, iss, sub) are present.
// Alternative: Use null with null checks in LayeredAssertionJwtTemplate. Rationale: Null object
// pattern eliminates conditional logic in LayeredAssertionJwtTemplate — every layer always has
// a valid template, simplifying the putAll() composition loop.
//
// CROSS-CUTTING: Used as the base layer by AssertionUtils.staticAssertionJwtTemplate() which
// populates header/payload from SASL config values (aud, iss, sub claims). When no static claims
// are configured, the no-arg constructor is used to provide empty maps.
// Used in LayeredAssertionJwtTemplate composition — typically the first (lowest priority) layer.
// No external dependencies beyond java.util.Collections and java.util.Map.
// Impact: Changes to this class's contract (e.g., returning mutable maps) would break the
// immutability assumption in LayeredAssertionJwtTemplate's putAll() merge.
public class StaticAssertionJwtTemplate implements AssertionJwtTemplate {

    private final Map<String, Object> header;

    private final Map<String, Object> payload;

    public StaticAssertionJwtTemplate() {
        this.header = Map.of();
        this.payload = Map.of();
    }

    // DECISION: Wraps provided maps in Collections.unmodifiableMap() for immutability. The no-arg
    // constructor uses Map.of() which is already immutable. This ensures callers cannot modify the
    // template's claims after construction. Alternative: Defensive copy + unmodifiable. Rationale:
    // The caller (AssertionUtils.staticAssertionJwtTemplate) creates the maps locally and does not
    // retain references, so defensive copy is unnecessary.
    public StaticAssertionJwtTemplate(Map<String, Object> header, Map<String, Object> payload) {
        this.header = Collections.unmodifiableMap(header);
        this.payload = Collections.unmodifiableMap(payload);
    }

    @Override
    public Map<String, Object> header() {
        return header;
    }

    @Override
    public Map<String, Object> payload() {
        return payload;
    }
}
