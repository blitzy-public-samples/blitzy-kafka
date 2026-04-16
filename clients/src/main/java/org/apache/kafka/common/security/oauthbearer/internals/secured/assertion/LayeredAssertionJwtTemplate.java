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

import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.utils.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This {@link AssertionJwtTemplate} layers multiple templates to produce an aggregated template.
 * This is used, in practice, to achieve a layered approach where templates added later take precedence
 * over templates that appear earlier in the list. Take for example the following list of templates,
 * added in this order:
 *
 * <ol>
 *     <li>Static/configuration-based JWT headers and claims via {@link StaticAssertionJwtTemplate}</li>
 *     <li>File-based JWT headers and claims via {@link FileAssertionJwtTemplate}</li>
 *     <li>Dynamic JWT headers and claims via {@link DynamicAssertionJwtTemplate}</li>
 * </ol>
 *
 * The templates are specified in ascending order of precedence. That is, in the list, a template with
 * a list index of <i>N+1</i> will effectively overwrite values provided by template at index <i>N</i>.
 * In the above example, the {@link DynamicAssertionJwtTemplate} (index 2) will overwrite any values
 * specified by the {@link FileAssertionJwtTemplate} (index 1), which will in turn overwrite any values
 * from the {@link StaticAssertionJwtTemplate}.
 *
 * <p/>
 *
 * In practice, there shouldn't be much in the way of overwriting. The headers and claims provided
 * by each layer are mostly distinct. For example, a {@link StaticAssertionJwtTemplate} loads values
 * mainly from the configuration, such as the <code>iss</code> (Issuer) claim
 * ({@link SaslConfigs#SASL_OAUTHBEARER_ASSERTION_CLAIM_ISS}). The <code>iss</code> claim probably
 * doesn't change all that often, statically configuring it is sensible. However, other values, such
 * as the <code>exp</code> (Expires) claim changes dynamically over time. Specifying a static expiration
 * value doesn't make much sense.
 *
 * <p/>
 *
 * There are probably cases where it may make sense to overwrite static configuration with values that
 * are more up-to-date. In that case, the {@link FileAssertionJwtTemplate} allows the user to provide
 * headers and claims via a file that can be reloaded when it is modified. So, for example, if the value
 * of the <code>iss</code> (Issuer) claim changes <em>temporarily</em>, the user can update the assertion
 * template file ({@link SaslConfigs#SASL_OAUTHBEARER_ASSERTION_TEMPLATE_FILE}) to add an
 * <code>iss</code> claim. In so doing, the template file will be reloaded, the
 * {@code FileAssertionJwtTemplate} will overwrite the claim value in the generated assertion, and the
 * client/application does not need to be restarted for the new value to take effect. Likewise, when the
 * <code>iss</code> claim needs to be changed back to its normal value, the user can either update the
 * template file with the new value, or simply remove the claim from the file altogether so that the
 * original, static claim value is restored.
 */
// DECISION: Layering strategy: later layers override earlier layers' claims via Map.putAll().
// The layering order is determined by AssertionUtils.layeredAssertionJwtTemplate(): static base ->
// file-based -> dynamic (iat/exp/jti). This means dynamic claims take highest priority, ensuring
// time-based claims are always fresh and cannot be overridden by stale file or config values.
// Alternative: Merge with conflict detection (throw on duplicate keys). Rationale: Override
// semantics are more operationally flexible -- admins can override claims by adding a file template
// without changing broker config. Silent override avoids operational disruptions.
// CROSS-CUTTING: Composes multiple AssertionJwtTemplate instances. Created by
// AssertionUtils.layeredAssertionJwtTemplate() which assembles static -> file -> dynamic layers.
// Used by DefaultAssertionCreator.create() which calls header()/payload() to get merged claims.
// Depends on: Utils.closeQuietly() for safe lifecycle cleanup. Each child template
// (StaticAssertionJwtTemplate, FileAssertionJwtTemplate, DynamicAssertionJwtTemplate) is
// independently configurable and closeable.
// Impact: Changes to layering order in AssertionUtils affect claim override precedence for
// all jwt-bearer OAuth assertion flows.
public class LayeredAssertionJwtTemplate implements AssertionJwtTemplate {

    private final List<AssertionJwtTemplate> templates;

    // DECISION: Two constructor overloads: varargs (for programmatic construction) and List (for
    // AssertionUtils factory). The varargs version wraps in Arrays.asList() (fixed-size list).
    // The List version wraps in Collections.unmodifiableList() to prevent external modification.
    public LayeredAssertionJwtTemplate(AssertionJwtTemplate... templates) {
        this.templates = Arrays.asList(templates);
    }

    public LayeredAssertionJwtTemplate(List<AssertionJwtTemplate> templates) {
        this.templates = Collections.unmodifiableList(templates);
    }

    // DECISION: Recomputes merged header map on every call rather than caching the merged result.
    // Alternative: Cache merged map and invalidate on template change. Rationale: Template sources
    // (DynamicAssertionJwtTemplate, FileAssertionJwtTemplate) may return different values on each
    // call (time-based claims, file modifications). Caching would require change detection across
    // all child templates. Fresh computation is simpler and correct -- the overhead of HashMap
    // allocation + putAll() for 2-4 templates is negligible compared to the HTTP token request.
    @Override
    public Map<String, Object> header() {
        Map<String, Object> header = new HashMap<>();

        for (AssertionJwtTemplate template : templates)
            header.putAll(template.header());

        return Collections.unmodifiableMap(header);
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> payload = new HashMap<>();

        for (AssertionJwtTemplate template : templates)
            payload.putAll(template.payload());

        return Collections.unmodifiableMap(payload);
    }

    // DECISION: Delegates close() to all child templates via Utils.closeQuietly(). This ensures
    // proper lifecycle propagation in the composite -- each child's resources (e.g., CachedFile
    // in FileAssertionJwtTemplate) are released. Utils.closeQuietly() suppresses exceptions to
    // ensure all children are closed even if one throws.
    @Override
    public void close() {
        for (AssertionJwtTemplate template : templates) {
            Utils.closeQuietly(template, "JWT assertion template");
        }
    }
}
