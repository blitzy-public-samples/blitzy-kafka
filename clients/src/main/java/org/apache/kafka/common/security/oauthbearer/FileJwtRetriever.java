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

package org.apache.kafka.common.security.oauthbearer;

import org.apache.kafka.common.security.oauthbearer.internals.secured.CachedFile;
import org.apache.kafka.common.security.oauthbearer.internals.secured.ConfigurationUtils;

import java.io.File;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;

import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL;
import static org.apache.kafka.common.security.oauthbearer.internals.secured.CachedFile.RefreshPolicy.lastModifiedPolicy;
import static org.apache.kafka.common.security.oauthbearer.internals.secured.CachedFile.STRING_JSON_VALIDATING_TRANSFORMER;

/**
 * <code>FileJwtRetriever</code> is an {@link JwtRetriever} that will load the contents
 * of a file, interpreting them as a JWT access key in the serialized form.
 *
 * @implNote DECISION: Uses CachedFile with lastModifiedPolicy for refresh rather than polling
 * or filesystem watch events. Alternatives: (1) WatchService-based notifications, (2) Re-read
 * on every retrieve(). Rationale: lastModified check is simple, cross-platform, and avoids
 * WatchService registration overhead. Token files change infrequently, so stat() on each
 * retrieve() is acceptable. Risk: NFS/CIFS mounts may have stale mtime metadata.
 */
// SECURITY: (MEDIUM) File-based JWT retrieval — reads a JWT access token from a local file.
// Why: The token file contains a valid, usable bearer token. If the file is readable by
// unauthorized users or processes, the token can be stolen and used for impersonation.
// Exploit: If the token file has world-readable permissions (e.g., 644 on Linux), any process
// on the same host can read the file, extract the JWT, and use it to authenticate to the
// Kafka broker as the legitimate service account. A local attacker or compromised container
// in a shared-host environment could exploit this.
// Improvement: Validate file permissions at configure() time — warn or fail if the file is
// group/world readable. Consider supporting file-system ACLs or SELinux context checks.
//
// CROSS-CUTTING: Depends on internals/secured/CachedFile (file caching with refresh policy),
// internals/secured/ConfigurationUtils (config resolution for SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL).
// Used by DefaultJwtRetriever when token endpoint URL has "file:" scheme.
// Contract: configure() must be called before retrieve(). Not closeable (no resources to release).
public class FileJwtRetriever implements JwtRetriever {

    private CachedFile<String> jwtFile;

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        ConfigurationUtils cu = new ConfigurationUtils(configs, saslMechanism);
        File file = cu.validateFileUrl(SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL);
        // SECURITY: (LOW) CachedFile with lastModifiedPolicy — re-reads file when mtime changes.
        // This allows token rotation by updating the file. However, there is a TOCTOU race:
        // between checking mtime and reading, the file could be swapped by an attacker.
        // STRING_JSON_VALIDATING_TRANSFORMER validates JSON structure, rejecting non-JSON content.
        jwtFile = new CachedFile<>(file, STRING_JSON_VALIDATING_TRANSFORMER, lastModifiedPolicy());
    }

    // SECURITY: Token content is returned as a raw String — not wrapped in Password type.
    // The token value will be held in memory by the JAAS Subject's private credentials
    // until logout. GC behavior means the String may persist in memory after logout.
    @Override
    public String retrieve() throws JwtRetrieverException {
        if (jwtFile == null)
            throw new IllegalStateException("JWT is null; please call configure() first");

        try {
            return jwtFile.transformed();
        } catch (Exception e) {
            throw new JwtRetrieverException(e);
        }
    }
}
