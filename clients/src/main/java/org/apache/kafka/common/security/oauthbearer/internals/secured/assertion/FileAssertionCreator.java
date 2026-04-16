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

import org.apache.kafka.common.security.oauthbearer.internals.secured.CachedFile;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.apache.kafka.common.security.oauthbearer.internals.secured.CachedFile.RefreshPolicy.lastModifiedPolicy;
import static org.apache.kafka.common.security.oauthbearer.internals.secured.CachedFile.STRING_JSON_VALIDATING_TRANSFORMER;

/**
 * An {@link AssertionCreator} which takes a file from which the pre-created assertion is loaded and returned.
 * If the file changes on disk, it will be reloaded in memory without needing to restart the client/application.
 */
// SECURITY: (HIGH) File-based assertion source. If the assertion file is world-readable, any user on
// the system can steal the pre-signed JWT and impersonate the Kafka client to the OAuth provider.
// Exploit: An attacker with local access reads the assertion file, then uses the pre-signed JWT in a
// direct call to the token endpoint, obtaining an access token with the Kafka client's identity and
// privileges. The pre-signed assertion has a fixed expiry -- the attacker can replay it until expiry.
// Improvement: Verify file permissions (0600 or more restrictive) before reading. Log a warning if
// the file is group/world readable. Consider short-lived assertion files with frequent rotation.
//
// CROSS-CUTTING: Used by JwtBearerJwtRetriever when assertionCreatorClass config points to this
// class. Depends on CachedFile for file management and caching, and CachedFile's
// STRING_JSON_VALIDATING_TRANSFORMER for JWT structural validation.
// Implements AssertionCreator interface. Unlike DefaultAssertionCreator, this class does not
// perform any cryptographic operations -- it trusts the file contains a pre-signed assertion.
// Impact: File changes on disk are detected via lastModified polling -- changes within the same
// filesystem timestamp granularity may be missed (typically 1-second on ext4).
public class FileAssertionCreator implements AssertionCreator {

    private final CachedFile<String> assertionFile;

    public FileAssertionCreator(File assertionFile) {
        // DECISION: Uses CachedFile with STRING_JSON_VALIDATING_TRANSFORMER and lastModifiedPolicy for
        // automatic reload on file change. Alternative: Read file on every create() call. Rationale:
        // Caching avoids filesystem I/O on every token refresh while supporting assertion rotation via
        // file modification detection. The validator ensures the cached string has valid JWT structure.
        this.assertionFile = new CachedFile<>(assertionFile, STRING_JSON_VALIDATING_TRANSFORMER, lastModifiedPolicy());
    }

    // SECURITY: (MEDIUM) The template parameter is intentionally ignored -- the pre-signed assertion
    // from disk is returned as-is. Dynamic claims (iat, exp, jti) from the template are NOT applied.
    // The file must contain a complete, valid, signed JWT. If the file contains an expired assertion,
    // the token endpoint will reject it. No structural validation is performed beyond
    // STRING_JSON_VALIDATING_TRANSFORMER which checks JWT 3-segment structure.
    //
    // DECISION: Ignores the template parameter entirely -- returns the file contents as the assertion.
    // Alternative: Merge template claims with file content. Rationale: A pre-signed assertion is
    // immutable -- modifying claims would invalidate the signature. The file is expected to contain
    // a complete, ready-to-use signed JWT assertion.
    @Override
    public String create(AssertionJwtTemplate ignored) throws GeneralSecurityException, IOException {
        return assertionFile.transformed();
    }
}
