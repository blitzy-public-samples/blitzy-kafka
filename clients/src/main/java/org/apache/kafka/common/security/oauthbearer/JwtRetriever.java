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

import org.apache.kafka.common.security.oauthbearer.internals.secured.HttpJwtRetriever;
import org.apache.kafka.common.security.oauthbearer.internals.secured.OAuthBearerConfigurable;


/**
 * A <code>JwtRetriever</code> is the internal API by which the login module will
 * retrieve an access token for use in authorization by the broker. The implementation may
 * involve authentication to a remote system, or it can be as simple as loading the contents
 * of a file or configuration setting.
 *
 * <i>Retrieval</i> is a separate concern from <i>validation</i>, so it isn't necessary for
 * the <code>JwtRetriever</code> implementation to validate the integrity of the JWT
 * access token.
 *
 * @see HttpJwtRetriever
 * @see FileJwtRetriever
 */

// DECISION: Separate retrieval (JwtRetriever) from validation (JwtValidator) concerns.
// Alternative: Single JwtProvider interface that retrieves and validates. Rationale:
// Separation of concerns — retrieval may involve HTTP calls, file I/O, or token exchange
// (each with different security properties), while validation involves cryptographic
// operations. Different OAuth grant types only differ in retrieval, not validation.
// This enables the pluggable retriever pattern (DefaultJwtRetriever, ClientCredentials,
// JwtBearer, File) without duplicating validation logic.

// DECISION: Extends OAuthBearerConfigurable (configure + Closeable) rather than defining
// its own lifecycle. Alternative: Standalone interface with separate init/close. Rationale:
// OAuthBearerConfigurable standardizes the configure(Map, String,
// List<AppConfigurationEntry>) contract across all OAUTHBEARER components, enabling
// uniform initialization via ConfigurationUtils.getConfiguredInstance().

// CROSS-CUTTING: Contract interface for JWT token retrieval. Implementations:
// - DefaultJwtRetriever (delegates to File or ClientCredentials based on URL scheme)
// - ClientCredentialsJwtRetriever (OAuth client_credentials grant)
// - JwtBearerJwtRetriever (JWT bearer assertion grant)
// - FileJwtRetriever (local file)
// - internals/secured/HttpJwtRetriever (HTTP transport, used by delegation)
// Consumed by: OAuthBearerLoginCallbackHandler (via getConfiguredInstance),
// OAuthBearerLoginModule (indirectly via callback handler).
// External deps: OAuthBearerConfigurable (lifecycle), JwtRetrieverException (error).

public interface JwtRetriever extends OAuthBearerConfigurable {

    /**
     * Retrieves a JWT access token in its serialized three-part form. The implementation
     * is free to determine how it should be retrieved but should not perform validation
     * on the result.
     *
     * <b>Note</b>: This is a blocking function and callers should be aware that the
     * implementation may be communicating over a network, with the file system, coordinating
     * threads, etc. The facility in the {@link javax.security.auth.spi.LoginModule} from
     * which this is ultimately called does not provide an asynchronous approach.
     *
     * @return Non-<code>null</code> JWT access token string
     *
     * @throws JwtRetrieverException Thrown on errors related to IO during retrieval
     */

    // DECISION: Blocking API (no CompletableFuture or callback). Alternative: Async API.
    // Rationale: Called from JAAS LoginModule which uses synchronous JAAS callbacks.
    // The SASL authentication handshake is inherently synchronous in Kafka — async would
    // add complexity without benefit since the SASL channel is blocked until auth completes.

    String retrieve() throws JwtRetrieverException;
}
