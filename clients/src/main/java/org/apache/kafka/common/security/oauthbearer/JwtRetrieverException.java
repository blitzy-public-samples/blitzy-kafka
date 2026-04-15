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

import org.apache.kafka.common.KafkaException;

/**
 * A {@code JwtRetrieverException} is thrown in cases where the JWT cannot be retrieved.
 *
 * @see JwtRetriever#retrieve()
 */
// DECISION: Extends KafkaException (unchecked) rather than a checked exception. Alternative:
// Extend IOException (checked). Rationale: JwtRetriever.retrieve() declares this as a
// thrown exception but callers (OAuthBearerLoginCallbackHandler) catch it within their
// IOException-declaring handle() method. Using unchecked exception avoids forcing all
// intermediate callers to declare or catch it, while still allowing targeted catch blocks.
// Risk: Unchecked exceptions can propagate unexpectedly if not caught at appropriate levels.
//
// CROSS-CUTTING: Thrown by all JwtRetriever implementations (HttpJwtRetriever,
// FileJwtRetriever, ClientCredentialsJwtRetriever, JwtBearerJwtRetriever) on retrieval
// failures (network errors, file I/O, JSON parsing). Caught by OAuthBearerLoginCallbackHandler
// (client-side) and re-thrown as IOException to the SASL framework.
// Contract: Message should describe the retrieval failure without including sensitive data
// (tokens, credentials, secrets). Cause chain preserves original exception for debugging.
public class JwtRetrieverException extends KafkaException {

    public JwtRetrieverException(String message) {
        super(message);
    }

    public JwtRetrieverException(Throwable cause) {
        super(cause);
    }

    public JwtRetrieverException(String message, Throwable cause) {
        super(message, cause);
    }
}
