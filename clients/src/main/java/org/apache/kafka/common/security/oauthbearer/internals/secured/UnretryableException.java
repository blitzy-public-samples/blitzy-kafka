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

package org.apache.kafka.common.security.oauthbearer.internals.secured;

import org.apache.kafka.common.KafkaException;

// DECISION: Extends KafkaException (RuntimeException) rather than a checked exception.
// Alternatives: (1) Checked IOException subclass, (2) Custom checked exception.
// Rationale: UnretryableException is thrown from Retryable.call() lambdas. Using a
// RuntimeException (via KafkaException) allows clean lambda usage without try-catch
// boilerplate. The Retry.execute() method catches this specifically to break the retry
// loop immediately. The cause (wrapped Throwable) provides the actual error details.

// CROSS-CUTTING: Thrown by HttpJwtRetriever.handleOutput() when HTTP response code is in
// UNRETRYABLE_HTTP_CODES set (e.g., 401, 403, 404). Caught by Retry.execute() to
// short-circuit the retry loop. Part of the Retry/Retryable/UnretryableException framework.
// Contract: Wraps the actual cause (typically IOException). Retry.execute() extracts the
// cause and wraps it in ExecutionException for the caller.
public class UnretryableException extends KafkaException {

    public UnretryableException(Throwable cause) {
        super(cause);
    }

}
