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
package org.apache.kafka.common.internals;

import org.apache.kafka.common.utils.Exit;

/**
 * An error that indicates the need to exit the JVM process. This should only be used by the server or command-line
 * tools. Clients should never shutdown the JVM process.
 *
 * This exception is expected to be caught at the highest level of the thread so that no shared lock is held by
 * the thread when it calls {@link Exit#exit(int)}.
 */
// CROSS-CUTTING: Thrown by server-side components (core/server/BrokerServer,
// core/server/ControllerServer) and command-line tools to signal unrecoverable failure.
// Caught at the top-level thread in KafkaRaftServer/KafkaServer and triggers
// Exit.exit(statusCode). MUST NOT be thrown by client library code — clients should never
// terminate the JVM. Depends on common/utils/Exit for testable JVM termination.
// DECISION: Extends Error (not Exception or RuntimeException) to signal unrecoverable JVM
// failure. Alternative: System.exit() directly or custom RuntimeException. Rationale:
// Error subclass is unchecked AND not caught by generic catch(Exception) blocks — this
// ensures FatalExitError propagates through all catch chains to the top-level thread handler
// where Exit.exit() is called. Using RuntimeException would risk accidental catch by
// error-tolerant code paths (e.g., request handler loops).
public class FatalExitError extends Error {

    // DECISION: Explicit serialVersionUID for Error subclass. Although FatalExitError is
    // never intentionally serialized, the Serializable contract inherited from Throwable
    // requires a stable version ID for binary compatibility.
    private static final long serialVersionUID = 1L;

    // DECISION: Non-zero status code enforced by constructor validation (line 35-36). Zero
    // conventionally means success in Unix/JVM — a FatalExitError with status 0 would
    // misrepresent a fatal condition as normal termination. Default constructor uses 1
    // (generic error) for convenience.
    private final int statusCode;

    public FatalExitError(int statusCode) {
        if (statusCode == 0)
            throw new IllegalArgumentException("statusCode must not be 0");
        this.statusCode = statusCode;
    }

    public FatalExitError() {
        this(1);
    }

    public int statusCode() {
        return statusCode;
    }
}
