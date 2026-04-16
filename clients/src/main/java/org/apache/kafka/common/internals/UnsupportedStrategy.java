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

import java.security.PrivilegedAction;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionException;

import javax.security.auth.Subject;

/**
 * This is a fallback strategy to use if no other strategies are available.
 * <p>This is used to improve control flow and provide detailed error messages in unusual situations.
 */
// CROSS-CUTTING: Last-resort fallback in the SecurityManagerCompatibility strategy chain.
// Only activated when BOTH LegacyStrategy and ModernStrategy fail to load — expected only
// in unusual test environments or stripped JRE distributions, not in production deployments.
//
// DECISION: Diagnostic fallback strategy that preserves both root causes (Legacy failure +
// Modern failure) as suppressed exceptions on UnsupportedOperationException. Alternative:
// Throw immediately during CompositeStrategy construction. Rationale: Deferred failure
// provides better diagnostics — the exception includes both failure reasons and is only
// thrown when the functionality is actually needed, not at startup. This helps in test
// environments where SecurityManager features may not be required.
class UnsupportedStrategy implements SecurityManagerCompatibility {

    private final Throwable e1;
    private final Throwable e2;

    UnsupportedStrategy(Throwable e1, Throwable e2) {
        this.e1 = e1;
        this.e2 = e2;
    }

    // DECISION: Uses addSuppressed() (Java 7+) to attach both root causes to a single exception.
    // Alternative: Nested cause chain. Rationale: Suppressed exceptions appear in stack traces
    // and logging frameworks, making it easier to diagnose which specific loading failure occurred
    // for both LegacyStrategy and ModernStrategy.
    private UnsupportedOperationException createException(String message) {
        UnsupportedOperationException e = new UnsupportedOperationException(message);
        e.addSuppressed(e1);
        e.addSuppressed(e2);
        return e;
    }

    @Override
    public <T> T doPrivileged(PrivilegedAction<T> action) {
        throw createException("Unable to find suitable AccessController#doPrivileged implementation");
    }

    @Override
    public Subject current() {
        throw createException("Unable to find suitable Subject#getCurrent or Subject#current implementation");
    }

    @Override
    public <T> T callAs(Subject subject, Callable<T> action) throws CompletionException {
        throw createException("Unable to find suitable Subject#doAs or Subject#callAs implementation");
    }
}
