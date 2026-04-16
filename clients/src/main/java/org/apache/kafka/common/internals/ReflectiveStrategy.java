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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Utility methods for strategies which use reflection to access methods without requiring them at compile-time.
 */
// DECISION: Stateless utility class centralizing reflection invocation and exception
// normalization. Alternative: Each strategy (Legacy/Modern) handles its own reflection.
// Rationale: Consistent exception handling across strategies — IllegalAccessException
// always becomes UnsupportedOperationException (signaling "method exists but can't be
// called"), and InvocationTargetException is always unwrapped to its cause. This
// normalization is critical for CompositeStrategy's fallback logic which catches
// UnsupportedOperationException to trigger strategy switching.
//
// CROSS-CUTTING: Foundational reflection utility consumed by LegacyStrategy,
// ModernStrategy, and CompositeStrategy within this package. The Loader interface is
// also used for testing SecurityManagerCompatibility strategy selection. Not consumed
// outside of common/internals/ — this is purely internal plumbing.
class ReflectiveStrategy {

    // DECISION: IllegalAccessException→UnsupportedOperationException mapping enables
    // CompositeStrategy.performAction() to catch UnsupportedOperationException and switch
    // to fallback strategy. This happens when the JRE degrades AccessController (e.g.,
    // Java 17 with --illegal-access=deny). InvocationTargetException is unwrapped to
    // preserve the original exception type for callers.
    static Object invoke(Method method, Object obj, Object... args) {
        try {
            return method.invoke(obj, args);
        } catch (IllegalAccessException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        }
    }

    // DECISION: Generic checked exception variant using Class<T> parameter for type-safe
    // exception rethrowing. Alternative: Catch all exceptions as RuntimeException.
    // Rationale: LegacyStrategy.callAs() needs to propagate PrivilegedActionException
    // (checked) while ModernStrategy.callAs() needs CompletionException — this method
    // handles both via the generic type parameter.
    static <T extends Exception> Object invokeChecked(Method method, Class<T> ex, Object obj, Object... args) throws T {
        try {
            return method.invoke(obj, args);
        } catch (IllegalAccessException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (ex.isInstance(cause)) {
                throw ex.cast(cause);
            } else if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        }
    }

    /**
     * Interface to allow mocking out classloading infrastructure. This is used to test reflective operations.
     */
    // DECISION: Loader interface abstracts Class.forName() for testability. Alternative:
    // Direct Class.forName() calls in strategy constructors. Rationale: Tests can provide
    // mock Loaders that simulate ClassNotFoundException or return mock classes, enabling
    // comprehensive testing of the CompositeStrategy fallback chain without manipulating
    // the actual JRE classpath.
    interface Loader {
        Class<?> loadClass(String className) throws ClassNotFoundException;

        static Loader forName() {
            return className -> Class.forName(className, true, Loader.class.getClassLoader());
        }
    }
}
