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

import java.lang.reflect.Method;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionException;

import javax.security.auth.Subject;

/**
 * This class implements reflective access to the deprecated-for-removal methods of AccessController and Subject.
 * <p>Instantiating this class may fail if any of the required classes or methods are not found.
 * Method invocations for this class may fail with {@link UnsupportedOperationException} if all methods are found,
 * but the operation is not permitted to be invoked.
 * <p>This class is expected to be instantiable in JRE >=8 until the removal finally takes place.
 */
// CROSS-CUTTING: Implements SecurityManagerCompatibility for JRE <=17 using deprecated
// AccessController.doPrivileged() and Subject.doAs(). Consumed indirectly by all SASL/Kerberos
// authentication code paths via CompositeStrategy. Per KIP-1006, this strategy will become
// unreachable after the JDK removes AccessController entirely.
// DECISION: Reflective access to deprecated AccessController/Subject.doAs APIs rather than
// direct method calls. Alternative: Direct compile-time references. Rationale: Direct
// references would produce deprecation warnings (JRE 17) or compilation errors (JRE 24+ after
// removal). Reflection allows the same compiled bytecode to work across JRE versions —
// NoSuchMethodException at construction time triggers fallback to ModernStrategy.
@SuppressWarnings("unchecked")
class LegacyStrategy implements SecurityManagerCompatibility {

    private final Method doPrivileged;
    private final Method getContext;
    private final Method getSubject;
    private final Method doAs;

    // Visible for testing
    LegacyStrategy(ReflectiveStrategy.Loader loader) throws ClassNotFoundException, NoSuchMethodException {
        // DECISION: All four Method references (doPrivileged, getContext, getSubject, doAs) are
        // resolved eagerly at construction. If any resolution fails, the entire LegacyStrategy is
        // rejected and CompositeStrategy falls back. Alternative: Lazy resolution per method.
        // Rationale: Fail-fast avoids partial strategy state where some methods work and others don't.
        Class<?> accessController = loader.loadClass("java.security.AccessController");
        doPrivileged = accessController.getDeclaredMethod("doPrivileged", PrivilegedAction.class);
        getContext = accessController.getDeclaredMethod("getContext");
        Class<?> accessControlContext = loader.loadClass("java.security.AccessControlContext");
        Class<?> subject = loader.loadClass(Subject.class.getName());
        getSubject = subject.getDeclaredMethod("getSubject", accessControlContext);
        // Note that the Subject class isn't deprecated or removed, so reference it as an argument type.
        // This allows for mocking out the method implementation while still accepting Subject instances as arguments.
        // DECISION: Uses Subject.class.getName() for loadClass() to get the mock-compatible version,
        // but Subject.class directly as argument type for doAs(). This split enables tests to mock
        // the method implementation while preserving type-safe Subject parameter passing at runtime.
        doAs = subject.getDeclaredMethod("doAs", Subject.class, PrivilegedExceptionAction.class);
    }

    @Override
    public <T> T doPrivileged(PrivilegedAction<T> action) {
        return (T) ReflectiveStrategy.invoke(doPrivileged, null, action);
    }

    /**
     * @return the result of AccessController.getContext(), of type AccessControlContext
     */
    private Object getContext() {
        return ReflectiveStrategy.invoke(getContext, null);
    }

    /**
     * @param context The current AccessControlContext
     * @return The result of Subject.getSubject(AccessControlContext)
     */
    private Subject getSubject(Object context) {
        return (Subject) ReflectiveStrategy.invoke(getSubject, null, context);
    }

    @Override
    public Subject current() {
        return getSubject(getContext());
    }

    /**
     * @return The result of Subject.doAs(Subject, PrivilegedExceptionAction)
     */
    private <T> T doAs(Subject subject, PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        return (T) ReflectiveStrategy.invokeChecked(doAs, PrivilegedActionException.class, null, subject, action);
    }

    // DECISION: Adapts Callable→PrivilegedExceptionAction via method reference (callable::call)
    // to bridge the modern Callable-based API to the legacy PrivilegedExceptionAction-based API.
    // PrivilegedActionException is unwrapped to CompletionException to match the
    // SecurityManagerCompatibility contract.
    @Override
    public <T> T callAs(Subject subject, Callable<T> callable) throws CompletionException {
        try {
            return doAs(subject, callable::call);
        } catch (PrivilegedActionException e) {
            throw new CompletionException(e.getCause());
        }
    }
}
