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
 * This is a compatibility class to provide dual-support for JREs with and without SecurityManager support.
 * <p>Users should call {@link #get()} to retrieve a singleton instance, and call instance methods
 * {@link #doPrivileged(PrivilegedAction)}, {@link #current()}, and {@link #callAs(Subject, Callable)}.
 * <p>This class's motivation and expected behavior is defined in
 * <a href="https://cwiki.apache.org/confluence/display/KAFKA/KIP-1006%3A+Remove+SecurityManager+Support">KIP-1006</a>
 */
// DECISION: Interface-based abstraction (KIP-1006) for SecurityManager/Subject APIs that
// are being removed across JDK versions. Three strategies implement this interface:
// LegacyStrategy (JRE 8-17: AccessController + Subject.doAs), ModernStrategy (JRE 18+:
// Subject.current + Subject.callAs), and UnsupportedStrategy (fallback diagnostic).
// Alternative: Preprocessor-style conditional compilation or multi-release JAR.
// Rationale: Strategy pattern with runtime detection is simpler to build, test, and
// maintain in Kafka's Gradle build system. A single compiled artifact works across all
// supported JRE versions without build-time JRE detection.
//
// CROSS-CUTTING: Public entry point for all JRE security API abstraction in Kafka.
// Consumed by common/security/authenticator/SaslServerAuthenticator (SASL authentication),
// common/security/authenticator/SaslClientAuthenticator (client auth),
// common/security/kerberos/KerberosLogin (TGT refresh with Subject context),
// and connect/runtime/ (connector plugin privileged operations). Any code that needs
// AccessController.doPrivileged(), Subject.getSubject()/current(), or Subject.doAs()/callAs()
// MUST use this interface — direct JDK API calls will break on future JRE versions.
// Contract: get() never returns null; thread-safe; may silently switch strategies on
// first call if legacy APIs are degraded.
public interface SecurityManagerCompatibility {

    /**
     * @return an implementation of this interface which conforms to the functionality available in the current JRE.
     */
    // DECISION: Static factory returning CompositeStrategy.INSTANCE singleton. Alternative:
    // Service provider interface (SPI) with META-INF/services. Rationale: The strategy
    // selection is fully deterministic based on JRE reflection — no user configuration or
    // extensibility needed. Direct singleton reference is simpler and avoids SPI classloading
    // overhead in the authentication hot path.
    static SecurityManagerCompatibility get() {
        return CompositeStrategy.INSTANCE;
    }

    // DECISION: doPrivileged() is included in the interface even though the modern JRE makes
    // it a no-op (pass-through). Alternative: Remove doPrivileged from the interface and
    // replace call sites with direct action.run(). Rationale: Maintaining the method in the
    // interface preserves the calling convention across all JRE versions — call sites don't
    // need conditional logic. The ModernStrategy implementation simply calls action.run().
    /**
     * Performs the specified {@code PrivilegedAction} with privileges
     * enabled. The action is performed with <i>all</i> of the permissions
     * possessed by the caller's protection domain.
     *
     * <p> If the action's {@code run} method throws an (unchecked)
     * exception, it will propagate through this method.
     *
     * <p> Note that any DomainCombiner associated with the current
     * AccessControlContext will be ignored while the action is performed.
     *
     * @param <T> the type of the value returned by the PrivilegedAction's
     *            {@code run} method.
     *
     * @param action the action to be performed.
     *
     * @return the value returned by the action's {@code run} method.
     *
     * @exception NullPointerException if the action is {@code null}
     * @see java.security.AccessController#doPrivileged(PrivilegedAction)
     */
    <T> T doPrivileged(PrivilegedAction<T> action);

    /**
     * Returns the current subject.
     * <p>
     * The current subject is installed by the {@link #callAs} method.
     * When {@code callAs(subject, action)} is called, {@code action} is
     * executed with {@code subject} as its current subject which can be
     * retrieved by this method. After {@code action} is finished, the current
     * subject is reset to its previous value. The current
     * subject is {@code null} before the first call of {@code callAs()}.
     *
     * @return the current subject, or {@code null} if a current subject is
     *         not installed or the current subject is set to {@code null}.
     * @see #callAs(Subject, Callable)
     * @see Subject#current()
     * @see Subject#callAs(Subject, Callable)
     */
    Subject current();

    /**
     * Executes a {@code Callable} with {@code subject} as the
     * current subject.
     *
     * @param subject the {@code Subject} that the specified {@code action}
     *                will run as.  This parameter may be {@code null}.
     * @param action the code to be run with {@code subject} as its current
     *               subject. Must not be {@code null}.
     * @param <T> the type of value returned by the {@code call} method
     *            of {@code action}
     * @return the value returned by the {@code call} method of {@code action}
     * @throws NullPointerException if {@code action} is {@code null}
     * @throws CompletionException if {@code action.call()} throws an exception.
     *      The cause of the {@code CompletionException} is set to the exception
     *      thrown by {@code action.call()}.
     * @see #current()
     * @see Subject#current()
     * @see Subject#callAs(Subject, Callable)
     */
    <T> T callAs(Subject subject, Callable<T> action) throws CompletionException;
}
