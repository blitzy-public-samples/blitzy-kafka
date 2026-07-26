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
package org.apache.kafka.streams.kstream.internals;

import org.apache.kafka.common.errors.AuthenticationException;
import org.apache.kafka.common.errors.AuthorizationException;
import org.apache.kafka.common.errors.RetriableException;
import org.apache.kafka.streams.errors.ErrorHandlerContext;
import org.apache.kafka.streams.errors.TaskCorruptedException;
import org.apache.kafka.streams.errors.TaskMigratedException;

/**
 * Centralized, single-source-of-truth classifier that decides whether a failure is <em>eligible</em> to be routed
 * to a Dead Letter Queue (DLQ) topic by the opt-in, DSL-level DLQ layer. The three DLQ-aware decorators in
 * {@link DeadLetterQueueExceptionHandlerDecorator} consult these methods before dead-lettering a record, so the
 * eligibility boundary is defined exactly once rather than being scattered (and inconsistently applied) across the
 * deserialization, processing, and production paths.
 *
 * <p>Two categories of failure are <strong>always excluded</strong> from DLQ routing, on every path:
 * <ul>
 *     <li><em>Retriable</em> failures ({@link RetriableException}, e.g. a produce timeout). Dead-lettering a
 *         transient failure would prematurely give up on a record that the producer's own retry configuration can
 *         still deliver; such failures stay on the existing retry path. This matches the established
 *         "retry-before-dead-letter" pattern so that only irrecoverable records reach the DLQ.</li>
 *     <li><em>Fatal / framework</em> failures — see {@link #isFatal(Throwable)}. These indicate a broken
 *         application, a lost/rebalanced task, corrupted state, or a security/authorization problem; none of them
 *         is a "poison record" that dead-lettering could remediate, and swallowing them would hide a serious
 *         condition or violate the processing guarantees, so they must propagate unchanged.</li>
 * </ul>
 *
 * <p>The class is stateless (only {@code static} methods) and therefore thread-safe, which is required because
 * classification happens concurrently across {@code StreamThread} instances. It is package-private because it is an
 * internal detail of the {@code kstream.internals} DLQ layer.
 */
final class DeadLetterQueueEligibility {

    /**
     * Guards the {@link #isFatal(Throwable)} cause-chain walk against pathologically deep or (via broken custom
     * exceptions) cyclic chains. A depth of 50 comfortably exceeds any realistic wrapping while keeping the walk
     * bounded on the failure branch.
     */
    private static final int MAX_CAUSE_DEPTH = 50;

    private DeadLetterQueueEligibility() {
        // stateless classifier; not instantiable
    }

    /**
     * Return whether {@code throwable}, or any exception in its {@code cause} chain, is a fatal/framework failure
     * that must never be dead-lettered. The chain is walked (bounded by {@link #MAX_CAUSE_DEPTH}, with a self-cause
     * break) because the triggering exception is frequently a wrapper (for example a {@code StreamsException}
     * carrying the true cause).
     *
     * <p>The following are treated as fatal:
     * <ul>
     *     <li>{@link Error} — JVM-level failures (e.g. {@code OutOfMemoryError});</li>
     *     <li>{@link TaskMigratedException} — the task was reassigned; the thread must relinquish it;</li>
     *     <li>{@link TaskCorruptedException} — local state is corrupted and must be recovered;</li>
     *     <li>{@link AuthenticationException} / {@link AuthorizationException} — a security/ACL problem that
     *         dead-lettering cannot fix and that must surface to operators.</li>
     * </ul>
     *
     * @param throwable the failure to classify (may be {@code null})
     * @return {@code true} if the failure is fatal/framework and must propagate rather than be dead-lettered
     */
    static boolean isFatal(final Throwable throwable) {
        Throwable cause = throwable;
        int depth = 0;
        while (cause != null && depth < MAX_CAUSE_DEPTH) {
            if (cause instanceof Error
                || cause instanceof TaskMigratedException
                || cause instanceof TaskCorruptedException
                || cause instanceof AuthenticationException
                || cause instanceof AuthorizationException) {
                return true;
            }
            if (cause == cause.getCause()) {
                // defensive: a self-referential cause would otherwise loop until the depth guard
                break;
            }
            cause = cause.getCause();
            depth++;
        }
        return false;
    }

    /**
     * @param throwable the failure to classify (may be {@code null})
     * @return {@code true} if the failure is a {@link RetriableException} and should stay on the producer retry
     *         path instead of being dead-lettered
     */
    static boolean isRetriable(final Throwable throwable) {
        return throwable instanceof RetriableException;
    }

    /**
     * Deserialization-path eligibility. Every exception surfaced to the deserialization handler denotes a record
     * that could not be deserialized (a poison record), so it is eligible unless it is {@linkplain #isFatal fatal}.
     *
     * @param exception the deserialization failure
     * @return {@code true} if the failed record should be dead-lettered
     */
    static boolean isDeserializationEligible(final Exception exception) {
        return !isFatal(exception);
    }

    /**
     * Processing-path eligibility. A processing failure is eligible only when it is a user
     * {@link RuntimeException} (checked exceptions cannot escape user {@code Processor}/{@code Transformer} code),
     * is not {@linkplain #isFatal fatal}, and is tied to a real source record (see {@link #hasSourceRecord}).
     * Failures raised out-of-band — most notably from a punctuation callback — have no originating record to
     * dead-letter and are therefore excluded.
     *
     * @param exception the processing failure
     * @param context   the error handler context of the failure
     * @return {@code true} if the failed record should be dead-lettered
     */
    static boolean isProcessingEligible(final Exception exception, final ErrorHandlerContext context) {
        return exception instanceof RuntimeException && !isFatal(exception) && hasSourceRecord(context);
    }

    /**
     * Production-path eligibility for a broker/produce failure. Eligible unless the failure is
     * {@linkplain #isRetriable retriable} (kept on the retry path) or {@linkplain #isFatal fatal}.
     *
     * @param exception the production failure
     * @return {@code true} if the failed record should be dead-lettered
     */
    static boolean isProductionEligible(final Exception exception) {
        return !isRetriable(exception) && !isFatal(exception);
    }

    /**
     * Production-path eligibility for a serialization failure. A serialization failure is inherently
     * non-retriable, so it is eligible unless {@linkplain #isFatal fatal}.
     *
     * @param exception the serialization failure
     * @return {@code true} if the failed record should be dead-lettered
     */
    static boolean isSerializationEligible(final Exception exception) {
        return !isFatal(exception);
    }

    /**
     * Return whether the error context describes a real source record. During a punctuation callback (or while
     * processing a record forwarded by one, or on other "out-of-band" invocations) the context carries no source
     * topic and its partition/offset are the {@code -1} sentinel; in that case there is no original record whose
     * bytes could be dead-lettered.
     *
     * @param context the error handler context
     * @return {@code true} if a source topic/partition/offset are available
     */
    private static boolean hasSourceRecord(final ErrorHandlerContext context) {
        return context != null
            && context.topic() != null
            && context.partition() >= 0
            && context.offset() >= 0;
    }
}
