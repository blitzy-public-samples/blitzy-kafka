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
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.errors.TimeoutException;
import org.apache.kafka.common.errors.TopicAuthorizationException;
import org.apache.kafka.streams.errors.ErrorHandlerContext;
import org.apache.kafka.streams.errors.TaskCorruptedException;
import org.apache.kafka.streams.errors.TaskMigratedException;
import org.apache.kafka.streams.errors.internals.DefaultErrorHandlerContext;
import org.apache.kafka.streams.processor.TaskId;

import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link DeadLetterQueueEligibility}, the single source of truth for which failures the opt-in DLQ
 * layer routes to a Dead Letter Queue topic. The tests pin the two always-excluded categories (retriable and
 * fatal/framework), the fatal cause-chain walk (including a self-referential-cause guard), and the per-path
 * eligibility contracts — in particular that a punctuation-origin processing failure (no source record) is
 * excluded.
 */
public class DeadLetterQueueEligibilityTest {

    private static ErrorHandlerContext recordContext() {
        // A real source record: topic present, partition/offset non-negative.
        return new DefaultErrorHandlerContext(
            null, "source-topic", 3, 42L, null, "node", new TaskId(0, 0), 1_000L, null, null);
    }

    private static ErrorHandlerContext punctuationContext() {
        // A punctuation-origin invocation: no source record (topic null, partition/offset == -1 sentinel).
        return new DefaultErrorHandlerContext(
            null, null, -1, -1, null, "node", new TaskId(0, 0), 1_000L, null, null);
    }

    // ---------------------------------------------------------------------------------------------------------
    // isFatal
    // ---------------------------------------------------------------------------------------------------------

    @Test
    public void shouldClassifyErrorAsFatalWhetherDirectOrWrapped() {
        assertTrue(DeadLetterQueueEligibility.isFatal(new OutOfMemoryError("boom")));
        assertTrue(DeadLetterQueueEligibility.isFatal(
            new RuntimeException("wrapper", new StackOverflowError("deep"))));
    }

    @Test
    public void shouldClassifyFrameworkAndSecurityExceptionsAsFatal() {
        assertTrue(DeadLetterQueueEligibility.isFatal(new TaskMigratedException("migrated")));
        assertTrue(DeadLetterQueueEligibility.isFatal(
            new TaskCorruptedException(Collections.singleton(new TaskId(0, 0)))));
        assertTrue(DeadLetterQueueEligibility.isFatal(new TopicAuthorizationException("no acl")));
        assertTrue(DeadLetterQueueEligibility.isFatal(new AuthenticationException("bad creds")));
    }

    @Test
    public void shouldNotClassifyOrdinaryRuntimeExceptionOrNullAsFatal() {
        assertFalse(DeadLetterQueueEligibility.isFatal(new IllegalStateException("ordinary")));
        assertFalse(DeadLetterQueueEligibility.isFatal(new SerializationException("bad bytes")));
        assertFalse(DeadLetterQueueEligibility.isFatal(null));
    }

    @Test
    public void shouldTerminateFatalWalkOnSelfReferentialCause() {
        // A broken custom exception whose cause is itself must not loop the cause-chain walk.
        final RuntimeException selfCaused = new RuntimeException("self") {
            @Override
            public synchronized Throwable getCause() {
                return this;
            }
        };
        assertFalse(DeadLetterQueueEligibility.isFatal(selfCaused));
    }

    // ---------------------------------------------------------------------------------------------------------
    // isRetriable
    // ---------------------------------------------------------------------------------------------------------

    @Test
    public void shouldClassifyRetriableException() {
        assertTrue(DeadLetterQueueEligibility.isRetriable(new TimeoutException("retry me")));
        assertFalse(DeadLetterQueueEligibility.isRetriable(new IllegalStateException("permanent")));
    }

    // ---------------------------------------------------------------------------------------------------------
    // per-path eligibility
    // ---------------------------------------------------------------------------------------------------------

    @Test
    public void shouldMakeNonFatalDeserializationFailureEligible() {
        assertTrue(DeadLetterQueueEligibility.isDeserializationEligible(new SerializationException("bad")));
        assertTrue(DeadLetterQueueEligibility.isDeserializationEligible(new RuntimeException("custom deser")));
        assertFalse(DeadLetterQueueEligibility.isDeserializationEligible(
            new RuntimeException("wrapper", new OutOfMemoryError("fatal"))));
    }

    @Test
    public void shouldMakeProcessingFailureEligibleOnlyWithSourceRecordAndRuntimeException() {
        assertTrue(DeadLetterQueueEligibility.isProcessingEligible(
            new RuntimeException("boom"), recordContext()));
        // punctuation-origin failure: no source record to dead-letter
        assertFalse(DeadLetterQueueEligibility.isProcessingEligible(
            new RuntimeException("in punctuate"), punctuationContext()));
        // fatal failure is excluded even with a source record
        assertFalse(DeadLetterQueueEligibility.isProcessingEligible(
            new RuntimeException("wrapper", new OutOfMemoryError("fatal")), recordContext()));
        // a non-RuntimeException is excluded
        assertFalse(DeadLetterQueueEligibility.isProcessingEligible(
            new Exception("checked"), recordContext()));
    }

    @Test
    public void shouldExcludeRetriableAndFatalFromProductionEligibility() {
        assertTrue(DeadLetterQueueEligibility.isProductionEligible(new IllegalStateException("non-retriable")));
        assertFalse(DeadLetterQueueEligibility.isProductionEligible(new TimeoutException("retriable")));
        assertFalse(DeadLetterQueueEligibility.isProductionEligible(new TopicAuthorizationException("no acl")));
    }

    @Test
    public void shouldMakeNonFatalSerializationFailureEligible() {
        assertTrue(DeadLetterQueueEligibility.isSerializationEligible(new SerializationException("bad")));
        assertFalse(DeadLetterQueueEligibility.isSerializationEligible(
            new RuntimeException("wrapper", new OutOfMemoryError("fatal"))));
    }
}
