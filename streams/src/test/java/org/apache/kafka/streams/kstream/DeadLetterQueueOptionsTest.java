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
package org.apache.kafka.streams.kstream;

import org.apache.kafka.common.errors.InvalidTopicException;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DeadLetterQueueOptionsTest {

    private static final String DLQ_TOPIC = "dlq-topic";

    @Test
    public void shouldUseDefaultsWhenCreatedWithTopicOnly() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC);

        assertEquals(DLQ_TOPIC, options.dlqTopic());
        assertEquals(DeadLetterQueueOptions.NO_MAX_RECORD_SIZE, options.maxRecordSize());
        assertEquals(Integer.MAX_VALUE, options.maxRecordSize());
        assertTrue(options.includeHeaders());
    }

    @Test
    public void shouldReturnNewInstanceAndNotMutateOriginalWhenSettingMaxRecordSize() {
        final DeadLetterQueueOptions original = DeadLetterQueueOptions.with(DLQ_TOPIC);
        final DeadLetterQueueOptions updated = original.withMaxRecordSize(1024);

        assertNotSame(original, updated);
        assertEquals(DeadLetterQueueOptions.NO_MAX_RECORD_SIZE, original.maxRecordSize());
        assertEquals(1024, updated.maxRecordSize());
    }

    @Test
    public void shouldReturnNewInstanceAndNotMutateOriginalWhenSettingIncludeHeaders() {
        final DeadLetterQueueOptions original = DeadLetterQueueOptions.with(DLQ_TOPIC);
        final DeadLetterQueueOptions updated = original.withIncludeHeaders(false);

        assertNotSame(original, updated);
        assertTrue(original.includeHeaders());
        assertFalse(updated.includeHeaders());
    }

    @Test
    public void shouldCopyUnrelatedFieldsWhenSettingMaxRecordSize() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC)
            .withIncludeHeaders(false)
            .withMaxRecordSize(2048);

        assertEquals(DLQ_TOPIC, options.dlqTopic());
        assertEquals(2048, options.maxRecordSize());
        assertFalse(options.includeHeaders());
    }

    @Test
    public void shouldApplyChainedBuilderValues() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC)
            .withMaxRecordSize(512)
            .withIncludeHeaders(false);

        assertEquals(DLQ_TOPIC, options.dlqTopic());
        assertEquals(512, options.maxRecordSize());
        assertFalse(options.includeHeaders());
    }

    @Test
    public void shouldBeEqualWithSameHashCodeWhenAllFieldsMatch() {
        final DeadLetterQueueOptions a = DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(256);
        final DeadLetterQueueOptions b = DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(256);

        assertNotSame(a, b);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    public void shouldNotBeEqualWhenTopicDiffers() {
        final DeadLetterQueueOptions a = DeadLetterQueueOptions.with("topic-a");
        final DeadLetterQueueOptions b = DeadLetterQueueOptions.with("topic-b");

        assertNotEquals(a, b);
    }

    @Test
    public void shouldNotBeEqualWhenMaxRecordSizeDiffers() {
        final DeadLetterQueueOptions a = DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(128);
        final DeadLetterQueueOptions b = DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(256);

        assertNotEquals(a, b);
    }

    @Test
    public void shouldNotBeEqualWhenIncludeHeadersDiffers() {
        final DeadLetterQueueOptions a = DeadLetterQueueOptions.with(DLQ_TOPIC).withIncludeHeaders(true);
        final DeadLetterQueueOptions b = DeadLetterQueueOptions.with(DLQ_TOPIC).withIncludeHeaders(false);

        assertNotEquals(a, b);
    }

    @Test
    public void shouldIncludeAllFieldsInToString() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC)
            .withMaxRecordSize(4096)
            .withIncludeHeaders(false);

        // toString must expose every field so operators can inspect the effective DLQ configuration in logs.
        assertEquals(
            "DeadLetterQueueOptions{dlqTopic='" + DLQ_TOPIC + "', maxRecordSize=4096, includeHeaders=false}",
            options.toString());
    }

    @Test
    public void shouldBeAClosedFinalValueType() {
        // The options object is a closed, immutable value type: making it final prevents a subclass from
        // overriding accessors or the class-exact equals/hashCode contract, which is required for safe concurrent
        // sharing across StreamThreads. This asserts the design contract rather than relying on the compiler.
        assertTrue(java.lang.reflect.Modifier.isFinal(DeadLetterQueueOptions.class.getModifiers()),
            "DeadLetterQueueOptions must be final so the immutable value contract cannot be subverted");
    }

    @Test
    public void shouldRejectNullTopic() {
        assertThrows(NullPointerException.class, () -> DeadLetterQueueOptions.with(null));
    }

    @Test
    public void shouldRejectBlankTopic() {
        assertThrows(IllegalArgumentException.class, () -> DeadLetterQueueOptions.with(""));
        assertThrows(IllegalArgumentException.class, () -> DeadLetterQueueOptions.with("   "));
    }

    @Test
    public void shouldRejectInvalidTopicName() {
        // The canonical Kafka topic validator rejects illegal characters; DeadLetterQueueOptions.with must apply
        // it so an invalid DLQ topic fails fast at configuration time rather than at produce time.
        assertThrows(InvalidTopicException.class, () -> DeadLetterQueueOptions.with("has spaces"));
        assertThrows(InvalidTopicException.class, () -> DeadLetterQueueOptions.with("bad/topic"));
    }

    @Test
    public void shouldRejectNonPositiveMaxRecordSize() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC);
        assertThrows(IllegalArgumentException.class, () -> options.withMaxRecordSize(0));
        assertThrows(IllegalArgumentException.class, () -> options.withMaxRecordSize(-1));
    }

    @Test
    public void shouldAcceptNoMaxRecordSizeSentinelAndPositiveValues() {
        assertEquals(DeadLetterQueueOptions.NO_MAX_RECORD_SIZE,
            DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(DeadLetterQueueOptions.NO_MAX_RECORD_SIZE).maxRecordSize());
        assertEquals(1, DeadLetterQueueOptions.with(DLQ_TOPIC).withMaxRecordSize(1).maxRecordSize());
    }

    @Test
    public void shouldNotBeEqualToNull() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC);

        assertNotEquals(options, null);
    }

    @Test
    public void shouldNotBeEqualToInstanceOfDifferentType() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with(DLQ_TOPIC);

        assertNotEquals(options, DLQ_TOPIC);
        assertNotEquals(options, new Object());
    }
}
