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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link DeadLetterQueueOptions}: default values from the {@link DeadLetterQueueOptions#with(String)}
 * factory, immutability of the {@code with*} builder methods, and {@code equals}/{@code hashCode} semantics.
 */
public class DeadLetterQueueOptionsTest {

    @Test
    public void shouldApplyDefaultsFromFactory() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with("dlq");

        assertEquals("dlq", options.dlqTopic());
        // default: no size limit
        assertEquals(DeadLetterQueueOptions.NO_MAX_RECORD_SIZE, options.maxRecordSize());
        assertEquals(Integer.MAX_VALUE, DeadLetterQueueOptions.NO_MAX_RECORD_SIZE);
        // default: headers included
        assertTrue(options.includeHeaders());
    }

    @Test
    public void shouldSetMaxRecordSizeWithoutMutatingReceiver() {
        final DeadLetterQueueOptions base = DeadLetterQueueOptions.with("dlq");
        final DeadLetterQueueOptions withSize = base.withMaxRecordSize(1024);

        assertNotSame(base, withSize);
        assertEquals(1024, withSize.maxRecordSize());
        // receiver is unchanged (immutability)
        assertEquals(DeadLetterQueueOptions.NO_MAX_RECORD_SIZE, base.maxRecordSize());
        // other fields are copied through
        assertEquals("dlq", withSize.dlqTopic());
        assertTrue(withSize.includeHeaders());
    }

    @Test
    public void shouldSetIncludeHeadersWithoutMutatingReceiver() {
        final DeadLetterQueueOptions base = DeadLetterQueueOptions.with("dlq");
        final DeadLetterQueueOptions withoutHeaders = base.withIncludeHeaders(false);

        assertNotSame(base, withoutHeaders);
        assertEquals(false, withoutHeaders.includeHeaders());
        // receiver is unchanged (immutability)
        assertTrue(base.includeHeaders());
        // other fields are copied through
        assertEquals("dlq", withoutHeaders.dlqTopic());
        assertEquals(DeadLetterQueueOptions.NO_MAX_RECORD_SIZE, withoutHeaders.maxRecordSize());
    }

    @Test
    public void shouldChainBuilderMethods() {
        final DeadLetterQueueOptions options = DeadLetterQueueOptions.with("dlq")
            .withMaxRecordSize(2048)
            .withIncludeHeaders(false);

        assertEquals("dlq", options.dlqTopic());
        assertEquals(2048, options.maxRecordSize());
        assertEquals(false, options.includeHeaders());
    }

    @Test
    public void shouldImplementEqualsAndHashCode() {
        final DeadLetterQueueOptions a = DeadLetterQueueOptions.with("dlq").withMaxRecordSize(512);
        final DeadLetterQueueOptions b = DeadLetterQueueOptions.with("dlq").withMaxRecordSize(512);
        final DeadLetterQueueOptions differentTopic = DeadLetterQueueOptions.with("other").withMaxRecordSize(512);
        final DeadLetterQueueOptions differentSize = DeadLetterQueueOptions.with("dlq").withMaxRecordSize(256);
        final DeadLetterQueueOptions differentHeaders = DeadLetterQueueOptions.with("dlq")
            .withMaxRecordSize(512).withIncludeHeaders(false);

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, differentTopic);
        assertNotEquals(a, differentSize);
        assertNotEquals(a, differentHeaders);
    }
}
