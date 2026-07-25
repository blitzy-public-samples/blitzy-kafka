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

import java.util.Objects;

/**
 * Options for the opt-in, DSL-level Dead Letter Queue (DLQ) capability enabled via
 * {@link KStream#withDeadLetterQueue(String, DeadLetterQueueOptions)}.
 *
 * <p>A {@code DeadLetterQueueOptions} instance captures three settings that control how records that fail
 * deserialization or processing are routed to a configured DLQ topic:
 * <ul>
 *     <li>the DLQ topic name (see {@link #dlqTopic()});</li>
 *     <li>the maximum DLQ record value size in bytes, with {@link #NO_MAX_RECORD_SIZE} meaning "no limit"
 *         (see {@link #maxRecordSize()});</li>
 *     <li>whether the {@code dlq.*} diagnostic headers are attached to DLQ records, enabled by default
 *         (see {@link #includeHeaders()}).</li>
 * </ul>
 *
 * <p>Instances are immutable and therefore thread-safe: all fields are {@code final}, there are no setters, and
 * every {@code with*} method returns a brand-new instance rather than mutating the receiver. This is required
 * because the same options object may be read concurrently across multiple {@code StreamThread}s while a topology
 * is running. Build an instance with the {@link #with(String)} factory and refine it with
 * {@link #withMaxRecordSize(int)} and {@link #withIncludeHeaders(boolean)}, for example:
 *
 * <pre>{@code
 * DeadLetterQueueOptions options = DeadLetterQueueOptions.with("my-dlq-topic")
 *                                                        .withMaxRecordSize(1024 * 1024)
 *                                                        .withIncludeHeaders(true);
 * }</pre>
 *
 * @see KStream#withDeadLetterQueue(String, DeadLetterQueueOptions)
 */
public class DeadLetterQueueOptions {

    /**
     * Sentinel value for {@link #maxRecordSize()} meaning "no size limit"; when configured with this value, DLQ
     * record values are never truncated. This is the default applied by {@link #with(String)}.
     */
    public static final int NO_MAX_RECORD_SIZE = Integer.MAX_VALUE;

    private final String dlqTopic;
    private final int maxRecordSize;
    private final boolean includeHeaders;

    private DeadLetterQueueOptions(final String dlqTopic,
                                   final int maxRecordSize,
                                   final boolean includeHeaders) {
        this.dlqTopic = dlqTopic;
        this.maxRecordSize = maxRecordSize;
        this.includeHeaders = includeHeaders;
    }

    /**
     * Copy constructor that creates a new {@code DeadLetterQueueOptions} with the same settings as the supplied
     * instance. Provided for parity with the other DSL options objects (for example {@code Produced} and
     * {@code Repartitioned}) so that subclasses within this package can share the immutable state.
     *
     * @param options the options instance to copy; its {@code dlqTopic}, {@code maxRecordSize} and
     *                {@code includeHeaders} values are copied
     */
    protected DeadLetterQueueOptions(final DeadLetterQueueOptions options) {
        this(options.dlqTopic, options.maxRecordSize, options.includeHeaders);
    }

    /**
     * Create a {@code DeadLetterQueueOptions} for the given DLQ topic, with no record-size limit
     * ({@link #NO_MAX_RECORD_SIZE}) and header inclusion enabled.
     *
     * @param dlqTopic the name of the (pre-existing) Dead Letter Queue topic
     * @return a new {@code DeadLetterQueueOptions} instance
     */
    public static DeadLetterQueueOptions with(final String dlqTopic) {
        return new DeadLetterQueueOptions(dlqTopic, NO_MAX_RECORD_SIZE, true);
    }

    /**
     * Return a new instance configured with the provided maximum DLQ record (value) size in bytes. Use
     * {@link #NO_MAX_RECORD_SIZE} (or a negative value) to indicate no limit. This method never mutates the
     * receiver; it returns a new {@code DeadLetterQueueOptions} that copies the existing topic and
     * header-inclusion settings.
     *
     * @param maxRecordSize the maximum record value size in bytes
     * @return a new {@code DeadLetterQueueOptions} instance
     */
    public DeadLetterQueueOptions withMaxRecordSize(final int maxRecordSize) {
        return new DeadLetterQueueOptions(dlqTopic, maxRecordSize, includeHeaders);
    }

    /**
     * Return a new instance configured with whether the {@code dlq.*} diagnostic headers are added to DLQ records.
     * This method never mutates the receiver; it returns a new {@code DeadLetterQueueOptions} that copies the
     * existing topic and max-record-size settings.
     *
     * @param includeHeaders whether to include the {@code dlq.*} headers
     * @return a new {@code DeadLetterQueueOptions} instance
     */
    public DeadLetterQueueOptions withIncludeHeaders(final boolean includeHeaders) {
        return new DeadLetterQueueOptions(dlqTopic, maxRecordSize, includeHeaders);
    }

    /**
     * @return the configured Dead Letter Queue topic name
     */
    public String dlqTopic() {
        return dlqTopic;
    }

    /**
     * @return the maximum DLQ record value size in bytes; {@link #NO_MAX_RECORD_SIZE} means no limit
     */
    public int maxRecordSize() {
        return maxRecordSize;
    }

    /**
     * @return whether the {@code dlq.*} diagnostic headers are added to DLQ records (default {@code true})
     */
    public boolean includeHeaders() {
        return includeHeaders;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final DeadLetterQueueOptions that = (DeadLetterQueueOptions) o;
        return maxRecordSize == that.maxRecordSize &&
               includeHeaders == that.includeHeaders &&
               Objects.equals(dlqTopic, that.dlqTopic);
    }

    @Override
    public int hashCode() {
        return Objects.hash(dlqTopic, maxRecordSize, includeHeaders);
    }

    @Override
    public String toString() {
        return "DeadLetterQueueOptions{" +
               "dlqTopic='" + dlqTopic + '\'' +
               ", maxRecordSize=" + maxRecordSize +
               ", includeHeaders=" + includeHeaders +
               '}';
    }
}
