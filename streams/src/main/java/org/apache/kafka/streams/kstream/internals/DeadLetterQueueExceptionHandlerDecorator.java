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

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.RetriableException;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.errors.DeserializationExceptionHandler;
import org.apache.kafka.streams.errors.ErrorHandlerContext;
import org.apache.kafka.streams.errors.ProcessingExceptionHandler;
import org.apache.kafka.streams.errors.ProductionExceptionHandler;
import org.apache.kafka.streams.errors.internals.DlqRecordBuilder;
import org.apache.kafka.streams.kstream.DeadLetterQueueOptions;
import org.apache.kafka.streams.processor.api.Record;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Internal, DLQ-aware decorators that layer the opt-in, DSL-level Dead Letter Queue (DLQ) capability on top of
 * the existing exception-handler extension points, following the "decorate, do not modify" principle: each
 * decorator <em>wraps</em> a configured (or default) handler, <em>delegates</em> to it to preserve its behaviour
 * and any records it produced, and only then — when DLQ is enabled for the wrapped node — augments the response
 * with a DLQ record built by {@link DlqRecordBuilder}. No public handler interface is modified.
 *
 * <p>This holder is non-instantiable; it exposes three {@code public static} nested decorators, one per handler
 * contract, because {@link DeserializationExceptionHandler}, {@link ProductionExceptionHandler} and
 * {@link ProcessingExceptionHandler} each declare their own distinct nested {@code Response} / {@code Result}
 * types. Keeping each implementation in its own nested class lets the unqualified names {@code Response} and
 * {@code Result} resolve unambiguously to the interface each class implements. The nested classes are
 * {@code public static} so that the runtime wiring in {@code org.apache.kafka.streams.processor.internals}
 * (a different package) can attach them.
 *
 * <p>On a DLQ-eligible failure a decorator:
 * <ol>
 *     <li>invokes the wrapped delegate (a {@code null} delegate is treated as an implicit
 *         {@link DeserializationExceptionHandler.Response#resume() resume} for the deserialization and processing
 *         paths, and as a {@link ProductionExceptionHandler.Response#retry() retry} or
 *         {@link ProductionExceptionHandler.Response#fail() fail} for the production path depending on whether the
 *         exception is a {@link RetriableException});</li>
 *     <li>resolves the effective DLQ topic using the precedence
 *         <em>DSL topic &rarr; options topic &rarr; global default topic</em>;</li>
 *     <li>builds a {@code ProducerRecord<byte[], byte[]>} carrying the original key/value bytes plus the six
 *         {@code dlq.*} diagnostic headers via {@link DlqRecordBuilder}; and</li>
 *     <li>returns {@code Response.resume(merged)} so that a DLQ-routed failure never terminates the
 *         {@code StreamThread}.</li>
 * </ol>
 *
 * <p>Retriable production exceptions are deliberately <em>not</em> dead-lettered: when the delegate's result is
 * {@link ProductionExceptionHandler.Result#RETRY RETRY} the decorator returns that response verbatim so the
 * record stays on the producer retry path. When DLQ is not enabled for the node, every decorator returns the
 * delegate's response unchanged, guaranteeing byte-for-byte identical legacy behaviour for topologies that do not
 * opt in.
 *
 * <p>The authoritative {@code dlq-records-sent-total} metric and the per-write {@code WARN} log are emitted at the
 * runtime send sites in {@code org.apache.kafka.streams.processor.internals}, not here; this class only performs
 * an optional {@code DEBUG} trace when it routes a record. All decorators are effectively stateless apart from the
 * two global-default values captured in {@link #configure(Map) configure}, and they hold only an immutable
 * {@link DeadLetterQueueOptions}, {@code String}s, a {@code boolean} and the delegate handler, so they are safe to
 * share across concurrent {@code StreamThread} instances.
 */
public final class DeadLetterQueueExceptionHandlerDecorator {

    private static final Logger log = LoggerFactory.getLogger(DeadLetterQueueExceptionHandlerDecorator.class);

    private DeadLetterQueueExceptionHandlerDecorator() {
        // non-instantiable holder for the three nested decorators
    }

    /**
     * Resolve the effective DLQ topic name using the precedence <em>DSL topic &rarr; options topic &rarr; global
     * default topic</em>, returning the first non-{@code null} value, or {@code null} when none is configured.
     *
     * @param dslTopic           the topic supplied directly to the DSL {@code withDeadLetterQueue} call (may be null)
     * @param options            the DSL options, whose {@link DeadLetterQueueOptions#dlqTopic()} is consulted next
     *                           (may be null)
     * @param globalDefaultTopic the global {@code default.deadletterqueue.topic} value (may be null)
     * @return the resolved topic, or {@code null} if no topic is configured at any level
     */
    private static String resolveTopic(final String dslTopic,
            final DeadLetterQueueOptions options,
            final String globalDefaultTopic) {
        if (dslTopic != null) {
            return dslTopic;
        }
        if (options != null && options.dlqTopic() != null) {
            return options.dlqTopic();
        }
        return globalDefaultTopic;
    }

    /**
     * Determine whether the DLQ layer is active for a record. It is disabled whenever no topic could be resolved.
     * A DSL-level opt-in (a non-null {@code dslTopic} or {@code options}) always enables it; otherwise the
     * global-only path defers to the {@code default.deadletterqueue.enabled} switch.
     *
     * @param dslTopic             the DSL topic (non-null indicates an explicit opt-in)
     * @param options              the DSL options (non-null indicates an explicit opt-in)
     * @param resolvedTopic        the already-resolved effective topic (see {@link #resolveTopic})
     * @param globalDefaultEnabled the global {@code default.deadletterqueue.enabled} value
     * @return {@code true} if DLQ routing should occur, {@code false} otherwise
     */
    private static boolean isEnabled(final String dslTopic,
            final DeadLetterQueueOptions options,
            final String resolvedTopic,
            final boolean globalDefaultEnabled) {
        if (resolvedTopic == null) {
            return false;
        }
        if (dslTopic != null || options != null) {
            return true;
        }
        return globalDefaultEnabled;
    }

    /**
     * Return the effective options for a build. When no DSL options were supplied (the global-only path) a default
     * instance is created for the resolved topic so downstream code always has valid header-inclusion and
     * max-record-size settings.
     *
     * @param options       the DSL options, or {@code null} on the global-only path
     * @param resolvedTopic the resolved (non-null) topic used to seed default options
     * @return the DSL options when present, otherwise {@link DeadLetterQueueOptions#with(String)} defaults
     */
    private static DeadLetterQueueOptions effectiveOptions(final DeadLetterQueueOptions options,
            final String resolvedTopic) {
        return options != null ? options : DeadLetterQueueOptions.with(resolvedTopic);
    }

    /**
     * Read the global {@code default.deadletterqueue.topic} value from the supplied configuration map, mirroring
     * the read pattern used by the out-of-the-box handlers.
     *
     * @param configs the handler configuration map
     * @return the configured global default topic, or {@code null} when unset
     */
    private static String readGlobalTopic(final Map<String, ?> configs) {
        return configs.get(StreamsConfig.DEFAULT_DEAD_LETTER_QUEUE_TOPIC_CONFIG) != null
            ? String.valueOf(configs.get(StreamsConfig.DEFAULT_DEAD_LETTER_QUEUE_TOPIC_CONFIG))
            : null;
    }

    /**
     * Read the global {@code default.deadletterqueue.enabled} switch from the supplied configuration map.
     *
     * @param configs the handler configuration map
     * @return {@code true} only when the value is present and parses to {@code true}
     */
    private static boolean readGlobalEnabled(final Map<String, ?> configs) {
        return configs.get(StreamsConfig.DEFAULT_DEAD_LETTER_QUEUE_ENABLED_CONFIG) != null
            && Boolean.parseBoolean(String.valueOf(configs.get(StreamsConfig.DEFAULT_DEAD_LETTER_QUEUE_ENABLED_CONFIG)));
    }

    /**
     * Return a new mutable list containing the delegate's DLQ records followed by the newly built DLQ record. The
     * delegate list (which may be an unmodifiable view) is copied, so neither the input list nor the caller's state
     * is mutated.
     *
     * @param delegateRecords the records the wrapped delegate already produced (never {@code null})
     * @param dlqRecord       the DLQ record built by this layer
     * @return a new list holding the delegate records plus {@code dlqRecord}
     */
    private static List<ProducerRecord<byte[], byte[]>> merge(final List<ProducerRecord<byte[], byte[]>> delegateRecords,
            final ProducerRecord<byte[], byte[]> dlqRecord) {
        final List<ProducerRecord<byte[], byte[]>> merged = new ArrayList<>(delegateRecords);
        merged.add(dlqRecord);
        return merged;
    }

    /**
     * Build the DLQ record for a failed record, emitting an optional {@code DEBUG} trace. Delegates to
     * {@link DlqRecordBuilder#buildDeadLetterQueueRecord} with the {@link #effectiveOptions effective options}.
     *
     * @param topic     the resolved (non-null) DLQ topic
     * @param rawKey    the original key bytes (may be {@code null})
     * @param rawValue  the original value bytes (may be {@code null})
     * @param context   the error handler context of the failure
     * @param exception the exception that caused the failure
     * @param options   the DSL options (may be {@code null} on the global-only path)
     * @return the DLQ {@link ProducerRecord} to append to the handler response
     */
    private static ProducerRecord<byte[], byte[]> buildDlqRecord(final String topic,
            final byte[] rawKey,
            final byte[] rawValue,
            final ErrorHandlerContext context,
            final Exception exception,
            final DeadLetterQueueOptions options) {
        if (log.isDebugEnabled()) {
            log.debug("Routing failed record to dead letter queue topic '{}' (source topic: {}, partition: {}, "
                    + "offset: {}) due to {}",
                topic,
                context.topic(),
                context.partition(),
                context.offset(),
                exception.getClass().getName());
        }
        return DlqRecordBuilder.buildDeadLetterQueueRecord(topic, rawKey, rawValue, context, exception,
            effectiveOptions(options, topic));
    }

    /**
     * DLQ-aware decorator for the {@link DeserializationExceptionHandler} contract. On a deserialization failure it
     * routes the original record bytes to the configured DLQ topic and resumes processing, or returns the wrapped
     * delegate's response unchanged when DLQ is not enabled for the node.
     */
    public static class DeserializationDecorator implements DeserializationExceptionHandler {

        private final DeserializationExceptionHandler delegate;
        private final String dlqTopic;
        private final DeadLetterQueueOptions options;
        private String globalDefaultTopic;
        private boolean globalDefaultEnabled;

        /**
         * Create a decorator around the supplied deserialization handler.
         *
         * @param delegate the wrapped handler; may be {@code null}, in which case an implicit
         *                 {@link Response#resume()} with no records is assumed
         * @param dlqTopic the DSL-supplied DLQ topic, or {@code null} to fall back to options / global default
         * @param options  the immutable DSL options, or {@code null} to fall back to the global default
         */
        public DeserializationDecorator(final DeserializationExceptionHandler delegate,
                final String dlqTopic,
                final DeadLetterQueueOptions options) {
            this.delegate = delegate;
            this.dlqTopic = dlqTopic;
            this.options = options;
        }

        @Override
        public void configure(final Map<String, ?> configs) {
            if (delegate != null) {
                delegate.configure(configs);
            }
            globalDefaultTopic = readGlobalTopic(configs);
            globalDefaultEnabled = readGlobalEnabled(configs);
        }

        @Override
        public Response handleError(final ErrorHandlerContext context,
                final ConsumerRecord<byte[], byte[]> record,
                final Exception exception) {
            final Response delegateResponse = delegate == null
                ? Response.resume()
                : delegate.handleError(context, record, exception);
            final String topic = resolveTopic(dlqTopic, options, globalDefaultTopic);
            if (!isEnabled(dlqTopic, options, topic, globalDefaultEnabled)) {
                return delegateResponse;
            }
            final byte[] rawKey = context.sourceRawKey() != null ? context.sourceRawKey() : record.key();
            final byte[] rawValue = context.sourceRawValue() != null ? context.sourceRawValue() : record.value();
            final ProducerRecord<byte[], byte[]> dlqRecord =
                buildDlqRecord(topic, rawKey, rawValue, context, exception, options);
            return Response.resume(merge(delegateResponse.deadLetterQueueRecords(), dlqRecord));
        }
    }

    /**
     * DLQ-aware decorator for the {@link ProductionExceptionHandler} contract. It preserves the delegate's
     * {@link Result#RETRY RETRY} decisions verbatim so retriable produce errors stay on the producer retry path and
     * are never dead-lettered; for non-retriable failures it routes to the DLQ topic and resumes.
     */
    public static class ProductionDecorator implements ProductionExceptionHandler {

        private final ProductionExceptionHandler delegate;
        private final String dlqTopic;
        private final DeadLetterQueueOptions options;
        private String globalDefaultTopic;
        private boolean globalDefaultEnabled;

        /**
         * Create a decorator around the supplied production handler.
         *
         * @param delegate the wrapped handler; may be {@code null}, in which case a {@link Response#retry()} is
         *                 assumed for {@link RetriableException}s and a {@link Response#fail()} otherwise
         * @param dlqTopic the DSL-supplied DLQ topic, or {@code null} to fall back to options / global default
         * @param options  the immutable DSL options, or {@code null} to fall back to the global default
         */
        public ProductionDecorator(final ProductionExceptionHandler delegate,
                final String dlqTopic,
                final DeadLetterQueueOptions options) {
            this.delegate = delegate;
            this.dlqTopic = dlqTopic;
            this.options = options;
        }

        @Override
        public void configure(final Map<String, ?> configs) {
            if (delegate != null) {
                delegate.configure(configs);
            }
            globalDefaultTopic = readGlobalTopic(configs);
            globalDefaultEnabled = readGlobalEnabled(configs);
        }

        @Override
        public Response handleError(final ErrorHandlerContext context,
                final ProducerRecord<byte[], byte[]> record,
                final Exception exception) {
            final Response delegateResponse = delegate == null
                ? (exception instanceof RetriableException ? Response.retry() : Response.fail())
                : delegate.handleError(context, record, exception);
            if (delegateResponse.result() == Result.RETRY) {
                return delegateResponse;
            }
            final String topic = resolveTopic(dlqTopic, options, globalDefaultTopic);
            if (!isEnabled(dlqTopic, options, topic, globalDefaultEnabled)) {
                return delegateResponse;
            }
            final byte[] rawKey = context.sourceRawKey() != null ? context.sourceRawKey() : record.key();
            final byte[] rawValue = context.sourceRawValue() != null ? context.sourceRawValue() : record.value();
            final ProducerRecord<byte[], byte[]> dlqRecord =
                buildDlqRecord(topic, rawKey, rawValue, context, exception, options);
            return Response.resume(merge(delegateResponse.deadLetterQueueRecords(), dlqRecord));
        }

        @SuppressWarnings("rawtypes")
        @Override
        public Response handleSerializationError(final ErrorHandlerContext context,
                final ProducerRecord record,
                final Exception exception,
                final SerializationExceptionOrigin origin) {
            final Response delegateResponse = delegate == null
                ? Response.fail()
                : delegate.handleSerializationError(context, record, exception, origin);
            if (delegateResponse.result() == Result.RETRY) {
                return delegateResponse;
            }
            final String topic = resolveTopic(dlqTopic, options, globalDefaultTopic);
            if (!isEnabled(dlqTopic, options, topic, globalDefaultEnabled)) {
                return delegateResponse;
            }
            // The offending record failed to serialize, so its byte[] payload is unavailable here; fall back to the
            // source bytes from the error context (which may be null) — the dlq.* headers still capture diagnostics.
            final ProducerRecord<byte[], byte[]> dlqRecord =
                buildDlqRecord(topic, context.sourceRawKey(), context.sourceRawValue(), context, exception, options);
            return Response.resume(merge(delegateResponse.deadLetterQueueRecords(), dlqRecord));
        }
    }

    /**
     * DLQ-aware decorator for the {@link ProcessingExceptionHandler} contract. On a processing failure it routes the
     * original source-record bytes (from the error context) to the configured DLQ topic and resumes, or returns the
     * wrapped delegate's response unchanged when DLQ is not enabled for the node.
     */
    public static class ProcessingDecorator implements ProcessingExceptionHandler {

        private final ProcessingExceptionHandler delegate;
        private final String dlqTopic;
        private final DeadLetterQueueOptions options;
        private String globalDefaultTopic;
        private boolean globalDefaultEnabled;

        /**
         * Create a decorator around the supplied processing handler.
         *
         * @param delegate the wrapped handler; may be {@code null}, in which case an implicit
         *                 {@link Response#resume()} with no records is assumed
         * @param dlqTopic the DSL-supplied DLQ topic, or {@code null} to fall back to options / global default
         * @param options  the immutable DSL options, or {@code null} to fall back to the global default
         */
        public ProcessingDecorator(final ProcessingExceptionHandler delegate,
                final String dlqTopic,
                final DeadLetterQueueOptions options) {
            this.delegate = delegate;
            this.dlqTopic = dlqTopic;
            this.options = options;
        }

        @Override
        public void configure(final Map<String, ?> configs) {
            if (delegate != null) {
                delegate.configure(configs);
            }
            globalDefaultTopic = readGlobalTopic(configs);
            globalDefaultEnabled = readGlobalEnabled(configs);
        }

        @Override
        public Response handleError(final ErrorHandlerContext context,
                final Record<?, ?> record,
                final Exception exception) {
            final Response delegateResponse = delegate == null
                ? Response.resume()
                : delegate.handleError(context, record, exception);
            final String topic = resolveTopic(dlqTopic, options, globalDefaultTopic);
            if (!isEnabled(dlqTopic, options, topic, globalDefaultEnabled)) {
                return delegateResponse;
            }
            // Processing failures preserve the ORIGINAL source-record bytes from the error context; the typed
            // Record key/value are deserialized objects, not the raw bytes required for the DLQ payload.
            final ProducerRecord<byte[], byte[]> dlqRecord =
                buildDlqRecord(topic, context.sourceRawKey(), context.sourceRawValue(), context, exception, options);
            return Response.resume(merge(delegateResponse.deadLetterQueueRecords(), dlqRecord));
        }
    }
}
