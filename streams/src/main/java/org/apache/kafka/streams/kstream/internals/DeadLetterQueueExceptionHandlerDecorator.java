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

import java.util.Collections;
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
 * <p>On a failure a decorator:
 * <ol>
 *     <li>invokes the wrapped delegate <em>exactly once</em> (a {@code null} delegate is treated as an implicit
 *         {@link DeserializationExceptionHandler.Response#resume() resume} for the deserialization and processing
 *         paths, and as a {@link ProductionExceptionHandler.Response#retry() retry} or
 *         {@link ProductionExceptionHandler.Response#fail() fail} for the production path depending on whether the
 *         exception is a {@link RetriableException}), preserving all of the delegate's side effects;</li>
 *     <li>resolves the effective DLQ topic using the precedence
 *         <em>DSL topic &rarr; options topic &rarr; global default topic</em>;</li>
 *     <li>determines whether the failure is <em>eligible</em> for the DLQ via
 *         {@link DeadLetterQueueEligibility} (retriable and fatal/framework failures are never dead-lettered; a
 *         punctuation-origin processing failure with no source record is excluded); when the DLQ is disabled for
 *         the node <em>or</em> the failure is ineligible, the decorator returns the delegate's response
 *         <em>unchanged</em> so custom / KIP-1034 decisions and byte-for-byte legacy behaviour are preserved;
 *         and</li>
 *     <li>otherwise builds a single {@code ProducerRecord<byte[], byte[]>} carrying the original key/value bytes
 *         plus the six {@code dlq.*} diagnostic headers via {@link DlqRecordBuilder} and returns
 *         {@code Response.resume(singletonList(dlqRecord))} — a single, unambiguous routing result — so that a
 *         DLQ-routed failure never terminates the {@code StreamThread}.</li>
 * </ol>
 *
 * <p><strong>Exactly one routing result per failure.</strong> The decorator <em>replaces</em> (rather than
 * appends to) any DLQ records the delegate produced. This prevents double-routing when the wrapped delegate is an
 * existing KIP-1034 handler that would itself build a {@code __streams.errors.*} record: for an opted-in node the
 * DSL {@code dlq.*} record is the sole record produced.
 *
 * <p><strong>Forced resume is scoped to eligible, opted-in records only.</strong> When the DLQ is enabled for the
 * node and the failure is eligible, the decorator resumes even if the delegate chose to fail — that is the
 * opt-in contract. For every other case (DLQ disabled, or an ineligible failure such as a retriable produce
 * timeout or a fatal/framework error) the delegate's decision — including {@code FAIL} and
 * {@link ProductionExceptionHandler.Result#RETRY RETRY} — is returned verbatim, guaranteeing byte-for-byte
 * identical legacy behaviour for topologies that do not opt in.
 *
 * <p>Each decorator supports two immutable configuration forms. The <em>single-config</em> form (a DSL topic /
 * options, with the global default filled in by {@link #configure(Map) configure}) routes every eligible failure it
 * sees to one effective topic and is used for the per-source deserialization wiring and by unit tests. The
 * <em>per-source-origin</em> form ({@link ProcessingDecorator} / {@link ProductionDecorator} only) carries an
 * immutable {@code Map<sourceTopic, DeadLetterQueueOptions>} plus a resolved global fallback and is used by the
 * task-scoped runtime install: because a processing/production exception handler is shared across an entire
 * subtopology (which may contain several sources that opted in to <em>different</em> DLQ topics — e.g. a merge),
 * the effective config is resolved per failed record from its originating source ({@link ErrorHandlerContext#topic()}),
 * preserving independent per-source policies and the DSL-per-source &rarr; global precedence.
 *
 * <p>The authoritative {@code dlq-records-sent-total} metric and the per-write {@code WARN} log are emitted at the
 * runtime send sites in {@code org.apache.kafka.streams.processor.internals}, not here; this class only performs
 * an optional {@code DEBUG} trace when it routes a record. All decorators hold only immutable state (an immutable
 * options map / {@link DeadLetterQueueOptions}, {@code String}s, {@code boolean}s and the delegate handler) once
 * {@code configure} has run during single-threaded task initialization, so they are safe to share across concurrent
 * {@code StreamThread} instances.
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
            if (!isEnabled(dlqTopic, options, topic, globalDefaultEnabled)
                    || !DeadLetterQueueEligibility.isDeserializationEligible(exception)) {
                // DLQ disabled for this node, or the failure is fatal/framework: preserve the delegate's decision
                // (including FAIL) so non-opted-in and ineligible paths are byte-for-byte unchanged.
                return delegateResponse;
            }
            final byte[] rawKey = context.sourceRawKey() != null ? context.sourceRawKey() : record.key();
            final byte[] rawValue = context.sourceRawValue() != null ? context.sourceRawValue() : record.value();
            final ProducerRecord<byte[], byte[]> dlqRecord =
                buildDlqRecord(topic, rawKey, rawValue, context, exception, options);
            // Single routing result: REPLACE any delegate-produced records so an opted-in node never double-routes.
            return Response.resume(Collections.singletonList(dlqRecord));
        }

        /**
         * @return the DSL-supplied DLQ topic for this decorator (the resolved effective topic when installed by the
         *         runtime wiring), or {@code null} when only a global default applies
         */
        public String deadLetterQueueTopic() {
            return dlqTopic;
        }

        /**
         * @return the immutable DSL options for this decorator, or {@code null} on the global-only path
         */
        public DeadLetterQueueOptions deadLetterQueueOptions() {
            return options;
        }
    }

    /**
     * DLQ-aware decorator for the {@link ProductionExceptionHandler} contract. It preserves the delegate's
     * {@link Result#RETRY RETRY} decisions verbatim so retriable produce errors stay on the producer retry path and
     * are never dead-lettered; for non-retriable failures it routes to the DLQ topic and resumes.
     */
    public static class ProductionDecorator implements ProductionExceptionHandler {

        private final ProductionExceptionHandler delegate;
        // Single-config form (used by the deserialization-style per-node wiring and by unit tests): a DSL topic
        // and/or options that apply to every eligible failure this decorator sees, with the global default filled
        // in by configure(). Both null on the per-source-map form.
        private final String dlqTopic;
        private final DeadLetterQueueOptions options;
        // Per-source-origin form (used by the task-scoped runtime install): an immutable topic -> options map keyed
        // by SOURCE topic, consulted first via the record's ErrorHandlerContext#topic(), plus a resolved global
        // fallback. Because a production exception handler is shared across a whole subtopology (which may contain
        // several sources that opted in with DIFFERENT DLQ topics, e.g. a merge), the effective config is resolved
        // per failed record from its originating source rather than from one collapsed subtopology-wide value.
        private final Map<String, DeadLetterQueueOptions> perSourceConfig;
        private final DeadLetterQueueOptions explicitGlobalOptions;
        private final boolean resolvedAtConstruction;
        private String globalDefaultTopic;
        private boolean globalDefaultEnabled;

        /**
         * Create a single-config decorator around the supplied production handler that routes every eligible
         * failure it sees to one effective topic (DSL topic/options, else the global default read in
         * {@link #configure(Map)}). Used by the deserialization-style wiring and by unit tests.
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
            this.perSourceConfig = Collections.emptyMap();
            this.explicitGlobalOptions = null;
            this.resolvedAtConstruction = false;
        }

        /**
         * Create a per-source-origin decorator used by the task-scoped runtime install. Each failed record is
         * routed using the DLQ options of its <em>originating source topic</em>
         * ({@link ErrorHandlerContext#topic()}); a record whose source is not present in the map falls back to
         * {@code globalOptions}. This preserves independent per-source policies within one subtopology (so a merge
         * of two sources that opted in to different DLQ topics routes each source's failures to its own topic)
         * while keeping the DSL-per-source &rarr; global precedence.
         *
         * @param delegate         the wrapped handler (already configured); may be {@code null}
         * @param perSourceConfig  immutable map of source topic &rarr; DLQ options for the opted-in sources
         * @param globalOptions    the resolved global fallback options, or {@code null} when the global default is
         *                         disabled/unset
         */
        public ProductionDecorator(final ProductionExceptionHandler delegate,
                final Map<String, DeadLetterQueueOptions> perSourceConfig,
                final DeadLetterQueueOptions globalOptions) {
            this.delegate = delegate;
            this.dlqTopic = null;
            this.options = null;
            this.perSourceConfig = Map.copyOf(perSourceConfig);
            this.explicitGlobalOptions = globalOptions;
            this.resolvedAtConstruction = true;
        }

        @Override
        public void configure(final Map<String, ?> configs) {
            if (delegate != null) {
                delegate.configure(configs);
            }
            if (!resolvedAtConstruction) {
                globalDefaultTopic = readGlobalTopic(configs);
                globalDefaultEnabled = readGlobalEnabled(configs);
            }
        }

        /**
         * Resolve the effective DLQ options for a failed record: the per-source-origin map (keyed by
         * {@link ErrorHandlerContext#topic()}) first, then the global fallback, then — on the single-config form —
         * the DSL/global resolution captured at construction/configure. Returns {@code null} when DLQ routing is
         * not enabled for the record.
         */
        private DeadLetterQueueOptions resolveConfig(final ErrorHandlerContext context) {
            final String sourceTopic = context == null ? null : context.topic();
            if (sourceTopic != null) {
                final DeadLetterQueueOptions perSource = perSourceConfig.get(sourceTopic);
                if (perSource != null) {
                    return perSource;
                }
            }
            if (resolvedAtConstruction) {
                return explicitGlobalOptions;
            }
            final String topic = resolveTopic(dlqTopic, options, globalDefaultTopic);
            if (!isEnabled(dlqTopic, options, topic, globalDefaultEnabled)) {
                return null;
            }
            return effectiveOptions(options, topic);
        }

        @Override
        public Response handleError(final ErrorHandlerContext context,
                final ProducerRecord<byte[], byte[]> record,
                final Exception exception) {
            final Response delegateResponse = delegate == null
                ? (exception instanceof RetriableException ? Response.retry() : Response.fail())
                : delegate.handleError(context, record, exception);
            final DeadLetterQueueOptions effective = resolveConfig(context);
            if (effective == null
                    || delegateResponse.result() == Result.RETRY
                    || !DeadLetterQueueEligibility.isProductionEligible(exception)) {
                // DLQ disabled for this record's source, the delegate elected to RETRY, or the failure is
                // retriable/fatal: never dead-letter — return the delegate response verbatim (retriable failures
                // stay on the retry path).
                return delegateResponse;
            }
            // For a produce failure the offending OUTPUT record already holds the serialized bytes that failed to be
            // delivered; those are the correct payload to dead-letter and remain available regardless of the source
            // record's lifetime (the raw source bytes may already have been freed by the record collector).
            final byte[] outputKey = record == null ? null : record.key();
            final byte[] outputValue = record == null ? null : record.value();
            final ProducerRecord<byte[], byte[]> dlqRecord =
                buildDlqRecord(effective.dlqTopic(), outputKey, outputValue, context, exception, effective);
            return Response.resume(Collections.singletonList(dlqRecord));
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
            final DeadLetterQueueOptions effective = resolveConfig(context);
            if (effective == null
                    || delegateResponse.result() == Result.RETRY
                    || !DeadLetterQueueEligibility.isSerializationEligible(exception)) {
                return delegateResponse;
            }
            // The offending record failed to serialize, so its byte[] payload was never produced; fall back to the
            // source bytes from the error context. Serialization is attempted before the collector frees the raw
            // input record, so these bytes are available here (they may still be null if the source itself had a
            // null key/value) — the dlq.* headers always capture the diagnostic coordinates regardless.
            final ProducerRecord<byte[], byte[]> dlqRecord =
                buildDlqRecord(effective.dlqTopic(), context.sourceRawKey(), context.sourceRawValue(), context,
                    exception, effective);
            return Response.resume(Collections.singletonList(dlqRecord));
        }

        /**
         * @return the DSL-supplied DLQ topic for the single-config form, or {@code null} on the per-source-origin
         *         form (query {@link #perSourceDlqOptions()} / {@link #globalDlqOptions()} instead)
         */
        public String deadLetterQueueTopic() {
            return dlqTopic;
        }

        /**
         * @return the immutable DSL options for the single-config form, or {@code null} on the per-source-origin
         *         form or the global-only path
         */
        public DeadLetterQueueOptions deadLetterQueueOptions() {
            return options;
        }

        /**
         * @return the immutable per-source-origin topic &rarr; options map (empty on the single-config form)
         */
        public Map<String, DeadLetterQueueOptions> perSourceDlqOptions() {
            return perSourceConfig;
        }

        /**
         * @return the resolved global fallback options on the per-source-origin form, or {@code null}
         */
        public DeadLetterQueueOptions globalDlqOptions() {
            return explicitGlobalOptions;
        }
    }

    /**
     * DLQ-aware decorator for the {@link ProcessingExceptionHandler} contract. On a processing failure it routes the
     * original source-record bytes (from the error context) to the configured DLQ topic and resumes, or returns the
     * wrapped delegate's response unchanged when DLQ is not enabled for the node.
     */
    public static class ProcessingDecorator implements ProcessingExceptionHandler {

        private final ProcessingExceptionHandler delegate;
        // Single-config form (used by unit tests): a DSL topic and/or options applied to every eligible failure,
        // with the global default filled in by configure(). Both null on the per-source-map form.
        private final String dlqTopic;
        private final DeadLetterQueueOptions options;
        // Per-source-origin form (used by the task-scoped runtime install): topic -> options keyed by SOURCE topic,
        // consulted first via the record's ErrorHandlerContext#topic(), plus a resolved global fallback. A
        // processing exception handler is shared across a whole subtopology (all of its nodes are initialized with
        // the same handler), which may span several sources that opted in with DIFFERENT DLQ topics; the effective
        // config is therefore resolved per failed record from its originating source.
        private final Map<String, DeadLetterQueueOptions> perSourceConfig;
        private final DeadLetterQueueOptions explicitGlobalOptions;
        private final boolean resolvedAtConstruction;
        private String globalDefaultTopic;
        private boolean globalDefaultEnabled;

        /**
         * Create a single-config decorator that routes every eligible processing failure it sees to one effective
         * topic (DSL topic/options, else the global default read in {@link #configure(Map)}). Used by unit tests.
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
            this.perSourceConfig = Collections.emptyMap();
            this.explicitGlobalOptions = null;
            this.resolvedAtConstruction = false;
        }

        /**
         * Create a per-source-origin decorator used by the task-scoped runtime install. Each failed record is
         * routed using the DLQ options of its <em>originating source topic</em>
         * ({@link ErrorHandlerContext#topic()}); a record whose source is not present in the map falls back to
         * {@code globalOptions}. A punctuation-origin failure (no source record) is never dead-lettered, per
         * {@link DeadLetterQueueEligibility#isProcessingEligible}.
         *
         * @param delegate         the wrapped handler (already configured); may be {@code null}
         * @param perSourceConfig  immutable map of source topic &rarr; DLQ options for the opted-in sources
         * @param globalOptions    the resolved global fallback options, or {@code null} when disabled/unset
         */
        public ProcessingDecorator(final ProcessingExceptionHandler delegate,
                final Map<String, DeadLetterQueueOptions> perSourceConfig,
                final DeadLetterQueueOptions globalOptions) {
            this.delegate = delegate;
            this.dlqTopic = null;
            this.options = null;
            this.perSourceConfig = Map.copyOf(perSourceConfig);
            this.explicitGlobalOptions = globalOptions;
            this.resolvedAtConstruction = true;
        }

        @Override
        public void configure(final Map<String, ?> configs) {
            if (delegate != null) {
                delegate.configure(configs);
            }
            if (!resolvedAtConstruction) {
                globalDefaultTopic = readGlobalTopic(configs);
                globalDefaultEnabled = readGlobalEnabled(configs);
            }
        }

        /**
         * Resolve the effective DLQ options for a failed record: the per-source-origin map (keyed by
         * {@link ErrorHandlerContext#topic()}) first, then the global fallback, then — on the single-config form —
         * the DSL/global resolution captured at construction/configure. Returns {@code null} when DLQ routing is
         * not enabled for the record.
         */
        private DeadLetterQueueOptions resolveConfig(final ErrorHandlerContext context) {
            final String sourceTopic = context == null ? null : context.topic();
            if (sourceTopic != null) {
                final DeadLetterQueueOptions perSource = perSourceConfig.get(sourceTopic);
                if (perSource != null) {
                    return perSource;
                }
            }
            if (resolvedAtConstruction) {
                return explicitGlobalOptions;
            }
            final String topic = resolveTopic(dlqTopic, options, globalDefaultTopic);
            if (!isEnabled(dlqTopic, options, topic, globalDefaultEnabled)) {
                return null;
            }
            return effectiveOptions(options, topic);
        }

        @Override
        public Response handleError(final ErrorHandlerContext context,
                final Record<?, ?> record,
                final Exception exception) {
            final Response delegateResponse = delegate == null
                ? Response.resume()
                : delegate.handleError(context, record, exception);
            final DeadLetterQueueOptions effective = resolveConfig(context);
            if (effective == null
                    || !DeadLetterQueueEligibility.isProcessingEligible(exception, context)) {
                // DLQ disabled for this record's source, a fatal/framework failure, or a punctuation-origin failure
                // that has no source record to dead-letter: preserve the delegate's decision unchanged.
                return delegateResponse;
            }
            // Processing failures preserve the ORIGINAL source-record bytes from the error context; the typed
            // Record key/value are deserialized objects, not the raw bytes required for the DLQ payload.
            final ProducerRecord<byte[], byte[]> dlqRecord =
                buildDlqRecord(effective.dlqTopic(), context.sourceRawKey(), context.sourceRawValue(), context,
                    exception, effective);
            return Response.resume(Collections.singletonList(dlqRecord));
        }

        /**
         * @return the DSL-supplied DLQ topic for the single-config form, or {@code null} on the per-source-origin
         *         form (query {@link #perSourceDlqOptions()} / {@link #globalDlqOptions()} instead)
         */
        public String deadLetterQueueTopic() {
            return dlqTopic;
        }

        /**
         * @return the immutable DSL options for the single-config form, or {@code null} otherwise
         */
        public DeadLetterQueueOptions deadLetterQueueOptions() {
            return options;
        }

        /**
         * @return the immutable per-source-origin topic &rarr; options map (empty on the single-config form)
         */
        public Map<String, DeadLetterQueueOptions> perSourceDlqOptions() {
            return perSourceConfig;
        }

        /**
         * @return the resolved global fallback options on the per-source-origin form, or {@code null}
         */
        public DeadLetterQueueOptions globalDlqOptions() {
            return explicitGlobalOptions;
        }
    }
}
