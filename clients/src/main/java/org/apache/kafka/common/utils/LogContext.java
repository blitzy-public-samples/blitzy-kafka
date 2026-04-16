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
package org.apache.kafka.common.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MessageFormatter;
import org.slf4j.spi.LocationAwareLogger;

/**
 * This class provides a way to instrument loggers with a common context which can be used to
 * automatically enrich log messages. For example, in the KafkaConsumer, it is often useful to know
 * the groupId of the consumer, so this can be added to a context object which can then be passed to
 * all of the dependent components in order to build new loggers. This removes the need to manually
 * add the groupId to each message.
 */
// CROSS-CUTTING: Created by every Kafka client (KafkaProducer, KafkaConsumer,
// KafkaAdminClient, KafkaStreams, Connect Worker) during initialization. Passed to all
// internal components for consistent log context. The logPrefix typically includes clientId,
// groupId, and/or transactional ID for operational log correlation.
// Depends on SLF4J API (org.slf4j:slf4j-api:1.7.36).
//
// DECISION: Custom LogContext with prefix-based log enrichment rather than SLF4J MDC.
// Alternative: Use MDC (Mapped Diagnostic Context) for structured logging context.
// Rationale: Kafka's threading model (single thread per consumer/producer, shared threads
// in server) makes MDC unreliable -- MDC is thread-local and does not propagate correctly
// when callbacks execute on different threads (e.g., CompletableFuture callbacks in admin
// client, or selector threads processing multiple connections). Prefix-based logging
// (prepending "[Consumer clientId=X, groupId=Y]") is attached to the logger instance
// itself, making it independent of thread context. This design is simpler and more
// reliable for Kafka's use case.
public class LogContext {

    // DECISION: Immutable prefix string set at construction. Alternative: Mutable context
    // with add/remove key support. Rationale: LogContext is created once per client
    // lifecycle (during construction of KafkaProducer, KafkaConsumer, etc.) and never
    // modified -- immutability avoids synchronization concerns when the logger is shared
    // across threads.
    private final String logPrefix;

    public LogContext(String logPrefix) {
        this.logPrefix = logPrefix == null ? "" : logPrefix;
    }

    public LogContext() {
        this("");
    }

    public Logger logger(Class<?> clazz) {
        return logger(LoggerFactory.getLogger(clazz));
    }

    public Logger logger(String clazz) {
        return logger(LoggerFactory.getLogger(clazz));
    }

    // DECISION: Two wrapper implementations -- LocationAwareKafkaLogger (for LocationAware
    // SLF4J implementations like Logback) and LocationIgnorantKafkaLogger (for others).
    // Alternative: Single wrapper using reflection. Rationale: LocationAwareLogger preserves
    // correct source file/line information in log output by passing the FQCN of the wrapper
    // class. Without this, all log lines would show LogContext as the source rather than the
    // actual calling class.
    private Logger logger(Logger logger) {
        if (logger instanceof LocationAwareLogger) {
            return new LocationAwareKafkaLogger(logPrefix, (LocationAwareLogger) logger);
        } else {
            return new LocationIgnorantKafkaLogger(logPrefix, logger);
        }
    }

    public String logPrefix() {
        return logPrefix;
    }

    private abstract static class AbstractKafkaLogger implements Logger {
        private final String prefix;

        protected AbstractKafkaLogger(final String prefix) {
            this.prefix = prefix;
        }

        protected String addPrefix(final String message) {
            return prefix + message;
        }
    }

    // DECISION: Wraps LocationAwareLogger.log() with FQCN for correct caller location.
    // The fqcn field is set to LocationAwareKafkaLogger.class.getName() -- SLF4J's
    // location-aware backends (Logback, Log4j2) use this to walk the stack trace and find
    // the actual caller above this class.
    private static class LocationAwareKafkaLogger extends AbstractKafkaLogger {
        private final LocationAwareLogger logger;
        private final String fqcn;

        LocationAwareKafkaLogger(String logPrefix, LocationAwareLogger logger) {
            super(logPrefix);
            this.logger = logger;
            this.fqcn = LocationAwareKafkaLogger.class.getName();
        }

        @Override
        public String getName() {
            return logger.getName();
        }

        @Override
        public boolean isTraceEnabled() {
            return logger.isTraceEnabled();
        }

        @Override
        public boolean isTraceEnabled(Marker marker) {
            return logger.isTraceEnabled(marker);
        }

        @Override
        public boolean isDebugEnabled() {
            return logger.isDebugEnabled();
        }

        @Override
        public boolean isDebugEnabled(Marker marker) {
            return logger.isDebugEnabled(marker);
        }

        @Override
        public boolean isInfoEnabled() {
            return logger.isInfoEnabled();
        }

        @Override
        public boolean isInfoEnabled(Marker marker) {
            return logger.isInfoEnabled(marker);
        }

        @Override
        public boolean isWarnEnabled() {
            return logger.isWarnEnabled();
        }

        @Override
        public boolean isWarnEnabled(Marker marker) {
            return logger.isWarnEnabled(marker);
        }

        @Override
        public boolean isErrorEnabled() {
            return logger.isErrorEnabled();
        }

        @Override
        public boolean isErrorEnabled(Marker marker) {
            return logger.isErrorEnabled(marker);
        }

        @Override
        public void trace(String message) {
            if (logger.isTraceEnabled()) {
                writeLog(null, LocationAwareLogger.TRACE_INT, message, null, null);
            }
        }

        @Override
        public void trace(String format, Object arg) {
            if (logger.isTraceEnabled()) {
                writeLog(null, LocationAwareLogger.TRACE_INT, format, new Object[]{arg}, null);
            }
        }

        @Override
        public void trace(String format, Object arg1, Object arg2) {
            if (logger.isTraceEnabled()) {
                writeLog(null, LocationAwareLogger.TRACE_INT, format, new Object[]{arg1, arg2}, null);
            }
        }

        @Override
        public void trace(String format, Object... args) {
            if (logger.isTraceEnabled()) {
                writeLog(null, LocationAwareLogger.TRACE_INT, format, args, null);
            }
        }

        @Override
        public void trace(String msg, Throwable t) {
            if (logger.isTraceEnabled()) {
                writeLog(null, LocationAwareLogger.TRACE_INT, msg, null, t);
            }
        }

        @Override
        public void trace(Marker marker, String msg) {
            if (logger.isTraceEnabled()) {
                writeLog(marker, LocationAwareLogger.TRACE_INT, msg, null, null);
            }
        }

        @Override
        public void trace(Marker marker, String format, Object arg) {
            if (logger.isTraceEnabled()) {
                writeLog(marker, LocationAwareLogger.TRACE_INT, format, new Object[]{arg}, null);
            }
        }

        @Override
        public void trace(Marker marker, String format, Object arg1, Object arg2) {
            if (logger.isTraceEnabled()) {
                writeLog(marker, LocationAwareLogger.TRACE_INT, format, new Object[]{arg1, arg2}, null);
            }
        }

        @Override
        public void trace(Marker marker, String format, Object... argArray) {
            if (logger.isTraceEnabled()) {
                writeLog(marker, LocationAwareLogger.TRACE_INT, format, argArray, null);
            }
        }

        @Override
        public void trace(Marker marker, String msg, Throwable t) {
            if (logger.isTraceEnabled()) {
                writeLog(marker, LocationAwareLogger.TRACE_INT, msg, null, t);
            }
        }

        @Override
        public void debug(String message) {
            if (logger.isDebugEnabled()) {
                writeLog(null, LocationAwareLogger.DEBUG_INT, message, null, null);
            }
        }

        @Override
        public void debug(String format, Object arg) {
            if (logger.isDebugEnabled()) {
                writeLog(null, LocationAwareLogger.DEBUG_INT, format, new Object[]{arg}, null);
            }
        }

        @Override
        public void debug(String format, Object arg1, Object arg2) {
            if (logger.isDebugEnabled()) {
                writeLog(null, LocationAwareLogger.DEBUG_INT, format, new Object[]{arg1, arg2}, null);
            }
        }

        @Override
        public void debug(String format, Object... args) {
            if (logger.isDebugEnabled()) {
                writeLog(null, LocationAwareLogger.DEBUG_INT, format, args, null);
            }
        }

        @Override
        public void debug(String msg, Throwable t) {
            if (logger.isDebugEnabled()) {
                writeLog(null, LocationAwareLogger.DEBUG_INT, msg, null, t);
            }
        }

        @Override
        public void debug(Marker marker, String msg) {
            if (logger.isDebugEnabled()) {
                writeLog(marker, LocationAwareLogger.DEBUG_INT, msg, null, null);
            }
        }

        @Override
        public void debug(Marker marker, String format, Object arg) {
            if (logger.isDebugEnabled()) {
                writeLog(marker, LocationAwareLogger.DEBUG_INT, format, new Object[]{arg}, null);
            }
        }

        @Override
        public void debug(Marker marker, String format, Object arg1, Object arg2) {
            if (logger.isDebugEnabled()) {
                writeLog(marker, LocationAwareLogger.DEBUG_INT, format, new Object[]{arg1, arg2}, null);
            }
        }

        @Override
        public void debug(Marker marker, String format, Object... arguments) {
            if (logger.isDebugEnabled()) {
                writeLog(marker, LocationAwareLogger.DEBUG_INT, format, arguments, null);
            }
        }

        @Override
        public void debug(Marker marker, String msg, Throwable t) {
            if (logger.isDebugEnabled()) {
                writeLog(marker, LocationAwareLogger.DEBUG_INT, msg, null, t);
            }
        }

        @Override
        public void warn(String message) {
            writeLog(null, LocationAwareLogger.WARN_INT, message, null, null);
        }

        @Override
        public void warn(String format, Object arg) {
            writeLog(null, LocationAwareLogger.WARN_INT, format, new Object[]{arg}, null);
        }

        @Override
        public void warn(String message, Object arg1, Object arg2) {
            writeLog(null, LocationAwareLogger.WARN_INT, message, new Object[]{arg1, arg2}, null);
        }

        @Override
        public void warn(String format, Object... args) {
            writeLog(null, LocationAwareLogger.WARN_INT, format, args, null);
        }

        @Override
        public void warn(String msg, Throwable t) {
            writeLog(null, LocationAwareLogger.WARN_INT, msg, null, t);
        }

        @Override
        public void warn(Marker marker, String msg) {
            writeLog(marker, LocationAwareLogger.WARN_INT, msg, null, null);
        }

        @Override
        public void warn(Marker marker, String format, Object arg) {
            writeLog(marker, LocationAwareLogger.WARN_INT, format, new Object[]{arg}, null);
        }

        @Override
        public void warn(Marker marker, String format, Object arg1, Object arg2) {
            writeLog(marker, LocationAwareLogger.WARN_INT, format, new Object[]{arg1, arg2}, null);
        }

        @Override
        public void warn(Marker marker, String format, Object... arguments) {
            writeLog(marker, LocationAwareLogger.WARN_INT, format, arguments, null);
        }

        @Override
        public void warn(Marker marker, String msg, Throwable t) {
            writeLog(marker, LocationAwareLogger.WARN_INT, msg, null, t);
        }

        @Override
        public void error(String message) {
            writeLog(null, LocationAwareLogger.ERROR_INT, message, null, null);
        }

        @Override
        public void error(String format, Object arg) {
            writeLog(null, LocationAwareLogger.ERROR_INT, format, new Object[]{arg}, null);
        }

        @Override
        public void error(String format, Object arg1, Object arg2) {
            writeLog(null, LocationAwareLogger.ERROR_INT, format, new Object[]{arg1, arg2}, null);
        }

        @Override
        public void error(String format, Object... args) {
            writeLog(null, LocationAwareLogger.ERROR_INT, format, args, null);
        }

        @Override
        public void error(String msg, Throwable t) {
            writeLog(null, LocationAwareLogger.ERROR_INT, msg, null, t);
        }

        @Override
        public void error(Marker marker, String msg) {
            writeLog(marker, LocationAwareLogger.ERROR_INT, msg, null, null);
        }

        @Override
        public void error(Marker marker, String format, Object arg) {
            writeLog(marker, LocationAwareLogger.ERROR_INT, format, new Object[]{arg}, null);
        }

        @Override
        public void error(Marker marker, String format, Object arg1, Object arg2) {
            writeLog(marker, LocationAwareLogger.ERROR_INT, format, new Object[]{arg1, arg2}, null);
        }

        @Override
        public void error(Marker marker, String format, Object... arguments) {
            writeLog(marker, LocationAwareLogger.ERROR_INT, format, arguments, null);
        }

        @Override
        public void error(Marker marker, String msg, Throwable t) {
            writeLog(marker, LocationAwareLogger.ERROR_INT, msg, null, t);
        }

        @Override
        public void info(String msg) {
            writeLog(null, LocationAwareLogger.INFO_INT, msg, null, null);
        }

        @Override
        public void info(String format, Object arg) {
            writeLog(null, LocationAwareLogger.INFO_INT, format, new Object[]{arg}, null);
        }

        @Override
        public void info(String format, Object arg1, Object arg2) {
            writeLog(null, LocationAwareLogger.INFO_INT, format, new Object[]{arg1, arg2}, null);
        }

        @Override
        public void info(String format, Object... args) {
            writeLog(null, LocationAwareLogger.INFO_INT, format, args, null);
        }

        @Override
        public void info(String msg, Throwable t) {
            writeLog(null, LocationAwareLogger.INFO_INT, msg, null, t);
        }

        @Override
        public void info(Marker marker, String msg) {
            writeLog(marker, LocationAwareLogger.INFO_INT, msg, null, null);
        }

        @Override
        public void info(Marker marker, String format, Object arg) {
            writeLog(marker, LocationAwareLogger.INFO_INT, format, new Object[]{arg}, null);
        }

        @Override
        public void info(Marker marker, String format, Object arg1, Object arg2) {
            writeLog(marker, LocationAwareLogger.INFO_INT, format, new Object[]{arg1, arg2}, null);
        }

        @Override
        public void info(Marker marker, String format, Object... arguments) {
            writeLog(marker, LocationAwareLogger.INFO_INT, format, arguments, null);
        }

        @Override
        public void info(Marker marker, String msg, Throwable t) {
            writeLog(marker, LocationAwareLogger.INFO_INT, msg, null, t);
        }

        // DECISION: Uses SLF4J's MessageFormatter.format() to apply {} placeholders before
        // prepending prefix. Alternative: Prepend prefix to format string. Rationale:
        // Prepending to format string would break placeholder indexing if prefix contained
        // {} characters.
        private void writeLog(Marker marker, int level, String format, Object[] args, Throwable exception) {
            String message = format;
            if (args != null && args.length > 0) {
                FormattingTuple formatted = MessageFormatter.arrayFormat(format, args);
                if (exception == null && formatted.getThrowable() != null) {
                    exception = formatted.getThrowable();
                }
                message = formatted.getMessage();
            }
            logger.log(marker, fqcn, level, addPrefix(message), null, exception);
        }
    }

    // DECISION: Fallback wrapper for non-LocationAware SLF4J implementations. Simply
    // prepends prefix to all messages. Location information is not available -- log lines
    // will show LocationIgnorantKafkaLogger as the source. This is acceptable for simple
    // SLF4J backends.
    private static class LocationIgnorantKafkaLogger extends AbstractKafkaLogger {
        private final Logger logger;

        LocationIgnorantKafkaLogger(String logPrefix, Logger logger) {
            super(logPrefix);
            this.logger = logger;
        }

        @Override
        public String getName() {
            return logger.getName();
        }

        @Override
        public boolean isTraceEnabled() {
            return logger.isTraceEnabled();
        }

        @Override
        public boolean isTraceEnabled(Marker marker) {
            return logger.isTraceEnabled(marker);
        }

        @Override
        public boolean isDebugEnabled() {
            return logger.isDebugEnabled();
        }

        @Override
        public boolean isDebugEnabled(Marker marker) {
            return logger.isDebugEnabled(marker);
        }

        @Override
        public boolean isInfoEnabled() {
            return logger.isInfoEnabled();
        }

        @Override
        public boolean isInfoEnabled(Marker marker) {
            return logger.isInfoEnabled(marker);
        }

        @Override
        public boolean isWarnEnabled() {
            return logger.isWarnEnabled();
        }

        @Override
        public boolean isWarnEnabled(Marker marker) {
            return logger.isWarnEnabled(marker);
        }

        @Override
        public boolean isErrorEnabled() {
            return logger.isErrorEnabled();
        }

        @Override
        public boolean isErrorEnabled(Marker marker) {
            return logger.isErrorEnabled(marker);
        }

        @Override
        public void trace(String message) {
            if (logger.isTraceEnabled()) {
                logger.trace(addPrefix(message));
            }
        }

        @Override
        public void trace(String message, Object arg) {
            if (logger.isTraceEnabled()) {
                logger.trace(addPrefix(message), arg);
            }
        }

        @Override
        public void trace(String message, Object arg1, Object arg2) {
            if (logger.isTraceEnabled()) {
                logger.trace(addPrefix(message), arg1, arg2);
            }
        }

        @Override
        public void trace(String message, Object... args) {
            if (logger.isTraceEnabled()) {
                logger.trace(addPrefix(message), args);
            }
        }

        @Override
        public void trace(String msg, Throwable t) {
            if (logger.isTraceEnabled()) {
                logger.trace(addPrefix(msg), t);
            }
        }

        @Override
        public void trace(Marker marker, String msg) {
            if (logger.isTraceEnabled()) {
                logger.trace(marker, addPrefix(msg));
            }
        }

        @Override
        public void trace(Marker marker, String format, Object arg) {
            if (logger.isTraceEnabled()) {
                logger.trace(marker, addPrefix(format), arg);
            }
        }

        @Override
        public void trace(Marker marker, String format, Object arg1, Object arg2) {
            if (logger.isTraceEnabled()) {
                logger.trace(marker, addPrefix(format), arg1, arg2);
            }
        }

        @Override
        public void trace(Marker marker, String format, Object... argArray) {
            if (logger.isTraceEnabled()) {
                logger.trace(marker, addPrefix(format), argArray);
            }
        }

        @Override
        public void trace(Marker marker, String msg, Throwable t) {
            if (logger.isTraceEnabled()) {
                logger.trace(marker, addPrefix(msg), t);
            }
        }

        @Override
        public void debug(String message) {
            if (logger.isDebugEnabled()) {
                logger.debug(addPrefix(message));
            }
        }

        @Override
        public void debug(String message, Object arg) {
            if (logger.isDebugEnabled()) {
                logger.debug(addPrefix(message), arg);
            }
        }

        @Override
        public void debug(String message, Object arg1, Object arg2) {
            if (logger.isDebugEnabled()) {
                logger.debug(addPrefix(message), arg1, arg2);
            }
        }

        @Override
        public void debug(String message, Object... args) {
            if (logger.isDebugEnabled()) {
                logger.debug(addPrefix(message), args);
            }
        }

        @Override
        public void debug(String msg, Throwable t) {
            if (logger.isDebugEnabled()) {
                logger.debug(addPrefix(msg), t);
            }
        }

        @Override
        public void debug(Marker marker, String msg) {
            if (logger.isDebugEnabled()) {
                logger.debug(marker, addPrefix(msg));
            }
        }

        @Override
        public void debug(Marker marker, String format, Object arg) {
            if (logger.isDebugEnabled()) {
                logger.debug(marker, addPrefix(format), arg);
            }
        }

        @Override
        public void debug(Marker marker, String format, Object arg1, Object arg2) {
            if (logger.isDebugEnabled()) {
                logger.debug(marker, addPrefix(format), arg1, arg2);
            }
        }

        @Override
        public void debug(Marker marker, String format, Object... arguments) {
            if (logger.isDebugEnabled()) {
                logger.debug(marker, addPrefix(format), arguments);
            }
        }

        @Override
        public void debug(Marker marker, String msg, Throwable t) {
            if (logger.isDebugEnabled()) {
                logger.debug(marker, addPrefix(msg), t);
            }
        }

        @Override
        public void warn(String message) {
            logger.warn(addPrefix(message));
        }

        @Override
        public void warn(String message, Object arg) {
            logger.warn(addPrefix(message), arg);
        }

        @Override
        public void warn(String message, Object arg1, Object arg2) {
            logger.warn(addPrefix(message), arg1, arg2);
        }

        @Override
        public void warn(String message, Object... args) {
            logger.warn(addPrefix(message), args);
        }

        @Override
        public void warn(String msg, Throwable t) {
            logger.warn(addPrefix(msg), t);
        }

        @Override
        public void warn(Marker marker, String msg) {
            logger.warn(marker, addPrefix(msg));
        }

        @Override
        public void warn(Marker marker, String format, Object arg) {
            logger.warn(marker, addPrefix(format), arg);
        }

        @Override
        public void warn(Marker marker, String format, Object arg1, Object arg2) {
            logger.warn(marker, addPrefix(format), arg1, arg2);
        }

        @Override
        public void warn(Marker marker, String format, Object... arguments) {
            logger.warn(marker, addPrefix(format), arguments);
        }

        @Override
        public void warn(Marker marker, String msg, Throwable t) {
            logger.warn(marker, addPrefix(msg), t);
        }

        @Override
        public void error(String message) {
            logger.error(addPrefix(message));
        }

        @Override
        public void error(String message, Object arg) {
            logger.error(addPrefix(message), arg);
        }

        @Override
        public void error(String message, Object arg1, Object arg2) {
            logger.error(addPrefix(message), arg1, arg2);
        }

        @Override
        public void error(String message, Object... args) {
            logger.error(addPrefix(message), args);
        }

        @Override
        public void error(String msg, Throwable t) {
            logger.error(addPrefix(msg), t);
        }

        @Override
        public void error(Marker marker, String msg) {
            logger.error(marker, addPrefix(msg));
        }

        @Override
        public void error(Marker marker, String format, Object arg) {
            logger.error(marker, addPrefix(format), arg);
        }

        @Override
        public void error(Marker marker, String format, Object arg1, Object arg2) {
            logger.error(marker, addPrefix(format), arg1, arg2);
        }

        @Override
        public void error(Marker marker, String format, Object... arguments) {
            logger.error(marker, addPrefix(format), arguments);
        }

        @Override
        public void error(Marker marker, String msg, Throwable t) {
            logger.error(marker, addPrefix(msg), t);
        }

        @Override
        public void info(String message) {
            logger.info(addPrefix(message));
        }

        @Override
        public void info(String message, Object arg) {
            logger.info(addPrefix(message), arg);
        }

        @Override
        public void info(String message, Object arg1, Object arg2) {
            logger.info(addPrefix(message), arg1, arg2);
        }

        @Override
        public void info(String message, Object... args) {
            logger.info(addPrefix(message), args);
        }

        @Override
        public void info(String msg, Throwable t) {
            logger.info(addPrefix(msg), t);
        }

        @Override
        public void info(Marker marker, String msg) {
            logger.info(marker, addPrefix(msg));
        }

        @Override
        public void info(Marker marker, String format, Object arg) {
            logger.info(marker, addPrefix(format), arg);
        }

        @Override
        public void info(Marker marker, String format, Object arg1, Object arg2) {
            logger.info(marker, addPrefix(format), arg1, arg2);
        }

        @Override
        public void info(Marker marker, String format, Object... arguments) {
            logger.info(marker, addPrefix(format), arguments);
        }

        @Override
        public void info(Marker marker, String msg, Throwable t) {
            logger.info(marker, addPrefix(msg), t);
        }

    }

}
