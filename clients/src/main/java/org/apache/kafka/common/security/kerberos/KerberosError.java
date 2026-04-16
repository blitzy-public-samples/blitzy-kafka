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
package org.apache.kafka.common.security.kerberos;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.authenticator.SaslClientAuthenticator;
import org.apache.kafka.common.utils.Java;

import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;

import javax.security.sasl.SaslClient;

/**
 * Kerberos exceptions that may require special handling. The standard Kerberos error codes
 * for these errors are retrieved using KrbException#errorCode() from the underlying Kerberos
 * exception thrown during {@link SaslClient#evaluateChallenge(byte[])}.
 */
// SECURITY: SEC-KERB-003 (LOW) Uses reflection to access JDK-internal Kerberos error types
// Why: Kerberos authentication handles security-critical ticket
// exchange and principal resolution.
// (sun.security.krb5.KrbException or com.ibm.security.krb5.KrbException).
// There is no public API for Kerberos error code classification.
// Exploit: JDK version changes may break reflection access, causing KafkaException during
// static initialization, which could prevent broker startup and deny service.
// Improvement: Add fallback behavior when reflection fails instead of throwing
// KafkaException, or petition for a public JDK API for Kerberos error classification.
//
// DECISION: Reflection over JDK-internal classes because the Java SE API does not expose
// Kerberos error codes through any public interface. IBM JDK variants use different
// package paths (see static initializer below).
// Alternative: Parse exception messages with regex — rejected as fragile and
// locale-dependent.
// Risk: Every JDK major version upgrade requires verification that internal class paths
// still exist.
//
// CROSS-CUTTING: Used by SaslClientAuthenticator (authenticator/) to classify Kerberos
// errors during SASL challenge-response. The retriable flag (e.g., CLIENT_NOT_YET_VALID,
// TICKET_NOT_YET_VALID) determines whether the client retries authentication or propagates
// the failure.
public enum KerberosError {
    // (Mechanism level: Server not found in Kerberos database (7) - UNKNOWN_SERVER)
    // This is retriable, but included here to add extra logging for this case.
    SERVER_NOT_FOUND(7, false),
    // (Mechanism level: Client not yet valid - try again later (21))
    CLIENT_NOT_YET_VALID(21, true),
    // (Mechanism level: Ticket not yet valid (33) - Ticket not yet valid)])
    // This could be a small timing window.
    TICKET_NOT_YET_VALID(33, true),
    // (Mechanism level: Request is a replay (34) - Request is a replay)
    // Replay detection used to prevent DoS attacks can result in false positives, so retry on error.
    REPLAY(34, true);

    private static final Logger log = LoggerFactory.getLogger(SaslClientAuthenticator.class);
    private static final Class<?> KRB_EXCEPTION_CLASS;
    private static final Method KRB_EXCEPTION_RETURN_CODE_METHOD;

    // DECISION: Static initializer discovers KrbException class and returnCode method at
    // class load time. Fail-fast on initialization (throws KafkaException) rather than
    // fail-lazy on first use. This ensures misconfigured JDK environments are detected
    // during broker startup, not during runtime authentication.
    static {
        try {
            // different IBM JDKs versions include different security implementations
            if (Java.isIbmJdk() && canLoad("com.ibm.security.krb5.KrbException")) {
                KRB_EXCEPTION_CLASS = Class.forName("com.ibm.security.krb5.KrbException");
            } else if (Java.isIbmJdk() && canLoad("com.ibm.security.krb5.internal.KrbException")) {
                KRB_EXCEPTION_CLASS = Class.forName("com.ibm.security.krb5.internal.KrbException");
            } else {
                KRB_EXCEPTION_CLASS = Class.forName("sun.security.krb5.KrbException");
            }
            KRB_EXCEPTION_RETURN_CODE_METHOD = KRB_EXCEPTION_CLASS.getMethod("returnCode");
        } catch (Exception e) {
            throw new KafkaException("Kerberos exceptions could not be initialized", e);
        }
    }

    private static boolean canLoad(String clazz) {
        try {
            Class.forName(clazz);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private final int errorCode;
    private final boolean retriable;

    KerberosError(int errorCode, boolean retriable) {
        this.errorCode = errorCode;
        this.retriable = retriable;
    }

    public boolean retriable() {
        return retriable;
    }

    // SECURITY: SEC-KERB-004 (LOW) Walks the exception cause chain to find a KrbException instance
    // Why: Kerberos authentication handles security-critical ticket
    // exchange and principal resolution.
    // via reflection. If the reflective invocation of returnCode() fails, returns null
    // (falls through to unknown error).
    // Exploit: A crafted exception chain that triggers a reflection failure causes
    // the error to be classified as unknown, potentially skipping retry logic for
    // retriable Kerberos errors and denying authentication.
    // Improvement: Log at WARN level (not just TRACE) when reflection fails so
    // operators can detect JDK compatibility issues in production.
    public static KerberosError fromException(Exception exception) {
        Throwable cause = exception.getCause();
        while (cause != null && !KRB_EXCEPTION_CLASS.isInstance(cause)) {
            cause = cause.getCause();
        }
        if (cause == null)
            return null;
        else {
            try {
                Integer errorCode = (Integer) KRB_EXCEPTION_RETURN_CODE_METHOD.invoke(cause);
                return fromErrorCode(errorCode);
            } catch (Exception e) {
                log.trace("Kerberos return code could not be determined from {}", exception, e);
                return null;
            }
        }
    }

    private static KerberosError fromErrorCode(int errorCode) {
        for (KerberosError error : values()) {
            if (error.errorCode == errorCode)
                return error;
        }
        return null;
    }

    // DECISION: GSSException.NO_CRED is treated as retriable on client-side because it
    // can transiently occur during the window between KerberosLogin.reLogin() logout and
    // subsequent login. Other GSSException major codes are not retriable — they indicate
    // permanent failures.
    /**
     * Returns true if the exception should be handled as a transient failure on clients.
     * We handle GSSException.NO_CRED as retriable on the client-side since this may
     * occur during re-login if a clients attempts to authentication after logout, but
     * before the subsequent login.
     */
    public static boolean isRetriableClientGssException(Exception exception) {
        Throwable cause = exception.getCause();
        while (cause != null && !(cause instanceof GSSException)) {
            cause = cause.getCause();
        }
        if (cause != null) {
            GSSException gssException = (GSSException) cause;
            return gssException.getMajor() == GSSException.NO_CRED;
        }
        return false;
    }
}
