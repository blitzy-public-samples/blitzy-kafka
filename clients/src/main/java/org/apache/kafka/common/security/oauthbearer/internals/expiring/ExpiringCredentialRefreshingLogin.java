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
package org.apache.kafka.common.security.oauthbearer.internals.expiring;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.Login;
import org.apache.kafka.common.utils.KafkaThread;
import org.apache.kafka.common.utils.Time;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Objects;
import java.util.Random;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * This class is responsible for refreshing logins for both Kafka client and
 * server when the login is a type that has a limited lifetime/will expire. The
 * credentials for the login must implement {@link ExpiringCredential}.
 */
// SECURITY: (HIGH) Background daemon thread runs token refresh with broker/client privileges.
// The refresh thread has access to the Subject and can modify its credential set.
// Why: This class is the scheduling engine for ALL expiring credential refresh -- both
// OAUTHBEARER and Kerberos TGT. The refresh daemon runs with the same privileges as the Kafka
// process and can replace credentials in the JAAS Subject. The class-level lock (synchronized
// on the provided Class<?> object at line 364) serializes refresh operations -- a blocked
// refresh (e.g., stuck HTTP call to an OAuth provider) blocks ALL refreshes sharing the same
// lock in the JVM.
// Exploit: If the refresh thread is compromised (e.g., via a malicious LoginContextFactory
// injected through the test-visible constructor at line 160), it could replace valid tokens
// with attacker-controlled tokens in the Subject. Because the Subject is volatile (line 146)
// and shared across threads, the attacker's token would be picked up by all subsequent SASL
// authentications. Additionally, a blocked refresh (stuck synchronized block) prevents ALL
// credential refresh operations, causing eventual token expiry and authentication failure.
// Improvement: Add a timeout on the synchronized block (e.g., tryLock with timeout) to prevent
// indefinite blocking. Consider health monitoring for the refresh thread via a JMX gauge
// tracking last successful refresh time and current refresh thread state.
// CROSS-CUTTING: Extended by OAuthBearerRefreshingLogin (the concrete OAuth implementation in
// oauthbearer/internals/OAuthBearerRefreshingLogin.java). Also used for Kerberos TGT refresh.
// Depends on: ExpiringCredential (credential expiry interface), ExpiringCredentialRefreshConfig
// (refresh policy from SaslConfigs), AuthenticateCallbackHandler (login callback from
// auth/ package), KafkaThread (daemon thread from common/utils/), Time (clock abstraction).
// Uses javax.security.auth.login.LoginContext for JAAS login/logout operations.
// Impact: This is the scheduling engine for ALL expiring credential types -- both OAUTHBEARER
// token refresh and Kerberos TGT renewal flow through this class.
public abstract class ExpiringCredentialRefreshingLogin implements AutoCloseable {
    /**
     * Class that can be overridden for testing
     */
    static class LoginContextFactory {
        public LoginContext createLoginContext(ExpiringCredentialRefreshingLogin expiringCredentialRefreshingLogin)
                throws LoginException {
            return new LoginContext(expiringCredentialRefreshingLogin.contextName(),
                    expiringCredentialRefreshingLogin.subject(), expiringCredentialRefreshingLogin.callbackHandler(),
                    expiringCredentialRefreshingLogin.configuration());
        }

        public void refresherThreadStarted() {
            // empty
        }

        public void refresherThreadDone() {
            // empty
        }
    }

    private static class ExitRefresherThreadDueToIllegalStateException extends Exception {
        private static final long serialVersionUID = -6108495378411920380L;

        public ExitRefresherThreadDueToIllegalStateException(String message) {
            super(message);
        }
    }

    // COMPLEXITY: Refresher.run() is ~59 lines (lines 72-130) -- core refresh scheduling loop.
    // Structure: Outer while(true) loop computes next refresh time via refreshMs(), sleeps until
    // that time, then enters inner while(true) retry loop calling reLogin().
    // Control flow: (1) Compute nextRefreshMs -- null means exit thread (line 83), past-time
    // means adjust to 10s from now (KAFKA-7945 safety, line 90). (2) Sleep until nextRefreshMs
    // (line 94). (3) Check thread interrupt -- exit if interrupted (line 95-100). (4) Inner
    // retry loop: call reLogin() -- on success break to outer loop for next credential lifetime.
    // On ExitRefresherThreadDueToIllegalStateException -- log error and exit thread. On
    // LoginException -- sleep 10s (DELAY_SECONDS_BEFORE_NEXT_RETRY_WHEN_RELOGIN_FAILS) and
    // retry, exit if interrupted during retry sleep.
    // Exit paths: (a) refreshMs returns null, (b) thread interrupted, (c) irrecoverable error.
    private class Refresher implements Runnable {
        @Override
        public void run() {
            log.info("[Principal={}]: Expiring credential re-login thread started.", principalLogText());
            while (true) {
                /*
                 * Refresh thread's main loop. Each expiring credential lives for one iteration
                 * of the loop. Thread will exit if the loop exits from here.
                 */
                long nowMs = currentMs();
                Long nextRefreshMs = refreshMs(nowMs);
                if (nextRefreshMs == null) {
                    loginContextFactory.refresherThreadDone();
                    return;
                }
                // safety check motivated by KAFKA-7945,
                // should generally never happen except due to a bug
                if (nextRefreshMs < nowMs) {
                    log.warn("[Principal={}]: Expiring credential re-login sleep time was calculated to be in the past! Will explicitly adjust. ({})", principalLogText(),
                            new Date(nextRefreshMs));
                    nextRefreshMs = nowMs + 10 * 1000; // refresh in 10 seconds
                }
                log.info("[Principal={}]: Expiring credential re-login sleeping until: {}", principalLogText(),
                        new Date(nextRefreshMs));
                time.sleep(nextRefreshMs - nowMs);
                if (Thread.currentThread().isInterrupted()) {
                    log.info("[Principal={}]: Expiring credential re-login thread has been interrupted and will exit.",
                            principalLogText());
                    loginContextFactory.refresherThreadDone();
                    return;
                }
                while (true) {
                    /*
                     * Perform a re-login over and over again with some intervening delay
                     * unless/until either the refresh succeeds or we are interrupted.
                     */
                    try {
                        reLogin();
                        break; // success
                    } catch (ExitRefresherThreadDueToIllegalStateException e) {
                        log.error(e.getMessage(), e);
                        loginContextFactory.refresherThreadDone();
                        return;
                    } catch (LoginException loginException) {
                        log.warn(String.format(
                                "[Principal=%s]: LoginException during login retry; will sleep %d seconds before trying again.",
                                principalLogText(), DELAY_SECONDS_BEFORE_NEXT_RETRY_WHEN_RELOGIN_FAILS),
                                loginException);
                        // Sleep and allow loop to run/try again unless interrupted
                        time.sleep(DELAY_SECONDS_BEFORE_NEXT_RETRY_WHEN_RELOGIN_FAILS * 1000);
                        if (Thread.currentThread().isInterrupted()) {
                            log.error(
                                    "[Principal={}]: Interrupted while trying to perform a subsequent expiring credential re-login after one or more initial re-login failures: re-login thread exiting now: {}",
                                    principalLogText(), loginException.getMessage());
                            loginContextFactory.refresherThreadDone();
                            return;
                        }
                    }
                }
            }
        }
    }

    // DECISION: Daemon thread via KafkaThread rather than ScheduledExecutorService for refresh.
    // Alternative: ScheduledExecutorService with scheduleAtFixedRate or scheduleWithFixedDelay.
    // Rationale: A single dedicated daemon thread simplifies lifecycle management -- interrupt()
    // + join() on close() (lines 249-258) is straightforward. The refresh interval is dynamic
    // (computed per-token based on expiry window, jitter, and buffer) which doesn't fit
    // fixed-rate scheduling. The daemon flag ensures the JVM can exit without waiting for
    // the refresh thread. Risk: No thread pool -- if the thread dies unexpectedly (uncaught
    // exception), refresh stops entirely with no automatic recovery.
    private static final Logger log = LoggerFactory.getLogger(ExpiringCredentialRefreshingLogin.class);
    private static final long DELAY_SECONDS_BEFORE_NEXT_RETRY_WHEN_RELOGIN_FAILS = 10L;
    private static final Random RNG = new Random();
    private final Time time;
    private Thread refresherThread;

    private final LoginContextFactory loginContextFactory;
    private final String contextName;
    private final Configuration configuration;
    private final ExpiringCredentialRefreshConfig expiringCredentialRefreshConfig;
    private final AuthenticateCallbackHandler callbackHandler;

    // mark volatile due to existence of public subject() method
    private volatile Subject subject = null;
    private boolean hasExpiringCredential = false;
    private String principalName = null;
    private LoginContext loginContext = null;
    private ExpiringCredential expiringCredential = null;
    // DECISION: Class-level lock (mandatoryClassToSynchronizeOnPriorToRefresh) for refresh
    // serialization rather than instance-level lock. This ensures only one refresh across ALL
    // instances (in the same JVM) sharing the same lock class runs at a time. Alternative:
    // Instance-level lock -- each Login refreshes independently. Rationale: Serialization
    // prevents thundering herd on the OAuth/Kerberos provider when multiple clients refresh
    // simultaneously. Risk: A hung refresh blocks all other refreshes sharing the lock.
    private final Class<?> mandatoryClassToSynchronizeOnPriorToRefresh;

    public ExpiringCredentialRefreshingLogin(String contextName, Configuration configuration,
            ExpiringCredentialRefreshConfig expiringCredentialRefreshConfig,
            AuthenticateCallbackHandler callbackHandler, Class<?> mandatoryClassToSynchronizeOnPriorToRefresh) {
        this(contextName, configuration, expiringCredentialRefreshConfig, callbackHandler,
                mandatoryClassToSynchronizeOnPriorToRefresh, new LoginContextFactory(), Time.SYSTEM);
    }

    public ExpiringCredentialRefreshingLogin(String contextName, Configuration configuration,
            ExpiringCredentialRefreshConfig expiringCredentialRefreshConfig,
            AuthenticateCallbackHandler callbackHandler, Class<?> mandatoryClassToSynchronizeOnPriorToRefresh,
            LoginContextFactory loginContextFactory, Time time) {
        this.contextName = Objects.requireNonNull(contextName);
        this.configuration = Objects.requireNonNull(configuration);
        this.expiringCredentialRefreshConfig = Objects.requireNonNull(expiringCredentialRefreshConfig);
        this.callbackHandler = callbackHandler;
        this.mandatoryClassToSynchronizeOnPriorToRefresh = Objects
                .requireNonNull(mandatoryClassToSynchronizeOnPriorToRefresh);
        this.loginContextFactory = loginContextFactory;
        this.time = Objects.requireNonNull(time);
    }

    public Subject subject() {
        return subject; // field requires volatile keyword
    }

    public String contextName() {
        return contextName;
    }

    public Configuration configuration() {
        return configuration;
    }

    public AuthenticateCallbackHandler callbackHandler() {
        return callbackHandler;
    }

    public String serviceName() {
        return "kafka";
    }

    /**
     * Performs login for each login module specified for the login context of this
     * instance and starts the thread used to periodically re-login.
     * <p>
     * The synchronized keyword is not necessary because an implementation of
     * {@link Login} will delegate to this code (e.g. OAuthBearerRefreshingLogin),
     * and the {@code login()} method on the delegating class will itself be
     * synchronized if necessary.
     */
    // COMPLEXITY: 43 lines -- Initial login and refresh thread bootstrap.
    // Structure: (1) Create LoginContext via factory (line 204), (2) login() call (line 205),
    // (3) Extract Subject (line 208) and ExpiringCredential (line 209), (4) If no credential,
    // return early -- no refresh needed (lines 211-216). (5) Check clock skew -- if now >
    // expiry, log error and return without starting refresh (lines 222-232). (6) Start daemon
    // KafkaThread running Refresher (lines 241-244). Exit paths: return loginContext (normal,
    // line 245), return loginContext without refresh (no credential, line 216; clock skew,
    // line 231).
    public LoginContext login() throws LoginException {
        LoginContext tmpLoginContext = loginContextFactory.createLoginContext(this);
        tmpLoginContext.login();
        log.info("Successfully logged in.");
        loginContext = tmpLoginContext;
        subject = loginContext.getSubject();
        expiringCredential = expiringCredential();
        hasExpiringCredential = expiringCredential != null;
        if (!hasExpiringCredential) {
            // do not bother with re-logins.
            log.debug("No Expiring Credential");
            principalName = null;
            refresherThread = null;
            return loginContext;
        }

        principalName = expiringCredential.principalName();

        // Check for a clock skew problem
        long expireTimeMs = expiringCredential.expireTimeMs();
        long nowMs = currentMs();
        if (nowMs > expireTimeMs) {
            log.error(
                    "[Principal={}]: Current clock: {} is later than expiry {}. This may indicate a clock skew problem."
                            + " Check that this host's and remote host's clocks are in sync. Not starting refresh thread."
                            + " This process is likely unable to authenticate SASL connections (for example, it is unlikely"
                            + " to be able to authenticate a connection with a Kafka Broker).",
                    principalLogText(), new Date(nowMs), new Date(expireTimeMs));
            return loginContext;
        }

        if (log.isDebugEnabled())
            log.debug("[Principal={}]: It is an expiring credential", principalLogText());

        /*
         * Re-login periodically. How often is determined by the expiration date of the
         * credential and refresh-related configuration values.
         */
        refresherThread = KafkaThread.daemon(String.format("kafka-expiring-relogin-thread-%s", principalName),
                new Refresher());
        refresherThread.start();
        loginContextFactory.refresherThreadStarted();
        return loginContext;
    }

    public void close() {
        if (refresherThread != null && refresherThread.isAlive()) {
            refresherThread.interrupt();
            try {
                refresherThread.join();
            } catch (InterruptedException e) {
                log.warn("[Principal={}]: Interrupted while waiting for re-login thread to shutdown.",
                        principalLogText(), e);
                Thread.currentThread().interrupt();
            }
        }
    }

    public abstract ExpiringCredential expiringCredential();

    /**
     * Determine when to sleep until before performing a refresh
     * 
     * @param relativeToMs
     *            the point (in terms of number of milliseconds since the epoch) at
     *            which to perform the calculation
     * @return null if no refresh should occur, otherwise the time to sleep until
     *         (in terms of the number of milliseconds since the epoch) before
     *         performing a refresh
     */
    // COMPLEXITY: 88 lines -- Computes the next refresh timestamp with jitter and buffer
    // constraints. Structure: 6 conditional branches: (1) null credential -> retry after
    // DELAY_SECONDS (line 280), (2) clock past expiry + logout required -> exit thread
    // (line 293), (3) clock past expiry + no logout required -> retry after DELAY_SECONDS
    // (line 302), (4) absoluteLastRefreshTimeMs exceeded -> exit thread (line 315),
    // (5) remaining lifetime too short for min+buffer -> apply pct within remaining time
    // (line 337), (6) normal case -> compute proposedRefreshMs from start+pct, then clamp to
    // [endOfMinRefreshBufferTime, beginningOfEndBufferTimeMs].
    // Key: pct = windowFactor + (windowJitter * random) -- introduces randomness to prevent
    // thundering herd across multiple clients refreshing the same token lifetime.
    private Long refreshMs(long relativeToMs) {
        if (expiringCredential == null) {
            /*
             * Re-login failed because our login() invocation did not generate a credential
             * but also did not generate an exception. Try logging in again after some delay
             * (it seems likely to be a bug, but it doesn't hurt to keep trying to refresh).
             */
            long retvalNextRefreshMs = relativeToMs + DELAY_SECONDS_BEFORE_NEXT_RETRY_WHEN_RELOGIN_FAILS * 1000L;
            log.warn("[Principal={}]: No Expiring credential found: will try again at {}", principalLogText(),
                    new Date(retvalNextRefreshMs));
            return retvalNextRefreshMs;
        }
        long expireTimeMs = expiringCredential.expireTimeMs();
        if (relativeToMs > expireTimeMs) {
            boolean logoutRequiredBeforeLoggingBackIn = isLogoutRequiredBeforeLoggingBackIn();
            if (logoutRequiredBeforeLoggingBackIn) {
                log.error(
                        "[Principal={}]: Current clock: {} is later than expiry {}. This may indicate a clock skew problem."
                                + " Check that this host's and remote host's clocks are in sync. Exiting refresh thread.",
                        principalLogText(), new Date(relativeToMs), new Date(expireTimeMs));
                return null;
            } else {
                /*
                 * Since the current soon-to-expire credential isn't logged out until we have a
                 * new credential with a refreshed lifetime, it is possible that the current
                 * credential could expire if the re-login continually fails over and over again
                 * making us unable to get the new credential. Therefore keep trying rather than
                 * exiting.
                 */
                long retvalNextRefreshMs = relativeToMs + DELAY_SECONDS_BEFORE_NEXT_RETRY_WHEN_RELOGIN_FAILS * 1000L;
                log.warn("[Principal={}]: Expiring credential already expired at {}: will try to refresh again at {}",
                        principalLogText(), new Date(expireTimeMs), new Date(retvalNextRefreshMs));
                return retvalNextRefreshMs;
            }
        }
        Long absoluteLastRefreshTimeMs = expiringCredential.absoluteLastRefreshTimeMs();
        if (absoluteLastRefreshTimeMs != null && absoluteLastRefreshTimeMs < expireTimeMs) {
            log.warn("[Principal={}]: Expiring credential refresh thread exiting because the"
                    + " expiring credential's current expiration time ({}) exceeds the latest possible refresh time ({})."
                    + " This process will not be able to authenticate new SASL connections after that"
                    + " time (for example, it will not be able to authenticate a new connection with a Kafka Broker).",
                    principalLogText(), new Date(expireTimeMs), new Date(absoluteLastRefreshTimeMs));
            return null;
        }
        Long optionalStartTime = expiringCredential.startTimeMs();
        long startMs = optionalStartTime != null ? optionalStartTime : relativeToMs;
        log.info("[Principal={}]: Expiring credential valid from {} to {}", expiringCredential.principalName(),
                new java.util.Date(startMs), new java.util.Date(expireTimeMs));

        double pct = expiringCredentialRefreshConfig.loginRefreshWindowFactor()
                + (expiringCredentialRefreshConfig.loginRefreshWindowJitter() * RNG.nextDouble());
        /*
         * Ignore buffer times if the credential's remaining lifetime is less than their
         * sum.
         */
        long refreshMinPeriodSeconds = expiringCredentialRefreshConfig.loginRefreshMinPeriodSeconds();
        long clientRefreshBufferSeconds = expiringCredentialRefreshConfig.loginRefreshBufferSeconds();
        if (relativeToMs + 1000L * (refreshMinPeriodSeconds + clientRefreshBufferSeconds) > expireTimeMs) {
            long retvalRefreshMs = relativeToMs + (long) ((expireTimeMs - relativeToMs) * pct);
            log.warn(
                    "[Principal={}]: Expiring credential expires at {}, so buffer times of {} and {} seconds"
                            + " at the front and back, respectively, cannot be accommodated.  We will refresh at {}.",
                    principalLogText(), new Date(expireTimeMs), refreshMinPeriodSeconds, clientRefreshBufferSeconds,
                    new Date(retvalRefreshMs));
            return retvalRefreshMs;
        }
        long proposedRefreshMs = startMs + (long) ((expireTimeMs - startMs) * pct);
        // Don't let it violate the requested end buffer time
        long beginningOfEndBufferTimeMs = expireTimeMs - clientRefreshBufferSeconds * 1000;
        if (proposedRefreshMs > beginningOfEndBufferTimeMs) {
            log.info(
                    "[Principal={}]: Proposed refresh time of {} extends into the desired buffer time of {} seconds before expiration, so refresh it at the desired buffer begin point, at {}",
                    expiringCredential.principalName(), new Date(proposedRefreshMs), clientRefreshBufferSeconds,
                    new Date(beginningOfEndBufferTimeMs));
            return beginningOfEndBufferTimeMs;
        }
        // Don't let it violate the minimum refresh period
        long endOfMinRefreshBufferTime = relativeToMs + 1000 * refreshMinPeriodSeconds;
        if (proposedRefreshMs < endOfMinRefreshBufferTime) {
            log.info(
                    "[Principal={}]: Expiring credential re-login thread time adjusted from {} to {} since the former is sooner "
                            + "than the minimum refresh interval ({} seconds from now).",
                    principalLogText(), new Date(proposedRefreshMs), new Date(endOfMinRefreshBufferTime),
                    refreshMinPeriodSeconds);
            return endOfMinRefreshBufferTime;
        }
        // Proposed refresh time doesn't violate any constraints
        return proposedRefreshMs;
    }

    // SECURITY: (HIGH) Performs the actual logout/reLogin cycle under a class-level lock.
    // The synchronized block on mandatoryClassToSynchronizeOnPriorToRefresh (line 364) ensures
    // only one refresh across ALL instances (sharing the same lock class) runs at a time.
    // The method accesses and mutates: loginContext, expiringCredential, hasExpiringCredential,
    // principalName. All of these are non-volatile instance fields protected by the lock.
    // COMPLEXITY: 68 lines -- Logout/reLogin cycle under class-level lock.
    // Structure: synchronized block -> (1) If logout required and has credential: logout old
    // context, verify credential removed (throw ExitRefresherThread if still present, line 376).
    // (2) Save current credential/loginContext for potential rollback. (3) Create new
    // LoginContext, login. (4) If old credential exists, logout old context. (5) finally: if
    // login failed, restore original loginContext (line 397-399). (6) Extract new credential --
    // if null, log error; if same object as old credential, throw ExitRefresherThread (line 422).
    // (7) Update principalName. Exit paths: ExitRefresherThreadDueToIllegalStateException
    // (2 throw sites), LoginException (propagated to caller), normal return.
    private void reLogin() throws LoginException, ExitRefresherThreadDueToIllegalStateException {
        synchronized (mandatoryClassToSynchronizeOnPriorToRefresh) {
            // Only perform one refresh of a particular type at a time
            boolean logoutRequiredBeforeLoggingBackIn = isLogoutRequiredBeforeLoggingBackIn();
            if (hasExpiringCredential && logoutRequiredBeforeLoggingBackIn) {
                String principalLogTextPriorToLogout = principalLogText();
                log.info("Initiating logout for {}", principalLogTextPriorToLogout);
                loginContext.logout();
                // Make absolutely sure we were logged out
                expiringCredential = expiringCredential();
                hasExpiringCredential = expiringCredential != null;
                if (hasExpiringCredential)
                    // We can't force the removal because we don't know how to do it, so abort
                    throw new ExitRefresherThreadDueToIllegalStateException(String.format(
                            "Subject's private credentials still contains an instance of %s even though logout() was invoked; exiting refresh thread",
                            expiringCredential.getClass().getName()));
            }
            /*
             * Perform a login, making note of any credential that might need a logout()
             * afterwards
             */
            ExpiringCredential optionalCredentialToLogout = expiringCredential;
            LoginContext optionalLoginContextToLogout = loginContext;
            boolean cleanLogin = false; // remember to restore the original if necessary
            try {
                loginContext = loginContextFactory.createLoginContext(ExpiringCredentialRefreshingLogin.this);
                log.info("Initiating re-login for {}, logout() still needs to be called on a previous login = {}",
                        principalName, optionalCredentialToLogout != null);
                loginContext.login();
                cleanLogin = true; // no need to restore the original
                // Perform a logout() on any original credential if necessary
                if (optionalCredentialToLogout != null)
                    optionalLoginContextToLogout.logout();
            } finally {
                if (!cleanLogin)
                    // restore the original
                    loginContext = optionalLoginContextToLogout;
            }
            /*
             * Get the new credential and make sure it is not any old one that required a
             * logout() after the login()
             */
            expiringCredential = expiringCredential();
            hasExpiringCredential = expiringCredential != null;
            if (!hasExpiringCredential) {
                /*
                 * Re-login has failed because our login() invocation has not generated a
                 * credential but has also not generated an exception. We won't exit here;
                 * instead we will allow login retries in case we can somehow fix the issue (it
                 * seems likely to be a bug, but it doesn't hurt to keep trying to refresh).
                 */
                log.error("No Expiring Credential after a supposedly-successful re-login");
                principalName = null;
            } else {
                if (expiringCredential == optionalCredentialToLogout)
                    /*
                     * The login() didn't identify a new credential; we still have the old one. We
                     * don't know how to fix this, so abort.
                     */
                    throw new ExitRefresherThreadDueToIllegalStateException(String.format(
                            "Subject's private credentials still contains the previous, soon-to-expire instance of %s even though login() followed by logout() was invoked; exiting refresh thread",
                            expiringCredential.getClass().getName()));
                principalName = expiringCredential.principalName();
                if (log.isDebugEnabled())
                    log.debug("[Principal={}]: It is an expiring credential after re-login as expected",
                            principalLogText());
            }
        }
    }

    private String principalLogText() {
        return expiringCredential == null ? principalName
                : expiringCredential.getClass().getSimpleName() + ":" + principalName;
    }

    private long currentMs() {
        return time.milliseconds();
    }

    private boolean isLogoutRequiredBeforeLoggingBackIn() {
        return !expiringCredentialRefreshConfig.loginRefreshReloginAllowedBeforeLogout();
    }
}
