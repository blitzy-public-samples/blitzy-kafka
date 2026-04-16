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

/**
 * A credential that expires and that can potentially be refreshed
 * 
 * @see ExpiringCredentialRefreshingLogin
 */
// SECURITY: SEC-OAUTH-069 (MEDIUM) Interface defines the credential expiry contract used by the refresh
// scheduler. Implementations must ensure thread-safe access to startTimeMs()/expireTimeMs()
// as these are read by the background refresh thread and written during credential rotation.
// Why: The credential's expiry timestamp drives the refresh scheduler in
// ExpiringCredentialRefreshingLogin.refreshMs(). If expireTimeMs() returns incorrect or stale
// values, refresh scheduling is wrong — either refreshing too early (wasting resources and
// potentially DoS-ing the OAuth provider) or too late (causing expired credential errors).
// Exploit: If an attacker can manipulate the ExpiringCredential implementation (e.g., via a
// malicious JAAS LoginModule that returns a custom implementation), they could return
// Long.MAX_VALUE for expireTimeMs(), preventing token refresh forever. The token would
// eventually expire without refresh, disrupting all SASL connections on this client/broker.
// Improvement: Consider adding a sanity check in the refresh scheduler that rejects credentials
// with expiry times more than a configurable maximum (e.g., 24 hours) into the future.
// DECISION: Interface-based expiry contract rather than a concrete class. This enables reuse
// for non-OAuth credentials — Kerberos TGTs use the same expiry/refresh infrastructure via
// ExpiringCredentialRefreshingLogin. Alternative: Dedicated OAuthBearerExpiringCredential
// concrete class. Rationale: The interface allows ExpiringCredentialRefreshingLogin to be
// protocol-agnostic, supporting any credential type that can express expiry semantics.
// Risk: Implementations may violate implicit contracts (e.g., thread-safety, consistent
// start/expire times) since Java interfaces cannot enforce these at compile time.
// CROSS-CUTTING: Implemented by an anonymous class in OAuthBearerRefreshingLogin.configure()
// (oauthbearer/internals/OAuthBearerRefreshingLogin.java) which wraps OAuthBearerToken.
// Consumed by ExpiringCredentialRefreshingLogin (this package) — startTimeMs() and
// expireTimeMs() drive refresh scheduling in refreshMs(); absoluteLastRefreshTimeMs() controls
// refresh thread termination. principalName() is used for logging throughout the refresh cycle.
// Contract: expireTimeMs() must always return a valid epoch ms (primitive long, never stale).
// startTimeMs() may be null. absoluteLastRefreshTimeMs() may be null (no refresh deadline).
// Impact: Any change to these method signatures breaks all credential refresh across OAUTHBEARER
// and Kerberos authentication paths.
public interface ExpiringCredential {
    /**
     * The name of the principal to which this credential applies (used only for
     * logging)
     * 
     * @return the always non-null/non-empty principal name
     */
    String principalName();

    /**
     * When the credential became valid, in terms of the number of milliseconds
     * since the epoch, if known, otherwise null. An expiring credential may not
     * necessarily indicate when it was created -- just when it expires -- so we
     * need to support a null return value here.
     * 
     * @return the time when the credential became valid, in terms of the number of
     *         milliseconds since the epoch, if known, otherwise null
     */
    Long startTimeMs();

    /**
     * When the credential expires, in terms of the number of milliseconds since the
     * epoch. All expiring credentials by definition must indicate their expiration
     * time -- thus, unlike other methods, we do not support a null return value
     * here.
     * 
     * @return the time when the credential expires, in terms of the number of
     *         milliseconds since the epoch
     */
    // SECURITY: SEC-OAUTH-070 (HIGH) expireTimeMs() is the critical security-relevant method — it determines when
    // Why: Expiring credential lifecycle management determines when
    // authentication material becomes invalid.
    // the credential is no longer valid. Returning a manipulated value (too far in the future
    // or too far in the past) directly impacts authentication reliability.
    // Exploit: An attacker could present an expired credential during
    // the refresh buffer window before the system detects expiration.
    // Improvement: Enforce strict expiry checks before returning
    // credential data and add access auditing for credential reads.
    long expireTimeMs();

    /**
     * The point after which the credential can no longer be refreshed, in terms of
     * the number of milliseconds since the epoch, if any, otherwise null. Some
     * expiring credentials can be refreshed over and over again without limit, so
     * we support a null return value here.
     * 
     * @return the point after which the credential can no longer be refreshed, in
     *         terms of the number of milliseconds since the epoch, if any,
     *         otherwise null
     */
    // SECURITY: SEC-OAUTH-071 (MEDIUM) If absoluteLastRefreshTimeMs() returns a time before expireTimeMs(), the refresh
    // Why: Expiring credential lifecycle management determines when
    // authentication material becomes invalid.
    // thread will exit (ExpiringCredentialRefreshingLogin line 309-316), leaving the credential
    // to expire without further refresh attempts. A malicious implementation could use this to
    // force credential expiry by returning a past timestamp.
    // Exploit: An attacker could present an expired credential during
    // the refresh buffer window before the system detects expiration.
    // Improvement: Enforce strict expiry checks before returning
    // credential data and add access auditing for credential reads.
    Long absoluteLastRefreshTimeMs();
}
