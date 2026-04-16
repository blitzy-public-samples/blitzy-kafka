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
package org.apache.kafka.common.security.token.delegation;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * A class representing a delegation token.
 *
 */
public class DelegationToken {
    // SECURITY: SEC-TOKEN-001 (HIGH) This class holds the HMAC shared secret for delegation token authentication.
    // Why: Delegation tokens carry HMAC secrets that serve as
    // authentication credentials for token-based access.
    // The HMAC is the effective credential — possession allows authentication as the token owner.
    // Exploit: If HMAC bytes leak via logs, serialization, or toString(), an attacker can forge
    // token-based authentication requests by constructing a SCRAM authentication using the HMAC.
    // Improvement: Consider defensive-copying the byte[] hmac in constructor and hmac() accessor
    // to prevent external mutation of the shared secret.
    //
    // DECISION: Immutable value object design — tokenInformation carries identity metadata,
    // hmac carries the authentication secret. Separating identification (tokenId) from
    // authentication (hmac) follows standard credential management patterns (KIP-48).
    //
    // CROSS-CUTTING: Consumed by metadata/DelegationTokenData for KRaft metadata records,
    // authenticator/CredentialCache for SCRAM credential storage, and core/DelegationTokenManager
    // for broker-side token lifecycle (issue/renew/expire).

    private final TokenInformation tokenInformation;
    private final byte[] hmac;

    public DelegationToken(TokenInformation tokenInformation, byte[] hmac) {
        this.tokenInformation = tokenInformation;
        this.hmac = hmac;
    }

    public TokenInformation tokenInfo() {
        return tokenInformation;
    }

    // SECURITY: SEC-TOKEN-002 (MEDIUM) Returns raw byte[] reference without defensive copy.
    // Why: Delegation tokens carry HMAC secrets that serve as
    // authentication credentials for token-based access.
    // Callers can mutate the internal HMAC, potentially corrupting token authentication.
    // Improvement: Return Arrays.copyOf(hmac, hmac.length) to enforce immutability.
    // Exploit: A caller mutating the returned HMAC byte[] reference
    // could corrupt the token, causing denial of service for token users.
    public byte[] hmac() {
        return hmac;
    }

    public String hmacAsBase64String() {
        return Base64.getEncoder().encodeToString(hmac);
    }

    // SECURITY: SEC-TOKEN-003 (HIGH) Uses MessageDigest.isEqual() for constant-time HMAC comparison.
    // Why: Delegation tokens carry HMAC secrets that serve as
    // authentication credentials for token-based access.
    // This prevents timing side-channel attacks where an attacker measures comparison
    // latency to reconstruct the HMAC value byte-by-byte across many requests.
    // If this were replaced with Arrays.equals() (which short-circuits on first mismatch),
    // an attacker could determine each HMAC byte in O(256*N) requests.
    // Improvement: Add a unit test asserting this method uses constant-time comparison
    // to prevent accidental regression to Arrays.equals().
    // Exploit: A non-constant-time HMAC comparison would leak HMAC
    // bytes through timing analysis over many authentication attempts.
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        DelegationToken token = (DelegationToken) o;

        return Objects.equals(tokenInformation, token.tokenInformation) && MessageDigest.isEqual(hmac, token.hmac);
    }

    @Override
    public int hashCode() {
        int result = tokenInformation != null ? tokenInformation.hashCode() : 0;
        result = 31 * result + Arrays.hashCode(hmac);
        return result;
    }

    // SECURITY: SEC-TOKEN-004 (HIGH) Deliberately masks HMAC in toString() output to prevent secret
    // Why: Delegation tokens carry HMAC secrets that serve as
    // authentication credentials for token-based access.
    // leakage via logging frameworks (SLF4J/Log4j2). If HMAC appeared in logs, any
    // log reader could extract the token credential and authenticate as the token owner.
    // Exploit: If the HMAC masking in toString() is bypassed or removed,
    // log output would expose the full HMAC, enabling token impersonation.
    // Improvement: Add HMAC integrity verification before any
    // token operation to detect corruption or tampering.
    @Override
    public String toString() {
        return "DelegationToken{" +
            "tokenInformation=" + tokenInformation +
            ", hmac=[*******]" +
            '}';
    }
}
