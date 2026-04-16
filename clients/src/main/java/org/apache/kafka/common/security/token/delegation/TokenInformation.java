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

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

/**
 * A class representing a delegation token details.
 *
 */
public class TokenInformation {

    // SECURITY (HIGH): Token metadata includes principal identity and temporal bounds.
    // Both maxTimestamp (absolute lifetime) and expiryTimestamp (renewable window) MUST
    // be validated during authentication. If only expiryTimestamp is checked, a repeatedly-
    // renewed token could remain valid indefinitely past its intended maximum lifetime.
    // Improvement: Add a convenience isExpired(long currentTimeMs) method checking both
    // timestamps to prevent caller errors in expiry enforcement.
    //
    // DECISION: Separate maxTimestamp (absolute, immutable) from expiryTimestamp (renewable,
    // mutable) per KIP-48 delegation token design. maxTimestamp provides a hard upper bound
    // that cannot be extended by renewals, ensuring tokens have a finite lifetime regardless
    // of renewal frequency. This dual-timestamp design prevents indefinite token persistence.
    //
    // CROSS-CUTTING: Consumed by metadata/DelegationTokenData for KRaft metadata serialization,
    // DelegationTokenCache (internals) for in-memory token lookup, and core/DelegationTokenManager
    // for broker-side token lifecycle enforcement.

    private final KafkaPrincipal owner;
    private final KafkaPrincipal tokenRequester;
    private final Collection<KafkaPrincipal> renewers;
    private final long issueTimestamp;
    private final long maxTimestamp;
    // SECURITY: Mutable field -- not final. Updates via setExpiryTimestamp() are unsynchronized.
    // In a multi-threaded broker context, concurrent reads and renewal-writes to this field
    // could produce stale expiry checks. Callers must provide external synchronization.
    private long expiryTimestamp;
    private final String tokenId;

    public TokenInformation(String tokenId, KafkaPrincipal owner,
                            Collection<KafkaPrincipal> renewers, long issueTimestamp, long maxTimestamp, long expiryTimestamp) {
        this(tokenId, owner, owner, renewers, issueTimestamp, maxTimestamp, expiryTimestamp);
    }

    public TokenInformation(String tokenId, KafkaPrincipal owner, KafkaPrincipal tokenRequester,
                            Collection<KafkaPrincipal> renewers, long issueTimestamp, long maxTimestamp, long expiryTimestamp) {
        this.tokenId = tokenId;
        this.owner = owner;
        this.tokenRequester = tokenRequester;
        this.renewers = renewers;
        this.issueTimestamp =  issueTimestamp;
        this.maxTimestamp =  maxTimestamp;
        this.expiryTimestamp =  expiryTimestamp;
    }

    // Convert record elements into a TokenInformation
    public static TokenInformation fromRecord(String tokenId, KafkaPrincipal owner, KafkaPrincipal tokenRequester,
                            Collection<KafkaPrincipal> renewers, long issueTimestamp, long maxTimestamp, long expiryTimestamp) {
        return new TokenInformation(
            tokenId, owner, tokenRequester, renewers, issueTimestamp, maxTimestamp, expiryTimestamp);
    }

    public KafkaPrincipal owner() {
        return owner;
    }

    public String ownerAsString() {
        return owner.toString();
    }

    public KafkaPrincipal tokenRequester() {
        return tokenRequester;
    }

    public String tokenRequesterAsString() {
        return tokenRequester.toString();
    }

    public Collection<KafkaPrincipal> renewers() {
        return renewers;
    }

    public Collection<String> renewersAsString() {
        Collection<String> renewerList = new ArrayList<>();
        for (KafkaPrincipal renewer : renewers) {
            renewerList.add(renewer.toString());
        }
        return renewerList;
    }

    public long issueTimestamp() {
        return issueTimestamp;
    }

    public long expiryTimestamp() {
        return expiryTimestamp;
    }

    // SECURITY (MEDIUM): Unsynchronized mutation of expiry timestamp.
    // Exploit: If a token renewal (setExpiryTimestamp) races with an authentication check
    // (expiryTimestamp()), the auth check may see a stale value, allowing use of an
    // effectively-expired token. Improvement: Consider volatile or AtomicLong for
    // thread-safe reads without full synchronization.
    public void setExpiryTimestamp(long expiryTimestamp) {
        this.expiryTimestamp = expiryTimestamp;
    }

    public String tokenId() {
        return tokenId;
    }

    public long maxTimestamp() {
        return maxTimestamp;
    }

    // SECURITY (MEDIUM): Authorization check -- determines if a principal can operate on this token.
    // Owner, requester, and renewers all have management rights. KafkaPrincipal.equals() uses
    // type+name comparison; ensure principal type is validated upstream to prevent type confusion.
    // DECISION: Token requester (who created the token on behalf of the owner) is granted
    // the same management rights as the owner -- this supports delegation use cases where
    // a service creates tokens for end-users.
    public boolean ownerOrRenewer(KafkaPrincipal principal) {
        return owner.equals(principal) || tokenRequester.equals(principal) || renewers.contains(principal);
    }

    @Override
    public String toString() {
        return "TokenInformation{" +
            "owner=" + owner +
            ", tokenRequester=" + tokenRequester +
            ", renewers=" + renewers +
            ", issueTimestamp=" + issueTimestamp +
            ", maxTimestamp=" + maxTimestamp +
            ", expiryTimestamp=" + expiryTimestamp +
            ", tokenId='" + tokenId + '\'' +
            '}';
    }

    // DECISION: equals() intentionally omits expiryTimestamp because the same logical token
    // at different renewal stages should be considered equal. However, hashCode() includes
    // expiryTimestamp -- this asymmetry can cause issues in hashed collections where a token
    // whose expiry was updated may hash to a different bucket but still be "equal" to its
    // previous state. Callers using TokenInformation in HashSets/HashMaps must be aware
    // that mutating expiryTimestamp after insertion may cause lookup failures.
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        TokenInformation that = (TokenInformation) o;

        return issueTimestamp == that.issueTimestamp &&
            maxTimestamp == that.maxTimestamp &&
            Objects.equals(owner, that.owner) &&
            Objects.equals(tokenRequester, that.tokenRequester) &&
            Objects.equals(renewers, that.renewers) &&
            Objects.equals(tokenId, that.tokenId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(owner, tokenRequester, renewers, issueTimestamp, maxTimestamp, expiryTimestamp, tokenId);
    }
}
