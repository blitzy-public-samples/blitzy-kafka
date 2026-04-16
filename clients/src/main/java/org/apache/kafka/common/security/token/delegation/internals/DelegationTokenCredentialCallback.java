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
package org.apache.kafka.common.security.token.delegation.internals;

import org.apache.kafka.common.security.scram.ScramCredentialCallback;

public class DelegationTokenCredentialCallback extends ScramCredentialCallback {
    // SECURITY (LOW): Callback carrier extending ScramCredentialCallback to pass delegation
    // token metadata (owner, expiry) through the SASL/SCRAM callback mechanism during
    // token-based authentication. The ScramServerCallbackHandler populates this callback
    // with token owner and expiry from DelegationTokenCache, enabling the SCRAM server
    // to enforce token-specific authorization and expiry checks.
    //
    // CROSS-CUTTING: Used by ScramServerCallbackHandler (authenticator package) when
    // authenticating via delegation tokens. Extends ScramCredentialCallback (scram package)
    // to carry additional token-specific metadata alongside SCRAM credentials.
    private String tokenOwner;
    private Long tokenExpiryTimestamp;

    public void tokenOwner(String tokenOwner) {
        this.tokenOwner = tokenOwner;
    }

    public String tokenOwner() {
        return tokenOwner;
    }

    // SECURITY (LOW): Token expiry timestamp passed through SASL callback chain.
    // The SCRAM server uses this to reject authentication for expired tokens.
    // If this value is not set correctly, expired tokens may pass SCRAM authentication.
    public void tokenExpiryTimestamp(Long tokenExpiryTimestamp) {
        this.tokenExpiryTimestamp = tokenExpiryTimestamp;
    }

    public Long tokenExpiryTimestamp() {
        return tokenExpiryTimestamp;
    }
}