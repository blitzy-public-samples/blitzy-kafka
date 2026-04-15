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

package org.apache.kafka.common.security.oauthbearer;

import org.apache.kafka.common.KafkaException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

/**
 * A {@code JwtValidatorException} is thrown in cases where the validity of a JWT cannot be
 * determined. It is intended to be used when errors arise within the processing of a
 * {@link CallbackHandler#handle(Callback[])}. This error, however, is not thrown from that
 * method directly.
 *
 * @see JwtValidator#validate(String)
 */
// DECISION: Extends KafkaException (unchecked) rather than checked exception. Alternative:
// Extend SecurityException. Rationale: JwtValidator.validate() declares this as thrown,
// but it needs to propagate through CallbackHandler.handle() which only declares IOException
// and UnsupportedCallbackException. Using KafkaException (RuntimeException) allows it to
// propagate without modifying the JAAS Callback interface contract.
// Risk: Must be caught explicitly by callback handlers — uncaught instances will terminate
// the SASL handshake with an opaque error.
//
// CROSS-CUTTING: Thrown by BrokerJwtValidator (jose4j validation failures — expired tokens,
// invalid signatures, missing claims), ClientJwtValidator (structural parsing failures),
// and DefaultJwtValidator (delegation to either). Caught by OAuthBearerValidatorCallbackHandler
// and OAuthBearerLoginCallbackHandler which translate it to callback error responses.
// Contract: Exception message may be logged server-side but should NOT be returned to
// the client in SASL error responses (to prevent information leakage about validation logic).
public class JwtValidatorException extends KafkaException {

    public JwtValidatorException(String message) {
        super(message);
    }

    public JwtValidatorException(Throwable cause) {
        super(cause);
    }

    public JwtValidatorException(String message, Throwable cause) {
        super(message, cause);
    }
}
