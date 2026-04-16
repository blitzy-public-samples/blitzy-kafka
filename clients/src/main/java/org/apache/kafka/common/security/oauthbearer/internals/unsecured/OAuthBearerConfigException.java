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
package org.apache.kafka.common.security.oauthbearer.internals.unsecured;

import org.apache.kafka.common.KafkaException;

/**
 * Exception thrown when there is a problem with the configuration (an invalid
 * option in a JAAS config, for example).
 */
// DECISION: KafkaException subclass for configuration errors rather than using the
// existing org.apache.kafka.common.config.ConfigException. Alternative: Reuse ConfigException
// from the common config package. Rationale: This keeps the unsecured OAUTHBEARER package
// self-contained — callers can catch OAuthBearerConfigException specifically for JAAS option
// validation errors without conflating them with general Kafka configuration errors.
// OAuthBearerUnsecuredLoginCallbackHandler uses this for invalid claim values, reserved
// claim names, and malformed lifetime/number options. OAuthBearerValidationUtils uses
// this for negative clock skew values. OAuthBearerScopeUtils uses it for invalid scope items.
public class OAuthBearerConfigException extends KafkaException {
    private static final long serialVersionUID = -8056105648062343518L;

    public OAuthBearerConfigException(String s) {
        super(s);
    }

    public OAuthBearerConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
