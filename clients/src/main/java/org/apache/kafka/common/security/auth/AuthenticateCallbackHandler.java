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

package org.apache.kafka.common.security.auth;

import java.util.List;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;

/*
 * Callback handler for SASL-based authentication
 */
// DECISION: Extends javax.security.auth.callback.CallbackHandler with Configurable lifecycle
// (configure + close). Alternative: Use plain CallbackHandler directly.
// Rationale: Plain CallbackHandler.handle() provides no mechanism for passing Kafka-specific
// context (SASL mechanism name, JAAS config entries, listener-scoped Kafka configs). The
// configure() method bridges this gap, enabling mechanism-specific initialization (e.g.,
// SCRAM credential lookup, OAuth token endpoint configuration, Kerberos service name).
// The close() method ensures resource cleanup (e.g., closing HTTP connections in OAuth handlers).
//
// CROSS-CUTTING: Central extension point for ALL SASL mechanism callback handlers.
// Implemented by: authenticator/SaslClientCallbackHandler, authenticator/SaslServerCallbackHandler,
// oauthbearer/OAuthBearerLoginCallbackHandler, oauthbearer/OAuthBearerValidatorCallbackHandler,
// kerberos/KerberosClientCallbackHandler, plain/internals/PlainServerCallbackHandler,
// scram/internals/ScramServerCallbackHandler, and custom user-provided handlers.
// Loaded via reflection from SaslConfigs.SASL_CLIENT_CALLBACK_HANDLER_CLASS /
// SASL_SERVER_CALLBACK_HANDLER_CLASS / SASL_LOGIN_CALLBACK_HANDLER_CLASS.
// Contract: configure() is called once after construction; handle() may be called concurrently
// from multiple SASL authentication threads; close() is called during shutdown.
// Impact: Adding new callbacks or changing the configure() signature breaks all custom handlers.
public interface AuthenticateCallbackHandler extends CallbackHandler {

    /**
     * Configures this callback handler for the specified SASL mechanism.
     *
     * @param configs Key-value pairs containing the parsed configuration options of
     *        the client or broker. Note that these are the Kafka configuration options
     *        and not the JAAS configuration options. JAAS config options may be obtained
     *        from `jaasConfigEntries` for callbacks which obtain some configs from the
     *        JAAS configuration. For configs that may be specified as both Kafka config
     *        as well as JAAS config (e.g. sasl.kerberos.service.name), the configuration
     *        is treated as invalid if conflicting values are provided.
     * @param saslMechanism Negotiated SASL mechanism. For clients, this is the SASL
     *        mechanism configured for the client. For brokers, this is the mechanism
     *        negotiated with the client and is one of the mechanisms enabled on the broker.
     * @param jaasConfigEntries JAAS configuration entries from the JAAS login context.
     *        This list contains a single entry for clients and may contain more than
     *        one entry for brokers if multiple mechanisms are enabled on a listener using
     *        static JAAS configuration where there is no mapping between mechanisms and
     *        login module entries. In this case, callback handlers can use the login module in
     *        `jaasConfigEntries` to identify the entry corresponding to `saslMechanism`.
     *        Alternatively, dynamic JAAS configuration option
     *        {@link org.apache.kafka.common.config.SaslConfigs#SASL_JAAS_CONFIG} may be
     *        configured on brokers with listener and mechanism prefix, in which case
     *        only the configuration entry corresponding to `saslMechanism` will be provided
     *        in `jaasConfigEntries`.
     */
    void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries);

    /**
     * Closes this instance.
     */
    void close();
}
