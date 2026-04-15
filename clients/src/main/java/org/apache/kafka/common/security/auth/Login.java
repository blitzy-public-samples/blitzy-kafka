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

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * Login interface for authentication.
 */
// DECISION: Lifecycle interface for SASL login management, separating login (credential
// acquisition) from authentication (credential verification during SASL exchange).
// Alternative: Combine login and authentication in a single interface.
// Rationale: Login (credential acquisition via JAAS LoginContext) and authentication
// (SASL challenge-response via AuthenticateCallbackHandler) have different lifecycles:
// login happens once at startup (or periodically for Kerberos TGT renewal / OAuth token
// refresh), while authentication happens per-connection. Separating concerns allows
// mechanism-specific login strategies (e.g., KerberosLogin's background TGT renewal thread)
// without complicating the per-connection authentication path.
//
// CROSS-CUTTING: Implemented by authenticator/AbstractLogin (base lifecycle),
// authenticator/DefaultLogin (standard JAAS login), kerberos/KerberosLogin (TGT renewal daemon),
// oauthbearer/OAuthBearerRefreshingLogin (OAuth token refresh). Managed by
// authenticator/LoginManager which provides reference-counted lifecycle management.
// Contract: configure() must be called before login(). subject() returns the authenticated
// Subject after login() completes. close() must release all resources (e.g., TGT renewal thread).
// Impact: Adding methods to this interface breaks all custom Login implementations.
public interface Login {

    /**
     * Configures this login instance.
     * @param configs Key-value pairs containing the parsed configuration options of
     *        the client or broker. Note that these are the Kafka configuration options
     *        and not the JAAS configuration options. The JAAS options may be obtained
     *        from `jaasConfiguration`.
     * @param contextName JAAS context name for this login which may be used to obtain
     *        the login context from `jaasConfiguration`.
     * @param jaasConfiguration JAAS configuration containing the login context named
     *        `contextName`. If static JAAS configuration is used, this `Configuration`
     *         may also contain other login contexts.
     * @param loginCallbackHandler Login callback handler instance to use for this Login.
     *        Login callback handler class may be configured using
     *        {@link org.apache.kafka.common.config.SaslConfigs#SASL_LOGIN_CALLBACK_HANDLER_CLASS}.
     */
    void configure(Map<String, ?> configs, String contextName, Configuration jaasConfiguration,
                   AuthenticateCallbackHandler loginCallbackHandler);

    /**
     * Performs login for each login module specified for the login context of this instance.
     */
    LoginContext login() throws LoginException;

    /**
     * Returns the authenticated subject of this login context.
     */
    Subject subject();

    /**
     * Returns the service name to be used for SASL.
     */
    String serviceName();

    /**
     * Closes this instance.
     */
    void close();
}
