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
package org.apache.kafka.common.security.ssl;


import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.TrustManager;

// SECURITY: (LOW) SSL engine factory that adds CN logging to TLS connections.
// Why: Extends DefaultSslEngineFactory to log the Common Name (CN) of client
// certificates during TLS handshake via CommonNameLoggingTrustManagerFactoryWrapper.
// This is useful for identifying misconfigured clients presenting expired certs.
// Exploit: If log files are accessible to unauthorized users, the CN information
// (which may contain usernames, email addresses, or internal hostnames) could be
// used for reconnaissance, social engineering, or targeted attacks against clients.
// Improvement: Consider making CN logging configurable (off by default in
// production) and ensuring log files have restrictive permissions. Avoid logging
// full DN strings that may contain sensitive organizational unit or email fields.
public final class CommonNameLoggingSslEngineFactory extends DefaultSslEngineFactory {

    // CROSS-CUTTING: Configured via SslConfigs.SSL_ENGINE_FACTORY_CLASS_CONFIG when
    // CN logging is desired. Depends on: ssl/DefaultSslEngineFactory (base class),
    // ssl/CommonNameLoggingTrustManagerFactoryWrapper (wraps TrustManagerFactory for
    // CN extraction). Consumed by: ssl/SslFactory which instantiates this class via
    // reflection when configured. Contract: Overrides only getTrustManagers() -- all
    // other SSL engine behavior is inherited from DefaultSslEngineFactory.

    // DECISION: Extends DefaultSslEngineFactory rather than wrapping it (delegation).
    // Alternative: Use a wrapper/decorator that delegates to any SslEngineFactory.
    // Rationale: Extension allows inheriting all DefaultSslEngineFactory behavior
    // (SSLContext creation, cipher suite config, reconfiguration support) while only
    // overriding getTrustManagers() to inject logging. The decorator pattern would
    // require re-implementing the entire SslEngineFactory interface. Trade-off: this
    // class is tightly coupled to DefaultSslEngineFactory and cannot wrap custom
    // SslEngineFactory implementations.
    @Override
    protected TrustManager[] getTrustManagers(SecurityStore truststore, String tmfAlgorithm) throws NoSuchAlgorithmException, KeyStoreException {
        CommonNameLoggingTrustManagerFactoryWrapper tmf = CommonNameLoggingTrustManagerFactoryWrapper.getInstance(tmfAlgorithm);
        KeyStore ts = truststore == null ? null : truststore.get();
        tmf.init(ts);
        return tmf.getTrustManagers();
    }

}
