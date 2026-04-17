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
package org.apache.kafka.common.config.provider;

import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.config.ConfigChangeCallback;
import org.apache.kafka.common.config.ConfigData;

import java.io.Closeable;
import java.util.Set;

/**
 * A provider of configuration data, which may optionally support subscriptions to configuration changes.
 * <p>Implementations are required to safely support concurrent calls to any of the methods in this interface.
 * <p>Kafka Connect discovers implementations of this interface using the Java {@link java.util.ServiceLoader} mechanism.
 * To support this, implementations of this interface should also contain a service provider configuration file in
 * {@code META-INF/services/org.apache.kafka.common.config.provider.ConfigProvider}.
 */
// DECISION: SPI design extends both Configurable and Closeable. Configurable provides
// configure(Map<String, ?>) for late initialization with provider-specific settings.
// Closeable provides close() for resource cleanup (e.g., network connections to Vault).
// Alternative: Single combined interface with configure/close/get methods. Rationale:
// Reusing existing Kafka interfaces (Configurable, Closeable) follows the project's
// composition-over-inheritance pattern and integrates with AbstractConfig's plugin lifecycle.
//
// DECISION: Two get() methods — get(path) returns ALL keys at a path, get(path, keys)
// returns a subset. Alternative: Single get(path, key) per-key method. Rationale: Batch
// retrieval amortizes network round-trips for remote providers (HashiCorp Vault, AWS SSM,
// Azure Key Vault) where each call may involve TLS handshake + authentication overhead.
//
// CROSS-CUTTING: This is the SPI contract consumed by:
//   - org.apache.kafka.common.config.AbstractConfig.instantiateConfigProviders() — provider
//     lifecycle (create, configure, close)
//   - org.apache.kafka.common.config.ConfigTransformer — resolves ${provider:path:key}
//     variable references by calling get(path, keys)
//   - Kafka Connect runtime (org.apache.kafka.connect.runtime) — manages provider lifecycle
//     independently, including subscription support for secret rotation
// All three concrete implementations in this package (FileConfigProvider,
// DirectoryConfigProvider, EnvVarConfigProvider) implement this interface.
// Third-party providers (Vault, SSM, Key Vault) also implement it via ServiceLoader.
public interface ConfigProvider extends Configurable, Closeable {

    // DECISION: get(path) returns ConfigData containing ALL key-value pairs at the given path.
    // The path semantics are provider-specific: file path for FileConfigProvider, directory
    // path for DirectoryConfigProvider, ignored for EnvVarConfigProvider.
    /**
     * Retrieves the data at the given path.
     *
     * @param path the path where the data resides
     * @return the configuration data
     */
    ConfigData get(String path);

    // DECISION: get(path, keys) returns only the requested subset of keys. This enables
    // callers (ConfigTransformer) to fetch exactly the keys referenced in ${provider:path:key}
    // expressions, avoiding unnecessary data transfer from remote providers.
    /**
     * Retrieves the data with the given keys at the given path.
     *
     * @param path the path where the data resides
     * @param keys the keys whose values will be retrieved
     * @return the configuration data
     */
    ConfigData get(String path, Set<String> keys);

    // DECISION: subscribe/unsubscribe are default no-op methods that throw
    // UnsupportedOperationException. This makes subscription support optional — only
    // providers with native change-notification capabilities (e.g., Vault lease renewal,
    // K8s watch API) need to override these. Alternative: Polling-based change detection
    // in ConfigTransformer. Rationale: Push-based notification avoids polling overhead and
    // latency for providers that support it, while the default UnsupportedOperationException
    // signals to callers (Connect runtime) that this provider does not support subscriptions.
    /**
     * Subscribes to changes for the given keys at the given path (optional operation).
     *
     * @param path the path where the data resides
     * @param keys the keys whose values will be retrieved
     * @param callback the callback to invoke upon change
     * @throws UnsupportedOperationException if the subscribe operation is not supported
     */
    default void subscribe(String path, Set<String> keys, ConfigChangeCallback callback) {
        throw new UnsupportedOperationException();
    }

    /**
     * Unsubscribes to changes for the given keys at the given path (optional operation).
     *
     * @param path the path where the data resides
     * @param keys the keys whose values will be retrieved
     * @param callback the callback to be unsubscribed from changes
     * @throws UnsupportedOperationException if the unsubscribe operation is not supported
     */
    default void unsubscribe(String path, Set<String> keys, ConfigChangeCallback callback) {
        throw new UnsupportedOperationException();
    }

    // CROSS-CUTTING: unsubscribeAll() is called by Kafka Connect's provider lifecycle
    // management during connector shutdown to clean up all active subscriptions for a
    // provider instance. The default throws UnsupportedOperationException, which Connect
    // catches and ignores for providers that don't support subscriptions.
    /**
     * Clears all subscribers (optional operation).
     *
     * @throws UnsupportedOperationException if the unsubscribeAll operation is not supported
     */
    default void unsubscribeAll() {
        throw new UnsupportedOperationException();
    }
}
