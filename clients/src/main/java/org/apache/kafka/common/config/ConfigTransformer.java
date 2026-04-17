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
package org.apache.kafka.common.config;

import org.apache.kafka.common.config.provider.ConfigProvider;
import org.apache.kafka.common.config.provider.FileConfigProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class wraps a set of {@link ConfigProvider} instances and uses them to perform
 * transformations.
 *
 * <p>The default variable pattern is of the form <code>${provider:[path:]key}</code>,
 * where the <code>provider</code> corresponds to a {@link ConfigProvider} instance, as passed to
 * {@link ConfigTransformer#ConfigTransformer(Map)}.  The pattern will extract a set
 * of paths (which are optional) and keys and then pass them to {@link ConfigProvider#get(String, Set)} to obtain the
 * values with which to replace the variables.
 *
 * <p>For example, if a Map consisting of an entry with a provider name "file" and provider instance
 * {@link FileConfigProvider} is passed to the {@link ConfigTransformer#ConfigTransformer(Map)}, and a Properties
 * file with contents
 * <pre>
 * fileKey=someValue
 * </pre>
 * resides at the path "/tmp/properties.txt", then when a configuration Map which has an entry with a key "someKey" and
 * a value "${file:/tmp/properties.txt:fileKey}" is passed to the {@link #transform(Map)} method, then the transformed
 * Map will have an entry with key "someKey" and a value "someValue".
 *
 * <p>This class only depends on {@link ConfigProvider#get(String, Set)} and does not depend on subscription support
 * in a {@link ConfigProvider}, such as the {@link ConfigProvider#subscribe(String, Set, ConfigChangeCallback)} and
 * {@link ConfigProvider#unsubscribe(String, Set, ConfigChangeCallback)} methods.
 *
 * @implNote DECISION: Uses a regex-based variable pattern "${provider:[path:]key}" (KIP-297) rather than
 * a custom parser. Alternative: Recursive-descent parser for nested variables. Rationale: Regex is simpler
 * and sufficient — Kafka config values don't require nested variable expansion. The pattern uses non-greedy
 * matching ([^}]*?) to correctly handle multiple variables in a single value.
 *
 * DECISION: Two-phase processing (collect variables → batch lookup → replace) rather than inline resolution.
 * Alternative: Resolve each variable as encountered. Rationale: Batching lookups by provider+path enables
 * ConfigProvider.get(path, Set&lt;String&gt;) to fetch multiple keys in a single call, reducing round trips
 * to external secret stores (e.g., Vault, AWS Secrets Manager).
 *
 * DECISION: Unresolved variables (no matching provider) are preserved as-is in the output rather than
 * throwing. Rationale: Graceful degradation — allows partial resolution when only some providers are
 * configured. The caller (AbstractConfig) can detect unresolved placeholders if needed.
 */
public class ConfigTransformer {
    // CROSS-CUTTING: Used by AbstractConfig.resolveConfigVariables() during config construction.
    // The pattern is also implicitly consumed by Connect's DistributedHerder which passes
    // connector configs through AbstractConfig, enabling ${file:/path:key} secret resolution.
    public static final Pattern DEFAULT_PATTERN = Pattern.compile("\\$\\{([^}]*?):(([^}]*?):)?([^}]*?)\\}");
    private static final String EMPTY_PATH = "";

    private final Map<String, ConfigProvider> configProviders;

    /**
     * Creates a ConfigTransformer with the default pattern, of the form <code>${provider:[path:]key}</code>.
     *
     * @param configProviders a Map of provider names and {@link ConfigProvider} instances.
     */
    public ConfigTransformer(Map<String, ConfigProvider> configProviders) {
        this.configProviders = configProviders;
    }

    /**
     * Transforms the given configuration data by using the {@link ConfigProvider} instances to
     * look up values to replace the variables in the pattern.
     *
     * @param configs the configuration values to be transformed
     * @return an instance of {@link ConfigTransformerResult}
     */
    // COMPLEXITY: transform() is ~45 lines — Three-phase pipeline:
    // Phase 1 (lines 78-91): Collect — scan all config values for ${provider:path:key} variables,
    //   group by provider name and path for batched lookups.
    // Phase 2 (lines 93-114): Lookup — for each provider+path, call ConfigProvider.get(path, keys)
    //   and collect data + TTLs. Null/missing providers are silently skipped.
    // Phase 3 (lines 117-121): Replace — substitute matched variables with looked-up values using
    //   the replace() helper. Unmatched variables are preserved as-is.
    // Key paths: Normal resolution path, provider-not-found path (silent skip), null-value path.
    public ConfigTransformerResult transform(Map<String, String> configs) {
        Map<String, Map<String, Set<String>>> keysByProvider = new HashMap<>();
        Map<String, Map<String, Map<String, String>>> lookupsByProvider = new HashMap<>();

        // Collect the variables from the given configs that need transformation
        for (Map.Entry<String, String> config : configs.entrySet()) {
            if (config.getValue() != null) {
                List<ConfigVariable> configVars = getVars(config.getValue(), DEFAULT_PATTERN);
                for (ConfigVariable configVar : configVars) {
                    Map<String, Set<String>> keysByPath = keysByProvider.computeIfAbsent(configVar.providerName, k -> new HashMap<>());
                    Set<String> keys = keysByPath.computeIfAbsent(configVar.path, k -> new HashSet<>());
                    keys.add(configVar.variable);
                }
            }
        }

        // Retrieve requested variables from the ConfigProviders
        Map<String, Long> ttls = new HashMap<>();
        for (Map.Entry<String, Map<String, Set<String>>> entry : keysByProvider.entrySet()) {
            String providerName = entry.getKey();
            ConfigProvider provider = configProviders.get(providerName);
            Map<String, Set<String>> keysByPath = entry.getValue();
            if (provider != null && keysByPath != null) {
                for (Map.Entry<String, Set<String>> pathWithKeys : keysByPath.entrySet()) {
                    String path = pathWithKeys.getKey();
                    Set<String> keys = new HashSet<>(pathWithKeys.getValue());
                    ConfigData configData = provider.get(path, keys);
                    Map<String, String> data = configData.data();
                    Long ttl = configData.ttl();
                    if (ttl != null && ttl >= 0) {
                        ttls.put(path, ttl);
                    }
                    Map<String, Map<String, String>> keyValuesByPath =
                            lookupsByProvider.computeIfAbsent(providerName, k -> new HashMap<>());
                    keyValuesByPath.put(path, data);
                }
            }
        }

        // Perform the transformations by performing variable replacements
        Map<String, String> data = new HashMap<>(configs);
        for (Map.Entry<String, String> config : configs.entrySet()) {
            data.put(config.getKey(), replace(lookupsByProvider, config.getValue(), DEFAULT_PATTERN));
        }
        return new ConfigTransformerResult(data, ttls);
    }

    private static List<ConfigVariable> getVars(String value, Pattern pattern) {
        List<ConfigVariable> configVars = new ArrayList<>();
        Matcher matcher = pattern.matcher(value);
        while (matcher.find()) {
            configVars.add(new ConfigVariable(matcher));
        }
        return configVars;
    }

    private static String replace(Map<String, Map<String, Map<String, String>>> lookupsByProvider,
                                  String value,
                                  Pattern pattern) {
        if (value == null) {
            return null;
        }
        Matcher matcher = pattern.matcher(value);
        StringBuilder builder = new StringBuilder();
        int i = 0;
        while (matcher.find()) {
            ConfigVariable configVar = new ConfigVariable(matcher);
            Map<String, Map<String, String>> lookupsByPath = lookupsByProvider.get(configVar.providerName);
            if (lookupsByPath != null) {
                Map<String, String> keyValues = lookupsByPath.get(configVar.path);
                String replacement = keyValues.get(configVar.variable);
                builder.append(value, i, matcher.start());
                if (replacement == null) {
                    // No replacements will be performed; just return the original value
                    builder.append(matcher.group(0));
                } else {
                    builder.append(replacement);
                }
                i = matcher.end();
            }
        }
        builder.append(value, i, value.length());
        return builder.toString();
    }

    // DECISION: Private inner class rather than a record or tuple for regex match groups.
    // Alternative: Use Matcher groups directly. Rationale: Named fields (providerName, path,
    // variable) improve readability of the two-phase processing logic. Path defaults to
    // EMPTY_PATH when the optional middle group is absent.
    private static class ConfigVariable {
        final String providerName;
        final String path;
        final String variable;

        ConfigVariable(Matcher matcher) {
            this.providerName = matcher.group(1);
            this.path = matcher.group(3) != null ? matcher.group(3) : EMPTY_PATH;
            this.variable = matcher.group(4);
        }

        public String toString() {
            return "(" + providerName + ":" + (path != null ? path + ":" : "") + variable + ")";
        }
    }
}
