<!--
 ~ Licensed to the Apache Software Foundation (ASF) under one or more
 ~ contributor license agreements. See the NOTICE file distributed with
 ~ this work for additional information regarding copyright ownership.
 ~ The ASF licenses this file to You under the Apache License, Version 2.0
 ~ (the "License"); you may not use this file except in compliance with
 ~ the License. You may obtain a copy of the License at
 ~
 ~    http://www.apache.org/licenses/LICENSE-2.0
 ~
 ~ Unless required by applicable law or agreed to in writing, software
 ~ distributed under the License is distributed on an "AS IS" BASIS,
 ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ~ See the License for the specific language governing permissions and
 ~ limitations under the License.
-->

# Finding 01 — Filesystem Access and Path Traversal

> Navigation: [Audit Overview](../README.md) &bull; [Severity Matrix](../severity-matrix.md) &bull; [Remediation Roadmap](../remediation-roadmap.md) &bull; [Accepted Mitigations](../accepted-mitigations.md) &bull; [References](../references.md)

> **Audit Only — No code changes are proposed or applied in this run.** This document is a static, code-grounded observation of filesystem-access surfaces in the Apache Kafka 4.2.0-SNAPSHOT tree. Every citation refers to the repository's current `HEAD` at the time of the audit; no file outside `docs/security-audit/` is modified.

---

## Category

**Filesystem access and path traversal** (canonical user-supplied label, enumeration position 1 of 10).

---

## Definition

This category covers any Kafka code path that accepts a filesystem path, directory, or file URL from configuration — whether supplied statically at broker / Connect-worker startup, dynamically via broker reconfiguration, or through connector-configuration submission — and subsequently opens, reads, writes, or deletes a file or directory at that path. The attack vector is a **configuration-level injection** rather than a client-session injection: the adversary's primary prerequisite is a privilege to write (or substitute) a configuration value that reaches one of these resolvers. Path traversal inside a Kafka wire protocol message is not in scope because Kafka does not expose any filesystem read/write primitive to unauthenticated network clients — the on-disk surface is reachable only through configuration plumbing (`ConfigProvider` plug-ins, connector properties, OAuth JAAS configuration, Connect `plugin.path`, broker `kafka.csv.metrics.dir`). The finding documents each such resolver, the allow-list (if any) that mitigates it, and the residual exposure in a default-configuration deployment.

---

## Kafka Surface Inventory

Six sub-findings, enumerated in the order of increasing specificity (generic on-disk resolvers first, single-call-site surfaces last):

### 01.1 `FileConfigProvider` — full-filesystem reads without default path restriction `[Medium]`

`FileConfigProvider` is the canonical Kafka configuration indirection provider that resolves `${file:/path/to/props:key}` variable references by loading a Java `Properties` file from disk. The provider exposes an `allowed.paths` allow-list parameter, but the default value is `null` — which means every path readable by the broker / Connect-worker JVM is allowed.
- Surface summary: unrestricted regular-file read when `allowed.paths` is unset.
- Primary pointer: `Source: clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java:L41-L52`.

### 01.2 `DirectoryConfigProvider` — directory reads with optional `allowed.paths` allow-list `[Medium]`

`DirectoryConfigProvider` resolves `${directory:/path:key}` references by listing regular files in the named directory and returning one key per file. It shares the same `allowed.paths` parameter and `AllowedPaths` implementation with `FileConfigProvider`, so an operator who omits the allow-list at install time gets unrestricted directory enumeration of every directory readable by the JVM.
- Surface summary: unrestricted regular-file enumeration + read when `allowed.paths` is unset.
- Primary pointer: `Source: clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java:L43-L115`.

### 01.3 `EnvVarConfigProvider` — environment-variable reads with default `.*` allow-list `[Low]`

`EnvVarConfigProvider` resolves `${env:NAME}` variable references against the process environment. It exposes an `allowlist.pattern` regular expression that gates which environment-variable names the provider may return, but the **default value is `.*`** — which matches every environment variable in the broker or Connect-worker process.
- Surface summary: default allow-list admits every environment variable (including AWS keys, OAuth tokens, SCRAM passphrases, etc. inherited by the JVM process).
- Primary pointer: `Source: clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java:L42-L72`.

### 01.4 Connect `plugin.path` classpath traversal via `DelegatingClassLoader` / `PluginUtils` `[Medium]`

Connect workers load every plugin (Converter, Transformation, Connector, Policy, REST extension) from the directories listed in `plugin.path`. The `DelegatingClassLoader` is a `URLClassLoader` with child-first delegation that iterates each configured directory, recursively discovering JARs and class files, and registering every discovered `Connector`/`Transformation`/etc. into a reflective registry. If an adversary obtains write access to any directory on `plugin.path` — for example by compromising an unprivileged shell account that shares a plugin directory with the worker — the worker will load that adversary's code on its next restart.
- Surface summary: filesystem-scoped code-loading primitive; a single successful write to a plugin directory persists code execution across restarts.
- Primary pointers: `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java:L36-L50` and `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginUtils.java:L53`.

### 01.5 `KafkaCSVMetricsReporter` — directory deletion at a user-configured path `[Low]`

`KafkaCSVMetricsReporter` is an optional metrics reporter that writes CSV files to a configured directory. Before creating the directory, it performs a **recursive `Utils.delete(csvDir)`** on the configured path. No allow-list, `startsWith` check, or normalization is applied to the path. An administrator who sets `kafka.csv.metrics.dir=/var/log` (or another shared operator-owned path) will have the entire directory tree recursively deleted at broker startup.
- Surface summary: recursive-delete primitive gated only by the administrator's good judgement in choosing `kafka.csv.metrics.dir`.
- Primary pointer: `Source: core/src/main/scala/kafka/metrics/KafkaCSVMetricsReporter.scala:L48-L62`.

### 01.6 `FileJwtRetriever` and `JwtBearerJwtRetriever` — OAuth secrets read from arbitrary filesystem paths `[Medium]`

The Kafka OAuthBearer SASL stack reads three categories of secret material from disk:
- `sasl.oauthbearer.token.endpoint.url=file:/...` paired with `FileJwtRetriever` — reads a serialized JWT from the named file on every retrieval cycle.
- `sasl.oauthbearer.assertion.file=/...` — paired with `JwtBearerJwtRetriever` — reads a pre-built signed JWT assertion on every retrieval cycle.
- `sasl.oauthbearer.assertion.private.key.file=/...` — paired with `JwtBearerJwtRetriever` — reads a PEM-encoded private key used to sign new assertions.

File-path validation is delegated to `ConfigurationUtils.validateFile` / `validateFileUrl`, which verifies readability but does not restrict the path to an allow-list at the retriever layer. Broker-level enforcement is provided by `BrokerSecurityConfigs.ALLOWED_SASL_OAUTHBEARER_FILES_CONFIG` (default: empty string), which an operator must explicitly configure.
- Surface summary: three config keys that each read arbitrary filesystem content into the Kafka client JVM.
- Primary pointers: `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/FileJwtRetriever.java:L33-L58` and `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtBearerJwtRetriever.java:L48-L91,L138-L144`.

---

## Evidence

Each citation below references the exact file-path and line-range of the surface under analysis. Code excerpts are kept to 2-3 lines each to minimize copy-verbatim and to preserve clarity.

### Evidence 01.1 — `FileConfigProvider`

- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java:L41` — class declaration: `public class FileConfigProvider implements ConfigProvider`.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java:L45-L48` — declares `ALLOWED_PATHS_CONFIG = "allowed.paths"`, together with the documentation string **"A comma separated list of paths that this config provider is allowed to access. If not set, all paths are allowed."** and `private volatile AllowedPaths allowedPaths;` field.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java:L50-L52` — `configure()` calls `new AllowedPaths((String) configs.getOrDefault(ALLOWED_PATHS_CONFIG, null))`. When the key is absent, `null` propagates into `AllowedPaths`, which short-circuits the `startsWith` filter.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java:L60-L92` — `get(String path)` method calls `allowedPaths.parseUntrustedPath(path)` at line 70; when the provider is unconfigured (no `allowed.paths`), `parseUntrustedPath` returns the raw unresolved path (see evidence 01.2 below).

**Narrative.** The Javadoc at L46-L47 is explicit: if `allowed.paths` is not set, all paths are allowed. An operator who installs `FileConfigProvider` with the minimal configuration footprint will inherit this permissive default. The sink is `properties.load(reader)` at L76-L78, which parses whatever the path points to as a Java `Properties` file.

### Evidence 01.2 — `DirectoryConfigProvider`

- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java:L43` — class declaration.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java:L47-L49` — declares the **same** `ALLOWED_PATHS_CONFIG = "allowed.paths"` constant and the **identical** documentation string seen in `FileConfigProvider`.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java:L52-L55` — `configure()` likewise calls `new AllowedPaths((String) configs.getOrDefault(ALLOWED_PATHS_CONFIG, null))`.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java:L66-L69` — `get(String path)` delegates to the private `get(path, Files::isRegularFile)` helper.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java:L85-L115` — private `get(String path, Predicate<Path> fileFilter)`. Line 93: `Path dir = allowedPaths.parseUntrustedPath(path);`. Lines 102-107: `Files.list(dir)` iterates the directory, filters regular files, and calls `read(p)` for each — `read(p)` in turn calls `Files.readString(path)` at L119.
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/AllowedPaths.java:L28` — `public class AllowedPaths`.
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/AllowedPaths.java:L36-L60` — constructor `AllowedPaths(String configValue)` at L36, which calls `getAllowedPaths` at L40. The helper normalises each comma-separated entry via `Paths.get(b).normalize()` at L45, then validates `isAbsolute()` at L47 (throws `ConfigException` at L48 if relative) and `Files.exists()` at L49 (throws `ConfigException` at L50 if missing). A `null` or empty config value makes `getAllowedPaths` return `null` at L59.
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/AllowedPaths.java:L68-L81` — `parseUntrustedPath(String path)`. Line 69: `parsedPath = Paths.get(path)`. Lines 71-77: if an allow-list exists, the method normalises the untrusted input at L72 and accepts only paths whose normalised form starts with one of the configured allow-list entries (L73 `normalisedPath::startsWith` filter, L74-L75 reject with `null`, L77 accept). Line 80: when the allow-list is null, `parsedPath` is returned unchanged — the **default-configured branch**.

**Narrative.** `AllowedPaths.parseUntrustedPath` is an engineering-grade positive-security control: normalize-then-startsWith is the canonical pattern for preventing directory-traversal escape via `..` segments. The residual risk is entirely in the default configuration: operators who install `DirectoryConfigProvider` without an explicit `allowed.paths` value retain the pre-allow-list permissive behaviour.

### Evidence 01.3 — `EnvVarConfigProvider`

- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java:L35-L36` — Javadoc: "Using an allowlist pattern... Default allowlist pattern is `.*`."
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java:L42-L44` — `public static final String ALLOWLIST_PATTERN_CONFIG = "allowlist.pattern";`.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java:L57-L72` — `configure(Map<String, ?> configs)`:
  - Lines 60-63: if `configs` contains a non-null `allowlist.pattern` value, the operator-supplied regex is compiled via `Pattern.compile(String.valueOf(configs.get(ALLOWLIST_PATTERN_CONFIG)))`.
  - Line 65: otherwise, the fallback is `envVarPattern = Pattern.compile(".*");` — a pattern that matches **every** environment variable in the process.
- Subsequent lookups filter against `envVarPattern.matcher(envVarName).matches()`, so the default pattern admits every name.

**Narrative.** The `.*` default is documented in the Javadoc and constitutes an "insecure-by-default" surface in the sense of category 10 — but because the exploitation path requires both a sink (a connector configuration that interpolates `${env:NAME}` into a logged value) and an operator-privilege to configure that sink, the realised severity is `[Low]`. The same provider also has a non-functional ReDoS concern (unbounded regex compilation) that is carried into Finding 05.

### Evidence 01.4 — Connect `plugin.path` classpath traversal

- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java:L36-L46` — class Javadoc describing the child-first classloader model used for Connect plugin isolation.
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java:L47` — class declaration: `public class DelegatingClassLoader extends URLClassLoader`.
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java:L50` — field: `private final ConcurrentMap<String, SortedMap<PluginDesc<?>, ClassLoader>> pluginLoaders;`. This map is populated by scanning every directory in `plugin.path`.
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginUtils.java:L53` — `public class PluginUtils` — the utility class that resolves plugin JARs on disk and produces the `URL[]` passed to `PluginClassLoader`.

**Narrative.** Connect's plugin-isolation story is robust when `plugin.path` points at directories owned by root (or the Kafka service account) and marked immutable. The residual exposure is a **filesystem-trust model** exposure: any adversary who can drop a JAR into one of the configured directories will have that JAR loaded at the next worker restart. The finding does not identify a vulnerability in `DelegatingClassLoader` itself — the code honours its contract — but surfaces the operational trust assumption so that Kafka operators document and audit their `plugin.path` directory permissions.

### Evidence 01.5 — `KafkaCSVMetricsReporter` recursive directory deletion

- `Source: core/src/main/scala/kafka/metrics/KafkaCSVMetricsReporter.scala:L35` — `private class KafkaCSVMetricsReporter extends KafkaMetricsReporter with KafkaCSVMetricsReporterMBean with Logging`.
- `Source: core/src/main/scala/kafka/metrics/KafkaCSVMetricsReporter.scala:L48-L62` — `init(props: VerifiableProperties)` method:
  - Line 52: `csvDir = new File(props.getString("kafka.csv.metrics.dir", "kafka_metrics"))` — accepts any path string; default relative `"kafka_metrics"` directory is created in the broker's working directory.
  - **Line 53**: `Utils.delete(csvDir)` — **recursive deletion** of whatever path `csvDir` points to. `Utils.delete` walks the directory tree depth-first and issues `Files.delete(...)` for every entry.
  - Line 54: `Files.createDirectories(csvDir.toPath)` — recreates the now-empty directory.
  - Line 55: `underlying = new CsvReporter(KafkaYammerMetrics.defaultRegistry(), csvDir)` — begins emitting CSV files.
  - Line 56: `if (props.getBoolean("kafka.csv.metrics.reporter.enabled", default = false))` — reporter enabled only when the operator sets `kafka.csv.metrics.reporter.enabled=true` (default `false`).

**Narrative.** The reporter is disabled by default, so the delete primitive is gated behind a second config toggle. Nevertheless, when enabled, the delete is unconditional and immediate: there is no path normalisation, no `startsWith` check, no symlink resolution, and no dry-run mode. An administrator mis-editing the broker configuration — or an administrator whose configuration file is tampered with between reviews — can accidentally wipe a shared log directory on the next broker start.

### Evidence 01.6 — `FileJwtRetriever` and `JwtBearerJwtRetriever`

`FileJwtRetriever`:
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/FileJwtRetriever.java:L33-L36` — Javadoc describing the retriever as one that "loads the contents of a file, interpreting them as a JWT access key in the serialized form".
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/FileJwtRetriever.java:L37` — class declaration.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/FileJwtRetriever.java:L41-L46` — `configure()` calls `cu.validateFileUrl(SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL)` to turn the `file:` URL into a `File`, then wraps it in a `CachedFile<String>` that reloads on every access.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/FileJwtRetriever.java:L48-L58` — `retrieve()` returns `jwtFile.transformed()`, which reads the file contents and parses them as a JWT access token.

`JwtBearerJwtRetriever`:
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtBearerJwtRetriever.java:L48-L91` — class Javadoc. Lines 84-85 list the two filesystem-path configuration keys: `sasl.oauthbearer.assertion.file` and `sasl.oauthbearer.assertion.private.key.file`.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtBearerJwtRetriever.java:L117` — `public class JwtBearerJwtRetriever implements JwtRetriever`.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtBearerJwtRetriever.java:L138-L144` — `configure()` method:
  - Line 138: if `SASL_OAUTHBEARER_ASSERTION_FILE` is set, `cu.validateFile(SASL_OAUTHBEARER_ASSERTION_FILE)` at L139 opens the configured assertion file; the file is passed into `FileAssertionCreator` at L140.
  - Line 144: else, `privateKeyFile = cu.validateFile(SASL_OAUTHBEARER_ASSERTION_PRIVATE_KEY_FILE)` reads the configured private-key file for signing.

Cross-reference (broker-side allow-list):
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L140` — `public static final String ALLOWED_SASL_OAUTHBEARER_FILES_CONFIG = "org.apache.kafka.sasl.oauthbearer.allowed.files";`. Line 141 declares the default value as an empty string, meaning the allow-list is empty and operators must opt in to any file read.

**Narrative.** The default empty allow-list at `BrokerSecurityConfigs.ALLOWED_SASL_OAUTHBEARER_FILES_CONFIG` is a **strict-by-default** posture: in its shipped state, no file read is permitted until an operator explicitly lists the allowed paths. The residual risk flows from operators who set a broad allow-list or who rely on the legacy per-retriever behaviour without enabling the broker-side allow-list.

---

## Attack Vector

Each sub-finding has a distinct attack precondition. The common theme is that the adversary requires a foothold at the configuration plane rather than at the network plane.

### Attack Vector 01.1 — `FileConfigProvider`

An adversary who can submit (or influence) a Kafka broker configuration, Connect-worker properties file, or connector-configuration submission — for example, via a stolen Connect REST credential, a misconfigured configuration-management pipeline, or a malicious Git commit against a GitOps-managed cluster — can reference any file on the broker / worker host by using `${file:/etc/shadow:pass}` or `${file:/var/lib/secrets/tls.pem:key}`. The retrieved contents are substituted into the configuration and subsequently flow to wherever that configuration value is used (inter-broker TLS handshakes, SCRAM credentials, SASL JAAS, logs). If the configuration key is a `password.encoder`-typed property, `Password.toString` masks it; if the key is plain-typed, it may appear in DEBUG-level logs or JMX attributes.

### Attack Vector 01.2 — `DirectoryConfigProvider`

The attack is equivalent to 01.1 but operates at directory granularity: a single `${directory:/var/lib/secrets}` reference enumerates every regular file in the target directory and returns one key-per-file in the resulting configuration. When `allowed.paths` is unset, the attack has no filesystem-scope bound except the JVM's read permission. Because `DirectoryConfigProvider` resolves a single `${directory:...:key}` reference into `key` (not the whole directory) the exploitation path requires the adversary to know the target filename, but because directory listings are inexpensive, an adversary can iterate.

### Attack Vector 01.3 — `EnvVarConfigProvider`

With the default `.*` allowlist, an adversary who controls a connector configuration can write `${env:AWS_SECRET_ACCESS_KEY}` into any string-typed property. The resolved value reaches wherever the configuration consumer forwards it. The realised exposure depends on the connector's logging posture and on whether the property is marked `Password`. A secondary concern is that the `.*` pattern makes any new environment variable (e.g., `KAFKA_OAUTH_TOKEN` introduced in a future release) immediately accessible without an explicit operator decision.

### Attack Vector 01.4 — Connect `plugin.path`

The exploit requires write access to any directory on `plugin.path`. Typical misconfigurations that satisfy this prerequisite: a shared `/opt/kafka/connect-plugins` directory writable by a group larger than the worker's UID, a `plugin.path=/tmp/plugins` setting adopted from a quick-start guide and left in production, or a CI/CD pipeline that deploys plugins with world-writable permissions. Once the adversary drops a malicious `plugin.jar` containing a `Connector` or `Transformation` implementation, the next worker restart picks it up via `DelegatingClassLoader`'s URL scan and registers it in `pluginLoaders`. Subsequent connector submissions that reference the malicious class name execute adversary-controlled code in the worker JVM.

### Attack Vector 01.5 — `KafkaCSVMetricsReporter`

The exploit requires two preconditions: (1) `kafka.csv.metrics.reporter.enabled=true` (non-default), and (2) `kafka.csv.metrics.dir` pointing at an operator-owned shared path. An adversary who can tamper with the broker's `server.properties` — e.g., via a mis-scoped configuration-management role — changes the directory value and waits for the broker to restart. The restart triggers `Utils.delete(csvDir)` at `KafkaCSVMetricsReporter.scala:L53`, recursively removing the target directory. This is a **destructive-integrity** primitive rather than a confidentiality leak: the attacker's payoff is denial of service or log destruction, not secret exfiltration.

### Attack Vector 01.6 — `FileJwtRetriever` / `JwtBearerJwtRetriever`

For clients, an adversary who can author the Kafka client's JAAS configuration can set `sasl.oauthbearer.token.endpoint.url=file:/path/to/stolen/jwt` to bypass an HTTPS JWKS retrieval in favour of a local file read. For brokers and Connect workers, a mis-configured `sasl.oauthbearer.assertion.private.key.file=/var/lib/secrets/any.pem` can redirect signing operations to a victim key. The principal mitigation is `BrokerSecurityConfigs.ALLOWED_SASL_OAUTHBEARER_FILES_CONFIG`; if that key is left empty (the default), the broker refuses all file reads, which is the strict-by-default posture. If an operator populates the allow-list broadly (e.g., `/var/lib/`), the effective protection collapses.

---

## Severity

Severities are assigned on the scale used across this audit: `[Critical]`, `[High]`, `[Medium]`, `[Low]`. The rationale column documents the CVSS-style reasoning without computing a numeric score.

| Sub-finding | Severity | Rationale |
| --- | --- | --- |
| 01.1 `FileConfigProvider` unrestricted file read | `[Medium]` | Requires configuration-plane privilege. Broad default (`allowed.paths` unset). Attack complexity low; privileges required high (operator-class); impact on confidentiality high when sinks exist. |
| 01.2 `DirectoryConfigProvider` without `allowed.paths` | `[Medium]` | Same preconditions as 01.1 with broader scope (directory enumeration). `AllowedPaths.parseUntrustedPath` is a strong positive-security control when configured. |
| 01.3 `EnvVarConfigProvider` default `allowlist.pattern` `.*` | `[Low]` | Requires both a configuration-plane privilege AND a downstream sink that reveals the resolved value. Pattern can be tightened by operator. |
| 01.4 Connect `plugin.path` traversal | `[Medium]` | Requires write access to a plugin directory AND a worker restart. When satisfied, the impact is arbitrary-code-execution in the worker JVM. Mitigated by filesystem permissions. |
| 01.5 `KafkaCSVMetricsReporter` recursive delete | `[Low]` | Requires `kafka.csv.metrics.reporter.enabled=true` (non-default) AND an unreviewed edit to `kafka.csv.metrics.dir`. Effect is destructive-integrity (denial of metrics / data loss) rather than confidentiality. |
| 01.6 `FileJwtRetriever` / `JwtBearerJwtRetriever` arbitrary file read | `[Medium]` | Client-side: operator privilege over JAAS config required. Broker-side: strict-by-default `ALLOWED_SASL_OAUTHBEARER_FILES_CONFIG` empty allow-list mitigates; broadly populated allow-list degrades the posture. |

No sub-finding in this category rises to `[High]` or `[Critical]` because every realised vector requires a configuration-plane privilege that is itself controlled by a different Kafka subsystem (KRaft ACLs, Connect REST authentication, SSH / file-system ACLs on the broker host). Category 01 interacts with those upstream controls and does not itself permit an unauthenticated network attacker to exfiltrate or destroy filesystem content.

---

## Business Impact

- **Secret disclosure**: Sub-findings 01.1, 01.2, 01.3, and 01.6 can leak TLS private keys, SCRAM passphrases, OAuth client secrets, delegation-token HMAC keys, AWS / cloud-provider credentials inherited in environment variables, and Connect-connector secrets. In regulated environments (SOC 2, ISO 27001, PCI-DSS, HIPAA), these are Tier-1 data-classification incidents and typically trigger a customer-notification obligation.
- **Code execution and supply-chain compromise**: Sub-finding 01.4 (`plugin.path`) is the category's only code-execution vector. A single successful write to a plugin directory survives worker restarts and typically persists until the plugin directory is re-imaged. Detection is difficult because the worker registers the malicious plugin as a legitimate connector class.
- **Availability and data-destruction**: Sub-finding 01.5 (`KafkaCSVMetricsReporter`) is a recursive-delete primitive. A mis-targeted configuration change on a broker that shares a directory tree (e.g., `/var/log`) with other services causes an availability incident proportional to the size of the deleted tree.
- **Regulatory posture**: Under audit frameworks that require "least privilege" (e.g., NIST SP 800-53 AC-6), operators must document why each of these surfaces is enabled and what allow-list or directory-permission control bounds it. The findings below provide the reverse-lookup that such an audit requires.

---

## Accepted Mitigations Already Present

The following mitigations are implemented in the current codebase. They are documented here so that a future maintainer who re-reads this finding does not regress them. Cross-references link to the consolidated accepted-mitigations catalogue.

- **`AllowedPaths.parseUntrustedPath` — normalize + `startsWith` filter.** A strong positive-security control: the implementation at `Source: clients/src/main/java/org/apache/kafka/common/config/internals/AllowedPaths.java:L68-L81` normalises the untrusted input (collapsing `..` segments via `Path.normalize()` at L72) and admits the path only when it starts with one of the operator-configured allow-list entries (L73 filter + L74-L75 reject). The implementation is correct for the canonical directory-traversal threat model.
- **`AllowedPaths` constructor validation — fail-fast on relative or non-existent paths.** The constructor at `Source: clients/src/main/java/org/apache/kafka/common/config/internals/AllowedPaths.java:L36-L60` validates every comma-separated allow-list entry at configuration time: it rejects relative paths (`ConfigException` at L48 if `!isAbsolute()`) and non-existent paths (`ConfigException` at L50 if `!Files.exists(normalisedPath)`). This precludes the "operator configures `allowed.paths=..`" misconfiguration.
- **`EnvVarConfigProvider.allowlist.pattern` operator override.** Although the default is permissive, the operator has a canonical configuration key (`allowlist.pattern`) at `Source: clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java:L42-L44` that can be set to `^KAFKA_[A-Z0-9_]+$` (or tighter) to restrict the resolver to a curated set of environment variables.
- **`BrokerSecurityConfigs.ALLOWED_SASL_OAUTHBEARER_FILES_CONFIG` — strict-by-default empty allow-list.** The broker-side SASL OAuth file allow-list at `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L140` defaults to the empty string (`ALLOWED_SASL_OAUTHBEARER_FILES_DEFAULT = ""` at L141), which rejects every file-read attempt until an operator populates the allow-list. This is a category-10 "secure-by-default" posture.
- **Connect plugin isolation — `PluginClassLoader` child-first delegation.** Although `plugin.path` is itself an operator-trust surface, the child-first `URLClassLoader` model confines each plugin to its own classloader hierarchy, limiting cross-plugin contamination. See `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java:L36-L47` for the class Javadoc documenting the isolation guarantee.
- **`KafkaCSVMetricsReporter` disabled-by-default.** The reporter is opt-in via `kafka.csv.metrics.reporter.enabled=true`; the default `false` blocks the `Utils.delete(csvDir)` primitive from executing in a minimal-configuration broker.

Consolidated catalogue: see [`../accepted-mitigations.md`](../accepted-mitigations.md) entries "4. `DirectoryConfigProvider` `allowed.paths` path allow-list" and "5. `EnvVarConfigProvider` `allowlist.pattern` regex allow-list".

---

## Recommended Future Remediation (no changes in this run)

All items below are framed as **suggestions for future work**. Consistent with the audit-only rule, no code change is proposed, applied, or required in this run. Each item uses "consider", "could", or "may" language per the remediation-roadmap convention.

1. **Operator runbook — document `plugin.path` directory-permission best practice.** Future operator-facing documentation could recommend `chmod 0555` with root ownership on every directory listed in `plugin.path`, such that no non-root account can drop a JAR into a plugin directory. Related: Finding 01.4.
2. **Future KIP — change `EnvVarConfigProvider` default `allowlist.pattern` from `.*` to the empty set.** A future KIP could consider making `allowlist.pattern` a required parameter (with no compiled-in default) so that an operator must opt in to environment-variable exposure. Related: Finding 01.3 and category-10 "Insecure-by-Default Watchlist".
3. **Future KIP — add `allowed.paths` defaulting for production profiles.** A future KIP could consider a "hardened-profile" configuration flag that makes `allowed.paths` a required parameter on `FileConfigProvider` and `DirectoryConfigProvider` when the broker is started in a `security.profile=strict` mode. Related: Findings 01.1 and 01.2.
4. **Future KIP — path-normalisation audit logging for first-time JWT file reads.** A future KIP may add an `INFO`-level audit log line when `FileJwtRetriever` or `JwtBearerJwtRetriever` reads a file path not previously observed, giving operators a trail for spotting a freshly-tampered configuration. Related: Finding 01.6.
5. **Operator runbook — document `kafka.csv.metrics.dir` dedicated-directory convention.** Documentation could explicitly state that `kafka.csv.metrics.dir` must be a dedicated, operator-owned directory that contains no other files, given the recursive-delete semantics at `KafkaCSVMetricsReporter.scala:L53`. Related: Finding 01.5.
6. **Operator runbook — cross-reference `BrokerSecurityConfigs.ALLOWED_SASL_OAUTHBEARER_FILES_CONFIG`.** The Kafka security documentation may cross-reference this configuration key in the OAuth section so that operators who enable `FileJwtRetriever` or `JwtBearerJwtRetriever` know to populate the allow-list. Related: Finding 01.6.

**No code changes are applied in this audit run per the Audit Only rule.** The items above are proposals for future consideration by the Apache Kafka community via the KIP process.

---

## References and Cross-Links

- **Audit Navigation**
  - [`../README.md`](../README.md) — Audit overview, ten-category enumeration, navigation index.
  - [`../severity-matrix.md`](../severity-matrix.md) — Tabular Critical / High / Medium / Low matrix; Category 01 rows at section 3.1.
  - [`../remediation-roadmap.md`](../remediation-roadmap.md) — Future-state remediation suggestions phased by horizon.
  - [`../accepted-mitigations.md`](../accepted-mitigations.md) — Catalogue of existing positive-security controls; entries 4 and 5 reference Category 01.
  - [`../references.md`](../references.md) — Consolidated bibliography; Category 01 reverse-lookup at section 11 (category index).
  - [`../no-change-verification.md`](../no-change-verification.md) — Evidence that the audit produced zero modifications to existing source.
  - [`../dependency-inventory.md`](../dependency-inventory.md) — Dependency manifest context.

- **Diagrams**
  - [`../diagrams/attack-surface-map.md`](../diagrams/attack-surface-map.md) — Ten-category by Kafka-module matrix; Category 01 appears under the `clients.config.provider`, `connect.runtime.isolation`, `core.metrics`, and `clients.security.oauthbearer` nodes.
  - [`../diagrams/threat-model-overview.md`](../diagrams/threat-model-overview.md) — System-level data-flow with trust boundaries; the configuration-plane trust boundary is where Category 01 surfaces reside.

- **Source Code Citations (consolidated list for this finding)**
  - `clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java` — Finding 01.1.
  - `clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java` — Finding 01.2.
  - `clients/src/main/java/org/apache/kafka/common/config/internals/AllowedPaths.java` — Findings 01.1 and 01.2 (shared path-validation helper).
  - `clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java` — Finding 01.3.
  - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java` — Finding 01.4.
  - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginUtils.java` — Finding 01.4.
  - `core/src/main/scala/kafka/metrics/KafkaCSVMetricsReporter.scala` — Finding 01.5.
  - `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/FileJwtRetriever.java` — Finding 01.6.
  - `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtBearerJwtRetriever.java` — Finding 01.6.
  - `clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java` — Finding 01.6 (cross-reference for broker-side allow-list).

---

_End of Finding 01 — Filesystem Access and Path Traversal._
