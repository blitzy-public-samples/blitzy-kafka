<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

# References - Audit Evidence Bibliography

| Field                  | Value                                                                 |
|------------------------|-----------------------------------------------------------------------|
| Audit Target           | Apache Kafka 4.2.0-SNAPSHOT                                           |
| Audit Snapshot Date    | 2026-04-17                                                            |
| Git Branch             | `blitzy-4bdad1ad-dc01-4556-9ef0-4c760b777d5a`                         |
| Scope                  | Static, read-only security vulnerability assessment                   |
| Governing Rule         | Audit Only (see [`./README.md`](./README.md))                         |
| Change Posture         | Zero modifications to existing code, comments, tests, or build files  |
| Related Manifest       | [`./no-change-verification.md`](./no-change-verification.md)          |

This document is the single consolidated bibliography of every file referenced anywhere in the
`docs/security-audit/` artifacts (findings, diagrams, severity matrix, remediation roadmap,
accepted mitigations, dependency inventory, and the executive reveal.js deck). Reviewers should
use this file as the canonical lookup index when locating the source evidence underlying any
finding, diagram, or mitigation claim.

---

## Table of Contents

1. [How to Use this File](#1-how-to-use-this-file)
2. [Repository Build and Dependency Manifest](#2-repository-build-and-dependency-manifest)
3. [Clients Module](#3-clients-module)
4. [Core / Broker Module](#4-core--broker-module)
5. [Storage Internals Module](#5-storage-internals-module)
6. [Server-common Module](#6-server-common-module)
7. [Server Module](#7-server-module)
8. [Connect Module](#8-connect-module)
9. [Raft Module](#9-raft-module)
10. [Metadata Module](#10-metadata-module)
11. [Streams Module](#11-streams-module)
12. [Storage API Module](#12-storage-api-module)
13. [Coordinator and Transaction Modules](#13-coordinator-and-transaction-modules)
14. [Tools Module](#14-tools-module)
15. [Trogdor Module](#15-trogdor-module)
16. [Release Tooling](#16-release-tooling)
17. [Test Files (Read-Only Evidence for Mitigation Invariants)](#17-test-files-read-only-evidence-for-mitigation-invariants)
18. [Existing Kafka Documentation Referenced for Context](#18-existing-kafka-documentation-referenced-for-context)
19. [Technical Specification Sections Consulted](#19-technical-specification-sections-consulted)
20. [External Standards Referenced](#20-external-standards-referenced)
21. [Reverse Lookup by Vulnerability Category](#21-reverse-lookup-by-vulnerability-category)
22. [Closing Note](#22-closing-note)

---

## 1. How to Use this File

Every absolute path below resolves from the Apache Kafka repository root (the directory
containing the top-level `build.gradle`, `gradle/`, `clients/`, `core/`, `connect/`, and
`docs/` subtrees). Where line ranges appear (for example `:L42-L58` or `:L57`), they are the
span of evidence observed at the audit snapshot date. If the code has moved in a later Kafka
revision, a reviewer should consult `git blame` or `git log -p -- <path>` to locate the
current line range for the same symbol.

Citation format used throughout every audit artifact is:

    Source: <absolute/repository/path>:L<start>[-L<end>]

All files enumerated in this bibliography are referenced as READ-ONLY evidence. The audit has
not modified, created, or deleted any file listed below other than the artifacts placed under
`docs/security-audit/`. The `no-change-verification.md` companion artifact carries the `git
diff --name-status` evidence confirming this invariant.

Every entry in this file includes a one-line description of why the file is cited - the
vulnerability category (for example, "Finding 05") and/or the accepted mitigation it
underpins. The "Finding NN" labels map to the ten ordered category files under
`./findings/01-filesystem-access-path-traversal.md` through
`./findings/10-public-api-developer-misuse.md`.

A reverse-lookup table at the end of this document (section 21) maps each of the ten
vulnerability categories back to the files that are referenced in the corresponding finding.

### 1.1 Path-Accuracy Verifications

The paths below are common sources of confusion because they have migrated across modules in
the 4.x release line or because they exist as inner classes rather than standalone files. Each
path below was confirmed against the repository snapshot before being cited in this
bibliography:

| Symbol                        | Actual Path (verified)                                                                                |
|-------------------------------|-------------------------------------------------------------------------------------------------------|
| `BrokerJwtValidator`          | `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java`          |
| `ClientJwtValidator`          | `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java`          |
| `FileJwtRetriever`            | `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/FileJwtRetriever.java`            |
| `JwtBearerJwtRetriever`       | `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtBearerJwtRetriever.java`       |
| `SafeObjectInputStream`       | `connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java`              |
| `ConnectionQuotas`            | Inner class in `core/src/main/scala/kafka/network/SocketServer.scala:L1285+`                          |
| `ClientRequestQuotaManager`   | `core/src/main/java/kafka/server/ClientRequestQuotaManager.java` (Java, in `core/src/main/java/`)     |
| `ClientQuotaManager`          | `server/src/main/java/org/apache/kafka/server/quota/ClientQuotaManager.java` (Java, in `server/`)     |
| Mirror `Checkpoint`           | `connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java`                 |
| Streams checkpoint reader     | `streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java`                |
| `RecordRedactor` (metadata)   | `metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java`                           |
| `BrokerSecurityConfigs`       | `clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java`           |
| `SaslInternalConfigs`         | `clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslInternalConfigs.java`       |
| `ReplicationConfigs`          | `server/src/main/java/org/apache/kafka/server/config/ReplicationConfigs.java`                         |
| `KafkaYammerMetrics`          | `server-common/src/main/java/org/apache/kafka/server/metrics/KafkaYammerMetrics.java` (Java)          |
| `TransactionCoordinator`      | `core/src/main/scala/kafka/coordinator/transaction/TransactionCoordinator.scala`                      |
| `AddPartitionsToTxnManager`   | `server/src/main/java/org/apache/kafka/server/transaction/AddPartitionsToTxnManager.java`             |
| `AuthorizerIntegrationTest`   | `core/src/test/scala/integration/kafka/api/AuthorizerIntegrationTest.scala`                           |
| `DynamicConnectionQuotaTest`  | `core/src/test/scala/integration/kafka/network/DynamicConnectionQuotaTest.scala`                      |

---

## 2. Repository Build and Dependency Manifest

- `gradle/dependencies.gradle` - Canonical declaration of every runtime and test-scope
  dependency version cited by the audit. Runtime-affecting lines observed: Scala 2.13.17
  (L26), Bouncy Castle bcpkix 1.80 (L56), Gradle 9.1.0 (L63), Jackson 2.19.0 (L66), Jetty
  12.0.22 (L69), Jersey 3.1.10 (L70), jose4j 0.9.6 (L81), Log4j2 2.25.1 (L108), lz4-java
  1.8.0 (L110), Mockito 5.20.0 (L113, test-only), RocksDB JNI 10.1.3 (L118), snappy-java
  1.1.10.7 (L125), zstd-jni 1.5.6-10 (L131). Referenced by:
  [`./dependency-inventory.md`](./dependency-inventory.md), Finding 02 (low-level code
  safety), Finding 04 (module system), Finding 08 (deserialization).
- `build.gradle` - Top-level build orchestration; declares modules, source sets, and the
  `javadoc` task contract. Referenced by: [`./dependency-inventory.md`](./dependency-inventory.md).

---

## 3. Clients Module

Module root: `clients/src/main/java/org/apache/kafka/`

### 3.1 Configuration

- `clients/src/main/java/org/apache/kafka/common/config/ConfigDef.java` - Configuration
  definition framework; contains a compiled regex used during validator matching.
  `Pattern.compile` site. Referenced by: Finding 05 (infinite-loop and recursion DoS).
- `clients/src/main/java/org/apache/kafka/common/config/ConfigTransformer.java` - Config
  variable substitution; compiles a placeholder-extraction regex on each transformation pass.
  `Pattern.compile` site. Referenced by: Finding 05.
- `clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java` - Canonical SSL/TLS
  configuration constants including default protocol set (`TLSv1.2,TLSv1.3`), default
  endpoint-identification algorithm (`https`), default client-auth mode (`none`), and the
  `SSL_ALLOW_DN_CHANGES`/`SSL_ALLOW_SAN_CHANGES` permissive toggles. Referenced by: Finding
  10 (public API developer misuse).
- `clients/src/main/java/org/apache/kafka/common/config/SaslConfigs.java` - Canonical SASL
  configuration constants including the default enabled mechanism (`GSSAPI`) and related
  login-module class constants. Referenced by: Finding 10.
- `clients/src/main/java/org/apache/kafka/clients/CommonClientConfigs.java` - Shared client
  configuration constants including the default listener security protocol (`PLAINTEXT`).
  Referenced by: Finding 10.
- `clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java`
  - Broker-internal security configuration constants consumed by the authenticator stack.
  Referenced by: Finding 10.
- `clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java` -
  On-disk secret/config reader that resolves `${file:path:key}` placeholders from a key/value
  properties file. Referenced by: Finding 01 (filesystem access and path traversal).
- `clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java`
  - Directory-based config reader with an `allowed.paths` allow-list that restricts the
  filesystem sub-tree permitted for resolution. Referenced by: Finding 01 and
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java` -
  Environment-variable reader with an `allowlist.pattern` regex for filtering which variable
  names may be resolved. `Pattern.compile` site. Referenced by: Finding 01, Finding 05, and
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L24` - The
  `HIDDEN = "[hidden]"` redaction marker used by the `toString` method to prevent password
  value leakage in logs or serialized config images. Referenced by: Finding 09 (information
  leakage).

### 3.2 Compression

- `clients/src/main/java/org/apache/kafka/common/compress/Compression.java` - Dispatch entry
  point for every compression type.
- `clients/src/main/java/org/apache/kafka/common/compress/ZstdCompression.java` - Integrates
  zstd-jni with a Kafka-owned `BufferSupplier` and `ChunkedBytesStream`. The bounded
  decompression chunk size of 16 KB is declared at L59 and L107-L108. Referenced by: Finding
  02 (low-level code safety) and [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `clients/src/main/java/org/apache/kafka/common/compress/SnappyCompression.java` - snappy-java
  1.1.10.7 integration wrapper. Referenced by: Finding 02.
- `clients/src/main/java/org/apache/kafka/common/compress/Lz4Compression.java` - lz4-java
  1.8.0 integration wrapper. Referenced by: Finding 02.
- `clients/src/main/java/org/apache/kafka/common/compress/Lz4BlockInputStream.java`,
  `clients/src/main/java/org/apache/kafka/common/compress/Lz4BlockOutputStream.java` - LZ4
  block I/O wrappers. Referenced by: Finding 02.
- `clients/src/main/java/org/apache/kafka/common/compress/GzipCompression.java`,
  `clients/src/main/java/org/apache/kafka/common/compress/GzipOutputStream.java` - JDK-native
  Gzip wrappers (no JNI). Included for completeness of the compression inventory.
- `clients/src/main/java/org/apache/kafka/common/compress/NoCompression.java` - Null
  compression strategy.

### 3.3 Memory and Buffer Pool

- `clients/src/main/java/org/apache/kafka/common/memory/SimpleMemoryPool.java` - Bounded
  memory pool with a strict/non-strict allocation mode selected at construction. Non-strict
  mode permits temporary over-allocation. Referenced by: Finding 02 and Finding 03 (resource
  limit evasion).

### 3.4 Metrics and JMX

- `clients/src/main/java/org/apache/kafka/common/metrics/JmxReporter.java:L308-L309` -
  INCLUDE and EXCLUDE MBean filter regexes compiled at configure time. Two `Pattern.compile`
  sites. Referenced by: Finding 05 (ReDoS) and Finding 09 (information leakage via JMX
  exposure).

### 3.5 Network and Protocol

- `clients/src/main/java/org/apache/kafka/common/network/ServerConnectionId.java` - Connection
  identifier parsing includes a `Pattern.compile` site on an untrusted attribute.
  Referenced by: Finding 05.
- `clients/src/main/java/org/apache/kafka/common/requests/ApiVersionsRequest.java` - Parses
  client software name/version strings through a `Pattern.compile` site. Referenced by:
  Finding 05.

### 3.6 Security - Kerberos

- `clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosRule.java:L33,L38,L70,L72`
  - Four `Pattern.compile` sites including the `PARAMETER_PATTERN`, `NON_SIMPLE_PATTERN`,
  and caller-provided `match` / `fromPattern` principal-transformation regexes. Hottest
  ReDoS exposure surface in the clients module. Referenced by: Finding 05.
- `clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosName.java` -
  Compiles a regex to parse the `user/host@REALM` form of a Kerberos principal.
  `Pattern.compile` site. Referenced by: Finding 05.
- `clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosShortNamer.java` -
  Applies configured rules to shorten Kerberos principals to OS usernames. `Pattern.compile`
  site. Referenced by: Finding 05.

### 3.7 Security - OAuth/OIDC

- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L52,L131`
  - jose4j-backed JWT validator that enforces `DISALLOW_NONE` through the
  `AlgorithmConstraints` parameter. The static import at L52 and the
  `setJwsAlgorithmConstraints(DISALLOW_NONE)` invocation at L131 together guarantee the
  `alg:none` signature bypass cannot succeed at the broker. Referenced by: Finding 08
  (deserialization attacks) and [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java`
  - Client-side JWT validator that performs structural checks only (no signature
  verification). Clients must therefore trust the underlying transport (TLS) for JWT
  integrity. Referenced by: Finding 08.
- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtValidator.java` -
  Pluggable SPI implemented by `BrokerJwtValidator` and `ClientJwtValidator`. Consumed via
  reflective instantiation. Referenced by: Finding 04 (module system and built-in abuse).
- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtRetriever.java` -
  Pluggable SPI for retrieving JWTs at authentication time (implementations include
  `FileJwtRetriever`, `JwtBearerJwtRetriever`, and HTTP-based retrievers). Referenced by:
  Finding 04.
- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/OAuthBearerValidatorCallbackHandler.java`
  - Server-side SASL/OAUTHBEARER callback handler. Unconditionally accepts the SASL
  extension map supplied by the client without a configured allow-list. Referenced by:
  Finding 07 (external function and callback misuse).
- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/FileJwtRetriever.java`
  - Reads a JWT from an on-disk file path specified by the caller. Referenced by: Finding
  01.
- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtBearerJwtRetriever.java`
  - Reads a signed JWT assertion (and optionally the private key) from the filesystem and
  exchanges it for an access token. Referenced by: Finding 01.
- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java`
  - Legacy validator that accepts the `alg:none` JWT encoding. Explicitly documented as
  production-unsuitable. Referenced by: Finding 07 and Finding 10.
- `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/OAuthBearerClientInitialResponse.java`
  - Parses the SASL OAUTHBEARER client initial response through a `Pattern.compile` site.
  Referenced by: Finding 05.
- `clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslInternalConfigs.java`
  - SASL internal configuration keys used by the broker callback-handler wiring.
  Referenced by: Finding 10.

### 3.8 Security - SSL

- `clients/src/main/java/org/apache/kafka/common/security/auth/SslEngineFactory.java` -
  Pluggable SSL engine factory SPI consumed via reflective instantiation.
  Referenced by: Finding 04.
- `clients/src/main/java/org/apache/kafka/common/security/ssl/DefaultSslEngineFactory.java` -
  Default pluggable SSL engine implementation that consumes keystore/truststore config and
  builds an `SSLEngine`. Referenced by: Finding 04.
- `clients/src/main/java/org/apache/kafka/common/security/ssl/SslFactory.java` - Supports
  dynamic SSL reconfiguration, including the `CertificateEntries` compatibility check
  governed by `SSL_ALLOW_DN_CHANGES` and `SSL_ALLOW_SAN_CHANGES`. Referenced by: Finding 10.

### 3.9 Security - Delegation Token

- `clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L19,L60`
  - Immutable delegation-token value object. The `MessageDigest.isEqual` call at L60
  supplies constant-time HMAC comparison, defending against timing side-channel attacks
  against token HMACs. The `toString` method masks the HMAC with a placeholder.
  Referenced by: [`./accepted-mitigations.md`](./accepted-mitigations.md) and Finding 09.

### 3.10 Admin Client Internals

- `clients/src/main/java/org/apache/kafka/clients/admin/internals/FenceProducersHandler.java`
  - Admin-client-side handler that issues `InitProducerId` RPCs for producer fencing.
  Referenced by: [`./accepted-mitigations.md`](./accepted-mitigations.md).

### 3.11 Utilities

- `clients/src/main/java/org/apache/kafka/common/utils/Utils.java` - Generic file and
  directory utilities including `Utils.delete` which is used by `KafkaCSVMetricsReporter`
  and other broker-side callers. Referenced by: Finding 01.

---


## 4. Core / Broker Module

Module root: `core/src/main/scala/kafka/` (Scala, unless noted) and
`core/src/main/java/kafka/` (Java, rare - used for the `ClientRequestQuotaManager`).

### 4.1 Log Management

- `core/src/main/scala/kafka/log/LogManager.scala` - Broker log-directory manager. Consumes
  `log.dirs` configuration, acquires a per-directory `java.nio.channels.FileLock` on startup
  through the embedded `.lock` marker, and delegates directory failure handling to
  `LogDirFailureChannel`. Referenced by: Finding 01 (filesystem access and path traversal)
  and [`./accepted-mitigations.md`](./accepted-mitigations.md).

### 4.2 Metrics

- `core/src/main/scala/kafka/metrics/KafkaCSVMetricsReporter.scala` - CSV-file metrics
  reporter that uses `Utils.delete` to recursively remove the output directory on startup
  when configured. Referenced by: Finding 01.

### 4.3 Network - Connection Quotas

- `core/src/main/scala/kafka/network/SocketServer.scala:L1285` - The embedded
  `ConnectionQuotas` inner class exposes per-IP, per-listener, and broker-wide connection
  caps. The REPLICATION listener is explicitly exempted from the broker-wide cap to keep
  inter-broker replication responsive under client-listener back-pressure. Referenced by:
  Finding 03 (resource limit evasion) and [`./accepted-mitigations.md`](./accepted-mitigations.md).

### 4.4 Transaction Coordinator

- `core/src/main/scala/kafka/coordinator/transaction/TransactionCoordinator.scala` - Broker
  transaction coordinator. Rejects two-phase-commit requests when the 2PC pathway is
  disabled (`TRANSACTIONAL_ID_AUTHORIZATION_FAILED`), and implements epoch-based producer
  fencing that maps to `PRODUCER_FENCED` / `INVALID_PRODUCER_EPOCH`. Referenced by: Finding
  06 (network and subprocess access) and Finding 10 (public API developer misuse).

### 4.5 Broker Configuration

- `core/src/main/scala/kafka/server/KafkaConfig.scala` - Broker configuration entry point.
  Materialises the `allow.everyone.if.no.acl.found`, `unclean.leader.election.enable`,
  `auto.create.topics.enable`, and `controller.quorum.auto.join.enable` defaults among
  other security-relevant settings. Referenced by: Finding 10.

### 4.6 Request Quota Manager (Java inside `core/`)

- `core/src/main/java/kafka/server/ClientRequestQuotaManager.java:L42` - Percentage-based
  request-throttling manager. The `NANOS_TO_PERCENTAGE_PER_SECOND` constant at L42 underpins
  the 10-second sliding-window quota calculation and the 1000 ms spike-throttle behaviour.
  Referenced by: Finding 03.

---

## 5. Storage Internals Module

Module root: `storage/src/main/java/org/apache/kafka/storage/internals/log/`

- `storage/src/main/java/org/apache/kafka/storage/internals/log/LogDirFailureChannel.java` -
  Async channel through which broker components signal log-directory failures (for example
  I/O errors against a `log.dirs` entry). Consumed by `LogManager`. Referenced by: Finding
  01.
- `storage/src/main/java/org/apache/kafka/storage/internals/log/LogManager.java` - Java-side
  log-manager helper classes for segment and index file operations. Referenced by: Finding
  01.

---

## 6. Server-common Module

Module root: `server-common/src/main/java/org/apache/kafka/server/`

- `server-common/src/main/java/org/apache/kafka/server/metrics/KafkaYammerMetrics.java` -
  Process-wide Yammer metrics registry with a JVM shutdown hook that cleanly de-registers
  MBeans. Ships JMX exposure surface. Referenced by: Finding 09.
- `server-common/src/main/java/org/apache/kafka/server/config/ServerConfigs.java` -
  Canonical broker-scoped configuration keys. Referenced by: Finding 10.
- `server-common/src/main/java/org/apache/kafka/server/config/ServerLogConfigs.java` -
  Log-related broker configuration keys (retention, segment size, and related knobs).
  Referenced by: Finding 10.
- `server-common/src/main/java/org/apache/kafka/server/config/DelegationTokenManagerConfigs.java`
  - Delegation-token manager configuration keys. Referenced by: Finding 10 and
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `server-common/src/main/java/org/apache/kafka/server/config/QuotaConfig.java` - Shared
  quota configuration keys used by the request and connection quota managers. Referenced
  by: Finding 03 and Finding 10.

---

## 7. Server Module

Module root: `server/src/main/java/org/apache/kafka/server/`

- `server/src/main/java/org/apache/kafka/server/quota/ClientQuotaManager.java` - Per-user
  and per-client-id quota state machine. Supports produce, consume, and request quotas
  sharing a common sliding-window backbone. Referenced by: Finding 03.
- `server/src/main/java/org/apache/kafka/server/transaction/AddPartitionsToTxnManager.java`
  - Inter-broker helper that batches `AddPartitionsToTxn` RPCs. Maps
  `CLUSTER_AUTHORIZATION_FAILED` responses back to the caller. Referenced by: Finding 06.
- `server/src/main/java/org/apache/kafka/server/config/ReplicationConfigs.java` -
  Replication-related configuration keys including follower-fetch defaults. Referenced by:
  Finding 10.

---


## 8. Connect Module

### 8.1 Connect Runtime - REST Surface

Module root: `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/`

- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServer.java:L45,L276`
  - Connect REST transport. Imports `CrossOriginHandler` at L45 and instantiates it at
  L276 to wrap the Jersey servlet with a CORS filter. Referenced by: Finding 06.
- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java:L76`
  - Declares `ACCESS_CONTROL_ALLOW_ORIGIN_DEFAULT = ""`, the secure empty-string default
  for the Connect REST CORS allow-list. Referenced by: Finding 06 and
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestClient.java` -
  Outbound HTTP client used for worker-to-worker REST forwarding. Propagates the inbound
  `Authorization` header to outbound requests. Referenced by: Finding 06 and Finding 07
  (external function and callback misuse).
- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/util/SSLUtils.java` -
  Helper that materialises the Jetty `SslContextFactory` from Connect worker config.
  Contains a `Pattern.compile` for comma-with-whitespace splitting. Referenced by: Finding
  06.

### 8.2 Connect Runtime - Plugin Isolation

Module root: `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/`

- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java`
  - Top-level classloader that resolves classes against each plugin's
  `PluginClassLoader` based on a scanned plugin registry. Resolves `plugin.path`
  directories and per-plugin JAR trees. Referenced by: Finding 01 (path traversal during
  plugin discovery) and Finding 04 (module-system abuse via `ServiceLoader`).
- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginClassLoader.java`
  - Per-plugin child-first `URLClassLoader` that isolates plugin dependencies from the
  Connect worker runtime. Referenced by: Finding 04.
- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginClassLoaderFactory.java`
  - Factory that instantiates one `PluginClassLoader` per plugin location discovered on
  the configured `plugin.path`. Referenced by: Finding 04.
- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginUtils.java`
  - Helper utilities for plugin discovery including the `isConnectorClass` predicate and
  manifest parsing. Referenced by: Finding 04 and Finding 07.
- `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/ReflectionScanner.java`
  - Reflections-based scanner that enumerates connector, transformation, converter, and
  REST-extension implementations on a plugin classloader. Referenced by: Finding 04.

### 8.3 Connect Util - Safe Deserialization

- `connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L25-L62`
  - `ObjectInputStream` subclass that enforces a suffix-matching blocklist of disallowed
  class-name patterns during Java Serialisation deserialisation. Key content spans:
  the `DEFAULT_NO_DESERIALIZE_CLASS_NAMES` blocklist at **L27-L37**, the overridden
  `resolveClass(ObjectStreamClass)` gate at **L43-L52** which throws `SecurityException`
  for any blocked class, and the private `isBlocked(String name)` helper at **L54-L62**
  which performs the `endsWith(...)` suffix match. Referenced by: Finding 08
  (deserialization attacks).

### 8.4 Connect JSON Converter

Module root: `connect/json/src/main/java/org/apache/kafka/connect/json/`

- `connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L57` -
  Sets `ALLOW_LEADING_ZEROS_FOR_NUMBERS` on the Jackson `ObjectMapper`. Non-default Jackson
  feature flag that expands the set of accepted JSON number literals. Referenced by:
  Finding 08.
- `connect/json/src/main/java/org/apache/kafka/connect/json/JsonConverter.java` - Converts
  Connect `Struct` records to and from JSON using the `JsonDeserializer` pipeline.
  Referenced by: Finding 08.

### 8.5 Connect Basic Auth Extension

Module root:
`connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/`

- `.../JaasBasicAuthFilter.java:L55-L58` - Declares `INTERNAL_REQUEST_MATCHERS` as a set
  that bypasses Basic authentication for inter-worker requests (`POST
  /connectors/{name}/tasks`, `PUT /connectors/{name}/fence`). Requires a separate trusted
  transport or reverse-proxy ACL to remain safe. Referenced by: Finding 06 and Finding 10.
- `.../BasicAuthSecurityRestExtension.java` - `ConnectRestExtension` implementation that
  registers `JaasBasicAuthFilter` with the Jersey container. Discovered through
  `ServiceLoader`. Referenced by: Finding 04 and Finding 06.
- `.../PropertyFileLoginModule.java:L42-L50` - Simple JAAS `LoginModule` that reads
  username/password entries from a properties file. The class-level Javadoc at **L42-L49**
  explicitly states at **L47-L48** that this implementation is "NOT intended to be used in
  production since the credentials are stored in PLAINTEXT in the properties file"; the
  class declaration follows at **L50**. Referenced by: Finding 10.

### 8.6 Connect API

- `connect/api/src/main/java/org/apache/kafka/connect/rest/ConnectRestExtension.java` -
  SPI for Connect REST extensions; implementations are discovered through `ServiceLoader`
  on the Connect worker classpath. Referenced by: Finding 04.

### 8.7 MirrorMaker 2

- `connect/mirror/src/main/java/org/apache/kafka/connect/mirror/MirrorMakerConfig.java` -
  Aggregate configuration for a MirrorMaker 2 cluster (source clusters, target clusters,
  worker overrides). Referenced by: Finding 06.
- `connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/MirrorClientConfig.java`
  - Cross-cluster client configuration. Materialises caller-supplied secrets eagerly
  during construction, which causes secrets to surface through `AdminClient` logging if
  not carefully managed. Referenced by: Finding 06 and Finding 10.
- `connect/mirror/src/main/java/org/apache/kafka/connect/mirror/MirrorConnectorConfig.java`
  - Per-connector configuration. Preserves config-provider placeholders lazily through
  `connectorBaseConfig`. Referenced by: Finding 06.
- `connect/mirror/src/main/java/org/apache/kafka/connect/mirror/MirrorSourceConnector.java`
  - Mirror source connector. Implements `syncTopicAcls` which downgrades mirrored `ALLOW
  ALL` ACLs to `ALLOW READ` on the target cluster. Referenced by:
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java` -
  `Checkpoint.deserializeRecord` parses cross-cluster checkpoint records produced by
  MirrorCheckpointConnector. Referenced by: Finding 08.

---


## 9. Raft Module

Module root: `raft/src/main/java/org/apache/kafka/raft/`

- `raft/src/main/java/org/apache/kafka/raft/KafkaRaftClient.java` - Central KRaft quorum
  client. Handles the `VOTE`, `BEGIN_QUORUM_EPOCH`, `END_QUORUM_EPOCH`, `FETCH`,
  `ADD_RAFT_VOTER`, `REMOVE_RAFT_VOTER`, and `UPDATE_RAFT_VOTER` RPCs. Validates cluster
  ID, topic partition, voter key, and leader epoch on every inbound RPC. Referenced by:
  Finding 06.
- `raft/src/main/java/org/apache/kafka/raft/QuorumState.java` - Durable quorum state
  machine covering `Unattached`, `Follower`, `Voted`, `Prospective`, `Candidate`, and
  `Leader` transitions. Persists election metadata through the `QuorumStateStore`
  interface. Referenced by: Finding 06 and [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `raft/src/main/java/org/apache/kafka/raft/VoterSet.java` - Immutable voter-set record
  used for quorum reconfiguration. Exposes `hasOverlappingMajority` to guarantee that any
  reconfiguration preserves a majority common to both the prior and next voter sets.
  Referenced by: [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `raft/src/main/java/org/apache/kafka/raft/ElectionState.java` - Persistent election
  metadata (current leader, epoch, voted candidate). Durable on disk through the quorum
  state file. Referenced by: Finding 06.
- `raft/src/main/java/org/apache/kafka/raft/QuorumConfig.java` - `controller.quorum.*`
  configuration keys including `NON_ROUTABLE_HOST` placeholders. Referenced by: Finding 10.
- `raft/src/main/java/org/apache/kafka/raft/internals/UpdateVoterHandler.java` - Leader-side
  handler for the `UPDATE_RAFT_VOTER` RPC. Validates the prospective voter descriptor
  before committing the update through the Raft log. Referenced by: Finding 06.

---

## 10. Metadata Module

Module root: `metadata/src/main/java/org/apache/kafka/`

### 10.1 Authorizer

- `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java` -
  KRaft-native `Authorizer` implementation. Loads an in-memory `StandardAuthorizerData`
  snapshot from the metadata log and serves `authorize` calls from an immutable
  copy-on-write cache. Referenced by: Finding 10 and [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java:L92,L221-L234`
  - Copy-on-write ACL cache with documented DENY-over-ALLOW precedence, literal-only
  resource pattern matching, and a `loadingComplete` gate that causes `authorize` to
  return `AUTHORIZER_NOT_READY` before the snapshot has been applied. Referenced by:
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `metadata/src/main/java/org/apache/kafka/metadata/authorizer/ClusterMetadataAuthorizer.java`
  - Interface that models the async ACL-mutation surface (through `AclMutator`). Consumed
  by the controller. Referenced by: Finding 04.
- `metadata/src/main/java/org/apache/kafka/metadata/authorizer/AclMutator.java` - SPI
  through which the authorizer requests asynchronous ACL updates from the controller.
  Referenced by: Finding 04.
- `metadata/src/main/java/org/apache/kafka/metadata/authorizer/AclCache.java` - Immutable
  cache of `StandardAcl` entries backed by `ImmutableNavigableSet` and `ImmutableMap` for
  race-free reads. Referenced by: [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAcl.java` -
  Immutable record representing a single ACL entry. Comparable under reverse-lexicographic
  resource ordering for prefix-matching performance. Referenced by:
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAclWithId.java` -
  Persisted form of a `StandardAcl` with its `Uuid`. Referenced by:
  [`./accepted-mitigations.md`](./accepted-mitigations.md).

### 10.2 Controller - ACL Control Manager

- `metadata/src/main/java/org/apache/kafka/controller/AclControlManager.java:L52,L99,L207-L209`
  - Controller-side manager that mutates the ACL snapshot. Enforces the
  `MAX_RECORDS_PER_USER_OP` bounded-list guard to prevent a single admin request from
  materialising an unbounded ACL batch. Referenced by:
  [`./accepted-mitigations.md`](./accepted-mitigations.md).

### 10.3 Metadata Image Nodes

- `metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java` - Tree
  node that renders broker/topic configuration within the `MetadataImage`. Emits
  `"[redacted]"` for password-typed config values when serialising for the metadata
  snapshot audit view. Referenced by: Finding 09.

### 10.4 Metadata Utilities

- `metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java` - Helper that
  redacts password-typed fields from `ConfigRecord` values before they are emitted to
  audit trails. Emits `"(redacted)"` in place of the cleartext value. Referenced by:
  Finding 09.

---

## 11. Streams Module

Module root: `streams/src/main/java/org/apache/kafka/streams/`

- `streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java` -
  Streams checkpoint file reader and writer. Parses offset checkpoint records from the
  state-store directory on restart. Referenced by: Finding 08.
- `streams/src/main/java/org/apache/kafka/streams/state/internals/RocksDBStore.java` -
  RocksDB-backed state-store implementation. Invokes the `rocksdbjni 10.1.3` native JNI
  boundary to open, read, and write to RocksDB column families. Referenced by: Finding 02.

---

## 12. Storage API Module

Module root: `storage/api/src/main/java/org/apache/kafka/server/log/remote/storage/`

- `storage/api/src/main/java/org/apache/kafka/server/log/remote/storage/RemoteStorageManager.java`
  - SPI for Tiered Storage "RSM" (Remote Storage Manager) implementations. Discovered
  through `ServiceLoader`. Referenced by: Finding 04.
- `storage/api/src/main/java/org/apache/kafka/server/log/remote/storage/RemoteLogMetadataManager.java`
  - SPI for Tiered Storage "RLMM" (Remote Log Metadata Manager) implementations.
  Discovered through `ServiceLoader`. Referenced by: Finding 04.

---


## 13. Coordinator and Transaction Modules

This section consolidates the transaction-coordinator, fencing, and inter-broker
transaction-management surface. The implementations span three different modules because
the coordinator lives in `core/` (Scala), the inter-broker helper lives in `server/`
(Java), and the admin-client fencing handler lives in `clients/` (Java). Each file is
listed at its actual verified path.

- `core/src/main/scala/kafka/coordinator/transaction/TransactionCoordinator.scala` -
  Broker-side 2PC coordinator. See section 4.4 above for the full description.
  Referenced by: Finding 06 and Finding 10.
- `server/src/main/java/org/apache/kafka/server/transaction/AddPartitionsToTxnManager.java`
  - Inter-broker helper that batches `AddPartitionsToTxn` RPCs on behalf of the coordinator.
  See section 7 above for the full description. Referenced by: Finding 06.
- `clients/src/main/java/org/apache/kafka/clients/admin/internals/FenceProducersHandler.java`
  - Admin-client-side `InitProducerId` handler used by administrative producer fencing. See
  section 3.10 above for the full description. Referenced by:
  [`./accepted-mitigations.md`](./accepted-mitigations.md).

---

## 14. Tools Module

Module root: `tools/src/main/java/org/apache/kafka/tools/`

- `tools/src/main/java/org/apache/kafka/tools/JmxTool.java` - CLI that queries local or
  remote JMX-exposed MBeans. The default configuration is unauthenticated (suitable for
  integration-test scenarios only). Operator usage must explicitly enable JMX auth to
  prevent unauthenticated metric scraping. Referenced by: Finding 09.

---

## 15. Trogdor Module

Module root: `trogdor/src/main/java/org/apache/kafka/trogdor/`

- `trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L39` - Enables
  Jackson feature flags `ACCEPT_SINGLE_VALUE_AS_ARRAY`, `ALLOW_COMMENTS`, and
  `FAIL_ON_EMPTY_BEANS=false` on the shared Trogdor `ObjectMapper`. Expands the set of
  accepted JSON payloads that Trogdor agents and coordinator accept. Referenced by:
  Finding 08.

---

## 16. Release Tooling

Module root: `release/`

- `release/release.py:L334-L362` - Release-engineer automation that invokes `./gradlew`
  build/publish targets, copies distribution artifacts, runs `gpg --print-md` for
  md5/sha1/sha512 digests, and runs `mvn deploy -Pgpg-signing`. Uses `subprocess` with
  `shell=True` and f-string interpolation for filename variables. Execution context is
  the release engineer's workstation, not the broker runtime. Referenced by: Finding 06.
- `release/runtime.py:L101,L109` - Thin wrapper providing the `cmd(action, cmd_arg, *args,
  **kwargs)` helper (L109) that delegates to `subprocess.check_output` (L101). The
  concrete invocation sites in `release.py` determine whether `shell=True` is used.
  Referenced by: Finding 06.
- `release/gpg.py` - GPG signing wrapper invoked from `release.py` for artifact signing.
  Referenced by: Finding 06.
- `release/svn.py` - SVN subprocess wrapper invoked from `release.py` for dist.apache.org
  staging. Referenced by: Finding 06.

---

## 17. Test Files (Read-Only Evidence for Mitigation Invariants)

The following test files are cited in findings and accepted-mitigations documents
strictly as read-only evidence of existing security properties. No test file is modified
by the audit.

### 17.1 Clients - SSL

- `clients/src/test/java/org/apache/kafka/common/network/SslTransportLayerTest.java` -
  Exercises the SSL transport layer including dynamic SSL-context updates.
- `clients/src/test/java/org/apache/kafka/common/security/ssl/DefaultSslEngineFactoryTest.java`
  - Covers PEM material handling and reload behaviour in the default `SslEngineFactory`.
- `clients/src/test/java/org/apache/kafka/common/security/ssl/SslFactoryTest.java` -
  Exercises the `CertificateEntries` compatibility check governed by
  `SSL_ALLOW_DN_CHANGES`/`SSL_ALLOW_SAN_CHANGES`.

### 17.2 Core - Connection and Request Quotas

- `core/src/test/scala/unit/kafka/network/ConnectionQuotasTest.scala` - Unit-tests the
  per-IP, per-listener, and broker-wide connection-quota enforcement paths.
- `core/src/test/scala/integration/kafka/network/DynamicConnectionQuotaTest.scala` -
  Integration-tests dynamic reconfiguration of connection quotas at runtime.

### 17.3 Core - Authorization

- `core/src/test/scala/integration/kafka/api/AuthorizerIntegrationTest.scala` -
  Integration test exercising the `Authorizer` contract against the KRaft-native
  `StandardAuthorizer` through live broker APIs.

### 17.4 Metadata - Authorizer

- `metadata/src/test/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerTest.java`
  - Unit-tests the `StandardAuthorizer` implementation covering super-user bypass,
  DENY-over-ALLOW precedence, and literal-pattern matching.

### 17.5 Raft - Quorum Safety

- `raft/src/test/java/org/apache/kafka/raft/KafkaRaftClientClusterAuthTest.java` -
  Exercises the `CLUSTER_AUTHORIZATION_FAILED` response propagation for KRaft RPCs.
- `raft/src/test/java/org/apache/kafka/raft/KafkaRaftClientReconfigTest.java` - Exercises
  the `AddVoter`/`RemoveVoter`/`UpdateVoter` reconfiguration safety including the
  `hasOverlappingMajority` invariant.
- `raft/src/test/java/org/apache/kafka/raft/KafkaRaftClientPreVoteTest.java` - Exercises
  the pre-vote protocol that prevents disruptive elections from minority voters.

### 17.6 Connect - MirrorMaker 2 SSL

- `connect/mirror/src/test/java/org/apache/kafka/connect/mirror/integration/MirrorConnectorsIntegrationSSLTest.java`
  - End-to-end MirrorMaker 2 integration test that exercises source-to-target replication
  over SSL.

---


## 18. Existing Kafka Documentation Referenced for Context

The following existing documentation files inside the repository's `docs/` tree are
consulted for context during the audit. None is modified by this audit; every reference
is READ-ONLY.

- `docs/security.html` - Apache Kafka security documentation. Describes how to configure
  SSL, SASL, authorization, and delegation tokens. Does not currently enumerate
  threat-surface material at the level of detail produced by this audit. NOT MODIFIED.
- `docs/ops.html` - Apache Kafka operational guidance. Touches on JMX exposure, broker
  deployment, and basic security posture. NOT MODIFIED.
- `docs/connect.html` - Apache Kafka Connect documentation. Describes the Connect REST
  API surface. NOT MODIFIED.
- `docs/configuration.html` - Apache Kafka broker configuration reference. Documents
  individual configuration keys. NOT MODIFIED.
- `docs/README.md` - Minimal pointer documenting how the docs site is built. NOT
  MODIFIED.

---

## 19. Technical Specification Sections Consulted

The following sections of the project technical specification were consulted during
Phase 3 reconnaissance. They are referenced conceptually, not reproduced in the audit
artifacts.

- Section 1.1 Executive Summary
- Section 1.2 System Overview
- Section 1.3 Scope
- Section 3.2 Frameworks and Libraries
- Section 3.3 Open-Source Dependencies
- Section 5.4 Cross-Cutting Concerns
- Section 6.3 Integration Architecture
- Section 6.4 Security Architecture

---

## 20. External Standards Referenced

The following external frameworks inform the severity classification and threat-model
structure of the audit. They are referenced conceptually only; no live URLs are fetched
and no third-party text is reproduced.

- CVSS v3.1 (Common Vulnerability Scoring System) - applied conceptually when assigning
  Critical / High / Medium / Low severity labels. The audit does not publish a formal
  CVSS vector for each finding, but the severity assignments are grounded in CVSS base
  metrics (attack vector, attack complexity, privileges required, user interaction,
  scope, and confidentiality/integrity/availability impact).
- OWASP Top Ten - supplies the structural pattern used by each finding (Definition,
  Kafka Surface Inventory, Evidence, Attack Vector, Severity, Business Impact, Accepted
  Mitigations, Recommended Future Remediation).
- STRIDE - used to frame the data-flow and trust-boundary annotations in the threat-model
  overview diagram.

---

## 21. Reverse Lookup by Vulnerability Category

This two-column table maps each vulnerability category (in the user-specified canonical
order) back to the files most directly referenced in the corresponding finding. The
listing is a subset; the complete set of citations for each category is in the
corresponding finding file under `./findings/`.

| Category                                               | Referenced Files (subset)                                                                                                                                                                                                                                                                                                                                      |
|--------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 01 Filesystem Access and Path Traversal                | `FileConfigProvider`, `DirectoryConfigProvider`, `EnvVarConfigProvider`, `LogManager.scala`, `LogDirFailureChannel`, `DelegatingClassLoader`, `KafkaCSVMetricsReporter`, `FileJwtRetriever`, `JwtBearerJwtRetriever`                                                                                                                                           |
| 02 Low-Level Code Safety                               | `ZstdCompression`, `SnappyCompression`, `Lz4Compression`, `RocksDBStore`, `SimpleMemoryPool`                                                                                                                                                                                                                                                                   |
| 03 Resource Limit Evasion                              | `SocketServer.scala` (inner `ConnectionQuotas`), `ClientRequestQuotaManager`, `ClientQuotaManager`, `SimpleMemoryPool`, `QuotaConfig`                                                                                                                                                                                                                          |
| 04 Module System and Built-in Abuse                    | `PluginClassLoader`, `DelegatingClassLoader`, `ConnectRestExtension`, `RemoteStorageManager`, `RemoteLogMetadataManager`, `StandardAuthorizer`, `JwtValidator`, `JwtRetriever`, `SslEngineFactory`, `DefaultSslEngineFactory`                                                                                                                                  |
| 05 Infinite Loop and Recursion DoS                     | `KerberosRule` (four `Pattern.compile` sites), `KerberosName`, `KerberosShortNamer`, `JmxReporter` (two sites), `ConfigDef`, `ConfigTransformer`, `EnvVarConfigProvider`, `ServerConnectionId`, `ApiVersionsRequest`, `OAuthBearerClientInitialResponse`                                                                                                      |
| 06 Network and Subprocess Access                       | `RestServer`, `RestServerConfig`, `RestClient`, `JaasBasicAuthFilter`, `KafkaRaftClient`, `UpdateVoterHandler`, `TransactionCoordinator.scala`, `AddPartitionsToTxnManager`, `release.py`, `runtime.py`, `gpg.py`, `svn.py`                                                                                                                                     |
| 07 External Function and Callback Misuse               | `OAuthBearerUnsecuredValidatorCallbackHandler`, `OAuthBearerValidatorCallbackHandler`, `RestClient`, `PluginUtils`                                                                                                                                                                                                                                             |
| 08 Deserialization Attacks                             | `JsonDeserializer`, Trogdor `JsonUtil`, `SafeObjectInputStream`, `BrokerJwtValidator`, `ClientJwtValidator`, Streams `OffsetCheckpoint`, Mirror `Checkpoint`                                                                                                                                                                                                   |
| 09 Information Leakage                                 | `Password` (`[hidden]`), `RecordRedactor` (`(redacted)`), `ConfigurationImageNode` (`[redacted]`), `DelegationToken` (`toString` mask), `JmxReporter`, `JmxTool`                                                                                                                                                                                              |
| 10 Public API Developer Misuse                         | `SslConfigs`, `SaslConfigs`, `CommonClientConfigs`, `RestServerConfig`, `PropertyFileLoginModule`, `KafkaConfig.scala`, `BrokerSecurityConfigs`, `SaslInternalConfigs`, `ReplicationConfigs`, `QuotaConfig`, `OAuthBearerUnsecuredValidatorCallbackHandler`                                                                                                    |

---

## 22. Closing Note

For the evidence underlying any claim in this audit, locate the file above via its
absolute repository path, then navigate to the cited line range. For per-category
narratives, use the ordered finding files under `./findings/`.


