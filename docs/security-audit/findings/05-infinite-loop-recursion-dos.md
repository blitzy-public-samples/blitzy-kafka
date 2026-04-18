<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Finding 05 — Infinite Loop and Recursion Denial-of-Service

> Navigation: [Audit Overview](../README.md) • [Severity Matrix](../severity-matrix.md) • [Remediation Roadmap](../remediation-roadmap.md) • [Accepted Mitigations](../accepted-mitigations.md) • [Attack Surface Map](../diagrams/attack-surface-map.md) • [Dependency Inventory](../dependency-inventory.md)

> **Audit-only notice.** This document is a read-only static analysis artifact for Apache Kafka 4.2.0-SNAPSHOT. No source code, configuration, or runtime behavior has been modified in the course of producing this finding. Every cited line range was resolved directly from the tracked repository at the audit snapshot commit.

---

## 1. Category

**Infinite loop and recursion DoS** — enumeration position 5 of 10, as specified by the Agent Action Plan's verbatim category list.

## 2. Definition

Infinite-loop and recursion denial-of-service primitives cause a program to consume unbounded CPU or stack resources on input the program was expected to reject or process in linear time. Two distinct primitives fall under this category. **Regular-expression denial-of-service (ReDoS)** exploits catastrophic backtracking in `java.util.regex` patterns that contain nested quantifiers, overlapping alternations, or unbounded repetition of ambiguous sub-expressions; an attacker who controls the input string against such a pattern can drive matching time from linear to exponential in input length. **Recursion or traversal DoS** exploits object graphs, protocol records, or deserialization streams whose nesting depth the deserializer does not bound, producing stack overflow or CPU exhaustion during parse. This finding inventories every non-test `Pattern.compile` call site across the Apache Kafka tracked source tree and classifies each site by (a) whether the compiled pattern is a fixed literal under Kafka's own control or is sourced from an external input channel, (b) whether the input the pattern is matched against is bounded in length by a protocol or configuration constraint, and (c) whether the pattern shape contains any of the backtracking-prone constructs that are the prerequisite of a ReDoS primitive. The companion recursion-bounding component, `SafeObjectInputStream` in the Connect runtime, is documented in Section 4.6 as an accepted mitigation for the deserialization graph-walk surface discussed in [Finding 08 — Deserialization Attacks](./08-deserialization-attacks.md).

## 3. Kafka Surface Inventory

This finding enumerates five distinct regex surfaces and one recursion-bounding mitigation grouped under the infinite-loop and recursion DoS category. The five sub-findings are numbered `05.1` through `05.5` in the canonical order used by the [severity matrix](../severity-matrix.md) and the [remediation roadmap](../remediation-roadmap.md). Section 4.6 documents `SafeObjectInputStream` as an accepted mitigation — it is not itself a sub-finding because it does not introduce a DoS primitive; it reduces the recursion-DoS and deserialization-gadget surface.

| ID   | Surface                                                                                                                             | Severity   |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| 05.1 | Kerberos auth-to-local rule parsing (`KerberosRule`, `KerberosName`, `KerberosShortNamer`) — four `Pattern.compile` sites in `KerberosRule` plus two in the companion classes | `[Medium]` |
| 05.2 | `JmxReporter` compiles operator-supplied include/exclude regexes from `metrics.jmx.include` and `metrics.jmx.exclude`               | `[Low]`    |
| 05.3 | `ConfigDef`, `ConfigTransformer`, and Streams `OffsetCheckpoint` fixed regex literals compiled at class initialization              | `[Low]`    |
| 05.4 | `EnvVarConfigProvider` compiles the operator-supplied `allowlist.pattern` (default `.*`)                                            | `[Low]`    |
| 05.5 | Wire-format parsers (`ServerConnectionId`, `ApiVersionsRequest`, `OAuthBearerClientInitialResponse`) compile fixed patterns against length-bounded client input | `[Low]`    |

Each sub-finding is evidenced, analysed, and rated in the sections that follow. Section 4.6 then records `SafeObjectInputStream` as the recursion/graph-walk mitigation that applies to the deserialization surface described in Finding 08.

## 4. Evidence

All line numbers below were verified by direct inspection of the tracked source files at the audit snapshot. The citation format is `Source: <repository-relative path>:L<start>[-L<end>]`. Regex literals are reproduced verbatim from the tracked source; any apparent double-escaping (for example `\\s` rather than `\s`) reflects the Java string literal as written in source, not a transcription error.

### 4.1 Kerberos auth-to-local rule parsing (05.1)

The Kerberos principal-to-short-name translation layer compiles six regex patterns across three classes. Two of the six are compiled from operator-supplied regex fragments drawn from the `sasl.kerberos.principal.to.local.rules` broker configuration; the remaining four are fixed literals embedded in Kafka source.

- `Source: clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosRule.java:L33` — `private static final Pattern PARAMETER_PATTERN = Pattern.compile("([^$]*)(\\$(\\d*))?");` — fixed literal compiled once at class initialization, matches parameter substitution tokens (`$1`, `$2`, …) inside a rule's replacement expression.
- `Source: clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosRule.java:L38` — `private static final Pattern NON_SIMPLE_PATTERN = Pattern.compile("[/@]");` — fixed literal compiled once at class initialization, used to reject short names that contain Kerberos delimiters.
- `Source: clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosRule.java:L70` — `this.match = match == null ? null : Pattern.compile(match);` — **operator-supplied regex**. The `match` string is extracted from the auth-to-local rule fragment that appears after `RULE:[…](match)s/from/to/` in the broker configuration.
- `Source: clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosRule.java:L72` — `this.fromPattern = fromPattern == null ? null : Pattern.compile(fromPattern);` — **operator-supplied regex**. The `fromPattern` string is the substitution source of the `s/from/to/` clause inside each rule.
- `Source: clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosName.java:L27` — `private static final Pattern NAME_PARSER = Pattern.compile("([^/@]*)(/([^/@]*))?@([^/@]*)");` — fixed literal that parses a full Kerberos principal `user[/instance]@REALM` into its three components. The pattern uses only non-greedy-safe negated character classes against a protocol-bounded input (Kerberos principal strings are capped by the underlying Kerberos protocol and by the SASL frame length).
- `Source: clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosShortNamer.java:L36` — `private static final Pattern RULE_PARSER = Pattern.compile("((DEFAULT)|((RULE:\\[(\\d*):([^\\]]*)](\\(([^)]*)\\))?(s/([^/]*)/([^/]*)/(g)?)?/?(L|U)?)))");` — fixed literal compiled once at class initialization. The pattern's grouping is deep but its input — a single auth-to-local rule as written by the operator — is parsed exactly once per rule at broker startup, and the alternation structure does not contain overlapping quantifier ambiguity of the `(a+)+` or `(a|a)*` form that is the prerequisite of catastrophic backtracking.

Cross-reference: `KerberosRule` construction (L70 and L72) is invoked once per rule at `KerberosShortNamer` initialisation. The operator-supplied regex fragments are materialised into `Pattern` objects at configuration time, so a pathological regex fails fast at broker startup rather than quietly during an authentication attempt.

### 4.2 `JmxReporter` include/exclude regex (05.2)

The `JmxReporter` compiles two operator-supplied regexes from the prefixed configuration keys `metrics.jmx.include` and `metrics.jmx.exclude`, used to filter which Yammer/Kafka metrics are registered into the JMX platform MBean server.

- `Source: clients/src/main/java/org/apache/kafka/common/metrics/JmxReporter.java:L308` — `Pattern includePattern = Pattern.compile(include);` — local variable scoped to the `compilePredicate(Map<String, ?>)` helper method; compiled from the value of the `INCLUDE_CONFIG` key.
- `Source: clients/src/main/java/org/apache/kafka/common/metrics/JmxReporter.java:L309` — `Pattern excludePattern = Pattern.compile(exclude);` — local variable scoped to the same `compilePredicate` helper; compiled from the value of the `EXCLUDE_CONFIG` key.

Both patterns are matched against Kafka-internal metric names composed of `group.name` tuples the broker itself authors. The input surface — the catalogue of metric names — is Kafka-authored and not attacker-controlled. The only exploitation path is operator misconfiguration: an operator who authors a pathological include or exclude pattern causes the JMX reporter thread, not the broker request-handling threads, to stall while evaluating the predicate on every emitted metric.

### 4.3 `ConfigDef`, `ConfigTransformer`, and Streams `OffsetCheckpoint` fixed patterns (05.3)

Four fixed regex literals are compiled at class initialization. None accepts external input into its pattern definition; each is matched against input that is either Kafka-authored or structurally bounded.

- `Source: clients/src/main/java/org/apache/kafka/common/config/ConfigDef.java:L83` — `private static final Pattern COMMA_WITH_WHITESPACE = Pattern.compile("\\s*,\\s*");` — matches comma separators surrounded by optional whitespace while splitting list-valued configuration values. The pattern is strictly linear and has no catastrophic-backtracking potential.
- `Source: clients/src/main/java/org/apache/kafka/common/config/ConfigTransformer.java:L56` — `public static final Pattern DEFAULT_PATTERN = Pattern.compile("\\$\\{([^}]*?):(([^}]*?):)?([^}]*?)\\}");` — matches `${providerName:path:key}` interpolation placeholders inside configuration values. The three non-greedy groups are each bounded by the terminating `}` character, so each group's match length is capped by the position of the next closing brace; the overall match is linear in the input length.
- `Source: streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java:L58` — `private static final Pattern WHITESPACE_MINIMUM_ONCE = Pattern.compile("\\s+");` — matches one-or-more whitespace characters when parsing on-disk checkpoint records. This pattern is cross-referenced from [Finding 08.5](./08-deserialization-attacks.md) as evidence that Streams checkpoint parsing is bounded, and is included here under Category 05 for inventory completeness: `\s+` is the canonical benign regex (strictly linear, no catastrophic backtracking).

All three patterns are compiled exactly once per JVM at class loading time, so the regex-compilation cost itself is not repeated per message or per request.

### 4.4 `EnvVarConfigProvider` allowlist pattern (05.4)

`EnvVarConfigProvider` compiles a regex from either an operator-supplied allowlist or a permissive default. The selection is made inside the provider's `configure(Map<String, ?>)` method.

- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java:L61-L63` — when the configuration map contains `ALLOWLIST_PATTERN_CONFIG` (the `allowlist.pattern` key), the provider compiles `Pattern.compile(String.valueOf(configs.get(ALLOWLIST_PATTERN_CONFIG)))`. This is the **operator-supplied regex** branch.
- `Source: clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java:L65` — when the allowlist is not configured, the provider falls back to `envVarPattern = Pattern.compile(".*");` — the default-permissive branch. This default admits every environment variable name and is strictly linear.

At match time the compiled pattern is evaluated against environment-variable names drawn from the JVM's `System.getenv()` map. The variable names are set by the operator or host environment, not by a remote attacker. A pathological `allowlist.pattern` value is therefore an operator-supplied footgun, not a remotely exploitable primitive — its worst-case outcome is that the `EnvVarConfigProvider.configure` call path stalls at broker startup (fail-fast) rather than during request handling.

Cross-reference: [`../accepted-mitigations.md`](../accepted-mitigations.md) entry #5 records `EnvVarConfigProvider` allowlist pattern as an accepted-by-design allow-list-over-blocklist mitigation; the section also records that a complex operator-supplied pattern can itself expose the configure path to a ReDoS primitive — which is precisely the residual concern documented in this sub-finding.

### 4.5 Wire-format parsers (05.5)

Four regex patterns are compiled at class initialization and matched against length-bounded fields in client-submitted protocol frames. Each pattern is a fixed literal; only the input comes from an untrusted client.

- `Source: clients/src/main/java/org/apache/kafka/common/network/ServerConnectionId.java:L36` — `private static final Pattern HOST_PORT_PARSE_EXP = Pattern.compile("([0-9a-zA-Z\\-%._:]*):([0-9]+)");` — parses `host:port` strings constructed internally by Kafka from `InetSocketAddress` values. The input channel is Kafka-internal, not remote.
- `Source: clients/src/main/java/org/apache/kafka/common/requests/ApiVersionsRequest.java:L70` — `private static final Pattern SOFTWARE_NAME_VERSION_PATTERN = Pattern.compile("[a-zA-Z0-9](?:[a-zA-Z0-9\\-.]*[a-zA-Z0-9])?");` — validates the `ClientSoftwareName` and `ClientSoftwareVersion` fields carried in the `ApiVersions` request from an untrusted client. The pattern shape is linear (a single anchored character class followed by a bounded optional repeat), and the input fields are length-bounded by the `COMPACT_STRING` type in the Kafka protocol framing.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/OAuthBearerClientInitialResponse.java:L38` — `private static final Pattern AUTH_PATTERN = Pattern.compile("(?<scheme>[\\w]+)[ ]+(?<token>[-_~+/\\.a-zA-Z0-9]+([=]*))");` — parses the SASL `AUTH` extension value; its two named groups are anchored to fixed character classes with no alternation ambiguity.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/OAuthBearerClientInitialResponse.java:L39-L40` — `private static final Pattern CLIENT_INITIAL_RESPONSE_PATTERN = Pattern.compile(String.format("n,(a=(?<authzid>%s))?,%s(?<kvpairs>%s)%s", SASLNAME, SEPARATOR, KVPAIRS, SEPARATOR));` — compiles the SASL GS2 header + key-value pair grammar. `SEPARATOR` is defined at L31 (`"\u0001"`), `SASLNAME` at L33, `KEY` at L34, `VALUE` at L35, and `KVPAIRS` at L37 (which itself composes `KEY`, `VALUE`, and `SEPARATOR` via a second `String.format`); all four are fixed string constants, so the composed `CLIENT_INITIAL_RESPONSE_PATTERN` is a fixed literal despite the `String.format` call.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/OAuthBearerClientInitialResponse.java:L47` — `public static final Pattern EXTENSION_KEY_PATTERN = Pattern.compile(KEY);` — the `KEY` constant resolves to `[A-Za-z]+`, a strictly linear character class repetition.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/OAuthBearerClientInitialResponse.java:L48` — `public static final Pattern EXTENSION_VALUE_PATTERN = Pattern.compile(VALUE);` — the `VALUE` constant resolves to `[\\x21-\\x7E \t\r\n]+`, also strictly linear.

The common property across these five patterns is that the input they match is delimited or length-capped by the Kafka protocol framing layer (`COMPACT_STRING`, `NULLABLE_STRING`, or the SASL frame boundaries). Length-bounded input against a linear-time pattern has no catastrophic-backtracking potential, regardless of the complexity of the pattern's grouping structure.

### 4.6 `SafeObjectInputStream` (accepted mitigation — not a sub-finding)

`SafeObjectInputStream` is the Connect runtime's hardening wrapper around `java.io.ObjectInputStream`. It does not itself introduce a DoS primitive; it bounds the gadget-class attack surface discussed in [Finding 08.3](./08-deserialization-attacks.md) by rejecting serialized graphs whose top-level class name matches any of nine well-known gadget-class suffixes.

- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L25` — `public class SafeObjectInputStream extends ObjectInputStream` — the wrapper class resides in the Connect runtime package (path prefix `connect/runtime/src/main/java/org/apache/kafka/connect/util/`), **not** in the Clients module.
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L27-L37` — `protected static final Set<String> DEFAULT_NO_DESERIALIZE_CLASS_NAMES = Set.of(...)` — nine-entry suffix blocklist covering: Apache Commons Collections 3.x `InvokerTransformer` and `InstantiateTransformer`; Apache Commons Collections 4.x `InvokerTransformer` and `InstantiateTransformer`; Groovy `ConvertedClosure` and `MethodClosure`; Spring `ObjectFactory`; JDK-internal Xalan `TemplatesImpl`; external Xalan `TemplatesImpl`.
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L39-L41` — constructor `public SafeObjectInputStream(InputStream in) throws IOException { super(in); }` — the wrapper exposes the same constructor signature as `ObjectInputStream`.
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L43-L52` — `resolveClass(ObjectStreamClass desc)` override. The override calls `isBlocked(name)` and throws a `SecurityException` with a descriptive message if the name matches; otherwise it delegates to the superclass resolver.
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L54-L62` — `private boolean isBlocked(String name)` performs an `endsWith` loop over the nine-entry blocklist. The method returns `true` on the first matching suffix and `false` if none match.

**Mitigation characterisation.** `SafeObjectInputStream` is a **blocklist**, not an allow-list. It reduces the recursion/graph-walk deserialization-DoS surface by pre-screening class names before the JVM resolves the class, but it does not by itself bound the nesting depth of a resolved object graph. The residual architectural concern — that a blocklist's protective value tracks the completeness of the list — is recorded in Finding 08.3 as a Medium sub-finding rather than here, because its primary consequence is a deserialization gadget-chain execution path, not a pattern-matching or recursion-exhaustion path.

## 5. Attack Vector

Each sub-section below describes the exploitation path that an adversary would follow against the corresponding sub-finding in Section 4. No exploitation is performed in this audit; the descriptions are diagnostic.

### 5.1 Operator-supplied regex in Kerberos auth-to-local rules (05.1)

An operator configures `sasl.kerberos.principal.to.local.rules` with one or more rule fragments, each of which contains a `match` clause and a `s/from/to/` substitution clause. The operator has full control over the regex fragments appearing in both clauses, and a mis-designed fragment — for example `(a+)+b` or `(a|a)*b` against an input string that fails to match — will exhibit catastrophic backtracking. The input the mis-designed regex is matched against is the Kerberos principal presented by a SASL/GSSAPI authentication attempt, which an adversary able to initiate authentication exchanges can choose within the bounds of the Kerberos principal grammar. The exploitation path therefore requires one of two preconditions: (a) an insider or supply-chain actor who can influence the broker's `sasl.kerberos.principal.to.local.rules` value, combined with an external authenticator who submits principals crafted against the mis-designed rule, or (b) an attacker who directly authors and then exploits a rule in a single privileged window. In the second case the attacker already controls broker configuration, and the DoS is a residual risk of an already-complete compromise. In the first case the operator-authored regex is the root cause; the attacker's role is to feed the trigger input. The consequence is per-authentication-attempt CPU exhaustion on a broker thread; because authentication runs on the broker network thread pool, sustained backtracking delays all inbound connections, not only those of the attacker. The four fixed `Pattern.compile` sites in `KerberosRule`, `KerberosName`, and `KerberosShortNamer` do not themselves constitute a vector because their patterns are under Kafka's control.

### 5.2 Operator-supplied JMX include/exclude regex (05.2)

`metrics.jmx.include` and `metrics.jmx.exclude` are operator-only configuration keys evaluated by the `JmxReporter` at broker startup and on each metric registration event. A mis-designed operator regex causes the JMX reporter to stall while evaluating the predicate on every metric name. The stall is confined to the JMX reporter thread; it does not block the broker request handlers. The attack surface is therefore strictly a configuration footgun — no remote adversary can influence the regex, and no remote adversary authors the strings the regex is matched against (metric names are Kafka-authored).

### 5.3 Fixed regex literals over Kafka-authored or bounded input (05.3)

None of the three fixed patterns in Section 4.3 admits an attacker-controlled regex literal. `ConfigDef.COMMA_WITH_WHITESPACE` is matched against configuration values whose total length is already bounded by the configuration subsystem. `ConfigTransformer.DEFAULT_PATTERN` is matched against configuration values; its match budget is bounded by the position of the next `}` within the value string. `OffsetCheckpoint.WHITESPACE_MINIMUM_ONCE` is matched against on-disk checkpoint records whose format is Kafka-authored. There is no adversary input channel to any of the three. The sub-finding rates `[Low]` to record these patterns for inventory completeness, not because an exploitable path exists.

### 5.4 Operator-supplied allowlist regex in `EnvVarConfigProvider` (05.4)

The `allowlist.pattern` key is an operator-only configuration value. A pathological operator-supplied pattern — for example one with deeply nested ambiguous quantifiers — stalls the provider's `configure(Map)` method at broker startup, delaying but not silently degrading broker availability (`configure` runs synchronously during broker initialization). Because the pattern is matched against environment-variable names from `System.getenv()` rather than from a remote input channel, no external adversary can influence the match input. The residual concern noted in [`../accepted-mitigations.md`](../accepted-mitigations.md) entry #5 is therefore operator-self-inflicted and fail-fast.

### 5.5 Wire-format parsers over length-bounded client input (05.5)

The five patterns enumerated in Section 4.5 are evaluated against fields carried in inbound client protocol frames. The frames are framed by the Kafka protocol layer (`COMPACT_STRING`, `NULLABLE_STRING`, or the SASL initial-response envelope), which imposes an upper bound on the length of each string field before the field reaches the regex engine. The five pattern shapes are strictly linear: each is either a fixed character-class repetition, a simple alternation between two character classes, or a composition thereof. No pattern contains the overlapping-quantifier ambiguity that is the prerequisite of catastrophic backtracking. An adversary who submits a maximum-length field exercises linear-time matching cost proportional to the bounded field length, which is within the broker's normal request-processing budget. No exploitation path produces super-linear CPU cost from these patterns.

### 5.6 No attack vector against `SafeObjectInputStream` itself

Section 4.6 documents `SafeObjectInputStream` as a mitigation, not a sub-finding. No attack vector is carried on the `Pattern.compile` dimension here because `SafeObjectInputStream` does not compile regexes; the class performs a nine-entry `endsWith` comparison loop that is strictly linear in the class-name length. The separate concern — that the blocklist is suffix-based rather than an allow-list — is the deserialization-gadget concern documented in [Finding 08.3](./08-deserialization-attacks.md) and is out of scope for this category.

## 6. Severity

The severity assignments below match the roll-up recorded in [`../severity-matrix.md`](../severity-matrix.md) Section 3.5 "Category 05 — Infinite Loop and Recursion DoS".

| Sub-finding | Severity   | Rationale                                                                                                                                                                                                                              |
| ----------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 05.1        | `[Medium]` | Two of the six patterns (`KerberosRule.java:L70,L72`) are compiled from operator-supplied regex fragments; the match input is the Kerberos principal presented by any SASL/GSSAPI authenticator, giving an adversary a limited input channel against an operator-authored pattern. The combination of user-supplied regex and adversary-influenceable input is the defining condition of a Medium ReDoS surface. |
| 05.2        | `[Low]`    | The regex is operator-only; the match input is Kafka-authored metric names. No remote adversary input channel exists on either axis. A stall is confined to the JMX reporter thread and does not block request handling.              |
| 05.3        | `[Low]`    | All three patterns are fixed literals under Kafka's control. Input is either Kafka-authored or bounded by the position of terminating delimiters. No attacker input channel on either axis.                                           |
| 05.4        | `[Low]`    | The regex is operator-only. The match input is environment-variable names from `System.getenv()`, which the operator or host environment controls. No remote adversary input channel.                                                 |
| 05.5        | `[Low]`    | All five patterns are fixed literals. The match input is length-bounded by the Kafka protocol framing layer. Pattern shapes are strictly linear and do not contain the overlapping-quantifier ambiguity that is the prerequisite of catastrophic backtracking. |

**Category roll-up.** Zero Critical, zero High, one Medium (05.1), four Low (05.2, 05.3, 05.4, 05.5) — five sub-findings in total. `SafeObjectInputStream` is recorded in Section 4.6 as an accepted mitigation and does not contribute to the category roll-up.

## 7. Business Impact

Business impact is reported per sub-finding rather than as a single category-wide statement because the five sub-findings differ materially in which operational domain they affect.

1. **Authentication-path CPU exhaustion (05.1).** A mis-designed auth-to-local regex affects the broker's ability to complete SASL/GSSAPI authentication within its normal per-request CPU budget. Because inbound SASL exchanges run on the broker network thread pool, sustained backtracking caused by crafted principals can delay not only the attacker's own authentication attempts but also the authentication attempts of legitimate clients and inter-broker connections. The business-impact reading is availability-oriented: reduced or lost ability to bring new clients and new brokers online while the pathological regex is in force. Correctness, confidentiality, and data integrity are not affected by this surface.
2. **JMX-pipeline stall (05.2).** A pathological operator-supplied JMX include or exclude regex stalls the JMX reporter thread only. The broker continues to process client requests normally; the observable consequence is that JMX-exposed metrics stop updating, which degrades observability tooling (Prometheus JMX exporter, management consoles, ops dashboards) but does not affect the Kafka data plane. Business impact is operational-visibility loss, not availability or correctness loss.
3. **Startup-time stall from `EnvVarConfigProvider` (05.4).** A pathological operator-supplied `allowlist.pattern` stalls the broker during the `configure(Map)` call path, which runs synchronously during initialization. The failure mode is fail-fast — the broker does not become available to clients during the stall — which is preferable to silent runtime degradation. Business impact is deployment-time, recoverable by configuration correction.
4. **Fixed-pattern sites (05.3) and wire-format parsers (05.5).** No material business impact. These patterns are inventoried for completeness and to demonstrate that Kafka's regex surface outside of the three user-influenceable sites is bounded by design. The finding's presence here serves as documentation that future `Pattern.compile` additions should receive the same architectural review.

## 8. Accepted Mitigations Already Present

The following protective properties already exist in the tracked source and are relied on by this finding's severity assignments. Each is recorded in [`../accepted-mitigations.md`](../accepted-mitigations.md) and must not be regressed by future changes outside the scope of this audit.

- **Operator-supplied regex compiled at configuration time (fail-fast).** Both the Kerberos rule regexes (`KerberosRule.java:L70,L72`) and the `EnvVarConfigProvider` allowlist (`EnvVarConfigProvider.java:L61-L63`) are compiled during the broker's `configure` call path, not per-request. A pathological regex fails fast at broker startup and becomes visible as a startup delay, which operators can detect and correct before the regex participates in any authentication attempt or configuration lookup.
- **`EnvVarConfigProvider` allowlist pattern is an allow-list-by-default (`.*`).** [`../accepted-mitigations.md`](../accepted-mitigations.md) entry #5 records the default behaviour of `EnvVarConfigProvider.java:L65` as an allow-list over a blocklist — all environment-variable names pass through by default, and only operators who explicitly configure a narrower allowlist substitute a more restrictive pattern. This mitigation prevents accidental blind-spot regression.
- **Protocol-framing length caps on wire-format parser input (05.5).** The Kafka protocol's `COMPACT_STRING` and `NULLABLE_STRING` types impose upper bounds on the length of each string field before the regex engine sees the input. This is a structural (not a regex-level) mitigation that turns otherwise-linear regex matching from "linear in an attacker-chosen length" into "linear in a protocol-capped length".
- **JMX filter predicate evaluated on a non-request thread (05.2).** The `JmxReporter` thread is distinct from the broker network threads and request-handler thread pool. A pathological predicate stalls observability, not the data plane.
- **`SafeObjectInputStream` nine-entry suffix blocklist (Section 4.6).** The Connect runtime's `SafeObjectInputStream.java:L27-L37` pre-screens known Java-deserialization gadget classes by class-name suffix. [`../accepted-mitigations.md`](../accepted-mitigations.md) catalogues this as the primary defence for the Connect deserialization recursion surface discussed in [Finding 08.3](./08-deserialization-attacks.md).

## 9. Recommended Future Remediation (No Changes in This Run)

The items below are forward-looking guidance for subsequent KIP proposals, operator runbook updates, or code-review exercises. No code change is applied in this audit run per the Audit Only rule; every item here cross-references the entry in [`../remediation-roadmap.md`](../remediation-roadmap.md) that records it in a prioritised form.

1. **[05.1] Narrow the operator-supplied regex surface in `KerberosRule`.** [`../remediation-roadmap.md`](../remediation-roadmap.md) Section 3.3.3 "[05.1] Consider narrowing the four Pattern.compile sites in `KerberosRule`" is the authoritative record. Candidate narrowing approaches the roadmap itemises include: validating operator-supplied regex shapes with a lightweight ReDoS linter at `configure` time; denying patterns containing nested quantifier ambiguity (the `(a+)+`, `(a|a)*`, `(a*)*` shape family); or migrating the rule parser to a purpose-built grammar that uses regex only for the `s/from/to/` substitution clause. The roadmap rates this a Medium-term work item.
2. **[05.*] Introduce a process-wide ReDoS-resistant regex facility.** [`../remediation-roadmap.md`](../remediation-roadmap.md) Section 3.4.3 "[05.*] Consider introducing a process-wide ReDoS-resistant regex facility" is the authoritative record. The roadmap explicitly counts the ten `Pattern.compile` sites enumerated in this Finding 05 and describes a future-state `Utils.compileSafe(String)` or `Utils.compileWithBudget(String, Duration)` helper that could impose a deterministic per-match budget on each compile. The roadmap rates this a Long-term work item and notes that its scope spans the entire Clients and Connect module surface.
3. **Publish an operator runbook for SASL/GSSAPI principal-to-local rule authoring.** A documentation-only follow-on would catalogue the ReDoS-prone regex shapes the operator should avoid in `sasl.kerberos.principal.to.local.rules`, with worked examples drawn from [`../findings/05-infinite-loop-recursion-dos.md`](./05-infinite-loop-recursion-dos.md) Section 5.1. No code changes are required; the deliverable sits entirely inside `docs/`.
4. **Migrate `SafeObjectInputStream` from a blocklist to an allow-list.** This is recorded in [`../remediation-roadmap.md`](../remediation-roadmap.md) Section 3.3.1 as a Medium-term item under sub-finding 08.3 (the primary owner of the blocklist-architecture concern). It is cross-listed here because a positive allow-list of expected deserialised class names would also make the recursion-graph surface explicit at the point of `resolveClass`, supporting both this finding and Finding 08.
5. **Document the `JmxReporter` include/exclude regex as operator-only and non-request-path.** A runbook-level note that a pathological include/exclude regex stalls observability rather than availability is low-effort and reduces operator anxiety when tuning the filters. No code changes are required.

**Closing.** No code changes are applied in this audit run, in compliance with the Audit Only rule. Every recommendation above is a forward-looking guidance item for the Kafka community to evaluate in subsequent KIP proposals, operator runbook updates, or code-review exercises.

## 10. Cross-References

- **Navigation root:** [`../README.md`](../README.md) — audit overview, severity tier definitions (Section 2.3), and navigation to every audit artifact.
- **Severity matrix:** [`../severity-matrix.md`](../severity-matrix.md) — Section 3.5 "Category 05 — Infinite Loop and Recursion DoS" enumerates rows `05.1` through `05.5` with the same severity assignments used in this document (one Medium, four Low).
- **Remediation roadmap:** [`../remediation-roadmap.md`](../remediation-roadmap.md) — Section 3.3.3 `[05.1]` "Narrow `KerberosRule` regex surface" (Medium-term); Section 3.4.3 `[05.*]` "Process-wide ReDoS-resistant regex facility" (Long-term). Both items are explicitly tagged to this Finding 05 and count the ten `Pattern.compile` sites inventoried in Section 4.
- **Accepted mitigations:** [`../accepted-mitigations.md`](../accepted-mitigations.md) — entry #5 records `EnvVarConfigProvider` `allowlist.pattern` as an accepted allow-list-over-blocklist mitigation; additional entries elsewhere in the document record the `SafeObjectInputStream` nine-entry blocklist (Section 4.6 here) and the fail-fast-at-`configure`-time compile-path property.
- **Attack surface map:** [`../diagrams/attack-surface-map.md`](../diagrams/attack-surface-map.md) — the Category 05 row intersects the Clients module (`common/security/kerberos`, `common/metrics`, `common/config`, `common/network`, `common/requests`, `common/security/oauthbearer`), the Streams module (`state/internals/OffsetCheckpoint`), and the Connect runtime (`connect/util/SafeObjectInputStream` as mitigation).
- **Dependency inventory:** [`../dependency-inventory.md`](../dependency-inventory.md) — the JDK's `java.util.regex.Pattern` implementation is the engine underlying every site inventoried here. No third-party regex dependency is introduced by Kafka; the JDK version (Java 17 LTS baseline per the repository build matrix) is the only supply-chain axis relevant to this category.
- **Related finding — Category 04 (Module System and Built-in Abuse):** [`./04-module-system-builtin-abuse.md`](./04-module-system-builtin-abuse.md) — the Kerberos principal-to-local rule surface (05.1) intersects the operator-privileged configuration trust boundary discussed in Category 04 sub-findings on pluggable authentication configuration. The two findings are complementary: Category 04 records the *module-level* trust boundary; Category 05 records the *pattern-level* DoS residual.
- **Related finding — Category 07 (External Function and Callback Misuse):** [`./07-external-function-callback-misuse.md`](./07-external-function-callback-misuse.md) — the `OAuthBearerClientInitialResponse` patterns documented in sub-finding 05.5 are evaluated inside the SASL/OAUTHBEARER callback chain; Finding 07 records the broader SASL callback trust boundary and is the upstream context for the regex surface here.
- **Related finding — Category 08 (Deserialization Attacks):** [`./08-deserialization-attacks.md`](./08-deserialization-attacks.md) — sub-finding 08.3 records the `SafeObjectInputStream` blocklist-versus-allow-list architectural concern. The same file is documented here in Section 4.6 as the recursion/graph-walk mitigation; the two findings are the dual of one another. Sub-finding 08.5 also cites `streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java:L58` `WHITESPACE_MINIMUM_ONCE` as evidence that Streams checkpoint parsing is bounded; the same citation appears in Section 4.3 of this document for regex-inventory completeness.
- **Related finding — Category 09 (Information Leakage):** [`./09-information-leakage.md`](./09-information-leakage.md) — the `JmxReporter` regex surface (05.2) filters metric names that are themselves potentially sensitive observability signals. Finding 09 records the broader JMX exposure story; Category 05 records only the regex-level residual.
- **Related finding — Category 10 (Public API Developer Misuse):** [`./10-public-api-developer-misuse.md`](./10-public-api-developer-misuse.md) — operator-supplied regex values (`metrics.jmx.include`, `metrics.jmx.exclude`, `sasl.kerberos.principal.to.local.rules`, `allowlist.pattern`) are public configuration keys, and a pathological value is a developer-misuse footgun. Finding 10 records the broader insecure-default posture for operator-facing configuration.

---

> **End of Finding 05.** For the next category, see [Finding 06 — Network and Subprocess Access](./06-network-subprocess-access.md). For the preceding categories (01 through 04), see the [Audit Overview](../README.md), which indexes every finding in the canonical enumeration order.
