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

# Finding 09 — Information Leakage

> Navigation: [Audit Overview](../README.md) • [Severity Matrix](../severity-matrix.md) • [Remediation Roadmap](../remediation-roadmap.md) • [Accepted Mitigations](../accepted-mitigations.md)

> **Audit-only notice.** This document is a read-only static analysis artifact for Apache Kafka 4.2.0-SNAPSHOT. No source code, configuration, or runtime behavior has been modified in the course of producing this finding. Every cited line range was resolved directly from the tracked repository at the audit snapshot commit.

---

## 1. Category

**Information leakage** — enumeration position 9 of 10, as specified by the Agent Action Plan's verbatim category list.

## 2. Definition

Information leakage covers the unintentional exposure of secrets, sensitive configuration material, internal cluster state, or verbose error-path details through log files, JMX metrics, API responses, or exception messages. Kafka already implements several redaction helpers — `Password`, `DelegationToken`, `RecordRedactor`, and `ConfigurationImageNode` — each of which masks sensitive values before they reach persistent storage or observability pipelines. However, these four helpers use **four distinct marker strings** (`[hidden]`, `[*******]`, `(redacted)`, `[redacted]`), which creates a real operational-consistency risk for log-parsing integrators who must scrub or detect redacted values in downstream SIEM systems. In addition, the bundled launcher scripts enable JMX with authentication and TLS disabled by default, and two OAuth JWT validators emit claim name/value pairs at DEBUG-level severity, which can leak personally identifiable information (PII) or group-membership data into operator logs when verbose logging is enabled. None of these surfaces constitute a direct credential-disclosure bug at the audit snapshot — they are **defense-in-depth gaps** that warrant explicit documentation so that future regressions are easier to detect and so that operators can apply the appropriate compensating controls.

## 3. Kafka Surface Inventory

This finding enumerates five distinct surfaces grouped under the information-leakage category. The sub-findings are numbered `09.1` through `09.5` in the canonical order used by the [severity matrix](../severity-matrix.md) and [remediation roadmap](../remediation-roadmap.md).

| ID   | Surface                                                                                   | Severity                               |
| ---- | ----------------------------------------------------------------------------------------- | -------------------------------------- |
| 09.1 | Inconsistent redaction markers across `Password`, `DelegationToken`, `RecordRedactor`, `ConfigurationImageNode` | `[Low]`                                |
| 09.2 | `DelegationToken.toString()` HMAC placeholder masking + constant-time equality comparison | `[Low]` (Accepted Mitigation)          |
| 09.3 | JMX authentication and SSL disabled by default in `kafka-run-class.sh` and `kafka-run-class.bat` | `[Medium]`                             |
| 09.4 | DEBUG-level JWT claim logging in `BrokerJwtValidator` and `ClientJwtValidator`            | `[Low]`                                |
| 09.5 | Error-message enumeration via `VoterSet.voterNodes` (full voter map in `IllegalArgumentException`) | `[Low]`                                |

Each sub-finding is evidenced, analysed, and rated in the sections that follow.

## 4. Evidence

All line numbers below were verified by direct inspection of the tracked source files at the audit snapshot. The citation format is `Source: <repository-relative path>:L<start>[-L<end>]`.

### 4.1 Inconsistent redaction markers across subsystems (09.1)

Kafka uses four separate redaction helpers, each of which emits a **different** literal string when masking sensitive values. The following sources were inspected and the exact marker literals extracted.

**`Password` (clients module):** Masks password values via a JVM-wide constant and overridden `toString`.

- `Source: clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L19-L21` — class Javadoc, "A wrapper class for passwords to hide them while logging a config"
- `Source: clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L22` — `public class Password {`
- `Source: clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L24` — `public static final String HIDDEN = "[hidden]";`
- `Source: clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L54-L57` — `@Override public String toString() { return HIDDEN; }`
- `Source: clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L64-L66` — `public String value() { return value; }` (returns the real password when explicitly requested)

**`DelegationToken` (clients module):** Masks HMAC bytes via a literal in the `toString` method.

- `Source: clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L28` — `public class DelegationToken {`
- `Source: clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L70-L76` — `toString()` emits `"DelegationToken{" + "tokenInformation=" + tokenInformation + ", hmac=[*******]" + '}'` — the literal `[*******]` is used in place of the HMAC bytes

**`RecordRedactor` (metadata module):** Redacts sensitive fields before emitting controller-record audit trails to slf4j logs.

- `Source: metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java:L27-L30` — class Javadoc, "Converts a metadata record to a string suitable for logging to slf4j. This means that passwords and key material are omitted from the output."
- `Source: metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java:L31` — `public final class RecordRedactor {`
- `Source: metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java:L38` — `public String toLoggableString(ApiMessage message) {` (the entry point used by controller log callers)
- `Source: metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java:L40-L48` — `CONFIG_RECORD` branch: when the configuration schema reports the value as sensitive, the record is duplicated and its value replaced with the literal `(redacted)` via `duplicate.setValue("(redacted)");` on line 46
- `Source: metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java:L49-L59` — `USER_SCRAM_CREDENTIAL_RECORD` branch: SCRAM credential rendering replaces three separate fields with the literal `(redacted)` — `salt=(redacted)` (L54), `storedKey=(redacted)` (L55), `serverKey=(redacted)` (L56)
- `Source: metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java:L57` — `", iterations=" + record.iterations()` — the SCRAM `iterations` field is emitted unmodified because iteration count is not secret material and is required for legitimate operational tracing; it therefore does **not** appear in any of the four redaction marker forms. (This is an intentional design, not a regression. A future auditor observing `iterations=4096` in a log line should not flag it as leaked credential material.)

**`ConfigurationImageNode` (metadata module):** Redacts sensitive configuration values when emitting the metadata image.

- `Source: metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java:L26` — `public class ConfigurationImageNode implements MetadataNode {`
- `Source: metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java:L51-L59` — `print(MetadataNodePrinter printer)` branch
- `Source: metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java:L53-L54` — predicate `printer.redactionCriteria().shouldRedactConfig(image.resource().type(), name)` drives the branch
- `Source: metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java:L55` — `printer.output("[redacted]");` — the literal used here is `[redacted]` (square brackets), distinct from `RecordRedactor`'s `(redacted)` (parentheses)

**Summary table — four distinct redaction markers, all in mainline code:**

| File (repository-relative path)                                                                   | Class                    | Marker literal | Format                     |
| --------------------------------------------------------------------------------------------------- | ------------------------ | -------------- | -------------------------- |
| `clients/src/main/java/org/apache/kafka/common/config/types/Password.java`                         | `Password`               | `[hidden]`     | square brackets, lowercase |
| `clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java`     | `DelegationToken`        | `[*******]`    | square brackets, asterisks |
| `metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java`                        | `RecordRedactor`         | `(redacted)`   | round parentheses          |
| `metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java`                   | `ConfigurationImageNode` | `[redacted]`   | square brackets            |

The marker literals were harvested by textual inspection of the source files cited above; the precise character composition (`[` vs `(`, asterisks vs text, casing) is material to any regex-based log scrubber and is the reason this sub-finding is recorded.

### 4.2 `DelegationToken.toString()` HMAC masking with constant-time comparison (09.2 — Accepted Mitigation)

`DelegationToken` combines two complementary defences against HMAC-byte disclosure and timing side-channel leakage. Both are already in place at the audit snapshot and are recorded here as accepted mitigations so that future refactoring cannot silently drop them.

- `Source: clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L19` — `import java.security.MessageDigest;` — imports the JDK facility used for constant-time byte-array comparison
- `Source: clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L28` — `public class DelegationToken {`
- `Source: clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L58-L61` — `equals(Object o)` returns `Objects.equals(tokenInformation, token.tokenInformation) && MessageDigest.isEqual(hmac, token.hmac);` — the HMAC comparison uses `MessageDigest.isEqual`, which performs a constant-time byte-by-byte comparison and **does not short-circuit** on the first differing byte, thereby neutralising timing-oracle attacks that would otherwise allow an attacker to recover HMAC bytes one-at-a-time by measuring `equals` latency
- `Source: clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L70-L76` — `toString()` emits `"DelegationToken{tokenInformation=..., hmac=[*******]}"` — the HMAC bytes are replaced with a fixed seven-asterisk placeholder before any possibility of being committed to a log line or a stack trace

These two properties together form a pair: `MessageDigest.isEqual` prevents active exploitation of the HMAC equality path, and the `toString` masking prevents accidental passive disclosure through diagnostic logging. Both are cross-referenced in [`../accepted-mitigations.md`](../accepted-mitigations.md) (Mitigation #1 for `MessageDigest.isEqual`; Mitigation #2 for `toString` masking).

### 4.3 JMX authentication and SSL disabled by default in launcher scripts (09.3)

Kafka ships with two launcher scripts that configure JVM flags for every tool the project distributes (broker, controller, Connect, Streams, admin CLIs, etc.). Both scripts set the `KAFKA_JMX_OPTS` environment variable with **authentication and SSL disabled** if the operator has not already exported a value.

**POSIX launcher (`bin/kafka-run-class.sh`):**

- `Source: bin/kafka-run-class.sh:L201` — `# JMX settings` comment
- `Source: bin/kafka-run-class.sh:L202-L204` — `if [ -z "$KAFKA_JMX_OPTS" ]; then ... fi` conditional
- `Source: bin/kafka-run-class.sh:L203` — `KAFKA_JMX_OPTS="-Dcom.sun.management.jmxremote=true -Dcom.sun.management.jmxremote.authenticate=false  -Dcom.sun.management.jmxremote.ssl=false "` — three JVM system properties are set:
  - `com.sun.management.jmxremote=true` — enables the JMX remote agent
  - `com.sun.management.jmxremote.authenticate=false` — disables JMX authentication
  - `com.sun.management.jmxremote.ssl=false` — disables TLS transport for JMX
- `Source: bin/kafka-run-class.sh:L207-L210` — `if [ $JMX_PORT ]; then ...` — if `JMX_PORT` is set, a JMX listener is opened on the specified port with the defaults above

**Windows launcher (`bin/windows/kafka-run-class.bat`):**

- `Source: bin/windows/kafka-run-class.bat:L102` — `rem JMX settings` comment
- `Source: bin/windows/kafka-run-class.bat:L103-L105` — `IF ["%KAFKA_JMX_OPTS%"] EQU [""] ...` conditional
- `Source: bin/windows/kafka-run-class.bat:L104` — `set KAFKA_JMX_OPTS=-Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.authenticate=false  -Dcom.sun.management.jmxremote.ssl=false` — the Windows form uses the bare `-Dcom.sun.management.jmxremote` flag (without `=true`) but keeps authentication and SSL disabled identically to the POSIX script
- `Source: bin/windows/kafka-run-class.bat:L107-L110` — `IF ["%JMX_PORT%"] NEQ [""] ...` opens the JMX listener when `JMX_PORT` is exported

The operator can override `KAFKA_JMX_OPTS` to enable authentication and TLS, but the script's **default** is a no-authentication JMX listener whenever `JMX_PORT` is also set. This is widely understood as a development-convenience default; the sub-finding documents it here so that production operators are explicitly reminded to override the variable before enabling `JMX_PORT`.

### 4.4 DEBUG-level JWT claim logging (09.4)

Kafka ships two JWT validator implementations for OAuth bearer tokens. Both extract individual claims from the JWT payload via a shared helper method that emits a DEBUG log line for every claim accessed. When operators enable DEBUG logging, every claim name **and its value** is committed to the log stream.

**`BrokerJwtValidator` (broker-side, jose4j-based):**

- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L191-L199` — `private <T> T getClaim(ClaimSupplier<T> supplier, String claimName) throws JwtValidatorException { try { T value = supplier.get(); log.debug("getClaim - {}: {}", claimName, value); return value; } catch (MalformedClaimException e) { throw new JwtValidatorException(...); } }`
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L194` — `log.debug("getClaim - {}: {}", claimName, value);` — the DEBUG statement that emits the claim name and its value

**`ClientJwtValidator` (client-side, structural-only validation):**

- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L134-L138` — `private Object getClaim(Map<String, Object> payload, String claimName) { Object value = payload.get(claimName); log.debug("getClaim - {}: {}", claimName, value); return value; }`
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L136` — identical DEBUG log line pattern

Claims routinely carried in production JWTs include the `sub` (subject, often a user identifier or email address), the issuer, scope set, expiration, issued-at timestamp, and — depending on identity-provider configuration — custom claims such as group membership, tenant identifiers, and authentication-method metadata. Each of these values is emitted at DEBUG level by every validator call. Operators who ship broker logs to a shared observability platform (ELK, Splunk, Loki, CloudWatch, etc.) without log-level filtering or claim-field redaction therefore risk exposing PII and authorisation-relevant metadata to a wider audience than the original token subject anticipated.

### 4.5 Error-message enumeration via `VoterSet.voterNodes` (09.5)

The `VoterSet` class is the KRaft quorum's canonical representation of the voter membership. When `voterNodes(Stream<Integer> voterIds, ListenerName listenerName)` is asked to resolve a voter id that is not present in the set, it throws an `IllegalArgumentException` whose message embeds the **entire** `voters` map, including every voter's id, every listener's endpoint host and port, and every voter's directory id.

- `Source: raft/src/main/java/org/apache/kafka/raft/VoterSet.java:L59-L62` — method Javadoc documents the throw contract: "@throws IllegalArgumentException if there are missing endpoints"
- `Source: raft/src/main/java/org/apache/kafka/raft/VoterSet.java:L63-L78` — method body
- `Source: raft/src/main/java/org/apache/kafka/raft/VoterSet.java:L66-L75` — the `orElseThrow` lambda constructs `new IllegalArgumentException(String.format("Unable to find endpoint for voter %d and listener %s in %s", voterId, listenerName, voters))` — the third `%s` substitution is the entire `voters` map, rendered by its default `Map<Integer, VoterNode>.toString()`

A concrete example of the rendered message (reconstructed from the format string, not a verbatim log sample):

```
Unable to find endpoint for voter 42 and listener CONTROLLER in {1=VoterNode{...endpoints=...directoryId=...}, 2=VoterNode{...}, 3=VoterNode{...}}
```

The message is raised by a routine leader-side path that consults the voter set during quorum operations. Depending on where the exception propagates, the full voter map string may appear in WARN/ERROR log lines, in HTTP error responses relayed through admin tooling, or in the stack trace of a surface that is visible to less-privileged operators.

## 5. Attack Vector

### 5.1 Redaction marker inconsistency (09.1)

A log-parsing integrator building a SIEM redaction rule observes that Kafka "redacts secrets in logs" and writes a regex matching the most common marker (`[hidden]`). The integrator's pipeline subsequently deploys into production. Because `DelegationToken`, `RecordRedactor`, and `ConfigurationImageNode` use three different markers, values masked through those code paths pass the integrator's redaction predicate untouched. The literal sensitive values are never re-exposed (Kafka still masks them locally before writing to disk), but the **redaction audit trail** that the SIEM pipeline relies upon becomes inaccurate: downstream consumers see values tagged with a redaction marker the integrator's rule did not recognise, and a future regression that drops one of the four markers entirely will not be detected by the scrubber because the scrubber only checks for one of them. This is a defensive-posture degradation rather than a direct leak.

### 5.2 DelegationToken HMAC masking and comparison (09.2)

No attack vector applies. Section 4.2 documents the current mitigations (`MessageDigest.isEqual` for constant-time equality and `toString` HMAC masking). The sub-finding is preserved in this document to lock in the regression-prevention contract: any future refactor that replaces `MessageDigest.isEqual` with `Arrays.equals`, or that inlines the HMAC into the `toString` output, must be caught in code review.

### 5.3 JMX no-authentication default (09.3)

An adversary who holds a network path to the broker's JMX port (typically 9999 in bundled test fixtures, or whatever port the operator supplies via `JMX_PORT`) connects without credentials and reads every registered MBean. Broker JMX metrics expose — at minimum — the complete topic list, partition counts, consumer group identifiers, client-id strings, per-topic byte-in and byte-out rates, replica sync state, controller state, and Kafka-internal topic names (`__consumer_offsets`, `__transaction_state`, etc.). These metrics are adequate to map cluster topology, identify heavy-traffic partitions worth attacking, enumerate tenant boundaries in multi-tenant deployments, and plan follow-on operations (produce floods, partition-starvation attacks, etc.). The adversary need not authenticate and need not possess a valid Kerberos ticket or OAuth bearer — the JMX listener happily serves every query. The attack does not require exploiting a bug; it requires only that the operator accepted the launcher-script default and that a firewall rule does not block the JMX port. (The JMX listener is only opened when `JMX_PORT` is also set, which mitigates the default surface area for operators who never export that variable; but the JMX port is commonly opened in containerised deployments and in operator-monitoring setups.)

### 5.4 DEBUG-level JWT claim leakage (09.4)

An operator enables DEBUG logging on `org.apache.kafka.common.security.oauthbearer` (for any legitimate reason — troubleshooting a token-validation failure, calibrating a new identity-provider integration, or tracing a claim-mapping issue). From that moment until DEBUG is disabled, every JWT processed by the validator emits one DEBUG line per accessed claim, with the claim name and value both visible. A log viewer with read access to the broker's log file, or any shared log-aggregation endpoint, now has visibility into subject identifiers, email addresses (common in `sub` or custom `email` claims), group memberships (common in custom claims), and any other claim the issuing identity provider embeds in its tokens.

### 5.5 VoterSet voter enumeration (09.5)

An attacker who can trigger a lookup for a non-existent voter id — for example, by submitting a malformed `UpdateVoter` RPC or by provoking an administrative tool to resolve an incorrect voter reference — causes the KRaft quorum leader to throw an `IllegalArgumentException` whose message contains the entire voter map. If that exception is logged at WARN or ERROR level (the default for most controller code paths), the full topology of the control-plane quorum — including every voter id, listener host, port, and directory id — is committed to the log stream. A reader with log-read access (or an adversary who controls a log aggregator) can now enumerate the full quorum, identify controller hosts by IP address, and plan follow-on attacks (targeted RPC storms, controller-host resource exhaustion, etc.). The attack does not require quorum authorisation — only the ability to trigger a voter-lookup error path.

## 6. Severity

Each sub-finding is scored using the Critical / High / Medium / Low tiers defined in [`../README.md`](../README.md).

| Sub-finding | Severity                          | Rationale                                                                                                                                                         |
| ----------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 09.1        | `[Low]`                           | Consistency risk, not a direct credential leak. Exploitation requires a downstream redaction scrubber that only recognises a subset of the four markers.          |
| 09.2        | `[Low]` (Accepted Mitigation)     | The `MessageDigest.isEqual` and `toString` masking defences are in place; the sub-finding exists to prevent regression. No live exposure at the audit snapshot.    |
| 09.3        | `[Medium]`                        | The no-authentication JMX default is set by the launcher script distributed with Kafka, not an operator opt-in; combined with `JMX_PORT`, it exposes broker telemetry to any network peer. Mitigated by firewalling but not by Kafka itself. |
| 09.4        | `[Low]`                           | DEBUG is not the default log level; exposure requires an explicit operator decision to enable DEBUG on the OAuth validator logger.                                |
| 09.5        | `[Low]`                           | Exposure requires (a) triggering a voter-lookup error path and (b) log-read access. The information gained is KRaft topology, not credential material.            |

Category-level roll-up: 0 Critical, 0 High, 1 Medium, 4 Low (one of which is an Accepted Mitigation). The category is driven principally by the JMX default (09.3); the other four sub-findings are defence-in-depth concerns.

## 7. Business Impact

The business impact of information leakage in Apache Kafka deployments centres on **observability hygiene** and **control-plane reconnaissance**, rather than direct theft of credential material. Four concrete consequences apply:

1. **Compliance posture drift (09.1).** Organisations operating under frameworks that require log redaction (PCI DSS, HIPAA, GDPR for identifier fields) typically implement a central redaction scrubber in their SIEM pipeline. When that scrubber only recognises `[hidden]` — the most frequently cited marker — redactions emitted through the three other paths pass the scrubber untouched and are stored as-is. The residual values are not actually sensitive (Kafka masked them locally), but the compliance audit trail becomes inconsistent and future regressions are harder to detect.
2. **Reconnaissance-driven follow-on attacks (09.3).** Unauthenticated JMX access yields a comprehensive picture of cluster topology, tenant boundaries, and traffic hot-spots. An adversary who has established network reach to the JMX port — typically through firewall misconfiguration, lateral movement from a compromised host in the same network segment, or an accidentally-exposed container orchestration endpoint — gains the reconnaissance material needed to plan high-impact follow-on operations such as produce floods against high-value partitions, controller-host resource exhaustion, or partition-starvation attacks.
3. **PII exposure in observability pipelines (09.4).** JWT claim values routinely include email addresses, subject identifiers, tenant identifiers, and group membership. When DEBUG logging is enabled on the OAuth validator code paths — for any legitimate operational reason — every processed token writes its claim content to the log stream. Log pipelines that are provisioned with access beyond the broker operator group (for example, a shared SRE dashboard that many teams can query) therefore briefly gain visibility into authentication-relevant PII.
4. **KRaft control-plane mapping (09.5).** A `voters` map rendered into a WARN/ERROR log line enumerates every quorum voter, its endpoint, and its directory identifier. This is precisely the information needed to target RPCs at specific controller hosts during a subsequent attack. In multi-datacentre deployments, it also reveals cross-datacentre controller placement and latency-sensitive quorum topology.

The cumulative business impact is **moderate**. No single sub-finding leaks credentials directly, but collectively these surfaces reduce the defence-in-depth margin of a Kafka deployment that follows the default operational postures. Operators can mitigate each surface through deployment-level controls (firewalling JMX, log-level policies, log-scrubber expansion) without any Kafka source-code change.

## 8. Accepted Mitigations Already Present

The following mitigations are already in place at the audit snapshot and are catalogued in [`../accepted-mitigations.md`](../accepted-mitigations.md). This audit does not propose to modify them; the purpose of enumerating them here is to prevent regression in future refactoring.

- **Mitigation #1 — Constant-time HMAC comparison in `DelegationToken`.** `DelegationToken.equals` uses `MessageDigest.isEqual` on HMAC byte arrays at `clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L60`. See [`../accepted-mitigations.md`](../accepted-mitigations.md).
- **Mitigation #2 — `DelegationToken.toString()` HMAC placeholder masking.** `DelegationToken.toString` emits `hmac=[*******]` at `clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L70-L76`. See [`../accepted-mitigations.md`](../accepted-mitigations.md).
- **Mitigation #17 — `Password.HIDDEN = "[hidden]"` masking via `toString`.** `Password.toString` returns the constant `HIDDEN` at `clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L54-L57`. See [`../accepted-mitigations.md`](../accepted-mitigations.md).
- **`RecordRedactor` redacts `CONFIG_RECORD` sensitive values and `USER_SCRAM_CREDENTIAL_RECORD` salt, storedKey, and serverKey fields.** `RecordRedactor.toLoggableString` at `metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java:L38-L62`. The `iterations` field at line 57 is intentionally emitted unmasked because iteration count is operational, non-secret data required for legitimate operational tracing; this is documented here so that future auditors do not flag it as a regression.
- **`ConfigurationImageNode` emits `[redacted]` for configurations flagged by the redaction criteria.** `ConfigurationImageNode.print` at `metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java:L51-L59`. The redaction decision is delegated to `printer.redactionCriteria().shouldRedactConfig(...)` so that the policy is pluggable.

## 9. Recommended Future Remediation (No Changes in This Run)

Per the Audit Only rule, **no source code or configuration changes are applied in this run**. The following items are forward-looking recommendations for subsequent Kafka Improvement Proposals (KIPs), code reviews, or operator-facing documentation updates. They are also enumerated with `[09.*]` tags in the [remediation roadmap](../remediation-roadmap.md).

1. **Consolidate redaction markers (09.1 — Long-term).** Propose a future KIP that unifies `Password.HIDDEN`, `DelegationToken`'s inline `[*******]`, `RecordRedactor`'s `(redacted)`, and `ConfigurationImageNode`'s `[redacted]` onto a single canonical marker (for example, `[REDACTED]`). Because this change breaks log-format compatibility for any downstream scrubber, a deprecation cycle would be required. Cross-reference: [remediation-roadmap.md Section 3.4 — `[09.1]` Consolidate redaction markers](../remediation-roadmap.md).
2. **Document redaction marker inventory for integrators (09.1 — Short-term).** Publish an operator-facing inventory of all current redaction markers (`[hidden]`, `[*******]`, `(redacted)`, `[redacted]`) so that SIEM redaction scrubbers can cover every one of them without a code change. Cross-reference: [remediation-roadmap.md Section 3.2 — `[09.1]` Document inconsistency](../remediation-roadmap.md).
3. **Operator runbook for JMX hardening (09.3 — Short-term).** Add an explicit warning near the `KAFKA_JMX_OPTS` documentation indicating that the launcher-script defaults disable JMX authentication and TLS. Recommend that production deployments always export `KAFKA_JMX_OPTS` with `com.sun.management.jmxremote.authenticate=true`, `com.sun.management.jmxremote.ssl=true`, a password file, and either a client-certificate truststore or SSL keystore before enabling `JMX_PORT`. No script change is proposed because changing the default would break existing development workflows.
4. **Redact JWT claim values in DEBUG logging (09.4 — Medium-term).** Propose a code-review recommendation for a future change that replaces `log.debug("getClaim - {}: {}", claimName, value);` in both `BrokerJwtValidator` and `ClientJwtValidator` with a formatter that masks the value (for known-sensitive claim names such as `sub`, `email`, and any custom tenant- or user-identifying claim) while keeping the claim name visible for debugging.
5. **Summarise voter map in error messages (09.5 — Medium-term).** Propose a future change that replaces the full `voters` map rendering in `VoterSet.voterNodes`'s `IllegalArgumentException` with a summary (voter count, quorum size, ranges of voter ids) that is sufficient for operators to diagnose the lookup failure without enumerating every voter endpoint. Callers who need the full map can resolve it via trusted admin tooling.

**Closing.** No code changes are applied in this audit run per the Audit Only rule. Every recommendation above is a forward-looking guidance item for the Kafka community to evaluate in subsequent KIP proposals, operator runbook updates, or code-review exercises.

## 10. Cross-References

- **Navigation root:** [`../README.md`](../README.md) — audit overview, severity tier definitions, and navigation to every audit artifact.
- **Severity matrix:** [`../severity-matrix.md`](../severity-matrix.md) — includes rows `09.1` through `09.5` with the same severity assignments used here.
- **Remediation roadmap:** [`../remediation-roadmap.md`](../remediation-roadmap.md) — Section 3.2 `[09.1]` Document redaction marker inconsistency (Short-term) and Section 3.4 `[09.1]` Consolidate redaction markers (Long-term).
- **Accepted mitigations:** [`../accepted-mitigations.md`](../accepted-mitigations.md) — Mitigation #1 (constant-time HMAC comparison), Mitigation #2 (`DelegationToken.toString` HMAC masking), Mitigation #17 (`Password.HIDDEN = "[hidden]"`).
- **Related finding — Category 08 (Deserialization Attacks):** [`./08-deserialization-attacks.md`](./08-deserialization-attacks.md) — OAuth dual-validator asymmetry (`BrokerJwtValidator` enforces `DISALLOW_NONE` via jose4j; `ClientJwtValidator` is structural-only). Sub-finding 09.4 documents the DEBUG-level claim logging that is common to **both** validators.
- **Related finding — Category 10 (Public API Developer Misuse):** [`./10-public-api-developer-misuse.md`](./10-public-api-developer-misuse.md) — documents insecure-by-default operational postures; the JMX no-authentication launcher default (09.3) is cross-referenced there as a developer-misuse concern.
- **Threat model overview:** [`../diagrams/threat-model-overview.md`](../diagrams/threat-model-overview.md) — the information-leakage surfaces are annotated on the data-flow diagram.

## Validation Checklist

The following checklist items are provided so that a future auditor or reviewer can re-verify this finding against a later Apache Kafka snapshot. Every item is a read-only check that can be performed with `git`, `grep`, or file inspection — no code execution and no modification of source is required, honoring the Audit Only rule.

- [ ] **09.1 — Four distinct redaction markers:** Confirm that the four redaction markers documented in Section 4 still exist and still render as `[hidden]` (`clients/src/main/java/org/apache/kafka/common/config/types/Password.java` — `HIDDEN` constant), `[*******]` (`clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java` — `toString` override), `(redacted)` (`connect/runtime/src/main/java/org/apache/kafka/connect/runtime/RecordRedactor.java`), and `[redacted]` (`metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java`).
- [ ] **09.2 — `DelegationToken.toString` HMAC masking:** Confirm that `DelegationToken.java`'s `toString` override still renders the HMAC byte array as a masked literal (accepted mitigation Entry 2) rather than emitting the raw bytes, at the line range cited in Section 4.2.
- [ ] **09.3 — JMX launcher-script defaults:** Confirm that `bin/kafka-run-class.sh` and `bin/windows/kafka-run-class.bat` still contain the literal `-Dcom.sun.management.jmxremote.authenticate=false` and `-Dcom.sun.management.jmxremote.ssl=false` defaults at the line ranges cited in Section 4.3 (anchors L203 in the shell script and L104 in the batch script at the audit snapshot).
- [ ] **09.4 — DEBUG-level JWT claim logging:** Confirm that `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/secured/BrokerJwtValidator.java` and `ClientJwtValidator.java` still contain the `log.debug` statements that render claim names and values at the line ranges cited in Section 4.4 (anchors `BrokerJwtValidator.java:L191-L199` and `ClientJwtValidator.java:L134-L138` in the audit snapshot).
- [ ] **09.5 — `VoterSet.voterNodes` error-message voter map:** Confirm that `raft/src/main/java/org/apache/kafka/raft/VoterSet.java`'s `voterNodes` method still renders the full voter map in its `IllegalArgumentException` message at the line range cited in Section 4.5.
- [ ] **`Password.HIDDEN` constant value:** Confirm that `Password.HIDDEN` is still declared with the exact literal value `"[hidden]"` (accepted mitigation Entry 17).
- [ ] **Severity alignment:** Confirm that the severity assignments for 09.1 through 09.5 in Section 6 of this finding match the row-level severities for the same sub-findings in [severity-matrix.md](../severity-matrix.md).
- [ ] **Remediation roadmap cross-references:** Confirm that the sub-findings referenced in Section 9 (09.1 → Sections 3.2, 3.4; 09.3 → short-term runbook; 09.4 → medium-term code change; 09.5 → medium-term code change) still resolve to the corresponding subsections in [remediation-roadmap.md](../remediation-roadmap.md).
- [ ] **Accepted-mitigation cross-references:** Confirm that [accepted-mitigations.md](../accepted-mitigations.md) Entries 1 (constant-time HMAC), 2 (`DelegationToken.toString` masking), and 17 (`Password.HIDDEN`) still cite the same line ranges as Sections 4.1, 4.2, and 8 of this finding.
- [ ] **No-change verification:** Confirm via [no-change-verification.md](../no-change-verification.md) that this finding introduced zero modifications to Kafka source, test, or build files; only the markdown file you are reading now (and its sibling artifacts under `docs/security-audit/`) were created.

## Key Insights

The following plain-language takeaways summarize this finding for operator consumption. They are intended to be read alongside (not in place of) the full finding above.

- **Dominant attack vector.** The most consequential Category 09 surface is the JMX launcher-script default (09.3), which disables JMX authentication and TLS via `com.sun.management.jmxremote.authenticate=false` and `com.sun.management.jmxremote.ssl=false`. If an operator exports `JMX_PORT` without additionally exporting an overriding `KAFKA_JMX_OPTS`, the broker exposes an unauthenticated JMX endpoint that leaks metric namespaces (including configuration keys and topic names) to anyone who can reach the port. The four-marker redaction inconsistency (09.1) is the second-most consequential surface because downstream SIEM scrubbers that only match one marker will miss the other three.

- **Strongest existing mitigations.** The delegation-token subsystem applies two strong controls: constant-time HMAC comparison via `MessageDigest.isEqual` (accepted mitigation Entry 1) and HMAC masking in `DelegationToken.toString` (Entry 2). Together these ensure that delegation-token secrets neither leak through timing channels during authentication nor through log-line rendering during debugging. `Password.HIDDEN = "[hidden]"` (Entry 17) provides a consistent masking for `Password` type values in `toString` rendering.

- **Primary residual risk.** The JMX launcher defaults (09.3) dominate residual risk because a single environment variable error (`export JMX_PORT=...` without `KAFKA_JMX_OPTS` override) can open an unauthenticated metrics surface on a production broker. The redaction-marker inconsistency (09.1) is a smaller but chronic risk — any SIEM redaction scrubber must implement all four markers to be complete, and a new subsystem that introduces a fifth marker would silently bypass all existing scrubbers. The DEBUG-level JWT claim logging (09.4) is latent — it only emits on DEBUG log level, but any operator who turns on DEBUG for OAUTHBEARER troubleshooting will emit claim values into the log stream.

- **Recommended operator posture.** (1) If enabling JMX, always set `KAFKA_JMX_OPTS` with `com.sun.management.jmxremote.authenticate=true`, `com.sun.management.jmxremote.ssl=true`, a password file, and either an SSL keystore or a client-certificate truststore — never rely on the launcher defaults. (2) Configure your SIEM redaction pipeline to match all four redaction markers (`[hidden]`, `[*******]`, `(redacted)`, `[redacted]`) so that log lines from any of the four subsystems are scrubbed consistently. (3) Keep OAuth validator log levels at INFO or WARN in production; turn on DEBUG only during active troubleshooting and revert immediately. (4) Ensure delegation-token rotation uses the `DelegationTokenManager` APIs that rely on `MessageDigest.isEqual` — do not build custom token-comparison code.

- **Relationship to other categories.** Category 09 intersects with Category 08 (deserialization — 09.4's DEBUG claim logging lives inside the same JWT validators catalogued in 08.4), Category 10 (public API developer misuse — 09.3's JMX no-auth default is cross-referenced under 10.x as a developer-misuse concern), and Category 06 (network and subprocess — information leaked through JMX becomes exploitable only when the JMX network surface is reachable, which is a Category 06 concern).

---

> **End of Finding 09.** For the next category, see [Finding 10 — Public API Developer Misuse](./10-public-api-developer-misuse.md). For the preceding category, see [Finding 08 — Deserialization Attacks](./08-deserialization-attacks.md).
