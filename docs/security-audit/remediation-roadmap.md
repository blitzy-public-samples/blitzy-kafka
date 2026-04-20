<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

# Remediation Roadmap — Future-State Recommendations

> **AUDIT ONLY — NO CHANGES APPLIED IN THIS RUN**
>
> This file catalogs recommended future-state actions surfaced by the audit. The audit itself made
> **zero** modifications to source code, tests, build scripts, or existing documentation. Any item
> below requires a Kafka Improvement Proposal (KIP) or equivalent engineering-review process before
> it can be acted on.
>
> Reviewers MUST verify the "No Changes" clause via
> [`docs/security-audit/no-change-verification.md`](./no-change-verification.md) before considering
> any recommendation for implementation.

---

## 1. Purpose and Intended Audience

This document organizes every finding surfaced by the audit into a **phased, future-state remediation
roadmap**. It is written for three audiences:

- **Operators** who may harden running Apache Kafka clusters today by configuration change alone,
  without requiring any code modification (Section 3.1).
- **Documentation maintainers** who may close operator-facing security-documentation gaps without any
  code modification (Section 3.2).
- **Apache Kafka committers and KIP authors** who may plan medium- and long-term code-level changes
  through formal engineering review (Sections 3.3 and 3.4).

Every recommendation cites the matching **finding ID** from
[`./severity-matrix.md`](./severity-matrix.md) (for example, `06.1`) and one or more **absolute
repository paths** for evidence traceability. Every recommendation uses future-state language —
"consider", "evaluate", "may", or "could" — never the imperative. The audit itself proposes no
changes; only the downstream engineering process may adopt any of the items listed below.

### 1.1 How To Read This Document

Each recommendation is presented in the following shape:

```
[<finding-id>] <Short descriptive heading using future-state verb>
  Action      : Descriptive characterization of the change (operator configuration, documentation
                revision, or code change requiring a KIP)
  Evidence    : Absolute repository path(s) and line range(s) citing the original finding
  Impact      : Operational or architectural impact of the hypothetical change
  Prerequisite: What must precede the change (e.g., KIP approval, deprecation cycle, operator survey)
  Change class: One of {Operator-config-only, Documentation-only, Non-breaking code change (KIP),
                Breaking / architectural (KIP + deprecation)}
```

A reader looking for a specific category of recommendation can jump to the phase that matches the
change class: Section 3.1 (operator-config-only), Section 3.2 (documentation-only), Section 3.3
(non-breaking code), or Section 3.4 (architectural).

---

## 2. Remediation Timeline — Future State

The Gantt chart below is **illustrative**. Dates depend on engineering capacity, KIP review cadence,
and the Apache Software Foundation release-cycle governance; no commitment is implied by this audit.
Task identifiers such as `imm1` and `mt2` are internal to this chart only. Every task is annotated
with the corresponding **finding ID** from [`./severity-matrix.md`](./severity-matrix.md) so that a
reader can drill down from the timeline entry to the originating finding.

```mermaid
%%{init: {'theme':'neutral'}}%%
gantt
    title Remediation Roadmap - Future State (no changes applied in this run)
    dateFormat  YYYY-MM-DD
    axisFormat  %Y-%m
    section Proposed - Immediate (operator action)
    Harden Connect REST basic-auth (06.1)            :crit, imm1, 2026-04-17, 30d
    Disable OAuthBearerUnsecured in prod (07.1,10.4) :crit, imm2, 2026-04-17, 30d
    Replace PropertyFileLoginModule (10.3)           :crit, imm3, after imm1, 45d
    Enforce TLS on all listeners (10.1)              :crit, imm4, after imm2, 45d
    section Proposed - Short-term (1-3 months)
    Document INTERNAL_REQUEST_MATCHERS (06.1)        :       st1,  after imm3, 30d
    Audit OAuth dual-validator posture (08.4)        :       st2,  after imm4, 30d
    Track upstream supply-chain CVEs (02.3, 06.6)    :crit,  st3,  after imm4, 30d
    section Proposed - Medium-term (3-6 months)
    Convert SafeObjectInputStream to allow-list (08.3) :     mt1,  2026-08-01, 60d
    Constrain release.py shell=True calls (06.4)       :     mt2,  2026-08-15, 30d
    section Proposed - Long-term (6+ months)
    ReDoS backstop via timeout-aware matcher (05.*)    :     lt1,  2026-11-01, 90d
    Consolidate redaction markers (09.1)               :     lt2,  2027-01-01, 60d
```

### 2.1 Gantt Legend

> **Important — Illustrative Emphasis Only**: The Gantt bars use the `:crit` marker for **visual
> emphasis only**. The marker does **NOT** mean the task is critical-path, in-progress, completed,
> or otherwise engaged. Every task in this chart is **proposed future work** that has not been
> started and will not be started by this audit. The `:crit` marker was chosen because alternative
> Mermaid Gantt markers such as `:done` and `:active` carry "completed" and "in-progress" semantics
> that would falsely imply the audit has applied changes.

| Marker                     | Meaning in this chart                                                                                        |
|----------------------------|--------------------------------------------------------------------------------------------------------------|
| `:crit,`                   | **Visual emphasis only** — this audit recommends operator-actionable phases highlighted; NOT critical-path, NOT engaged, NOT in progress. |
| (no marker)                | Represents a class of change that is **proposed** and requires a KIP or equivalent engineering review.       |
| Dates                      | Illustrative only. The audit recommends no binding schedule. ASF governance determines real timing.          |
| Finding ID in parentheses  | The originating finding ID as enumerated in [`./severity-matrix.md`](./severity-matrix.md).                  |
| "Proposed -" section prefix | Reinforces that every phase is a recommendation, not an activity engaged by this audit.                     |

### 2.2 Phase Summary

- **Immediate (Section 3.1)**: Changes an operator can apply today through configuration alone.
  No code modification, no KIP. Four items covering five of the six High-severity findings (06.1,
  07.1, 10.1, 10.3, 10.4) plus one Medium-severity hardening (10.5). The sixth High-severity
  finding (06.6 — Jetty `GzipHandler` / `GzipRequest` native-memory leak tracked as
  CVE-2026-1605) is surfaced separately under Short-term Section 3.2.7 because its remediation
  requires an upstream dependency version bump that falls outside the scope of an operator-only
  configuration change.
- **Short-term (Section 3.2)**: Documentation-only actions that close operator-facing gaps without
  modifying code or configuration schema. **Includes a supply-chain advisory cadence
  (Section 3.2.7) covering the audit's single `[Critical]` finding (02.3 — `org.lz4:lz4-java` 1.8.0
  CVE-2025-12183 and CVE-2025-66566) and the Jetty High-severity finding (06.6 — CVE-2026-1605),
  both surfaced by supply-chain CVE scanning during QA Final Checkpoint #4 and consolidated in
  [`./cve-snapshot.md`](./cve-snapshot.md).**
- **Medium-term (Section 3.3)**: Non-breaking code changes that require a KIP but do not remove or
  rename any public API surface.
- **Long-term (Section 3.4)**: Architectural or breaking changes that require a KIP plus a
  deprecation cycle per Apache Kafka compatibility policy. Includes an expanded
  native-dependency supply-chain monitoring programme (Section 3.4.4) that incorporates the
  tracking cadence triggered by the Final Checkpoint #4 CVE scan.

---

## 3. Phase-Organized Action List

Every entry below cites a **finding ID** from [`./severity-matrix.md`](./severity-matrix.md) and
one or more absolute repository paths. Entries are grouped by the minimum engineering ceremony
required. Within each subsection, the highest-severity findings appear first.

### 3.1 Immediate — Operator Configuration (No Code Change)

Every recommendation in this subsection is actionable **today** by a cluster operator using only
the configuration surfaces that already exist in Apache Kafka 4.2.0. No patch, no KIP, and no
behavioural change to the Kafka codebase is required. The audit proposes no code changes; it only
documents configuration-posture hardening that an operator could choose to apply independently.

#### 3.1.1 [10.1] Consider enforcing TLS on every listener (High)

- **Action**: Operators could configure the broker so that every listener uses `SASL_SSL` or `SSL`
  rather than `PLAINTEXT`. The relevant keys are `listeners`, `advertised.listeners`,
  `security.inter.broker.protocol`, `controller.listener.names`, and the SSL material keys
  (`ssl.keystore.location`, `ssl.keystore.password`, `ssl.truststore.location`,
  `ssl.truststore.password`, and related). A reasonable posture sets `ssl.protocol=TLSv1.3` and
  `ssl.endpoint.identification.algorithm=https`.
- **Evidence**: Finding 10.1 references
  `clients/src/main/java/org/apache/kafka/clients/CommonClientConfigs.java` for the PLAINTEXT
  default and `clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java` for the SSL
  defaults. The absence of TLS on any listener is the exposure; there is no code defect to patch.
- **Impact**: Eliminates plaintext exposure of wire traffic, credentials, and message payloads.
  Requires coordination with client keystores and with any intermediate load balancer or service
  mesh that may currently rely on PLAINTEXT-compatible health probes.
- **Prerequisite**: Operator has provisioned TLS material for every broker and every client.
- **Change class**: Operator-config-only.

#### 3.1.2 [07.1, 10.4] Consider replacing `OAuthBearerUnsecuredValidatorCallbackHandler` in every production deployment (High)

- **Action**: Operators could set
  `listener.name.<name>.oauthbearer.sasl.server.callback.handler.class` (and the equivalent
  login-callback-handler class) to
  `org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler` backed by the
  jose4j-driven `BrokerJwtValidator`, rather than the `OAuthBearerUnsecuredValidatorCallbackHandler`
  that ships as a development convenience. A production deployment typically also configures
  `sasl.oauthbearer.jwks.endpoint.url`, `sasl.oauthbearer.expected.issuer`, and
  `sasl.oauthbearer.expected.audience`.
- **Evidence**: The Javadoc at
  `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java:L79-L80`
  itself states the class is "not suitable for production use due to the use of unsecured JWT
  tokens". Finding 07.1 cross-references the same file and its unsecured-JWS acceptance semantics.
- **Impact**: Forces every JWT used for SASL/OAUTHBEARER authentication to carry a verifiable
  signature, closing the `alg:none` acceptance vector. Requires a working OAuth/OIDC provider
  reachable from every broker and client.
- **Prerequisite**: OIDC provider issuing RS256/ES256 (or equivalent non-`none`) tokens, plus a
  network path from brokers to the provider's JWKS endpoint.
- **Change class**: Operator-config-only.

#### 3.1.3 [10.3] Consider replacing `PropertyFileLoginModule` in Connect REST Basic-Auth deployments (High)

- **Action**: Operators could substitute the Connect Basic-Auth extension's shipped
  `PropertyFileLoginModule` with a production-grade JAAS login module (for example, an
  `LdapLoginModule`, a JDBC-backed login module, or a custom module that reads from a secret
  store). The Connect worker's `rest.extension.classes` and the worker JAAS-configuration file are
  the operator-facing surfaces to adjust.
- **Evidence**: Finding 10.3 identifies the plaintext-credentials posture in
  `connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java`.
  The module is provided as a reference implementation, not a production login module.
- **Impact**: Removes the requirement to store REST-API credentials on disk in plaintext; enables
  credential rotation and centralised access management.
- **Prerequisite**: Availability of a suitable production JAAS login module within the operator's
  identity-management estate.
- **Change class**: Operator-config-only.

#### 3.1.4 [06.1] Consider placing Connect REST behind a reverse proxy that authenticates every request (High)

- **Action**: Operators could deploy an authenticating reverse proxy (for example, an API gateway
  or service mesh sidecar) in front of every Connect worker's REST listener so that **no** request
  reaches `JaasBasicAuthFilter` unauthenticated. The proxy would enforce authentication uniformly
  for every path, including the internal-request paths that `JaasBasicAuthFilter` exempts from the
  Basic-Auth check.
- **Evidence**:
  `connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/JaasBasicAuthFilter.java:L55-L58`
  defines `INTERNAL_REQUEST_MATCHERS` listing `POST /connectors/*/tasks/?` and
  `PUT /connectors/*/fence/?`; the helper method at `JaasBasicAuthFilter.java:L88-L115` uses these
  matchers to skip authentication entirely when the signed-inter-worker header is present. Finding
  06.1 documents the attack surface.
- **Impact**: Closes the class of attack where a network-adjacent actor crafts a request matching
  the internal-request pattern to bypass the Basic-Auth filter. Does not remove the bypass from the
  codebase — it simply ensures the bypass is not reachable from an untrusted network.
- **Prerequisite**: Network topology supporting a reverse proxy. Correct forwarding of mutual-TLS
  or signed headers from the proxy into the Connect worker.
- **Change class**: Operator-config-only (deployment topology).

#### 3.1.5 [10.5] Consider declaring `ssl.allow.dn.changes` and `ssl.allow.san.changes` explicitly `false` (Medium)

- **Action**: Operators could set `ssl.allow.dn.changes=false` and `ssl.allow.san.changes=false`
  explicitly in `server.properties` so that dynamic certificate reload cannot silently widen the
  accepted DN or SAN set. Although these keys default to `false`, an explicit declaration protects
  against accidental operator override and makes the posture visible in configuration review.
- **Evidence**: `clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java` exposes the
  `SSL_ALLOW_DN_CHANGES_CONFIG` and `SSL_ALLOW_SAN_CHANGES_CONFIG` keys. Finding 10.5 documents the
  loosened-pinning risk when an operator toggles either key to `true`.
- **Impact**: Guarantees that a dynamic keystore reload cannot expand the accepted identity set
  without an explicit, reviewable configuration change.
- **Prerequisite**: None.
- **Change class**: Operator-config-only.

#### 3.1.6 [03.1] Consider constraining the REPLICATION listener at the network layer (Medium)

- **Action**: Operators could rely on network-level isolation (for example, a dedicated private
  subnet or host-firewall rules) to ensure that only peer brokers and controllers can reach the
  REPLICATION listener. This compensates for the fact that the REPLICATION listener is exempted
  from the broker-wide connection cap (an intentional availability preservation for the inter-broker
  protocol).
- **Evidence**: The REPLICATION listener exemption is implemented in
  `core/src/main/scala/kafka/network/SocketServer.scala` (documented around `L1285`+; see
  [`./accepted-mitigations.md`](./accepted-mitigations.md) for the full narrative of why the
  exemption exists). Finding 03.1 documents this as a Medium-severity surface if the REPLICATION
  listener is exposed beyond the trust boundary.
- **Impact**: Prevents a misconfigured deployment from exposing the REPLICATION listener — and its
  lack of a broker-wide connection cap — to an untrusted network.
- **Prerequisite**: Ability to segment the replication network from untrusted networks.
- **Change class**: Operator-config-only (network topology).

#### 3.1.7 [09.3] Consider enabling JMX authentication and JMX SSL in production (Medium)

- **Action**: Operators could set `-Dcom.sun.management.jmxremote.authenticate=true`,
  `-Dcom.sun.management.jmxremote.ssl=true`, and the associated access and password files for every
  broker and controller JVM. Alternatively, operators could expose metrics through a dedicated
  authenticated metrics reporter plugin rather than raw JMX.
- **Evidence**: Finding 09.3 documents JMX metric exposure without authentication. The JMX surface
  itself is managed by the JVM; Kafka's `JmxReporter`
  (`clients/src/main/java/org/apache/kafka/common/metrics/JmxReporter.java`) relies on the JVM's
  JMX configuration.
- **Impact**: Prevents unauthenticated metric exfiltration and unauthenticated MBean invocation.
- **Prerequisite**: JMX credential distribution to monitoring systems.
- **Change class**: Operator-config-only (JVM flags).

---


### 3.2 Short-Term — Documentation-Only (1-3 months)

Every recommendation in this subsection could be addressed by **operator-facing documentation
improvements alone**; no Kafka source file, build file, test file, or configuration schema needs
to change. These items surface operational gaps where the current documentation does not emphasise
a security-relevant posture that the code already supports.

#### 3.2.1 [06.1] Consider documenting the `INTERNAL_REQUEST_MATCHERS` bypass in the Connect security guide (High)

- **Action**: Documentation maintainers could add a dedicated advisory section to the Connect
  security documentation (under `docs/connect.html`) that describes the internal-request bypass
  pathway, enumerates the paths it exempts (`POST /connectors/*/tasks/?` and
  `PUT /connectors/*/fence/?`), and recommends a reverse-proxy deployment pattern to neutralise
  the bypass in production.
- **Evidence**: The bypass is implemented in
  `connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/JaasBasicAuthFilter.java:L55-L58`
  (matcher definition) and `JaasBasicAuthFilter.java:L88-L115` (helper bypass logic). Finding 06.1
  references both.
- **Impact**: Removes the information asymmetry in which operators may deploy Connect
  behind-the-firewall without understanding that the Basic-Auth filter does not protect the two
  listed paths.
- **Prerequisite**: None.
- **Change class**: Documentation-only.

#### 3.2.2 [08.4] Consider publishing a JWT-validator dual-architecture operator advisory (Low, Accepted-Mitigation-Adjacent)

- **Action**: Documentation maintainers could publish an operator-facing advisory distinguishing
  the two JWT validators that ship with Kafka: `BrokerJwtValidator` (jose4j-backed, enforces
  `DISALLOW_NONE`, appropriate for brokers) versus `ClientJwtValidator` (structural-only parsing,
  appropriate for clients that trust their token issuer through a separate channel such as mutual
  TLS to the token provider). The advisory could also mention the deprecated
  `OAuthBearerUnsecuredValidatorCallbackHandler` and reiterate that it is for development only.
- **Evidence**: `BrokerJwtValidator.java:L52,L131` (referenced in
  [`./accepted-mitigations.md`](./accepted-mitigations.md)) implements the `DISALLOW_NONE`
  enforcement; `ClientJwtValidator` performs structural parsing only. Finding 08.4 documents the
  asymmetry as an accepted architectural choice — not a defect — but notes that operators may
  choose the wrong validator if the distinction is not documented.
- **Impact**: Prevents operators from accidentally wiring the client-side validator on a broker or
  vice versa.
- **Prerequisite**: None.
- **Change class**: Documentation-only.

#### 3.2.3 [09.1] Consider documenting the redaction-marker inconsistency for log-parsing integrators (Low)

- **Action**: Documentation maintainers could publish a canonical list of redaction markers that
  Kafka emits into logs and configuration snapshots. Three distinct markers are present today:
  `[hidden]` in `clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L24`,
  `(redacted)` in `metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java`,
  and `[redacted]` in `metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java`.
  A SIEM or log-parser integrator needs to match all three.
- **Evidence**: Finding 09.1 enumerates the three markers and cross-references the source files.
- **Impact**: Prevents log-parsing pipelines from missing a redaction marker and surfacing a
  secret into a downstream index. Does not require any code change — the markers remain as they
  are for backward compatibility with existing log consumers.
- **Prerequisite**: None.
- **Change class**: Documentation-only.

#### 3.2.4 [10.*] Consider publishing a consolidated "Insecure-by-Default Watchlist" (High / Medium)

- **Action**: Documentation maintainers could publish a single operator-facing matrix listing
  every configuration key whose default value is oriented toward developer convenience rather than
  production security posture. The Category 10 findings already enumerate the surface: PLAINTEXT
  listener (10.1), GSSAPI-only default SASL (10.2), `PropertyFileLoginModule` (10.3),
  `OAuthBearerUnsecuredValidatorCallbackHandler` (10.4), `ssl.allow.dn.changes` and
  `ssl.allow.san.changes` (10.5), and `auto.create.topics.enable` (10.9). The "accepted-mitigation"
  counterparts — empty `access.control.allow.origin` (10.6), `allow.everyone.if.no.acl.found=false`
  (10.7), `unclean.leader.election.enable=false` (10.8) — could be listed in the same matrix to
  reassure operators that these defaults need no change.
- **Evidence**: All of the above keys are referenced in Category 10 findings and in
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- **Impact**: Removes the need for an operator to synthesise this matrix from multiple separate
  Javadoc pages; reduces the time-to-first-production-hardening for new deployments.
- **Prerequisite**: None.
- **Change class**: Documentation-only.

#### 3.2.5 [06.2, 07.3] Consider documenting the `RestClient` outbound-Authorization forwarding behaviour (Medium)

- **Action**: Documentation maintainers could add an advisory about the Connect worker's
  `RestClient` forwarding behaviour: when one Connect worker proxies a REST call to another worker,
  the inbound request's `Authorization` header is re-used as the outbound request's
  `Authorization` header. Operators could be advised that the forwarding is by design (so that
  Basic-Auth credentials survive leader-follower redirection) and that the forwarding target
  needs to remain a trusted Connect worker URL under all operational conditions.
- **Evidence**: Finding 06.2 and 07.3 reference
  `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestClient.java`.
- **Impact**: Prevents operators from configuring a non-worker URL as a redirect target for
  cluster-internal Connect traffic.
- **Prerequisite**: None.
- **Change class**: Documentation-only.

#### 3.2.6 [02.*] Consider publishing a native-dependency supply-chain advisory cadence (Low — excluding 02.3 which is tracked in 3.2.7)

- **Action**: Documentation maintainers (or the release-management team, where the boundary is
  appropriate) could publish a cadence for reviewing upstream advisories on the five native
  libraries that Kafka depends on: `com.github.luben:zstd-jni` 1.5.6-10, `org.xerial.snappy:snappy-java`
  1.1.10.7, `org.lz4:lz4-java` 1.8.0, `org.rocksdb:rocksdbjni` 10.1.3, and
  `org.bouncycastle:bcpkix-jdk18on` 1.80 (versions from `gradle/dependencies.gradle`). Any upstream
  CVE in these libraries has direct blast-radius implications for Kafka deployments. Note that
  `org.lz4:lz4-java` 1.8.0 (Finding 02.3) is the subject of a distinct, time-sensitive advisory in
  Section 3.2.7 because CVE-2025-12183 (CVSS 8.8, CWE-125 out-of-bounds read on
  `LZ4Factory.unsafeInstance()` / `fastestInstance()` / `fastestJavaInstance()` paths) and
  CVE-2025-66566 (CVSS 8.2, CWE-201 information leak through insufficient output-buffer clearing
  in `safeInstance()`) are active upstream CVEs at the pinned version and because upstream
  coordinate `org.lz4:lz4-java` has itself been archived. For the other four native libraries,
  this cadence sets the long-running monitoring baseline that a future `org.lz4:lz4-java`-style
  event could re-enter.
- **Evidence**: Findings 02.1 through 02.5 enumerate each native dependency and the JNI boundary.
  [`./dependency-inventory.md`](./dependency-inventory.md) lists the exact pinned versions with
  a CVE Snapshot column. [`./cve-snapshot.md`](./cve-snapshot.md) consolidates the per-CVE
  references for the lz4-java exception case.
- **Impact**: Provides operators an explicit expectation of how quickly an upstream native-library
  CVE would be reflected in a Kafka patch release.
- **Prerequisite**: None.
- **Change class**: Documentation-only.

#### 3.2.7 [02.3, 06.6] Consider publishing a time-sensitive supply-chain CVE advisory for lz4-java and Jetty (Critical / High)

- **Action**: Documentation maintainers (or the release-management team, where the boundary is
  appropriate) could publish a time-sensitive advisory that surfaces the three active upstream
  CVEs identified during QA Final Checkpoint #4 and already consolidated in
  [`./cve-snapshot.md`](./cve-snapshot.md):
  - **CVE-2025-12183** (`org.lz4:lz4-java` 1.8.0, CVSS 8.8 / High, CWE-125 out-of-bounds read) —
    reachable through the default `LZ4Factory.unsafeInstance()`, `fastestInstance()`, and
    `fastestJavaInstance()` code paths that Kafka's compression codec invokes whenever a
    producer, broker, or consumer sets `compression.type=lz4`.
  - **CVE-2025-66566** (`org.lz4:lz4-java` 1.8.0, CVSS 8.2 / High, CWE-201 information leak) —
    insufficient output-buffer clearing in `safeInstance()` may expose stale heap bytes. Reachable
    through the same default compression code path as CVE-2025-12183.
  - **CVE-2026-1605** (`org.eclipse.jetty:jetty-server` 12.0.22, CVSS 7.5 / High) — `GzipHandler`
    / `GzipRequest` native-memory leak through unbounded `Inflater` allocation when the Connect
    REST HTTP layer receives requests with `Content-Encoding: gzip`. The Connect REST HTTP
    listener (backed by `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServer.java`)
    is the exposed surface.
- **Action detail**: The advisory could enumerate three things: (a) that Kafka's compression
  codec path (`clients/src/main/java/org/apache/kafka/common/compress/Lz4Compression.java` and the
  `DefaultRecordBatch` decompression path) invokes the `org.lz4:lz4-java` entry points that the
  two lz4 CVEs affect; (b) that the upstream coordinate `org.lz4:lz4-java` has been archived and
  that a maintained successor fork (referenced in [`./dependency-inventory.md`](./dependency-inventory.md)
  and [`./cve-snapshot.md`](./cve-snapshot.md)) is the path a future KIP may evaluate; (c) that
  the Jetty advisory is remediated by upstream releases 12.0.34 and 12.1.8 (or later within each
  branch) and that an operator-facing reverse-proxy configuration may filter `Content-Encoding:
  gzip` on inbound Connect REST traffic as an interim mitigation.
- **Evidence**: [`./cve-snapshot.md`](./cve-snapshot.md) consolidates the per-CVE references,
  CVSS vectors, reachability rationale, and upstream fix-version citations.
  [`./dependency-inventory.md`](./dependency-inventory.md) carries the CVE Snapshot column for
  every pinned dependency. `gradle/dependencies.gradle` pins `lz4: "1.8.0"` (line 110) and
  `jetty: "12.0.22"` (line 69); the audit applies no change to either line.
- **Impact**: Makes the time-sensitive upstream CVE posture operationally legible to Kafka
  operators who are subscribed to the audit deliverables but who may not be subscribed to every
  upstream advisory feed directly.
- **Prerequisite**: None — this action could be performed by documentation maintainers without
  engineering involvement and without any code, build-file, or configuration schema change.
- **Change class**: Documentation-only. The audit itself proposes **no** code or dependency-version
  change; the advisory is purely an operator-facing document that consolidates information that
  already exists in upstream CVE feeds.

---

### 3.3 Medium-Term — Non-Breaking Code Changes (KIP Required, 3-6 months)

Every recommendation in this subsection would require a **Kafka Improvement Proposal (KIP)** and a
code change, but none would remove or rename any public API surface. The audit does **not** apply
any of these changes; each item requires community review, vote, and release-cycle planning.

#### 3.3.1 [08.3] Consider converting `SafeObjectInputStream` from suffix-matching blocklist to explicit allow-list

- **Action**: A KIP could propose replacing the blocklist-by-`endsWith` semantics in
  `SafeObjectInputStream` with an explicit **allow-list** of the canonical class names that
  Connect's internal serialized-state flows actually require. The allow-list would be closed to
  extension (so that a future attacker-controlled class name outside the list cannot be resolved),
  and the current blocklist would be retained only as a defence-in-depth secondary check.
- **Evidence**: The blocklist is defined at
  `connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L27-L37`
  (nine entries). The suffix-matching helper is at `SafeObjectInputStream.java:L54-L62`; the
  `resolveClass` override at `SafeObjectInputStream.java:L43-L52` delegates to it. Finding 08.3
  notes that suffix-matching can be circumvented by any class name whose simple name does not
  match an entry on the list, and that a blocklist approach places the security burden on future
  maintainers rather than on the design.
- **Impact**: Eliminates the entire class of bypass that depends on the attacker controlling the
  simple-name suffix of a gadget class. Minor implementation complexity increase.
- **Prerequisite**: KIP approval; full inventory of class names that Connect legitimately
  deserializes through this code path.
- **Change class**: Non-breaking code change (KIP).

#### 3.3.2 [06.4] Consider refactoring `release/release.py` to avoid `shell=True` with f-string interpolation

- **Action**: An engineering review (formal KIP may not be required because the release script
  is internal tooling, not a public API) could propose refactoring the
  `cmd(..., shell=True)` invocations at `release/release.py:L334-L362` so that each external
  command is invoked with a **list argv** (`subprocess.run(["./gradlew", "publish", ...])`) rather
  than a shell-interpolated string. Arguments that are currently interpolated via f-string —
  artifact file names, version strings, GPG key fingerprints — would be passed as discrete argv
  entries, eliminating the shell-metacharacter attack surface.
- **Evidence**: `release/release.py` invokes `shell=True` with f-string-interpolated arguments at
  L334, L335, L350, L351, L352, L361, and L362. Finding 06.4 documents the surface. The risk is
  bounded to the release engineer's privilege context (the script runs only during release
  cutting, not on brokers), so this is a Medium-severity item rather than High.
- **Impact**: Eliminates the class of command-injection vulnerability that would require an
  attacker to influence a release-input filename or version string. Makes the release tooling
  robust to filenames that contain shell metacharacters (spaces, quotes, backticks).
- **Prerequisite**: Engineering review of the release process; coordination with the release
  management team.
- **Change class**: Non-breaking code change (internal tooling; KIP optional).

#### 3.3.3 [05.1] Consider narrowing the four `Pattern.compile` sites in `KerberosRule`

- **Action**: A KIP could propose either narrower regular expressions or an alternative
  non-backtracking parser for the four regex sites in
  `clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosRule.java`. The simplest
  variant keeps the current regex contract for operator-facing rule syntax but bounds the match
  time with an `InterruptibleCharSequence` wrapper or by delegating to a non-backtracking engine
  such as `re2j`.
- **Evidence**: Finding 05.1 enumerates the four `Pattern.compile` sites in `KerberosRule`, where
  operator-supplied principal-to-local-name rules are compiled. A malicious principal-to-local-name
  rule combined with a hostile principal could cause catastrophic backtracking in the regex engine.
  `KerberosName.java` and `KerberosShortNamer.java` have additional pattern compilation sites.
- **Impact**: Closes a ReDoS surface whose worst-case would degrade authentication throughput on
  affected brokers.
- **Prerequisite**: KIP approval; regression-test coverage for existing principal-to-local-name
  rules.
- **Change class**: Non-breaking code change (KIP).

#### 3.3.4 [04.*] Consider tightening Connect plugin isolation defaults

- **Action**: A KIP could propose a configuration key that restricts
  `DelegatingClassLoader`/`PluginClassLoader` to a signed-plugin mode (for example, requiring every
  plugin JAR to carry a signature that chains to a trust anchor configured on the Connect worker).
  The key would default to permissive for backward compatibility and be opt-in for operators
  wanting stronger plugin supply-chain guarantees.
- **Evidence**: Finding 04.2 references
  `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java`
  and `PluginClassLoader.java`. The `ServiceLoader` discovery surface is broad and any JAR on the
  `plugin.path` is trusted for reflective instantiation.
- **Impact**: Raises the bar for a supply-chain attack to include either signing-key compromise
  or a worker misconfiguration; does not alter the default behaviour.
- **Prerequisite**: KIP approval; design review of the signing mechanism.
- **Change class**: Non-breaking code change (KIP); default preserves backward compatibility.

#### 3.3.5 [04.1] Consider extending ServiceLoader-driven `ConnectRestExtension` discovery with an explicit allow-list

- **Action**: A KIP could propose a new configuration key
  (`rest.extension.classes.allowed` or similar) that restricts which `ConnectRestExtension`
  implementations are accepted from the `ServiceLoader` scan. Today any class on the worker's
  classpath implementing `ConnectRestExtension` is eligible for activation if declared in
  `rest.extension.classes`.
- **Evidence**: Finding 04.1 references
  `connect/runtime/src/main/java/org/apache/kafka/connect/rest/ConnectRestExtension.java` and the
  `ServiceLoader` discovery site in the Connect runtime. The current contract relies on the
  operator trusting every JAR on the worker classpath.
- **Impact**: Adds a second line of defence against an unexpected extension being activated via a
  crafted JAR. Default preserves current behaviour.
- **Prerequisite**: KIP approval; design review of the allow-list semantics.
- **Change class**: Non-breaking code change (KIP).

#### 3.3.6 [08.1, 08.2] Consider reviewing the Jackson feature flags in `JsonDeserializer` and Trogdor `JsonUtil`

- **Action**: A KIP could propose reviewing — and potentially reverting — the two non-default
  Jackson feature flags currently enabled in the codebase:
  `ALLOW_LEADING_ZEROS_FOR_NUMBERS.mappedFeature()` at
  `connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L57`, and
  `ACCEPT_SINGLE_VALUE_AS_ARRAY` at
  `trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L39`. The review could
  document the historical rationale for each flag and evaluate whether contemporary use justifies
  the permissiveness.
- **Evidence**: Findings 08.1 and 08.2 reference the exact file-line locations.
- **Impact**: Potential elimination of two parser-permissiveness flags that have been linked to
  JSON-parser-differential vulnerabilities in other codebases. Trogdor is a test-harness
  (`trogdor/`) rather than a broker component, so the `JsonUtil` flag has a bounded blast radius.
- **Prerequisite**: KIP approval (for Connect) or engineering review (for Trogdor); regression
  testing against existing Connect and Trogdor workloads.
- **Change class**: Non-breaking code change (KIP for Connect; engineering review for Trogdor).

---


### 3.4 Long-Term — Architectural or Breaking Changes (KIP + Deprecation Cycle, 6+ months)

Every recommendation in this subsection would be **architectural** or **breaking**: it would
require a KIP, a deprecation cycle per the Apache Kafka compatibility policy, and potentially a
major-version release boundary. The audit applies none of these; each item is presented as a
candidate for future strategic planning.

#### 3.4.1 [09.1] Consider consolidating redaction markers to a single canonical token

- **Action**: A KIP could propose consolidating the three redaction markers currently emitted by
  different subsystems (`[hidden]`, `(redacted)`, `[redacted]`) to a single canonical token
  (for example, `[REDACTED]`). Because log-parsing integrators may already rely on the existing
  markers, the consolidation would require a deprecation cycle during which both the legacy and
  the canonical markers are emitted, followed by a removal of the legacy markers in a subsequent
  major release.
- **Evidence**: Finding 09.1 enumerates the three markers:
  `clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L24` (`[hidden]`),
  `metadata/src/main/java/org/apache/kafka/metadata/util/RecordRedactor.java` (`(redacted)`), and
  `metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java` (`[redacted]`).
- **Impact**: Simplifies SIEM and log-forwarding integration; reduces the cognitive overhead of
  verifying that every sensitive value has been masked. Risk: breaks existing log-parsing
  pipelines that match on the legacy markers.
- **Prerequisite**: KIP approval; deprecation plan; coordination with downstream observability
  ecosystems.
- **Change class**: Breaking / architectural (KIP + deprecation).

#### 3.4.2 [04.*] Consider consolidating the pluggable-SPI security posture across modules

- **Action**: A KIP could propose a cross-module design that standardises `ServiceLoader`
  plugin vetting across every extension point: Connect REST extensions (`ConnectRestExtension`),
  Connect plugins (`Converter`, `Transformation`, `Predicate`, `Connector`), MirrorMaker 2's
  `FORWARDING_ADMIN_CLASS`, the Tiered Storage `RemoteStorageManager` and
  `RemoteLogMetadataManager`, metrics reporters, and the OAuth `JwtValidator`/`JwtRetriever`
  SPIs. The standardised contract could include signature verification, classpath whitelist
  enforcement, and a deny-list for Kafka-internal classes that must never be instantiated
  reflectively.
- **Evidence**: Findings 04.1 through 04.6 enumerate six distinct `ServiceLoader`-backed
  extension surfaces. Each currently implements its own discovery semantics; a common framework
  would reduce the surface through which a supply-chain compromise propagates.
- **Impact**: Unifies the supply-chain security posture of every Kafka extension point.
  Risk: significant implementation and coordination effort across module teams.
- **Prerequisite**: KIP approval; cross-module design review; compatibility analysis for every
  affected extension point.
- **Change class**: Architectural (KIP + deprecation).

#### 3.4.3 [05.*] Consider introducing a process-wide ReDoS-resistant regex facility

- **Action**: A KIP could propose a Kafka-internal wrapper around `java.util.regex` (or a
  migration to `re2j`) that provides time-bounded matching across every regex hot-path in the
  codebase. The wrapper could default to a configurable timeout (for example, 100 ms) and throw
  a dedicated `RegexTimeoutException` that is translated to an operator-facing error. Migration
  would cover the ten `Pattern.compile` sites enumerated in Finding 05: `KerberosRule` (four
  sites), `KerberosName`, `KerberosShortNamer`, `JmxReporter` (two sites), `ConfigDef`,
  `ConfigTransformer`, `EnvVarConfigProvider`, `ServerConnectionId`, `ApiVersionsRequest`, and
  `OAuthBearerClientInitialResponse`.
- **Evidence**: Findings 05.1 through 05.5 inventory every non-test `Pattern.compile` call
  site. `java.util.regex.Matcher` natively provides no timeout; catastrophic-backtracking DoS
  can be mitigated only through input sanitisation, engine replacement, or an external timeout
  wrapper.
- **Impact**: Eliminates the ReDoS surface class. Risk: regex engines differ in feature
  support (for example, `re2j` does not support backreferences), so the migration may require
  code changes at sites that rely on unsupported features.
- **Prerequisite**: KIP approval; benchmark-driven validation that the selected engine or
  wrapper preserves existing latency profiles.
- **Change class**: Architectural (KIP).

#### 3.4.4 [02.*, 06.6] Consider a native-dependency and web-transport supply-chain monitoring programme

- **Action**: The release-management team could establish an **ongoing** native-dependency and
  web-transport supply-chain monitoring programme that tracks upstream advisories for
  `zstd-jni`, `snappy-java`, `lz4-java`, `rocksdbjni`, `bcpkix-jdk18on`, and the Jetty web
  server family (`jetty-server`, `jetty-client`, `jetty-ee10-servlet`, `jetty-ee10-servlets`)
  and that maintains a documented response SLA when an advisory touches a Kafka-bundled
  version. The existing OWASP Dependency-Check and Trivy configurations in the Kafka CI
  provide the data feed; the programme would add the process layer on top. The Final
  Checkpoint #4 advisory scan (consolidated in [`./cve-snapshot.md`](./cve-snapshot.md))
  surfaced three active CVEs that this programme could consider as its inaugural test case:
  CVE-2025-12183 and CVE-2025-66566 against `org.lz4:lz4-java` 1.8.0, and CVE-2026-1605 against
  `org.eclipse.jetty:jetty-server` 12.0.22. The programme could evaluate whether a future
  Kafka release may consider bumping Jetty to 12.0.34+ or 12.1.8+ (upstream fix versions) and
  whether a future KIP may evaluate migrating the lz4 coordinate to a maintained successor
  fork (since the upstream `org.lz4:lz4-java` coordinate has been archived).
- **Evidence**: `gradle/dependencies.gradle` pins each native library at an exact version
  (see [`./dependency-inventory.md`](./dependency-inventory.md), which now includes a CVE
  Snapshot column for every pinned dependency). Findings 02.1 through 02.5 and 06.6
  establish the blast-radius calculus for each JNI boundary and for the Connect REST web
  transport respectively. [`./cve-snapshot.md`](./cve-snapshot.md) consolidates the per-CVE
  citations for the three time-sensitive findings.
- **Impact**: Provides operators with a predictable expectation of how quickly an upstream
  native-library or web-transport CVE would be reflected in a Kafka patch release. Reduces
  the window during which a known-vulnerable library is bundled.
- **Prerequisite**: Buy-in from the release-management team; a communications channel for
  advisories to reach downstream operators.
- **Change class**: Process change (no code change required in the base case).

#### 3.4.5 [06.1] Consider narrowing or removing the `INTERNAL_REQUEST_MATCHERS` bypass entirely

- **Action**: A KIP could propose redesigning Connect's inter-worker task-distribution RPC
  path so that it does not rely on an auth-bypass matcher at the HTTP-filter layer. Candidate
  redesigns include: (a) gating the internal-request paths behind a separate worker-only
  listener with mutual TLS and no Basic-Auth filter; (b) replacing the HTTP filter's bypass
  with a cryptographic signature check performed before authorization; (c) moving the
  task-distribution RPC off HTTP entirely and onto an authenticated Kafka-native RPC channel.
- **Evidence**: The bypass is implemented at
  `connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/JaasBasicAuthFilter.java:L55-L58`
  with the helper at `JaasBasicAuthFilter.java:L88-L115`. Finding 06.1 rates this High because
  the bypass is reachable at the HTTP layer and because Connect deployments often place the
  REST listener on a routable network.
- **Impact**: Removes the highest-severity item in Category 06 at its root, rather than
  compensating for it at the deployment layer. Risk: breaks any downstream tooling that relies
  on the current inter-worker HTTP contract.
- **Prerequisite**: KIP approval; design review of the inter-worker RPC path.
- **Change class**: Architectural (KIP + deprecation).

#### 3.4.6 [10.4, 07.1] Consider deprecating `OAuthBearerUnsecuredValidatorCallbackHandler` for removal

- **Action**: A KIP could propose marking
  `OAuthBearerUnsecuredValidatorCallbackHandler` with a deprecation annotation and a scheduled
  removal in a future major release. During the deprecation window, the callback handler could
  log a `WARN` message on every invocation indicating that it is a development-only class and
  must not be used in production, and it could refuse to start unless the operator explicitly
  acknowledges the unsecured posture via a configuration key.
- **Evidence**: The Javadoc at
  `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java:L79-L80`
  itself states the class is "not suitable for production use". The class is the only remaining
  surface that accepts JWTs with `alg:none`. Findings 07.1 and 10.4 both reference it.
- **Impact**: Eliminates the `alg:none` acceptance vector at its root in a future major
  release. Risk: breaks development workflows that currently rely on the unsecured handler.
- **Prerequisite**: KIP approval; deprecation plan; documentation of migration paths for
  existing development workflows.
- **Change class**: Breaking / architectural (KIP + deprecation).

---

## 4. Non-Remediation Items — Accepted-Mitigation Reinforcement

The items below are **already mitigated** by existing code in the Kafka 4.2.0 snapshot. They
require **no remediation**. The audit surfaces them here so that future maintenance work does
not inadvertently regress a protection that the code currently provides. Every item is
cross-referenced in the full catalogue at [`./accepted-mitigations.md`](./accepted-mitigations.md).

- **Constant-time HMAC comparison in `DelegationToken`** — the equality check uses
  `java.security.MessageDigest.isEqual` rather than `Object.equals`, preventing a timing-side-channel
  recovery of the HMAC. Source:
  `clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java:L19,L60`.
  Regression risk: a future refactor that replaces the method call with a string `equals`
  comparison.

- **`DISALLOW_NONE` JWS enforcement in `BrokerJwtValidator`** — the jose4j-backed broker-side
  JWT validator explicitly rejects tokens whose algorithm header is `none`. Source:
  `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L52,L131`.
  Regression risk: a future change that relaxes the algorithm constraint.

- **REPLICATION listener exempt from broker-wide connection cap** — the inter-broker RPC path
  is protected from connection-count exhaustion induced by a burst of client connections on
  another listener. Source: `core/src/main/scala/kafka/network/SocketServer.scala:L1285+`
  (documented in [`./accepted-mitigations.md`](./accepted-mitigations.md)). Regression risk: a
  future refactor that standardises connection accounting across every listener.

- **DENY-over-ALLOW precedence in `StandardAuthorizerData`** — an explicit DENY ACE always
  overrides any ALLOW ACE for the same (principal, operation, resource) triple. Source:
  `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java:L221+`.
  Regression risk: a future refactor that flattens the precedence logic.

- **`MAX_RECORDS_PER_USER_OP` bound in `AclControlManager`** — a single ACL-operation request
  cannot produce more than the bounded number of metadata records, preventing a DoS through a
  pathologically large request. Source:
  `metadata/src/main/java/org/apache/kafka/controller/AclControlManager.java:L52,L99,L207-L209`.
  Regression risk: a future change that loosens the bound or removes the guard.

- **16 KB bounded decompression chunk in `ZstdCompression`** — the Kafka-owned `BufferSupplier`
  and `ChunkedBytesStream` ensure that zstd-jni cannot be coerced into allocating more than the
  bounded chunk at once, regardless of the compressed payload's claimed decompressed size.
  Source: `clients/src/main/java/org/apache/kafka/common/compress/ZstdCompression.java:L40-L80`.
  Regression risk: a future optimisation that raises the chunk size without reviewing the DoS
  calculus.

- **`Password.HIDDEN` masking in `toString`** — the `Password` value object redacts its
  value in `toString` so that an accidental `log.info("config = {}", config)` cannot leak the
  secret into logs. Source:
  `clients/src/main/java/org/apache/kafka/common/config/types/Password.java:L24,L56`.
  Regression risk: a future refactor that overrides `toString` with a different representation.

- **`VoterSet.hasOverlappingMajority` safety guard during KRaft reconfiguration** — a voter-set
  change is accepted only if the new voter set shares a majority with the old voter set,
  preventing a split-brain induced by a single mis-step during reconfiguration. Source:
  `raft/src/main/java/org/apache/kafka/raft/VoterSet.java`. Regression risk: a future refactor
  that bypasses the overlap check.

- **`allowed.paths` allow-list in `DirectoryConfigProvider`** — the directory-based
  configuration provider rejects paths outside the configured allow-list. Source:
  `clients/src/main/java/org/apache/kafka/common/config/provider/DirectoryConfigProvider.java:L47-L54`.
  Regression risk: a future change that widens the default or disables the guard.

- **`allowlist.pattern` in `EnvVarConfigProvider`** — environment-variable reads are filtered
  against an operator-supplied regex allow-list. Source:
  `clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java:L42-L62`.
  Regression risk: a future change that widens the default pattern.

- **Empty default for `access.control.allow.origin` in Connect REST** — the Connect REST
  server's CORS handler rejects every cross-origin request by default, requiring explicit
  operator opt-in. Source:
  `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java:L70,L76`.
  Regression risk: a future refactor that adopts a permissive CORS default.

- **Copy-on-write `AclCache`** — the KRaft ACL cache is immutable; a write produces a new
  cache instance atomically, eliminating a class of race conditions in authorization decisions.
  Source: `metadata/src/main/java/org/apache/kafka/metadata/authorizer/AclCache.java`. Regression
  risk: a future refactor that introduces a mutable cache for "performance".

- **`DelegationToken.toString` masks the HMAC placeholder** — the `toString` representation
  replaces the HMAC with a fixed placeholder so that the token cannot be reconstructed from a
  log line. Source:
  `clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java`.
  Regression risk: a future refactor that exposes the HMAC field in `toString`.

The full catalogue of 19 accepted mitigations — with threat / mechanism / effectiveness /
regression-risk narrative for each — lives in
[`./accepted-mitigations.md`](./accepted-mitigations.md). Every item in that catalogue
represents an **existing** protection whose removal would regress the security posture of the
codebase. No code changes are proposed for any of these items.

---


## 5. Remediation Prioritization Matrix

The quadrant chart below plots each recommendation on two axes: **severity** (vertical, from the
severity assigned in [`./severity-matrix.md`](./severity-matrix.md)) against **implementation
cost** (horizontal, representing the engineering ceremony required: operator configuration is low,
a KIP + deprecation cycle is high). The chart is intended as a prioritization aid for engineering
leads; it does not commit any party to act on any item.

```mermaid
%%{init: {'theme':'neutral'}}%%
quadrantChart
    title Remediation Prioritization - Severity vs Implementation Cost
    x-axis Low Cost --> High Cost
    y-axis Low Severity --> High Severity
    quadrant-1 Address via KIP
    quadrant-2 Quick wins
    quadrant-3 Defer
    quadrant-4 Strategic initiatives
    Connect REST bypass (06.1): [0.2, 0.85]
    OAuthBearerUnsecured (07.1): [0.15, 0.8]
    PropertyFileLoginModule (10.3): [0.2, 0.8]
    PLAINTEXT default (10.1): [0.3, 0.8]
    ReDoS timeout (05.*): [0.7, 0.45]
    SafeObjectInputStream allow-list (08.3): [0.5, 0.55]
    Redaction marker unify (09.1): [0.6, 0.2]
    release.py shell=True (06.4): [0.4, 0.4]
```

### 5.1 Quadrant Legend

| Quadrant             | X-axis (cost)  | Y-axis (severity) | Recommended disposition                                                                   |
|----------------------|----------------|-------------------|-------------------------------------------------------------------------------------------|
| **Quick wins**       | Low cost       | High severity     | Apply through operator configuration today; no KIP required. Covered by Section 3.1.      |
| **Address via KIP**  | Low-ish cost   | Lower severity    | Defer to a standard KIP cycle; typically documentation or minor code changes.             |
| **Strategic**        | High cost      | High severity     | Warrant KIP-scale planning plus a deprecation cycle. Covered by Section 3.4.              |
| **Defer**            | High cost      | Low severity      | Tracked for completeness; no immediate action proposed. Covered by Section 3.4 or beyond. |

### 5.2 Quadrant Reading Notes

- The **Quick wins** quadrant is where the four configuration-only recommendations for five
  of the six High-severity findings land (06.1, 07.1, 10.1, 10.3, 10.4). The sixth
  High-severity finding (06.6 — Jetty `GzipHandler` CVE-2026-1605) and the single
  `[Critical]` finding (02.3 — `org.lz4:lz4-java` CVE-2025-12183 / CVE-2025-66566) are
  surfaced through the short-term supply-chain advisory in Section 3.2.7 rather than through
  an operator configuration change, because their remediation requires an upstream
  dependency-version bump (or a maintained-fork migration in the lz4 case) rather than a
  configuration toggle. Operators who read only one section of this roadmap could usefully
  limit themselves to this quadrant and Section 3.1, with Section 3.2.7 as a mandatory
  follow-on for the supply-chain pair.
- The **Strategic** quadrant contains items that would rewrite architectural assumptions (for
  example, the inter-worker Connect RPC redesign in 3.4.5, or the process-wide ReDoS-resistant
  regex facility in 3.4.3).
- The `ReDoS timeout (05.*)` item is plotted in the "Address via KIP" quadrant rather than
  "Strategic" because a sufficiently narrow wrapper around `java.util.regex.Matcher` is a
  bounded engineering effort; however, migrating to a non-backtracking engine would push the
  item fully into the "Strategic" quadrant.
- The `release.py shell=True` item sits near the boundary because while the code change is
  bounded to a single internal script, the release-management coordination required elevates
  the practical cost above zero.

---

## 6. Reviewer Checklist

The checklist below is intended for an engineering-lead reviewer who is considering adoption of
any item in this roadmap. Each box is a question the reviewer could answer before formally
proposing, accepting, or deferring a recommendation. Ticking a box on this checklist does not
apply any change — the audit remains strictly static — but it does create a traceable record of
the decision process.

- [ ] Confirm the severity rating for each item against the organisation's risk appetite. The
      severity tags in this roadmap derive from [`./severity-matrix.md`](./severity-matrix.md);
      an organisation with a different risk tolerance may up-rate or down-rate specific items.
- [ ] Identify a KIP author and co-authors for every item in Sections 3.3 and 3.4. Without a
      named author, a KIP cannot be filed with the Apache Kafka community.
- [ ] Verify that no item overlaps with a KIP already in flight. The canonical record is the
      Apache Kafka KIP wiki; reviewers could search for "OAuth", "Connect REST", "ACL", "ReDoS",
      or "Pluggable" before proposing a new KIP in any of these areas.
- [ ] Schedule the Section 3.1 operator-hardening items into the next operational review cycle
      for every cluster the reviewer operates. No KIP or code change is required; these items
      can be folded into the next configuration-review pass.
- [ ] Confirm that the existing CI supply-chain-monitoring pipelines (OWASP Dependency-Check,
      Trivy) are active on every Kafka branch the reviewer maintains, and that the response
      channel for an upstream native-library CVE is documented.
- [ ] Verify that `docs/security-audit/no-change-verification.md` reports a clean differential
      for the Kafka source tree before taking any action on this roadmap. If that file reports
      unexpected modifications, the audit's "Audit Only" posture has been violated and the
      roadmap should not be used as a basis for action.
- [ ] For every Section 3.4 architectural item, verify that the reviewer has the mandate to
      propose a deprecation cycle. Items in Section 3.4 are breaking by design; proposing them
      without mandate will generate friction that does not benefit the codebase.

---

## 7. Cross-References

- [`./README.md`](./README.md) — audit scope, methodology, and top-level navigation.
- [`./severity-matrix.md`](./severity-matrix.md) — canonical enumeration of every finding ID
  referenced in this roadmap, with severity tags and business-impact narrative.
- [`./accepted-mitigations.md`](./accepted-mitigations.md) — full catalogue of 19 existing
  protections in the Kafka 4.2.0 snapshot, plus regression-risk narrative for each. Section 4
  of this roadmap is a distilled summary of that catalogue.
- [`./dependency-inventory.md`](./dependency-inventory.md) — canonical version manifest for
  the runtime-affecting dependencies referenced throughout this roadmap (Jackson 2.19.0,
  Jose4j 0.9.6, Jetty 12.0.22, zstd-jni 1.5.6-10, snappy-java 1.1.10.7, lz4-java 1.8.0,
  rocksdbjni 10.1.3, bcpkix-jdk18on 1.80, and others). Carries a CVE Snapshot column with
  per-dependency references to `./cve-snapshot.md` for every finding surfaced during QA
  Final Checkpoint #4.
- [`./cve-snapshot.md`](./cve-snapshot.md) — consolidated hub document for the three
  time-sensitive upstream CVEs identified during QA Final Checkpoint #4: **CVE-2025-12183**
  (`org.lz4:lz4-java` 1.8.0, CVSS 8.8, CWE-125 out-of-bounds read), **CVE-2025-66566**
  (`org.lz4:lz4-java` 1.8.0, CVSS 8.2, CWE-201 information leak), and **CVE-2026-1605**
  (`org.eclipse.jetty:jetty-server` 12.0.22, CVSS 7.5, `GzipHandler` / `GzipRequest`
  native-memory leak). Directly referenced by Section 3.2.7 (short-term advisory) and
  Section 3.4.4 (long-term supply-chain monitoring programme) of this roadmap.
- [`./no-change-verification.md`](./no-change-verification.md) — git-differential evidence
  that no source code, test, build file, or pre-existing documentation file was modified
  during the audit. Reviewers MUST verify this file before acting on any item in this
  roadmap.
- [`./references.md`](./references.md) — full bibliography of every repository path cited by
  the audit, organised by Kafka module.
- [`./findings/01-filesystem-access-path-traversal.md`](./findings/01-filesystem-access-path-traversal.md) — Category 01 detail.
- [`./findings/02-low-level-code-safety.md`](./findings/02-low-level-code-safety.md) — Category 02 detail.
- [`./findings/03-resource-limit-evasion.md`](./findings/03-resource-limit-evasion.md) — Category 03 detail.
- [`./findings/04-module-system-builtin-abuse.md`](./findings/04-module-system-builtin-abuse.md) — Category 04 detail.
- [`./findings/05-infinite-loop-recursion-dos.md`](./findings/05-infinite-loop-recursion-dos.md) — Category 05 detail.
- [`./findings/06-network-subprocess-access.md`](./findings/06-network-subprocess-access.md) — Category 06 detail.
- [`./findings/07-external-function-callback-misuse.md`](./findings/07-external-function-callback-misuse.md) — Category 07 detail.
- [`./findings/08-deserialization-attacks.md`](./findings/08-deserialization-attacks.md) — Category 08 detail.
- [`./findings/09-information-leakage.md`](./findings/09-information-leakage.md) — Category 09 detail.
- [`./findings/10-public-api-developer-misuse.md`](./findings/10-public-api-developer-misuse.md) — Category 10 detail.

---

## 8. Governing Rules Recap (Audit Only Posture)

This roadmap is bound by the following governing rules, restated here so that every downstream
reader understands the audit's posture without needing to consult a separate document. The
governing rule is reproduced **verbatim** from the user-supplied instruction set so that a
reviewer can compare this roadmap against the exact rule text it was built under.

### 8.1 Audit Only Rule (verbatim, user-supplied)

> "This run should serve as a dry run for potential changes, research, or documentation. DO
> NOT modify, create, or delete any existing code in the codebase. Avoid executing any code in
> the code base, this should be a static analysis. Every deliverable MUST include a markdown
> file summarizing security vulnerabilities, potential exploits, bugs in the codebase,
> perofrmace considerations, and remediation recommendations. Verify the NO CHANGES clause by
> confirming no changes to existing codebase featured in the git differential. Markdown files
> explicitly related to the analysis performed in this run are permitted."

The spelling `perofrmace` in the rule above is preserved **verbatim** from the user-supplied
rule. It is not a transcription error in this roadmap, and it must not be corrected anywhere
in the audit tree. The audit's Performance Considerations coverage (see Section 8.3 below) is
the deliverable that satisfies that clause.

### 8.2 Derived Operational Rules

1. **No code changes were applied in this audit.** Every item in this roadmap is a
   recommendation for future consideration. The audit's git differential — captured in
   [`./no-change-verification.md`](./no-change-verification.md) — shows only additions under
   `docs/security-audit/` and no modifications to any other repository path.
2. **No item in this roadmap is self-authorising.** Adoption of any recommendation requires the
   standard Apache Kafka engineering process: a KIP for code changes, a community-reviewed
   documentation pull request for documentation changes, and a coordinated operator rollout
   for configuration-only changes.
3. **The audit proposes no changes, even for the six High-severity findings.** The governing
   Audit Only rule quoted in Section 8.1 above (together with the companion "Minimal Change
   Clause") explicitly prohibits any code modification, even if necessary for remediation. The
   audit's sole product is documentation. The High-severity count now includes Finding 06.6
   (`org.eclipse.jetty:jetty-server` 12.0.22, CVE-2026-1605) alongside the previously
   enumerated 06.1, 07.1, 10.1, 10.3, and 10.4. Finding 02.3 (`org.lz4:lz4-java` 1.8.0,
   CVE-2025-12183 and CVE-2025-66566) is additionally classified `[Critical]` per
   [`./severity-matrix.md`](./severity-matrix.md) but is likewise governed by this clause —
   no dependency-version bump is applied. The advisory path for both supply-chain findings is
   documented in Section 3.2.7.
4. **Future-state language is used throughout.** Every recommendation in this roadmap is
   phrased as "consider", "may", or "could". No recommendation uses the imperative ("must",
   "will", or equivalent).
5. **Every recommendation is traceable.** Every item cites at least one finding ID from
   [`./severity-matrix.md`](./severity-matrix.md) and at least one absolute repository path so
   that a future reviewer can re-verify the underlying evidence.
6. **No code execution.** The audit performed no build, no test, no runtime benchmark, and
   no dynamic profiling against the Kafka codebase. Every observation is derived from static
   reading of the source files cited in [`./references.md`](./references.md).

### 8.3 Performance Considerations — Rule-Mandated Deliverable Topic

The Audit Only rule (Section 8.1) explicitly lists `perofrmace considerations` as one of the
topics that every deliverable must address. This roadmap satisfies that clause in two ways:

- **Per-finding coverage.** Each of the ten per-category findings files linked from Section
  7 above ([`./findings/01-...md`](./findings/01-filesystem-access-path-traversal.md) through
  [`./findings/10-...md`](./findings/10-public-api-developer-misuse.md)) carries a dedicated
  `## 8. Performance Considerations` section. That section covers hot-path signals, JMX
  metrics exposed for observability, performance trade-offs inherent in the existing
  mitigations, and future-state performance accounting for any of the recommended
  code-level changes catalogued in Section 3.3 and Section 3.4 of this roadmap. Each
  per-finding section ends with a no-code-change attestation.
- **Roadmap-level acknowledgement.** Every code-level recommendation in Sections 3.3 and
  3.4 above carries an implicit performance caveat: the hypothetical change could only be
  adopted after a KIP-driven benchmark exercise validated that the change does not regress
  throughput, latency, or resource-footprint on the relevant hot paths. The audit itself
  ran no benchmark; it only flagged the performance caveat. Example caveats include:
  - Section 3.4.3's ReDoS-resistant regex facility would require latency benchmarking of
    every migrated `Pattern.compile` call site to confirm that the replacement engine (for
    example, `re2j`) preserves the current matching latency profile.
  - Section 3.4.2's standardised `ServiceLoader` plugin-vetting framework would require
    cold-start benchmarking of every extension discovery point to confirm that signature
    verification does not materially lengthen worker startup.
  - Section 3.2.7's supply-chain advisory cadence is purely operator-process work and has
    no runtime performance cost.

Performance is therefore treated as a **first-class deliverable topic** in this audit,
alongside security vulnerabilities, potential exploits, bugs, and remediation recommendations,
exactly as the governing rule specifies.

End of roadmap.

