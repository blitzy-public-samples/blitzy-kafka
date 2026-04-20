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

# Apache Kafka Security Audit - Top-Level Navigation Index

(Audit performed against Apache Kafka 4.2.0-SNAPSHOT, pre-audit baseline commit: `6d16f687aa1a0df26f2f665436b7efaf0aec0c56`, snapshot date 2026-04-17, branch `blitzy-4bdad1ad-dc01-4556-9ef0-4c760b777d5a`. The pre-audit baseline is the Kafka `HEAD` immediately before the audit began; the "Zero modifications" attestation is meaningful only against this reference.)

## `[Audit Only]` Callout - Zero Code Changes Applied

**IMPORTANT:** This audit introduces **ZERO** modifications to the Apache Kafka 4.2.0-SNAPSHOT
codebase. No source file was edited, no inline comment was altered, no test was authored or
executed, and no build target was invoked against production code. The entire deliverable is a
set of new markdown and HTML files isolated under `docs/security-audit/`. Reviewers can verify
this by inspecting [`./no-change-verification.md`](./no-change-verification.md) or by running:

```
git diff --name-status <pre-audit-HEAD>..HEAD -- . ':(exclude)docs/security-audit/**'
```

The command output must be empty; if it is not, the **Audit Only** rule (see
[Section 3.1](#31-audit-only)) has been violated.

---

## Table of Contents

1. [Audit Scope](#1-audit-scope)
    - [1.1 Vulnerability Categories](#11-vulnerability-categories)
    - [1.2 Kafka Version and Dependency Snapshot](#12-kafka-version-and-dependency-snapshot)
2. [Methodology](#2-methodology)
    - [2.1 Static Code Reconnaissance Only](#21-static-code-reconnaissance-only)
    - [2.2 Finding Structure](#22-finding-structure)
    - [2.3 Severity Tiers](#23-severity-tiers)
3. [Governing Rules](#3-governing-rules)
    - [3.1 Audit Only](#31-audit-only)
    - [3.2 Visual Architecture Documentation](#32-visual-architecture-documentation)
    - [3.3 Executive Presentation](#33-executive-presentation)
4. [Navigation Map](#4-navigation-map)
    - [4.1 Core Documents](#41-core-documents)
    - [4.2 Findings (Per Category)](#42-findings-per-category)
    - [4.3 Diagrams (Mermaid)](#43-diagrams-mermaid)
5. [How to Read a Finding](#5-how-to-read-a-finding)
6. [Terminology](#6-terminology)
7. [Audit Date and Snapshot](#7-audit-date-and-snapshot)
8. [Compliance Verification](#8-compliance-verification)

---

## 1. Audit Scope

### 1.1 Vulnerability Categories

The audit assesses the following **ten vulnerability categories**, in the canonical order
specified by the user-supplied directive. No category is omitted, and the ordering is
preserved verbatim so a reviewer can pair this index with the user's original request on a
line-for-line basis.

1. **Filesystem access & path traversal** - on-disk config-provider resolvers,
   `allowed.paths` and `allowlist.pattern` allow-lists, log-directory locking, plugin-path
   expansion, directory-deletion surfaces, OAuth JWT and assertion file reads.
2. **Low-level code safety** - JVM-to-JNI boundaries, native library integration (zstd-jni,
   snappy-java, lz4-java, RocksDB JNI), buffer-ownership contracts across the trust boundary,
   exception propagation through `KafkaException` wrapping, memory-pool allocation modes.
3. **Resource limit evasion** - connection quotas (per-IP, per-listener, broker-wide),
   request-throttling with a percentage-based 10-second sliding window, `SimpleMemoryPool`
   strict and non-strict modes, REPLICATION-listener exemption from broker-wide caps.
4. **Module system & built-in abuse** - Java `ServiceLoader` discovery points across Connect
   plugins, Connect REST extensions, metrics reporters, OAuth `JwtRetriever`/`JwtValidator`,
   Tiered Storage RSM/RLMM, and authorizer plugins; reflective `Class.forName` paths in
   `DefaultSslEngineFactory` and `SslFactory`; `URLClassLoader` isolation in
   `DelegatingClassLoader`; plugin-path expansion rules.
5. **Infinite loop & recursion DoS** - regular-expression catastrophic-backtracking (ReDoS)
   surfaces across `KerberosRule`, `JmxReporter`, `ConfigDef`, `ConfigTransformer`, and
   related pattern-compilation sites; unbounded recursion in deserialization graph walks and
   protocol-record nested-structure decoding; `SafeObjectInputStream` suffix-matching limits.
6. **Network & subprocess access** - Connect REST and MirrorMaker 2 REST trust-boundary
   surfaces, CORS defaults, `JaasBasicAuthFilter` internal-request bypass matcher,
   `RestClient` outbound-`Authorization` forwarding, KRaft Raft RPCs
   (`VOTE`, `BEGIN/END_QUORUM_EPOCH`, `FETCH`, `ADD/REMOVE/UPDATE_RAFT_VOTER`), release
   tooling subprocess execution with `shell=True` and f-string interpolation.
7. **External function & callback misuse** - `OAuthBearerValidatorCallbackHandler` SASL
   extension acceptance posture, `OAuthBearerUnsecuredValidatorCallbackHandler` `alg:none`
   acceptance, outbound `Authorization` header forwarding as an SSRF vector, Connect
   converter and transform plugin reflection sites.
8. **Deserialization attacks** - JSON feature-flag posture
   (`ALLOW_LEADING_ZEROS_FOR_NUMBERS`, `ACCEPT_SINGLE_VALUE_AS_ARRAY`),
   `SafeObjectInputStream` suffix-matching blocklist limitations, the dual JWT validator
   architecture (`BrokerJwtValidator` with `DISALLOW_NONE` versus `ClientJwtValidator`
   structural-only), checkpoint record deserialization, Raft control-record reading.
9. **Information leakage** - redaction-marker inconsistency across subsystems
   (`[hidden]`, `(redacted)`, `[redacted]`), `DelegationToken.toString()` HMAC masking
   (accepted mitigation), JMX metric exposure, DEBUG-level JWT claim logging, error-message
   enumeration surfaces.
10. **Public API developer misuse (insecure defaults)** - consolidated watchlist of
    configuration defaults that create insecure posture if an operator does not override them
    (PLAINTEXT listener, GSSAPI-only SASL default, `PropertyFileLoginModule`,
    `OAuthBearerUnsecuredValidatorCallbackHandler`, `SSL_ALLOW_DN_CHANGES`/
    `SSL_ALLOW_SAN_CHANGES`), and the subset of defaults that are correctly secure by
    default (empty `access.control.allow.origin`, `allow.everyone.if.no.acl.found=false`,
    `unclean.leader.election.enable=false`).

Each category has a dedicated findings document under [`./findings/`](./findings/) with the
file-name prefix `NN-` matching its position in the list above.

### 1.2 Kafka Version and Dependency Snapshot

The audit target is **Apache Kafka 4.2.0-SNAPSHOT**. The dependency baseline below is read
directly from `gradle/dependencies.gradle` at the audit snapshot commit. No value is
paraphrased; every line-citation is verifiable by opening the manifest at the cited line.

| Dependency | Version | Source Citation | CVE Snapshot |
| ---------- | ------- | --------------- | ------------ |
| Jackson (JSON library family) | 2.19.0 | `gradle/dependencies.gradle:L66` | Clean |
| Jose4j (JWT/JOSE library) | 0.9.6 | `gradle/dependencies.gradle:L81` | Clean |
| Jetty (HTTP server/client/servlet) | 12.0.22 | `gradle/dependencies.gradle:L69` | **CVE-2026-1605 [High]** + Medium informational (see [`./cve-snapshot.md`](./cve-snapshot.md)) |
| Jersey (JAX-RS implementation) | 3.1.10 | `gradle/dependencies.gradle:L70` | Clean |
| Log4j2 (logging facade + bridge) | 2.25.1 | `gradle/dependencies.gradle:L108` | Medium informational (operator-configuration-dependent; see [`./cve-snapshot.md`](./cve-snapshot.md)) |
| lz4-java (native compression) | 1.8.0 | `gradle/dependencies.gradle:L110` | **CVE-2025-12183 [Critical]** + **CVE-2025-66566 [Critical]** (see [`./cve-snapshot.md`](./cve-snapshot.md)) |
| RocksDB JNI (state store) | 10.1.3 | `gradle/dependencies.gradle:L118` | Clean |
| snappy-java (native compression) | 1.1.10.7 | `gradle/dependencies.gradle:L125` | Clean |
| zstd-jni (native compression) | 1.5.6-10 | `gradle/dependencies.gradle:L131` | Clean |
| Bouncy Castle (bcpkix-jdk18on) | 1.80 | `gradle/dependencies.gradle:L56` | Low informational (non-exploitable in Kafka use pattern; see [`./cve-snapshot.md`](./cve-snapshot.md)) |
| Scala (default 2.13 line) | 2.13.17 | `gradle/dependencies.gradle:L26` | Clean |
| Gradle (build tool) | 9.1.0 | `gradle/dependencies.gradle:L63` | Build-time only (non-runtime; preconditions absent from Kafka build config) |

The comprehensive dependency inventory, supply-chain narrative, and Maven coordinate lines
are in [`./dependency-inventory.md`](./dependency-inventory.md). The audit applies **no**
changes to the manifest. A consolidated advisory hub aggregating the three gating
dependency-scan findings (lz4-java Critical × 2 and Jetty High × 1) together with the
Medium/Low informational entries is in [`./cve-snapshot.md`](./cve-snapshot.md); all
recommended version bumps are staged as **future-state** engagements in
[`./remediation-roadmap.md`](./remediation-roadmap.md) Section 3.2.7 and Section 3.4.4,
consistent with the Audit Only rule.

---

## 2. Methodology

### 2.1 Static Code Reconnaissance Only

The audit is performed **entirely through static code review**. The auditor did **not**:

- Start a broker, controller, Connect worker, or MirrorMaker 2 process.
- Execute any Gradle task against Kafka code (no `build`, no `test`, no `check`, no `publish`,
  no `javadoc`).
- Run any `ducktape` system test, integration test, or unit test.
- Produce or consume any Kafka-protocol bytes on a network.
- Mutate any source file, configuration file, test file, build file, or inline comment.

Evidence in every finding is derived from reading the repository and citing file paths and
line ranges in the format `Source: <path>:L<start>-L<end>`. Reviewers can re-verify any claim
by opening the cited file at the cited line range in the pre-audit baseline commit
(`6d16f687aa1a0df26f2f665436b7efaf0aec0c56`) — the exact Kafka tree this audit was performed
against.

### 2.2 Finding Structure

Every per-category findings document (`./findings/NN-<category-slug>.md`) follows the same
fixed-order template so a reviewer can skim any finding with a consistent mental model. The
template is an 11-section layout (numbered sections plus an unnumbered Validation Checklist
and Key Insights appendix):

| Section | Purpose |
| ------- | ------- |
| 1. Category | The canonical user-specified category label (preserved verbatim). |
| 2. Definition | What the category means and what threat class it covers. |
| 3. Kafka Surface Inventory | The Kafka subsystems, classes, and configs that expose this surface. |
| 4. Evidence | File paths and line ranges backing each claim. |
| 5. Attack Vector | The step-by-step path an adversary would use to exploit a surface. |
| 6. Severity | Risk classification: Critical / High / Medium / Low. |
| 7. Business Impact | Operational consequence if the surface is exploited. |
| 8. Performance Considerations | Hot-path signals, observable metrics, performance trade-offs of current mitigations, and future-state performance accounting — all derived from static reading, never from measurement. This section satisfies the Audit Only rule's explicit requirement that every deliverable summarize "perofrmace considerations" (sic, verbatim from the user-supplied rule in [Section 3.1](#31-audit-only)). |
| 9. Accepted Mitigations Already Present | Existing positive-security controls that lower the observed risk. |
| 10. Recommended Future Remediation (no changes in this run) | Guidance for a future engagement; NO code is changed here. |
| 11. Cross-References | Links to severity matrix, remediation roadmap, accepted mitigations, relevant diagrams, and companion findings. |
| *Validation Checklist (unnumbered)* | Read-only `git`/`grep` checks a future auditor can run to re-verify the finding against a later Kafka snapshot. |
| *Key Insights (unnumbered)* | Plain-language takeaways for operator consumption, paired with the finding above. |

### 2.3 Severity Tiers

Severity is classified with four tiers. The same tier names are used by
[`./severity-matrix.md`](./severity-matrix.md), which cross-references every finding row.

| Tier | Definition |
| ---- | ---------- |
| `[Critical]` | Immediate operational risk. Likely remotely exploitable without prior authentication, or requires only a trivial bypass of a boundary. Would justify an emergency advisory if observed in a production deployment. |
| `[High]`     | Exploitable only with a specific misconfiguration, a privileged context (e.g., release engineer, Connect admin, compromised SASL credential), or an insecure default that an operator must explicitly avoid. |
| `[Medium]`   | Exploitable only under specific preconditions (particular plugin loaded, particular config enabled, particular code path exercised). Mitigated in most default deployments. |
| `[Low]`      | Defense-in-depth observation or a minor information-disclosure/consistency issue. No clear exploitation path in a default deployment. |

The audit also uses informational (non-severity) markers throughout its documents:

| Marker | Meaning |
| ------ | ------- |
| `[Accepted Mitigation]` | A positive-security control already present in the codebase; cataloged in [`./accepted-mitigations.md`](./accepted-mitigations.md) and NOT re-reported as a vulnerability. |
| `[Insecure Default]`    | A configuration default that creates insecure posture unless an operator overrides it; cataloged in [`findings/10-public-api-developer-misuse.md`](./findings/10-public-api-developer-misuse.md). |
| `[Audit Only]`          | A callout reminding the reader that no code change is being applied in this run. |

---

## 3. Governing Rules

This section reproduces the three user-supplied rules **verbatim**. Downstream readers should
treat these as non-negotiable constraints on every deliverable in `docs/security-audit/`.
Any apparent grammatical or spelling peculiarities (for example, the word `perofrmace` in the
first rule) are preserved from the original user input and MUST NOT be corrected, because the
rule is quoted, not paraphrased.

### 3.1 Audit Only

> This run should serve as a dry run for potential changes, research, or documentation. DO NOT modify, create, or delete any existing code in the codebase. Avoid executing any code in the code base, this should be a static analysis. Every deliverable MUST include a markdown file summarizing security vulnerabilities, potential exploits, bugs in the codebase, perofrmace considerations, and remediation recommendations. Verify the NO CHANGES clause by confirming no changes to existing codebase featured in the git differential. Markdown files explicitly related to the analysis performed in this run are permitted.

### 3.2 Visual Architecture Documentation

> All visual documentation MUST use Mermaid diagrams. Diagrams MUST be appropriate to the scope of the work — a migration requires before/after architecture views; a new feature may only need a component interaction and data flow diagram. Every diagram MUST have a descriptive title and legend. Diagrams MUST be referenced by name in accompanying documentation. Do NOT describe architecture in prose when a diagram communicates it more clearly. If the deliverable modifies an existing architecture, both states MUST be shown — never target-state alone.

### 3.3 Executive Presentation

> Every deliverable MUST include an executive summary as a reveal.js HTML artifact using any existing style guides found within the codebase and professional icons (not emojis). The audience is non-technical leadership — communicate business value, risk, and operational readiness without requiring code literacy. Cover what was done, why it was done, what changed architecturally, what risks exist and how they are mitigated, and how the team onboards and continues development. Embed Mermaid diagrams directly in the reveal.js slides. Every slide MUST include at least one visual element — no text-only slides. Scope the presentation to the work performed. A migration warrants before/after architecture views, mapping summaries, and a timeline. A new feature may only need a component diagram and a risk assessment.

---

## 4. Navigation Map

This section enumerates every artifact under `docs/security-audit/`. Links are relative to
this file. If a link appears to be broken during review, verify the target file exists on
disk at the expected path.

### 4.1 Core Documents

| Artifact | Purpose |
| -------- | ------- |
| [`./executive-summary.html`](./executive-summary.html)         | Non-technical leadership briefing rendered as a reveal.js HTML slide deck. Every slide embeds at least one visual element (Mermaid diagram, severity matrix, or professional SVG icon). See governing rule [Section 3.3](#33-executive-presentation). |
| [`./severity-matrix.md`](./severity-matrix.md)                 | Single at-a-glance drill-down table mapping every finding row to its severity tier (Critical / High / Medium / Low), affected subsystem, exploitation preconditions, business impact, and a back-link to the relevant findings document. |
| [`./remediation-roadmap.md`](./remediation-roadmap.md)         | Phased list of **future-state** remediation actions. No code changes are applied in this run; the roadmap is strictly a proposal for a subsequent engagement, consistent with the Audit Only rule. |
| [`./accepted-mitigations.md`](./accepted-mitigations.md)       | Catalog of **existing** positive-security controls already implemented in the codebase (for example, `MessageDigest.isEqual` constant-time comparison, `DISALLOW_NONE` JWS enforcement, REPLICATION-listener exemption, DENY-over-ALLOW ACL precedence). These are NOT re-reported as vulnerabilities. |
| [`./dependency-inventory.md`](./dependency-inventory.md)       | Supply-chain surface inventory with every dependency version read directly from `gradle/dependencies.gradle`, plus Maven coordinate lines, findings cross-reference, and already-configured supply-chain tooling posture (OWASP Dependency-Check, Trivy). |
| [`./cve-snapshot.md`](./cve-snapshot.md)                       | Consolidated CVE advisory hub aggregating the three gating dependency-scan findings identified at the audit snapshot — **lz4-java CVE-2025-12183 [Critical]** (CVSS 8.8, CWE-125 Out-of-bounds Read), **lz4-java CVE-2025-66566 [Critical]** (CVSS 8.2, CWE-201 Information Leak), and **Jetty CVE-2026-1605 [High]** (CVSS 7.5, GzipHandler native-memory DoS) — together with Medium/Low informational findings (Log4j2 CVE-2025-68161 operator-configuration-dependent; Bouncy Castle CVE-2026-0636 / CVE-2026-5588 non-exploitable in Kafka). Each entry is cross-referenced to its originating finding document ([`./findings/02-low-level-code-safety.md`](./findings/02-low-level-code-safety.md) for the lz4-java entries, [`./findings/06-network-subprocess-access.md`](./findings/06-network-subprocess-access.md) for the Jetty entry) and to the future-state remediation items staged in [`./remediation-roadmap.md`](./remediation-roadmap.md) Section 3.2.7 and Section 3.4.4. |
| [`./no-change-verification.md`](./no-change-verification.md)   | Evidence artifact proving the audit introduced zero modifications to non-audit paths. Contains the `git diff --name-status` command recipe and the expected empty-output semantics. |
| [`./references.md`](./references.md)                           | Consolidated bibliography of every source file inspected during reconnaissance, grouped by Kafka module (clients, core, connect, raft, metadata, storage, streams, coordinator, server-common, tools, trogdor, release). |

### 4.2 Findings (Per Category)

The ten findings documents are numbered `01` through `10` in the canonical user-specified
category order. Each document follows the [finding template](#22-finding-structure) and
contains file-line citations for every claim.

| # | Category | Document |
| - | -------- | -------- |
| 01 | Filesystem Access & Path Traversal         | [`./findings/01-filesystem-access-path-traversal.md`](./findings/01-filesystem-access-path-traversal.md) |
| 02 | Low-Level Code Safety (Native JNI)         | [`./findings/02-low-level-code-safety.md`](./findings/02-low-level-code-safety.md) |
| 03 | Resource Limit Evasion                      | [`./findings/03-resource-limit-evasion.md`](./findings/03-resource-limit-evasion.md) |
| 04 | Module System & Built-in Abuse              | [`./findings/04-module-system-builtin-abuse.md`](./findings/04-module-system-builtin-abuse.md) |
| 05 | Infinite Loop & Recursion DoS (ReDoS)       | [`./findings/05-infinite-loop-recursion-dos.md`](./findings/05-infinite-loop-recursion-dos.md) |
| 06 | Network & Subprocess Access                 | [`./findings/06-network-subprocess-access.md`](./findings/06-network-subprocess-access.md) |
| 07 | External Function & Callback Misuse         | [`./findings/07-external-function-callback-misuse.md`](./findings/07-external-function-callback-misuse.md) |
| 08 | Deserialization Attacks                     | [`./findings/08-deserialization-attacks.md`](./findings/08-deserialization-attacks.md) |
| 09 | Information Leakage                         | [`./findings/09-information-leakage.md`](./findings/09-information-leakage.md) |
| 10 | Public API Developer Misuse (Insecure Defaults) | [`./findings/10-public-api-developer-misuse.md`](./findings/10-public-api-developer-misuse.md) |

### 4.3 Diagrams (Mermaid)

Seven Mermaid diagrams are delivered as standalone markdown fragments so each diagram is a
self-contained, reviewable unit. Findings documents and the executive summary reference these
diagrams by name, per the [Visual Architecture Documentation rule](#32-visual-architecture-documentation).
Each diagram includes a descriptive title and a legend.

| Diagram | Purpose |
| ------- | ------- |
| [`./diagrams/threat-model-overview.md`](./diagrams/threat-model-overview.md)         | Data-flow with trust boundaries spanning producers, consumers, brokers, KRaft controllers, Connect workers, MirrorMaker 2, and external auth providers. Legend distinguishes transport boundaries (solid), trust boundaries (dashed), and plugin extension points (dotted). |
| [`./diagrams/attack-surface-map.md`](./diagrams/attack-surface-map.md)               | Component diagram cross-referencing the ten vulnerability categories against Kafka modules (clients, core, connect, raft, metadata, coordinator-*, storage, server-common, tools, trogdor, release). Severity color-coded legend. |
| [`./diagrams/authorization-decision-flow.md`](./diagrams/authorization-decision-flow.md) | Flowchart of `StandardAuthorizer.authorize`: super-user bypass, `loadingComplete` gate, `AclCache` lookup via `MatchingRuleBuilder`, DENY-over-ALLOW precedence, ALLOW implication rules, audit-log emission. |
| [`./diagrams/kraft-quorum-safety.md`](./diagrams/kraft-quorum-safety.md)             | State and sequence diagram covering `QuorumState` transitions, `VoterSet.hasOverlappingMajority` enforcement during reconfiguration, leader-epoch monotonicity, pre-vote semantics. |
| [`./diagrams/connect-rest-trust-boundary.md`](./diagrams/connect-rest-trust-boundary.md) | Sequence diagram for an inbound Connect REST request: reverse proxy, Jetty `CrossOriginHandler`, `JaasBasicAuthFilter` with `INTERNAL_REQUEST_MATCHERS` escape path, resource handler, `RestClient` forwarding call carrying the inbound `Authorization` header. |
| [`./diagrams/oauth-jwt-validation-paths.md`](./diagrams/oauth-jwt-validation-paths.md) | Flowchart distinguishing `BrokerJwtValidator` (jose4j with `DISALLOW_NONE`) from `ClientJwtValidator` (structural-only) and the legacy `OAuthBearerUnsecuredValidatorCallbackHandler` path accepting `alg:none`. |
| [`./diagrams/native-compression-boundary.md`](./diagrams/native-compression-boundary.md) | Component diagram showing Kafka-owned `BufferSupplier` and `ChunkedBytesStream` interacting with zstd-jni `RecyclingBufferPool` at the JVM/JNI boundary; explicit 16 KB chunk-size limit. |

---

## 5. How to Read a Finding

Every document under [`./findings/`](./findings/) uses the following identical section
layout. A reviewer who internalizes this structure once can navigate any finding in seconds.
The layout is 11 numbered sections plus two unnumbered appendices (Validation Checklist and
Key Insights).

```
## 1. Category
## 2. Definition
## 3. Kafka Surface Inventory
## 4. Evidence
## 5. Attack Vector
## 6. Severity
## 7. Business Impact
## 8. Performance Considerations
## 9. Accepted Mitigations Already Present
## 10. Recommended Future Remediation (no changes in this run)
## 11. Cross-References
## Validation Checklist       (unnumbered)
## Key Insights                (unnumbered)
```

Meaning of each section:

- **Category** - The canonical user-specified category label (for example, "Filesystem access
  and path traversal"). Preserved verbatim in the document title and in the top-of-document
  banner.
- **Definition** - A short (2-4 sentence) description of the threat class the category covers,
  using neutral security-industry terminology.
- **Kafka Surface Inventory** - The specific Kafka subsystems, classes, packages, and
  configuration keys that expose this surface. Organized by module so a subject-matter expert
  can jump directly to the code they own.
- **Evidence** - File paths and line ranges in the format `Source: <path>:L<start>-L<end>`.
  Every claim has at least one evidence citation; multi-surface findings have many. Evidence
  is read from the audit snapshot commit and is reproducible.
- **Attack Vector** - A step-by-step narrative of how an adversary could exploit the surface.
  Stated at a conceptual level with just enough detail to reproduce the risk analysis. No
  working exploit code is included, consistent with the Audit Only rule.
- **Severity** - A single tier: `[Critical]`, `[High]`, `[Medium]`, or `[Low]`. Rationale for
  the chosen tier is stated inline, including any conditions that would escalate or de-
  escalate the rating.
- **Business Impact** - What the organization would observe if the surface were exploited:
  data-confidentiality loss, operational outage, regulatory exposure, reputational harm, or
  supply-chain compromise. Written for cross-functional readers.
- **Performance Considerations** - Hot-path signals per sub-finding, JMX metrics that already
  exist in Kafka 4.2.0-SNAPSHOT and would indicate exploitation if observed, the performance
  trade-offs of each existing mitigation, and forward-looking performance accounting for every
  future-state recommendation. This section is required by the updated Audit Only rule in
  [Section 3.1](#31-audit-only), which mandates that every deliverable summarize "perofrmace
  considerations" (verbatim typo from the rule text). All characterisations are derived from
  static reading of source files and from the documented semantics of cited public APIs; no
  benchmarks, micro-benchmarks, or profilers were run against Kafka code during this audit.
- **Accepted Mitigations Already Present** - The specific positive-security controls that
  lower the severity of the finding, with a back-link to the relevant row in
  [`./accepted-mitigations.md`](./accepted-mitigations.md).
- **Recommended Future Remediation (no changes in this run)** - Guidance a future engagement
  could adopt. Explicitly labeled as "no changes applied here" so the reader never confuses
  a recommendation with an applied fix.
- **Cross-References** - Pointers to the severity matrix, remediation roadmap, accepted
  mitigations catalog, relevant Mermaid diagrams, and companion findings that share a surface
  or an exploit chain.
- **Validation Checklist (unnumbered)** - A list of read-only `git`/`grep`/file-inspection
  checks that a future auditor can run to re-verify the finding against a later Kafka
  snapshot. No code execution is ever required by the checklist, honoring the Audit Only
  rule for both the original audit and any re-verification pass.
- **Key Insights (unnumbered)** - Plain-language takeaways for operator consumption,
  summarising the dominant attack vector, the strongest existing mitigations, and the
  primary residual risks. Intended to be read alongside (not in place of) the full finding.

---

## 6. Terminology

The audit uses the following terms consistently across every deliverable. Reviewers should
apply the definitions below whenever the terms appear in a finding, a diagram, or the
executive summary.

| Term | Definition |
| ---- | ---------- |
| **Finding** | A reported issue - whether a vulnerability, weakness, or informational observation. Every finding has a severity tier and an evidence citation. |
| **Surface** | An attackable component or interface. Examples: the Connect REST API, the `FileConfigProvider`, the zstd-jni buffer boundary, a regex-compilation site. |
| **Vector** | The concrete path an adversary would follow to exploit a surface. A single surface may have multiple vectors (authenticated, unauthenticated, privilege-escalating, etc.). |
| **Mitigation** | An existing protection already implemented in the Kafka codebase. A mitigation lowers the severity of a finding but does not eliminate the finding. |
| **Severity** | Risk classification - Critical, High, Medium, or Low - as defined in [Section 2.3](#23-severity-tiers). |
| **Accepted Mitigation** | A positive-security control already present in the codebase; documented in [`./accepted-mitigations.md`](./accepted-mitigations.md). An accepted mitigation is NOT re-reported as a vulnerability. |
| **Insecure Default** | A configuration setting whose default value creates insecure posture unless an operator explicitly overrides it. Cataloged in [`./findings/10-public-api-developer-misuse.md`](./findings/10-public-api-developer-misuse.md). |
| **Audit Only** | The governing rule (verbatim in [Section 3.1](#31-audit-only)) that forbids modification, creation, or deletion of existing code and forbids execution of codebase code during this run. |
| **Evidence** | A file-path and line-range citation in the format `Source: <path>:L<start>-L<end>` that points a reviewer to the exact lines backing a claim in the audit snapshot commit. |
| **Subsystem** | A coherent Kafka functional area (Connect runtime, KRaft controller, Tiered Storage, MirrorMaker 2, transaction coordinator, delegation tokens, OAuth/OIDC SASL, native compression, release tooling). |

---

## 7. Audit Date and Snapshot

The following audit-snapshot block identifies the exact commit and environmental context
against which every finding, diagram, and executive-summary slide was produced. A subsequent
audit performed against a different Kafka commit must regenerate each artifact because
severity, evidence line-ranges, and the Kafka-surface inventory can all drift.

```
Audit Snapshot
--------------
  Audit name                : Apache Kafka 4.2.0-SNAPSHOT - Static Security Audit
  Kafka version             : 4.2.0-SNAPSHOT
  Dependency manifest       : gradle/dependencies.gradle
  Pre-audit baseline commit : 6d16f687aa1a0df26f2f665436b7efaf0aec0c56
  Short baseline            : 6d16f687aa
  Snapshot date             : 2026-04-17
  Git branch                : blitzy-4bdad1ad-dc01-4556-9ef0-4c760b777d5a
  Audit scope               : Read-only static code reconnaissance
  Modifications to codebase : ZERO (against the pre-audit baseline above)
  Analysis output           : docs/security-audit/ (new tree, isolated)
  Total artifacts (planned) : 1 README + 1 reveal.js HTML + 7 core markdowns
                              + 10 findings + 7 diagrams = 26 files at project
                              completion (the 7 core markdowns include
                              severity-matrix.md, remediation-roadmap.md,
                              accepted-mitigations.md, dependency-inventory.md,
                              cve-snapshot.md, no-change-verification.md, and
                              references.md)
  Delivered at this         : 26 files (1 README + 1 reveal.js HTML +
  checkpoint                  7 core markdowns + 7 diagrams + 10 per-category
                              findings). The cve-snapshot.md advisory hub was
                              added in response to the Final Checkpoint #4 QA
                              scan that surfaced the gating lz4-java Critical x 2
                              and Jetty High x 1 supply-chain CVE findings.
```

If any field above cannot be reproduced by a reviewer (for example, the pre-audit baseline
commit is different, the branch name has changed, or the dependency manifest has been
modified), the audit snapshot has drifted and the reviewer must treat the findings as stale
until a fresh audit is run.

---

## 8. Compliance Verification

The Audit Only rule in [Section 3.1](#31-audit-only) requires that **no existing code is
modified, created, or deleted** by this run and that **no code in the codebase is executed**.
Compliance with the rule is verifiable in three independent ways:

1. **Git differential check.** Reviewers may run the following command and expect empty
   output:

   ```
   git diff --name-status <pre-audit-HEAD>..HEAD -- . ':(exclude)docs/security-audit/**'
   ```

   If the command produces any output, the rule has been violated. The pre-audit HEAD commit
   is recorded in [`./no-change-verification.md`](./no-change-verification.md). Only new
   additions under `docs/security-audit/` are expected in the full differential; every other
   path must show zero modifications.

2. **Full artifact inventory check.** Reviewers may cross-check that every new file is
   accounted for in the [Navigation Map](#4-navigation-map) above and that no new file has
   been introduced outside `docs/security-audit/`. The total file count is 26 as recorded in
   the Audit Snapshot block (1 README + 1 reveal.js HTML + 7 core markdowns + 7 diagrams +
   10 per-category findings, where the 7 core markdowns comprise `severity-matrix.md`,
   `remediation-roadmap.md`, `accepted-mitigations.md`, `dependency-inventory.md`,
   `cve-snapshot.md`, `no-change-verification.md`, and `references.md`).

3. **Execution log check.** The audit execution log (available to reviewers on request via
   the audit engagement's operational tooling) shows zero invocations of Gradle tasks,
   `ducktape`, `mvn`, `kafka-*.sh` shell scripts, or any other executable that would run
   code from the Apache Kafka repository. Only read-only tools (`git`, `grep`, `find`, text
   inspection) were used.

For the authoritative verification artifact and the exact command recipes, see
[`./no-change-verification.md`](./no-change-verification.md).

---

## Closing Note

This audit is an **observation-only** engagement. Every finding describes the state of Apache
Kafka 4.2.0-SNAPSHOT as read from the snapshot commit. No code path has been altered, no
dependency has been upgraded, and no configuration has been adjusted. The future-state
guidance in [`./remediation-roadmap.md`](./remediation-roadmap.md) is strictly a proposal for
a subsequent engagement and must be adopted, discussed, and applied by the Apache Kafka
project (or a downstream operator of Kafka) through its normal change-management process -
not through this audit.

For questions about scope, methodology, or a specific finding, the consolidated bibliography
of source citations is in [`./references.md`](./references.md). For a non-technical overview
suitable for leadership, open [`./executive-summary.html`](./executive-summary.html) in any
modern web browser; the deck is self-contained and loads Mermaid, reveal.js, and Font Awesome
via public CDN endpoints with no build step required.

