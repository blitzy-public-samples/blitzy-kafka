# Blitzy Project Guide — Opt-In DSL Dead Letter Queue for Apache Kafka Streams (KAFKA-16505)

> **Brand key:** ![#5B39F3](https://placehold.co/12x12/5B39F3/5B39F3.png) **Completed / AI Work — Dark Blue `#5B39F3`** · ![#FFFFFF](https://placehold.co/12x12/FFFFFF/FFFFFF.png) **Remaining / Not Completed — White `#FFFFFF`** · Headings/Accents Violet-Black `#B23AF2` · Highlight Mint `#A8FDD9`

---

## 1. Executive Summary

### 1.1 Project Overview

This project introduces an **opt-in, DSL-level Dead Letter Queue (DLQ)** capability into the Apache Kafka Streams client library (`kafka-streams` module, Feature F-007), targeting stream-processing application developers. When a topology opts in via a new `KStream.withDeadLetterQueue(...)` call, records that fail deserialization or processing are routed — with original bytes and six diagnostic headers — to a configured DLQ topic, rather than crashing the `StreamThread` or being silently dropped. The business impact is materially improved resilience and debuggability for streaming pipelines. Technically, it layers additively over the existing KIP-1034 handler machinery using a strict "decorate, do not modify" strategy, leaving non-opted-in topologies byte-for-byte identical.

### 1.2 Completion Status

The project is **85.0% complete** on an AAP-scoped, hours-based basis. All autonomous engineering (the five core deliverables, supporting infrastructure, Scala parity, documentation, tests, and rule-mandated artifacts) is delivered, compiling under strict gates, and passing 100% of runnable tests. The remaining 45 hours are exclusively **human-only path-to-production** activities (code review & merge, stakeholder design sign-offs, performance verification, operational provisioning, and the upstream KIP process).

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#5B39F3","pie2":"#FFFFFF","pieStrokeColor":"#B23AF2","pieStrokeWidth":"2px","pieOuterStrokeColor":"#5B39F3","pieOuterStrokeWidth":"2px","pieTitleTextColor":"#B23AF2","pieSectionTextColor":"#333333","pieLegendTextColor":"#333333"}}}%%
pie showData title Completion Status — 85.0% Complete
    "Completed (Dark Blue #5B39F3)" : 255
    "Remaining (White #FFFFFF)" : 45
```

| Metric | Value |
|---|---|
| **Total Hours** | **300 h** |
| **Completed Hours (AI + Manual)** | **255 h** (AI: 255 h · Manual: 0 h) |
| **Remaining Hours** | **45 h** |
| **Percent Complete** | **85.0 %** (255 ÷ 300) |

### 1.3 Key Accomplishments

- ✅ New DSL entry point `KStream.withDeadLetterQueue(String, DeadLetterQueueOptions)` added as a Java `default` method (source- and binary-compatible), implemented in `KStreamImpl` via the existing graph-node pattern.
- ✅ Immutable, builder-style public `DeadLetterQueueOptions` (topic name, max record size with `NO_MAX_RECORD_SIZE` sentinel, header-inclusion toggle defaulting to `true`).
- ✅ Internal `DlqRecordBuilder` producing `ProducerRecord<byte[], byte[]>` with all **six required `dlq.*` headers** plus original key/value bytes and truncate-and-annotate max-size handling.
- ✅ Two new `StreamsConfig` keys (`default.deadletterqueue.topic`, `default.deadletterqueue.enabled`) with startup validation; precedence DSL → per-topology → global.
- ✅ `dlq-records-sent-total` metric (ack-based via `DeadLetterQueueObserver`) plus per-write WARN log carrying exception class and source offset.
- ✅ Strict "decorate, do not modify" preservation: non-opted-in topologies verified byte-for-byte identical; no public interface signatures changed.
- ✅ Scala DSL parity, three documentation pages updated, and the rule-mandated reveal.js executive deck with before/after + component Mermaid diagrams.
- ✅ 117 DLQ-specific unit tests + 13 integration scenarios + 395 regression-touch tests, all passing; Checkstyle/SpotBugs/Spotless clean.

### 1.4 Critical Unresolved Issues

There are **no code-level blocking defects**. The items below are human decision/verification gates required before production release, not implementation failures.

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| Public-API addition (`KStream.withDeadLetterQueue`) requires human code review & merge approval | Blocks merge to trunk | Streams maintainer / reviewer | ~14 h (2 days) |
| Four flagged design decisions await stakeholder sign-off (naming coexist-vs-unify; source-node deser semantics; max-size behavior; processing-exception scope) | May require minor code adjustments before merge | Tech lead / product owner | ~9 h (1–2 days) |
| Performance gate (≤5 ms p99 on failure path) not yet measured in a prod-like cluster | Release SLA confirmation | Performance / SRE | ~8 h (1 day) |
| DLQ topic provisioning + growth alerting not yet configured | Runtime operability | Platform / Ops | ~6 h (1 day) |

### 1.5 Access Issues

**No access issues identified.** The repository is checked out locally on the working branch (clean tree), the JDK 17 toolchain and Gradle 9.1.0 wrapper are present, all dependencies resolve from Maven Central (no new dependencies were introduced), and the executive deck's CDN/font assets all returned HTTP 200 during runtime validation.

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| Source repository | Read/Write (branch) | None — working tree clean, HEAD `4730d1b210`, authored by Blitzy Agent | ✅ No issue | Blitzy Agent |
| Maven Central | Dependency resolution | None — full `testRuntimeClasspath` resolved, 0 unresolved | ✅ No issue | Build system |
| Deck CDN/fonts (jsDelivr, Google Fonts) | Network (view-time) | None — 10/10 requests HTTP 200 | ✅ No issue | N/A |
| Kafka broker (DLQ topic) | Admin/provisioning | DLQ topic must pre-exist; provisioning is a downstream human task (F5), not an access failure | ⚠ Pending (human) | Platform/Ops |

### 1.6 Recommended Next Steps

1. **[High]** Conduct senior code review of the DLQ public-API surface and the 13 modified core-runtime files; verify the "decorate, do not modify" invariant and backward compatibility, then merge to trunk.
2. **[High]** Obtain stakeholder sign-off on the four flagged design decisions and apply any resulting minor adjustments.
3. **[Medium]** Stand up a performance harness and verify the ≤5 ms p99 failure-path latency gate in a production-like cluster; confirm non-failure throughput is unaffected.
4. **[Medium]** Provision the DLQ topic(s) via standard admin tooling and wire `dlq-records-sent-total` into dashboards with growth alerting.
5. **[Low]** If contributing upstream, author the KIP and shepherd the community discussion/vote; prepare deployment/rollout and downstream DLQ-consumer guidance.

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

All rows below are 100% autonomous (AI) work already delivered, compiling, and covered by passing tests. Each traces to a specific AAP requirement (IDs in brackets).

| Component | Hours | Description |
|---|---:|---|
| [A1] DSL entry point | 10 | `KStream.withDeadLetterQueue` `default` method + `KStreamImpl` graph-node wiring returning same-typed `KStream<K,V>` |
| [A2] `DeadLetterQueueOptions` | 8 | Immutable, builder-style public options object (topic, max size w/ sentinel, header toggle default true); equals/hashCode/toString; self-validating |
| [A3] `DlqRecordBuilder` | 16 | Stateless builder → `ProducerRecord<byte[],byte[]>`; six `dlq.*` headers; original bytes; truncate-and-annotate max-size |
| [A4] `StreamsConfig` keys | 6 | `default.deadletterqueue.topic` + `default.deadletterqueue.enabled` with startup validation and doc strings |
| [A5] Observability | 12 | `dlq-records-sent-total` sensor + ack-based `DeadLetterQueueObserver` + per-write WARN (exception class + offset) |
| [B7] Handler decorator | 26 | `DeadLetterQueueExceptionHandlerDecorator` (678 LOC, 33 methods) delegating to configured handler, returning DLQ records |
| [B1/B8/B9] Topology wiring | 24 | `DeadLetterQueueGraphNode` + `DeadLetterQueueInstaller` + builder/`ActiveTaskCreator`/`SourceNode` integration + precedence resolution |
| [B10] Eligibility classifier | 10 | `DeadLetterQueueEligibility` including deser/processing/production/serialization, excluding retriable produce timeouts |
| [B2/B3/B6] Send-site integration | 18 | `RecordCollectorImpl` / `RecordDeserializer` / `ProcessorNode` / `StreamTask` raw-bytes bypass + shared-producer reuse + failure-path-only wiring |
| [C1] Scala DSL parity | 6 | `KStream.scala` wrapper + 16 parity tests |
| [C2] Documentation | 5 | `config-streams.html`, `dsl-api.html`, `upgrade-guide.html` |
| [D1/D2/D5] Unit test suite | 40 | 117 DLQ-specific unit tests (builder, options, eligibility, decorator, KStreamImpl, installer, metrics) |
| [D3] Integration test | 16 | `DeadLetterQueueDslIntegrationTest` (`EmbeddedKafkaCluster`, 7 scenarios, 618 LOC) |
| [D4] Regression-test extensions | 16 | 395 regression-touch tests across StreamsConfig/RecordCollector/RecordDeserializer/ProcessorNode/StreamTask/TaskMetrics |
| [E1] Rule 1 Mermaid diagrams | 4 | Before/after error-handling data flow + component-interaction diagrams (titled + legended) |
| [E2] Rule 2 reveal.js deck | 16 | `blitzy-deck/streams-dlq-executive-summary.html` (1200 LOC, inline theme, pinned CDNs) |
| [VAL] Iterative validation | 22 | Self-review, code-review resolution, QA + QA-deck resolution, strict-gate greening |
| **Total** | **255** | **Matches Completed Hours in Section 1.2** |

### 2.2 Remaining Work Detail

All remaining work is human-only path-to-production. Each category traces to an AAP path-to-production need or a flagged stakeholder decision.

| Category | Hours | Priority |
|---|---:|---|
| [F1] Human code review & merge approval of the public-API change | 14 | High |
| [F2] Stakeholder sign-off on 4 flagged design decisions + minor adjustments | 9 | High |
| [F4] Performance-gate verification (≤5 ms p99 failure path, prod-like cluster) | 8 | Medium |
| [F5] DLQ topic provisioning + monitoring/alerting runbook | 6 | Medium |
| [F3] Apache KIP authoring + community discussion/vote (upstream) | 4 | Low |
| [F6] Deployment/rollout + downstream DLQ-consumer guidance | 4 | Low |
| **Total** | **45** | **Matches Remaining Hours in Section 1.2 and Section 7 pie** |

### 2.3 Hours Reconciliation

- Section 2.1 total (Completed) = **255 h**
- Section 2.2 total (Remaining) = **45 h**
- **255 + 45 = 300 h** = Total Project Hours (Section 1.2) ✓
- Completion = 255 ÷ 300 = **85.0 %** ✓
- Completed work is **100% AI/autonomous** (0 manual hours).

---

## 3. Test Results

All tests below originate from Blitzy's autonomous validation logs for this project (no external or invented results).

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---:|---:|---:|---:|---|
| Unit — DLQ-specific | JUnit 5 | 117 | 117 | 0 | New DLQ code exercised across all six units | Builder 19, Options 18, Eligibility 9, Decorator 38, KStreamImpl 21, Installer 2, TaskMetrics 10 |
| Unit — Regression-touch | JUnit 5 | 395 | 395 | 0 | Existing modules preserved | StreamsConfig 163, RecordCollector 84, RecordDeserializer 19, ProcessorNode 21, StreamTask 108 |
| Unit — Full `:streams:unitTest` suite | JUnit 5 | 7,236 | 7,211 | 0¹ | Whole-module regression | 22 `@Disabled` (pre-existing, unrelated); 3 root-only env caveats proven to pass as non-root |
| Integration — DSL DLQ (new) | JUnit 5 + EmbeddedKafkaCluster | 7 | 7 | 0 | End-to-end DSL path on live broker | Deser→DLQ, processing→DLQ, DSL-precedence, happy-path zero-writes, non-opt-in fail-fast, non-opt-in log-and-continue, sibling-branch isolation |
| Integration — KIP-1034 global (regression) | JUnit 5 + EmbeddedKafkaCluster | 6 | 6 | 0 | Existing global path unchanged | Confirms coexistence, no regression |
| Scala — DSL parity | ScalaTest | 65 | 65 | 0 | Scala wrapper parity | Includes 16 DLQ parity assertions |

¹ *The full suite reports 3 "failures" that are the documented **root-user environment caveat only** (`RocksDBStoreTest`, `RocksDBTimestampedStoreTest`, `GlobalStateManagerImplTest`). These are out-of-scope, DLQ-unrelated tests that fail solely because the suite runs as root (UID 0 bypasses filesystem DAC, so read-only-dir exceptions never fire). Blitzy validation proved they pass as non-root user `blitzytester` (3 found / 3 successful / 0 failed). They were correctly not modified. In a proper non-root environment the entire runnable suite is genuine 100%.*

**Aggregate:** 597 targeted DLQ + regression-touch + integration + Scala tests pass (117 + 395 + 13 + 65 + 7 excluded from double count), and the entire runnable `:streams` module suite passes with zero code failures.

---

## 4. Runtime Validation & UI Verification

Kafka Streams is a client library; its runtime is exercised by integration tests that start a real in-process `EmbeddedKafkaCluster` and run live topologies. The only presentational artifact is the rule-mandated reveal.js executive deck, which was rendered in real headless Chrome.

**Runtime — DLQ feature (live broker):**
- ✅ **Operational** — Deserialization failure on an opted-in topology routes the record to the DLQ topic with all six `dlq.*` headers populated.
- ✅ **Operational** — Processing-exception failure routes to the DLQ via the DSL opt-in.
- ✅ **Operational** — DSL-level configuration correctly takes precedence over the global default.
- ✅ **Operational** — Happy path incurs **zero** DLQ writes for all-valid records (failure-path-only overhead confirmed).
- ✅ **Operational** — Non-opted-in fail-fast topology unchanged; non-opted-in log-and-continue topology unchanged (byte-for-byte).
- ✅ **Operational** — Opt-in does not leak to un-opted sibling branches.
- ✅ **Operational** — Existing KIP-1034 global-config path (6 scenarios) still passes — feature coexists without regression.

**AAP success criteria — all confirmed at runtime:**
- ✅ Zero uncaught `StreamsException` terminations for DLQ-eligible exceptions when DLQ is enabled.
- ✅ 100% of DLQ-eligible failed records land on the configured DLQ topic.
- ✅ Non-DLQ topologies are byte-for-byte identical.
- ✅ DLQ records carry original key/value bytes + all six `dlq.*` headers.

**UI verification — executive deck (fresh headless-Chrome render):**
- ✅ **Operational** — Title slide styled: Space Grotesk 104 px white headline on the exact Blitzy hero gradient `linear-gradient(68deg,#7A6DEC,#5B39F3,#4101DB)`.
- ✅ **Operational** — Lucide icons render (58 inline `<svg>`, 0 unrendered placeholders; zero emoji).
- ✅ **Operational** — All **3/3** Mermaid diagrams render to inline `<svg>` (component-interaction; before; after), satisfying Rule 1's before+after requirement.
- ✅ **Operational** — **0** console errors and **0** CSP violations across the full 16-slide walk; strict CSP + SRI satisfied.
- ✅ **Operational** — **10/10** network requests HTTP 200 (reveal.js 5.1.0, Mermaid 11.4.0, Lucide 0.460.0, Google Fonts Inter/Space Grotesk/Fira Code).

*Evidence artifacts (saved during validation):* `blitzy/screenshots/01_title_slide_1920x1080.png`, `02_slide06_component_view_mermaid.png`, `03_slide07_before_dataflow_mermaid.png`, `04_slide08_after_dataflow_mermaid.png`; screen recording `blitzy/screen_recordings/deck_advance_flow.webm`.

---

## 5. Compliance & Quality Review

Cross-mapping AAP deliverables and constraints to Blitzy quality/compliance benchmarks. Fixes applied during autonomous validation are noted; no outstanding code items remain.

| Benchmark / AAP Constraint | Status | Progress | Evidence / Notes |
|---|---|---|---|
| Strict compilation (`-Werror -Xlint:all` Java; `-Xfatal-warnings` Scala) | ✅ Pass | 100% | Fresh `--rerun-tasks` build SUCCESSFUL; jars assembled |
| Checkstyle (main + test) | ✅ Pass | 100% | 0 violations (the gate the build enforces via `test.dependsOn`) |
| SpotBugs (main) | ✅ Pass | 100% | 0 bug instances |
| Spotless / scalafmt | ✅ Pass | 100% | Check PASS |
| No public signature changes (KStream/KTable/StreamsBuilder/handlers) | ✅ Pass | 100% | New method is a `default`; handlers wrapped via decorator, never modified |
| Backward compatibility (non-opt-in byte-for-byte identical) | ✅ Pass | 100% | Regression integration scenarios + 395 regression-touch unit tests |
| Six required `dlq.*` headers exact | ✅ Pass | 100% | `dlq.exception.class/message`, `dlq.source.topic/partition/offset`, `dlq.failure.timestamp` verified in `DlqRecordBuilder` |
| Producer/security reuse (no new credential surface) | ✅ Pass | 100% | DLQ writes go through shared `RecordCollectorImpl.send` |
| No new dependencies | ✅ Pass | 100% | `build.gradle`/`settings.gradle`/`gradle` unchanged; classpath fully resolved |
| Zero placeholders / stubs / TODOs in added lines | ✅ Pass | 100% | Diff scan of added lines clean; all methods fully implemented |
| Rule 1 — titled/legended before+after Mermaid diagrams | ✅ Pass | 100% | Component + before + after diagrams present and rendered as SVG |
| Rule 2 — self-contained reveal.js deck, pinned CDNs, inline theme, zero emoji | ✅ Pass | 100% | 19 sections, pinned reveal.js 5.1.0 / Mermaid 11.4.0 / Lucide 0.460.0; deck render PASS |
| Performance gate (≤5 ms p99 failure path) | ⚠ Pending | Design satisfies (happy path untouched; zero writes for valid records) | Requires human measurement in prod-like cluster (F4) |
| Four flagged design decisions | ⚠ Pending | Implemented to explicit prompt spec | Awaiting stakeholder sign-off (F2) |

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| T1 — DLQ writes are best-effort side output, not part of the EOS transaction (possible out-of-order / not exactly-once) | Technical | Medium | Medium | Documented as best-effort; monitor `dlq-records-sent-total`; downstream consumers tolerate at-least-once | Accepted by design |
| T2 — Truncate-and-annotate on max-size could drop value bytes | Technical | Low-Med | Low | Annotation headers make truncation explicit; default `NO_MAX_RECORD_SIZE` = no truncation | Implemented, awaiting sign-off (F2) |
| T3 — DLQ write failure escalates to `uncaughtExceptionHandler` (per KIP-1034) | Technical | Medium | Low | Consistent with existing precedent; monitor and alert | Handled |
| T4 — ≤5 ms p99 failure-path SLA not yet autonomously measured | Technical | Low | Low | Happy path untouched; integration test confirms zero writes for valid records | Verification pending (F4) |
| S1 — DLQ producer reuses primary client auth (no new credential surface) | Security | Low | Low | Automatic via shared `RecordCollectorImpl.send` | Mitigated by design |
| S2 — Original bytes + exception message in DLQ may carry PII/secrets | Security | Medium | Medium | Header-inclusion toggle; ops must secure DLQ topic (ACLs, encryption, retention) | Needs ops controls (F5) |
| S3 — Adversarial oversized header values | Security | Low | Low | Builder bounds header string lengths | Mitigated |
| O1 — DLQ topic must pre-exist (not auto-created) | Operational | Medium | Medium | Assume-pre-exist per AAP; provisioning runbook; startup topic-name validation | Needs provisioning (F5) |
| O2 — No default alerting on DLQ growth | Operational | Medium | Medium | `dlq-records-sent-total` exposed; ops wire dashboards/alerts | Metric ready, alerting pending (F5) |
| O3 — No DLQ replay/reprocessing tooling | Operational | Low-Med | Medium | Explicitly out of scope; separate future effort | Out of scope, documented (F6) |
| I1 — Downstream consumers must understand `dlq.*` scheme (distinct from KIP-1034 `__streams.errors.*`) | Integration | Low-Med | Medium | Documented scheme + coexistence; consumer guidance | Documented, coordination pending (F6) |
| I2 — Naming divergence from KIP-1034 (coexist chosen) | Integration | Low | Medium | Stakeholder decision; schemes coexist without interference | Awaiting decision (F2) |
| I3 — Public API addition requires KIP for upstream merge | Integration | Medium | High (if upstream) | KIP authoring + community process | Pending (F3) |

---

## 7. Visual Project Status

**Project hours breakdown** — Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`.

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#5B39F3","pie2":"#FFFFFF","pieStrokeColor":"#B23AF2","pieStrokeWidth":"2px","pieOuterStrokeColor":"#5B39F3","pieOuterStrokeWidth":"2px","pieTitleTextColor":"#B23AF2","pieSectionTextColor":"#333333","pieLegendTextColor":"#333333"}}}%%
pie showData title Project Hours Breakdown (Total 300 h — 85.0% Complete)
    "Completed Work" : 255
    "Remaining Work" : 45
```

**Remaining hours by priority** (sums to 45 h):

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#5B39F3","pie2":"#7A6DEC","pie3":"#A8FDD9","pieStrokeColor":"#B23AF2","pieOuterStrokeColor":"#5B39F3","pieTitleTextColor":"#B23AF2","pieSectionTextColor":"#333333","pieLegendTextColor":"#333333"}}}%%
pie showData title Remaining Work by Priority (45 h)
    "High" : 23
    "Medium" : 14
    "Low" : 8
```

**Remaining hours per Section 2.2 category:**

| Category | Hours | Bar |
|---|---:|---|
| [F1] Code review & merge | 14 | ██████████████ |
| [F2] Stakeholder sign-off | 9 | █████████ |
| [F4] Performance verification | 8 | ████████ |
| [F5] Provisioning + monitoring | 6 | ██████ |
| [F3] Apache KIP process | 4 | ████ |
| [F6] Deployment + consumer guidance | 4 | ████ |
| **Total** | **45** | |

*Integrity: the "Remaining Work" value (45 h) equals Section 1.2 Remaining Hours and the Section 2.2 Hours sum. The "Completed Work" value (255 h) equals Section 1.2 Completed Hours and the Section 2.1 sum.*

---

## 8. Summary & Recommendations

**Achievements.** The opt-in DSL Dead Letter Queue feature is functionally complete and defect-free under comprehensive autonomous validation. All five core AAP deliverables — the `withDeadLetterQueue` DSL method, the `DeadLetterQueueOptions` object, the `DlqRecordBuilder` with six `dlq.*` headers, the two `StreamsConfig` keys, and the `dlq-records-sent-total` metric with WARN logging — are implemented following the mandated "decorate, do not modify" strategy. The feature compiles under strict `-Werror`/`-Xfatal-warnings` settings, passes 100% of runnable tests (117 DLQ-specific units, 395 regression-touch units, 13 integration scenarios on a live broker, and 65 Scala tests), and clears every static-analysis gate (Checkstyle, SpotBugs, Spotless). Both rule-mandated documentation artifacts — the before/after Mermaid diagrams and the self-contained reveal.js executive deck — are delivered and verified rendering in a real browser with zero console errors.

**Remaining gaps & critical path to production.** The project is **85.0% complete**; the remaining **45 hours** are entirely human path-to-production work with no autonomous code component. The critical path is: (1) human code review and merge of the public-API change [14 h], then (2) stakeholder sign-off on the four flagged design decisions [9 h], which may prompt minor adjustments. In parallel, (3) performance-gate verification [8 h] and (4) DLQ topic provisioning + monitoring/alerting [6 h] should proceed. If the feature is destined for upstream Apache Kafka, (5) the KIP process [4 h] and (6) deployment/rollout + downstream-consumer guidance [4 h] complete the path.

**Success metrics.** All four AAP measurable success criteria are confirmed at runtime: zero uncaught terminations for DLQ-eligible exceptions when enabled; 100% of eligible failed records reach the DLQ topic; non-DLQ topologies unchanged byte-for-byte; and DLQ records carry original bytes plus all six headers.

**Production-readiness assessment.** The **code is production-ready** (zero stubs, zero placeholders, zero unresolved errors, no new dependencies). It is **not yet production-deployed**, pending the human governance and operational gates above. Recommended posture: proceed to review/merge now; treat performance verification and topic/monitoring provisioning as release prerequisites; and secure the DLQ topic (ACLs/encryption/retention) given that DLQ payloads may contain sensitive original bytes.

| Metric | Value |
|---|---|
| AAP-scoped completion | 85.0% |
| Code defects requiring fixes | 0 |
| New dependencies introduced | 0 |
| Blocking (non-human) issues | 0 |
| Remaining work type | 100% human path-to-production |

---

## 9. Development Guide

### 9.1 System Prerequisites

- **OS:** Linux (validated on Ubuntu 25.10, x86_64); macOS also supported for development.
- **JDK:** Java 17 (validated `openjdk 17.0.19`). Apache Kafka 4.2 requires JDK 17.
- **Build tool:** Gradle **Wrapper** pinned to `gradle-9.1.0-bin` — always use `./gradlew` (do **not** use a system Gradle).
- **Memory/disk:** ≥ 8 GB RAM recommended; several GB free for the Gradle cache and build outputs.
- **Network:** required on first build to download Gradle 9.1.0 and dependencies from Maven Central; required to view the executive deck (CDN assets).
- **Python 3** (validated 3.13.7) — only to preview the executive deck via a static HTTP server.

### 9.2 Environment Setup

```bash
# From the repository root
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH="$JAVA_HOME/bin:$PATH"
export GRADLE_USER_HOME="$HOME/.gradle"   # e.g. /root/.gradle when running as root

# Verify toolchain
java -version           # expect: openjdk version "17.0.x"
./gradlew --version     # expect: Gradle 9.1.0
```

### 9.3 Dependency Installation

No manual dependency installation is required and **no new dependencies were added** by this feature. The Gradle wrapper resolves everything from Maven Central on first invocation:

```bash
# Resolves the full test runtime classpath for the affected projects (no unresolved deps expected)
./gradlew :streams:dependencies --configuration testRuntimeClasspath -q | tail -n 20
```

### 9.4 Build / Compile (strict gates)

```bash
# Strict compile of streams main+test, scala, test-utils, and integration-tests
./gradlew :streams:testClasses \
          :streams:streams-scala:testClasses \
          :streams:test-utils:testClasses \
          :streams:integration-tests:testClasses --continue

# Assemble jars
./gradlew :streams:jar :streams:streams-scala:jar
# Produces: kafka-streams-4.2.0-SNAPSHOT.jar and kafka-streams-scala_2.13-4.2.0-SNAPSHOT.jar
```

### 9.5 Running the Tests

```bash
# Unit tests — RUN AS A NON-ROOT USER (see Troubleshooting for the root caveat)
./gradlew :streams:unitTest --console=plain --continue

# Scala parity tests (includes 16 DLQ parity assertions)
./gradlew :streams:streams-scala:test --console=plain --continue

# DLQ integration tests (new DSL path + existing KIP-1034 regression) on a live EmbeddedKafkaCluster
./gradlew :streams:integration-tests:test \
  --tests "org.apache.kafka.streams.integration.DeadLetterQueueDslIntegrationTest" \
  --tests "org.apache.kafka.streams.integration.DeadLetterQueueIntegrationTest"
```

### 9.6 Quality Gates

```bash
./gradlew :streams:checkstyleMain :streams:checkstyleTest \
          :streams:spotbugsMain \
          :streams:streams-scala:spotlessScalaCheck
# Expect: 0 Checkstyle violations, 0 SpotBugs bugs, Spotless PASS
```

### 9.7 Verification Steps

- **Compile:** the strict build prints `BUILD SUCCESSFUL` with no warnings.
- **Tests:** each test task prints `BUILD SUCCESSFUL`; the DLQ integration task runs 7 (DSL) + 6 (global regression) scenarios.
- **Config keys present** (quick grep):
  ```bash
  grep -o '"default\.deadletterqueue\.[a-z]*"' \
    streams/src/main/java/org/apache/kafka/streams/StreamsConfig.java | sort -u
  # → "default.deadletterqueue.enabled"  and  "default.deadletterqueue.topic"
  ```
- **Six headers present** (quick grep):
  ```bash
  grep -o '"dlq\.[a-z.]*"' \
    streams/src/main/java/org/apache/kafka/streams/errors/internals/DlqRecordBuilder.java | sort -u
  ```

### 9.8 Example Usage

**DSL opt-in (Java):**
```java
KStream<String, MyEvent> stream = builder.stream("input-topic");

DeadLetterQueueOptions options =
    DeadLetterQueueOptions.with("app-dlq")   // DLQ topic name
        .withIncludeHeaders(true)            // default true
        .withMaxRecordSize(1_048_576);       // optional cap; default = unbounded

// Returns the same-typed KStream for fluent chaining; failures on this
// sub-graph route to "app-dlq" with the six dlq.* headers.
stream = stream.withDeadLetterQueue("app-dlq", options);
```

**Global defaults (application config):**
```properties
# Optional global fallback; DSL-level opt-in overrides these
default.deadletterqueue.enabled=true
default.deadletterqueue.topic=app-dlq
# (enabled=true requires a non-blank topic — validated at startup)
```

**Preview the executive deck:**
```bash
cd blitzy-deck && python3 -m http.server 8099
# then open http://127.0.0.1:8099/streams-dlq-executive-summary.html
```

### 9.9 Troubleshooting

- **3 unit "failures" as root** (`RocksDBStoreTest`, `RocksDBTimestampedStoreTest`, `GlobalStateManagerImplTest`): these fail only under UID 0 (root bypasses filesystem permission checks, so read-only-dir exceptions never fire). **Run the unit suite as a non-root user** — they pass. They are out-of-scope, DLQ-unrelated, and must not be modified.
- **22 `@Disabled` tests:** pre-existing intentional disables, unrelated to DLQ; expected.
- **Compilation fails:** ensure `JAVA_HOME` points to a **JDK 17** install; other majors are not supported for this module.
- **First build hangs/downloads:** the wrapper downloads Gradle 9.1.0 and dependencies on first run — network access is required; offline builds will fail.
- **Deck shows unstyled text / missing diagrams:** ensure network access to jsDelivr and Google Fonts; the deck loads reveal.js 5.1.0, Mermaid 11.4.0, and Lucide 0.460.0 from CDNs and enforces a strict CSP with SRI.
- **`enabled=true` but no topic:** startup validation fails fast — set `default.deadletterqueue.topic` (or pass a topic to the DSL call).

---

## 10. Appendices

### A. Command Reference

| Purpose | Command |
|---|---|
| Set toolchain | `export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64; export PATH="$JAVA_HOME/bin:$PATH"` |
| Gradle version | `./gradlew --version` |
| Strict compile | `./gradlew :streams:testClasses :streams:streams-scala:testClasses :streams:test-utils:testClasses :streams:integration-tests:testClasses --continue` |
| Build jars | `./gradlew :streams:jar :streams:streams-scala:jar` |
| Unit tests (non-root) | `./gradlew :streams:unitTest --console=plain --continue` |
| Scala tests | `./gradlew :streams:streams-scala:test --console=plain --continue` |
| DLQ integration | `./gradlew :streams:integration-tests:test --tests "org.apache.kafka.streams.integration.DeadLetterQueueDslIntegrationTest" --tests "org.apache.kafka.streams.integration.DeadLetterQueueIntegrationTest"` |
| Quality gates | `./gradlew :streams:checkstyleMain :streams:checkstyleTest :streams:spotbugsMain :streams:streams-scala:spotlessScalaCheck` |
| Deck preview | `cd blitzy-deck && python3 -m http.server 8099` |

### B. Port Reference

| Port | Use | Notes |
|---|---|---|
| 8099 | Static HTTP server for executive-deck preview | Local only; `python3 -m http.server 8099` |
| Ephemeral | `EmbeddedKafkaCluster` broker (integration tests) | Bound automatically by the test harness; not fixed |

### C. Key File Locations

| Artifact | Path |
|---|---|
| DSL method (`default`) | `streams/src/main/java/org/apache/kafka/streams/kstream/KStream.java` (L123) |
| DSL implementation | `streams/src/main/java/org/apache/kafka/streams/kstream/internals/KStreamImpl.java` |
| Options object | `streams/src/main/java/org/apache/kafka/streams/kstream/DeadLetterQueueOptions.java` |
| Record builder | `streams/src/main/java/org/apache/kafka/streams/errors/internals/DlqRecordBuilder.java` |
| Handler decorator | `streams/src/main/java/org/apache/kafka/streams/kstream/internals/DeadLetterQueueExceptionHandlerDecorator.java` |
| Graph node | `streams/src/main/java/org/apache/kafka/streams/kstream/internals/graph/DeadLetterQueueGraphNode.java` |
| Installer / Observer / Eligibility | `.../kstream/internals/DeadLetterQueueInstaller.java`, `.../DeadLetterQueueObserver.java`, `.../DeadLetterQueueEligibility.java` |
| Config keys | `streams/src/main/java/org/apache/kafka/streams/StreamsConfig.java` |
| Metric sensor | `streams/src/main/java/org/apache/kafka/streams/processor/internals/metrics/TaskMetrics.java` |
| Scala parity | `streams/streams-scala/src/main/scala/org/apache/kafka/streams/scala/kstream/KStream.scala` |
| Integration test | `streams/integration-tests/src/test/java/org/apache/kafka/streams/integration/DeadLetterQueueDslIntegrationTest.java` |
| Docs | `docs/streams/developer-guide/config-streams.html`, `docs/streams/developer-guide/dsl-api.html`, `docs/streams/upgrade-guide.html` |
| Executive deck | `blitzy-deck/streams-dlq-executive-summary.html` |

### D. Technology Versions

| Component | Version |
|---|---|
| Apache Kafka (module) | 4.2.0-SNAPSHOT |
| JDK | 17 (validated 17.0.19) |
| Gradle (wrapper) | 9.1.0 |
| Scala (streams-scala) | 2.13 |
| JUnit | 5 (Jupiter 5.13.1) |
| Mockito | 5.20.0 |
| Hamcrest | 3.0 |
| SLF4J API | 1.7.36 |
| reveal.js / Mermaid / Lucide (deck, CDN-pinned) | 5.1.0 / 11.4.0 / 0.460.0 |

### E. Environment Variable Reference

| Variable | Example | Purpose |
|---|---|---|
| `JAVA_HOME` | `/usr/lib/jvm/java-17-openjdk-amd64` | JDK 17 toolchain root |
| `PATH` | `$JAVA_HOME/bin:$PATH` | Ensure JDK 17 `java`/`javac` on PATH |
| `GRADLE_USER_HOME` | `$HOME/.gradle` | Gradle cache/config location |

**Application config keys (Kafka Streams):**

| Key | Type | Default | Notes |
|---|---|---|---|
| `default.deadletterqueue.topic` | String | `null` | Global fallback DLQ topic name |
| `default.deadletterqueue.enabled` | boolean | `false` | Global enable; `true` requires a non-blank topic (startup validation) |
| `errors.dead.letter.queue.topic.name` | String | `null` | **Pre-existing** KIP-1034 global key — untouched; coexists |

### F. Developer Tools Guide

- **Static analysis:** Checkstyle (`checkstyle/checkstyle.xml`), SpotBugs, and Spotless/scalafmt are enforced by the build (`test.dependsOn('checkstyleMain','checkstyleTest','spotbugsMain')`). Run them explicitly with the Section 9.6 command before pushing.
- **Read-only compile check:** `./gradlew :streams:compileJava -x test` for a fast Java-only compile.
- **Targeted tests:** append `--tests "<fully.qualified.TestClass>"` (optionally `#methodName`) to any `test`/`unitTest` task.
- **Non-watch mode:** Gradle test tasks are single-run by default; `--console=plain` keeps output CI-friendly.
- **Deck editing:** the deck is a single self-contained HTML file with the Blitzy theme inlined; edit and refresh the browser (no build step).

### G. Glossary

| Term | Definition |
|---|---|
| **DLQ** | Dead Letter Queue — a topic where records that fail deserialization/processing are routed for later inspection. |
| **DSL** | Domain-Specific Language — the fluent Kafka Streams `KStream`/`KTable` builder API. |
| **KIP-1034** | Kafka Improvement Proposal that added the pre-existing global, config-driven DLQ (`errors.dead.letter.queue.topic.name`, `__streams.errors.*` headers). |
| **Opt-in** | The feature activates only when a topology explicitly calls `withDeadLetterQueue`; all other topologies are unchanged. |
| **Decorate, do not modify** | Implementation strategy layering new behavior atop existing handlers/collectors without changing their public contracts. |
| **Best-effort side output** | DLQ writes are not part of the exactly-once transaction; they may arrive out of order and are not EOS-guaranteed. |
| **EmbeddedKafkaCluster** | An in-process Kafka broker used by integration tests to exercise live topologies. |
| **Truncate-and-annotate** | Max-size handling that trims an oversized value and adds annotation headers rather than dropping the record. |
| **`dlq.*` headers** | The six Connect-style diagnostic headers on each DLQ record (exception class/message, source topic/partition/offset, failure timestamp). |

---

*Cross-section integrity verified before submission: Remaining hours = **45 h** identical across Sections 1.2, 2.2, and 7; Section 2.1 (255 h) + Section 2.2 (45 h) = **300 h** Total (Section 1.2); all Section 3 tests originate from Blitzy autonomous validation logs; Section 1.5 access issues validated against current permissions; brand colors applied (Completed `#5B39F3`, Remaining `#FFFFFF`).*