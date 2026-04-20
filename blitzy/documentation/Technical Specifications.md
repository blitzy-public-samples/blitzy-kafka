# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Documentation Objective

Based on the provided requirements, the Blitzy platform understands that the documentation objective is to produce a **static, audit-only security vulnerability assessment** of the Apache Kafka 4.2.0-SNAPSHOT monorepo. The engagement is scoped as a reconnaissance-and-documentation exercise that identifies threats across ten canonical vulnerability categories while explicitly prohibiting any modification, creation, or deletion of existing source code, tests, build configuration, comments, or runtime behavior.

- Request category: **Create new documentation** (supplementary security audit artifacts) and **Fix documentation gaps** (threat surface enumeration currently absent from the repository)
- Documentation types to produce:
    - Security assessment technical specification (markdown)
    - Executive reveal.js HTML presentation for non-technical leadership
    - Mermaid diagrams embedded within the specification (threat model, attack surface map, data-flow with trust boundaries, authentication/authorization decision graph, KRaft control-plane diagram, and before/after architecture views are not applicable because no changes are being proposed — single current-state views only)
- Primary deliverable classification: **Audit-only static analysis deliverable** governed by the user-provided "Audit Only" rule prohibiting code changes and execution of codebase code
- Explicit requirements extracted from the prompt, restated with technical precision:
    - Assess all ten vulnerability categories verbatim: (1) filesystem access and path traversal; (2) low-level code safety; (3) resource-limit evasion; (4) module system and built-in abuse; (5) infinite loop and recursion DoS; (6) network and subprocess access; (7) external function and callback misuse; (8) deserialization attacks; (9) information leakage; (10) public API developer misuse
    - Categorize each identified threat by criticality tier: Critical, High, Medium, Low — paired with business-impact context
    - Describe exploitation vectors and enumerate the specific systems, data, or operational domains at risk
    - Treat Blitzy's boundary as strictly read-only: Blitzy must not modify, create, or delete any existing code including inline comments
    - Confirm that all existing functionality remains completely untouched — verified via empty git differential for source code paths (markdown analysis artifacts are exempt per the Audit Only rule)

Implicit requirements surfaced from the user input and cross-referenced against the Kafka codebase reconnaissance:

- A threat-model section must map each of the ten categories to concrete Kafka subsystems (Connect runtime, Tiered Storage, KRaft controller, MirrorMaker 2, OAuth/OIDC SASL, transaction coordinator, delegation tokens, client quotas, native compression codecs, Connect REST extensions, release tooling)
- Every finding must be code-grounded with specific file-path and line-range citations because the deliverable is an audit of a real codebase, not a generic checklist
- Information about pre-existing security mitigations (for example, `MessageDigest.isEqual` constant-time comparison in `DelegationToken`, `DISALLOW_NONE` enforced by `BrokerJwtValidator`, secure default of empty string for `access.control.allow.origin`) must be documented as **accepted mitigations** — not re-reported as vulnerabilities
- A "verify no-change clause" artifact must demonstrate that the audit produced zero modifications to the tracked codebase via `git diff` semantics

### 0.1.2 Special Instructions and Constraints

The following user-specified directives are captured verbatim where the prompt requires exact preservation. Blitzy treats these as non-negotiable execution constraints:

**USER RULE — "Audit Only":** "This run should serve as a dry run for potential changes, research, or documentation. DO NOT modify, create, or delete any existing code in the codebase. Avoid executing any code in the code base, this should be a static analysis. Every deliverable MUST include a markdown file summarizing security vulnerabilities, potential exploits, bugs in the codebase, perofrmace considerations, and remediation recommendations. Verify the NO CHANGES clause by confirming no changes to existing codebase featured in the git differential. Markdown files explicitly related to the analysis performed in this run are permitted."

**USER RULE — "Visual Architecture Documentation":** "All visual documentation MUST use Mermaid diagrams. Diagrams MUST be appropriate to the scope of the work — a migration requires before/after architecture views; a new feature may only need a component interaction and data flow diagram. Every diagram MUST have a descriptive title and legend. Diagrams MUST be referenced by name in accompanying documentation. Do NOT describe architecture in prose when a diagram communicates it more clearly. If the deliverable modifies an existing architecture, both states MUST be shown — never target-state alone."

**USER RULE — "Executive Presentation":** "Every deliverable MUST include an executive summary as a reveal.js HTML artifact using any existing style guides found within the codebase and professional icons (not emojis). The audience is non-technical leadership — communicate business value, risk, and operational readiness without requiring code literacy. Cover what was done, why it was done, what changed architecturally, what risks exist and how they are mitigated, and how the team onboards and continues development. Embed Mermaid diagrams directly in the reveal.js slides. Every slide MUST include at least one visual element — no text-only slides. Scope the presentation to the work performed. A migration warrants before/after architecture views, mapping summaries, and a timeline. A new feature may only need a component diagram and a risk assessment."

**USER EXAMPLE — Vulnerability Categories (must be addressed in their entirety):** "Assess all 10 categories: (1) filesystem access & path traversal; (2) low-level code safety; (3) resource limit evasion; (4) module system & built-in abuse; (5) infinite loop & recursion DoS; (6) network & subprocess access; (7) external function & callback misuse; (8) deserialization attacks; (9) information leakage; (10) public API developer misuse."

**USER EXAMPLE — Severity Model:** "Categorize threats by criticality (Critical, High, Medium, Low) and potential business impact."

**USER EXAMPLE — Boundary Definition:** "Blitzy should not modify, create, or delete any existing code. This includes inline comments." and "All existing features should remain untouched."

**USER EXAMPLE — Minimal Change Clause:** "IMPORTANT: Make no changes, even if absolutely necessary to remediate the identified security vulnerabilities. Focus specifically on identifying the security gaps without modifying code. Your goal is to find vulnerabilities and suggest a path forward for remediation in the future."

Style preferences derived from the three user rules:
- Tone: Executive-grade prose for reveal.js slides; technical-but-plain for the markdown vulnerability report; code-literal for evidence citations
- Structure: Ten-category enumeration (canonical order preserved) with sub-section per Kafka subsystem
- Depth: Each finding documents location, mechanism, attack vector, observable evidence, severity, business impact, and recommended remediation path — without applying any remediation
- Format: Markdown with embedded Mermaid diagrams; reveal.js HTML with embedded Mermaid; professional SVG/icon-font icons (no emojis)

Web-search research requirements identified:
- Validation of Jackson `ALLOW_LEADING_ZEROS_FOR_NUMBERS` security semantics vs. default behavior (already catalogued in reconnaissance)
- CVSS v3.1 scoring guidance for deserialization, SSRF, command-injection, and ReDoS primitives (conceptually applied by the assessor, no external live lookup required because severity is derived from code behavior)
- Confirmation that dependency versions listed in `gradle/dependencies.gradle` (Jackson 2.19.0, Jose4j 0.9.6, Jetty 12.0.22, Jersey 3.1.10, Log4j2 2.25.1, Scala 2.13.17, Bouncy Castle bcpkix 1.80, zstd-jni 1.5.6-10, snappy-java 1.1.10.7, lz4-java 1.8.0, RocksDB 10.1.3, Mockito 5.20.0) are the current stable lines for Kafka 4.2 (validated against repository manifest)

### 0.1.3 Technical Interpretation

These documentation requirements translate to the following technical documentation strategy:

- To document filesystem access and path-traversal exposure, enumerate every on-disk resolver — `FileConfigProvider`, `DirectoryConfigProvider` (with `allowed.paths` allow-list), `EnvVarConfigProvider` (with `allowlist.pattern`), log directory locking in `LogDirFailureChannel`, plugin-path traversal in Connect's `DelegatingClassLoader`, `KafkaCSVMetricsReporter` directory deletion, `FileJwtRetriever` and `JwtBearerJwtRetriever` private-key and assertion files, and `SslStores` temp-directory handling in the ducktape test harness
- To document low-level code safety, catalog native library surfaces — `ZstdCompression` (zstd-jni with `RecyclingBufferPool` and externally supplied `BufferSupplier`), Snappy 1.1.10.7, LZ4 1.8.0, and RocksDB 10.1.3 JNI boundaries — plus the `SimpleMemoryPool` strict vs non-strict allocation semantics
- To document resource-limit evasion, map `SimpleMemoryPool`, `ConnectionQuotas` (per-IP, per-listener, broker-wide; REPLICATION listener exempt), and `ClientRequestQuotaManager` (percentage-based, 10-second sliding window, 1000 ms spike throttle) including the Yammer metric families that expose throttling state
- To document module-system and built-in abuse, enumerate every `ServiceLoader` discovery point — Connect REST extensions, Connect plugins, MirrorMaker `FORWARDING_ADMIN_CLASS`, metrics reporters, OAuth `JwtRetriever`/`JwtValidator`, Tiered Storage RSM/RLMM, `StandardAuthorizer`/`AclMutator` — and the reflective `Class.forName` pathways in `DefaultSslEngineFactory`, `SslFactory`, and pluggable config classes
- To document infinite-loop and recursion DoS surfaces, enumerate all `Pattern.compile` sites (ReDoS primitives — KerberosRule hot-spot with four patterns, JmxReporter INCLUDE/EXCLUDE regex, ConfigTransformer, EnvVarConfigProvider `allowlist.pattern`, ServerConnectionId, ApiVersionsRequest, OAuthBearerClientInitialResponse, KerberosShortNamer, KerberosName, ConfigDef), plus unbounded recursion in `SafeObjectInputStream` graph walks and protocol-record nested-structure decoding
- To document network and subprocess access, record the Connect REST API attack surface (JaasBasicAuthFilter + `INTERNAL_REQUEST_MATCHERS` bypass, PropertyFileLoginModule production-unsuitable default, CrossOriginHandler with secure empty-string default, RestClient forwarding `Authorization` headers), MirrorMaker 2 cross-cluster REST, OAuth token/JWKS retrieval, KRaft Raft RPCs (`VOTE`, `BEGIN/END_QUORUM_EPOCH`, `FETCH`, `ADD/REMOVE/UPDATE_RAFT_VOTER`), and release tooling subprocess execution (`release.py` lines 334–362 with `shell=True` and f-string interpolation)
- To document external function and callback misuse, enumerate the `OAuthBearerValidatorCallbackHandler` unconditional SASL-extension acceptance, `OAuthBearerUnsecuredValidatorCallbackHandler` (accepts `alg:none`), the `RestClient` outbound `Authorization` forwarding vector, and Connect converter/transform plugin reflection sites
- To document deserialization attacks, enumerate the `Deserializer` interface family, `SafeObjectInputStream` suffix-matching blocklist, `JsonDeserializer` with `ALLOW_LEADING_ZEROS_FOR_NUMBERS`, `JsonUtil.ACCEPT_SINGLE_VALUE_AS_ARRAY` in Trogdor, `Checkpoint.deserializeRecord`, and OAuth JWT parsing in `BrokerJwtValidator`/`ClientJwtValidator`
- To document information leakage, record `Password.HIDDEN = "[hidden]"` vs `RecordRedactor` "(redacted)" vs `ConfigurationImageNode` "[redacted]" marker inconsistency; JMX metric exposure; DEBUG-level JWT claim logging; `DelegationToken.toString()` HMAC placeholder masking (accepted mitigation); and error-message enumeration surfaces
- To document public API developer misuse, enumerate insecure defaults (PLAINTEXT listener protocol, GSSAPI default in SASL mechanism, `PropertyFileLoginModule`, `OAuthBearerUnsecuredValidatorCallbackHandler`, `SSL_ALLOW_DN_CHANGES`/`SSL_ALLOW_SAN_CHANGES`, empty `access.control.allow.origin`, `allow.everyone.if.no.acl.found`, `sasl.server.callback.handler.class` mis-wiring risks)

For each interpretation above, the deliverable will produce a markdown finding of the form: "To document [vulnerability vector], we will create `docs/security-audit/findings/<category>.md` referencing [specific Kafka source files] and [specific line ranges]."

### 0.1.4 Inferred Documentation Needs

Based on code analysis conducted during Phase 3 reconnaissance, the following documentation gaps are inferred and will be filled by audit artifacts:

- Based on code analysis: Connect REST runtime contains a production-unsuitable default (`PropertyFileLoginModule`) and an authentication-bypass matcher (`INTERNAL_REQUEST_MATCHERS` in `JaasBasicAuthFilter`) that lack a consolidated operator-facing security advisory in the repository
- Based on structure: Kafka's ten-category vulnerability surface spans multiple modules (clients, core, connect, raft, metadata, coordinator modules, storage, server-common, tools, trogdor, release) requiring a consolidated threat-model document that crosses module boundaries
- Based on dependencies: Integration between `zstd-jni` (native), `BufferSupplier` (Kafka-owned), and `ChunkedBytesStream` (Kafka-owned) requires an interface-contract narrative documenting the trust boundary between Java-heap buffer management and the native JNI layer
- Based on user journey: A non-technical executive audience requires a reveal.js briefing narrating what the audit examined, why the audit was commissioned, what architectural risk surfaces were discovered, and what mitigations already exist — without exposing code literacy
- Based on reconnaissance: Several mitigations are in place and under-documented — `MessageDigest.isEqual` for delegation-token HMAC comparison, `DISALLOW_NONE` JWT algorithm enforcement in `BrokerJwtValidator`, REPLICATION listener exemption from broker-wide connection caps, copy-on-write `StandardAuthorizerData` with DENY-over-ALLOW precedence, and `AclControlManager.MAX_RECORDS_PER_USER_OP` — warranting explicit documentation as "positive-security posture" artifacts to avoid future regression
- Based on pattern-matching: ReDoS exposure centralizes in `KerberosRule.java` (four `Pattern.compile` sites), `JmxReporter.java` (INCLUDE/EXCLUDE filters), and `ConfigDef.java` — requiring a regex inventory per the category-5 taxonomy
- Based on command-injection analysis: `release.py` lines 334–362 use `shell=True` with f-string interpolation for filename variables (`gpg --print-md`, `cp` of build distribution artifacts, `./gradlew publish`, `mvn deploy`). Scope is release-engineer privilege context only (not runtime), but it warrants explicit mention in the category-7 (command injection / subprocess) finding for completeness


## 0.2 Documentation Discovery and Analysis

### 0.2.1 Existing Documentation Infrastructure Assessment

Repository analysis reveals a mature, multi-surface documentation estate centered on user-facing documentation in the `docs/` tree, KIP-driven design docs, Javadoc-generated API references, per-module `README.md` files, and ducktape system-test documentation. Coverage of security-specific threat modeling is sparse — the repository documents how to configure security (SSL, SASL, ACLs, OAuth) but does not consolidate a code-grounded vulnerability audit.

- Current documentation framework: **Jekyll-style static site (Apache Kafka docs)** generated from the `docs/` tree into `kafka.apache.org/documentation/`; **Javadoc** generated by Gradle `javadoc` tasks across published modules; **KIPs (Kafka Improvement Proposals)** linked from Confluence wiki; per-module markdown READMEs
- Documentation generator configuration:
    - Root `docs/` directory contains HTML templates and Markdown fragments for the official Kafka docs site
    - Javadoc output is produced by each module's `build.gradle` `javadoc` task and published to Apache Maven Central under classifier `javadoc`
    - No repository-local MkDocs, Docusaurus, or Sphinx configuration was observed
- API documentation tools in use:
    - Javadoc (generated by Gradle) for all public Java APIs in `clients/`, `streams/`, `connect/api/`, `connect/runtime/`, `connect/json/`, `storage/`, `server-common/`
    - Scaladoc for Scala sources in `core/`
- Diagram tools detected: No centralized Mermaid/PlantUML convention observed in the repo's docs site; individual markdown READMEs occasionally embed ASCII diagrams. The "Visual Architecture Documentation" user rule mandates Mermaid for this audit's diagrams
- Documentation hosting/deployment: Apache infrastructure via the Kafka project's website repository; not a concern for this audit since deliverables are isolated under `docs/security-audit/`

### 0.2.2 Repository Code Analysis for Documentation

Search patterns used for code to document, grouped by the ten vulnerability categories. Key directories examined during Phase 3 reconnaissance are documented in full in Section 0.10 (References).

- Filesystem access and path traversal:
    - `clients/src/main/java/org/apache/kafka/common/config/provider/` — FileConfigProvider, DirectoryConfigProvider (`allowed.paths`), EnvVarConfigProvider (`allowlist.pattern`)
    - `core/src/main/scala/kafka/log/` and `storage/src/main/java/org/apache/kafka/storage/internals/log/` — log.dirs, LogDirFailureChannel, per-directory FileLock + UUID mechanisms
    - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/` — DelegatingClassLoader, PluginUtils, plugin.path resolution
    - `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/secured/` — FileJwtRetriever, JwtBearerJwtRetriever
    - `core/src/main/scala/kafka/metrics/KafkaCSVMetricsReporter.scala` — directory deletion via `Utils.delete`
- Low-level code safety / native library integration:
    - `clients/src/main/java/org/apache/kafka/common/compress/` — ZstdCompression (zstd-jni), LZ4 wrappers, Snappy wrappers
    - `streams/src/main/java/org/apache/kafka/streams/state/internals/` — RocksDBStore JNI boundary
    - `clients/src/main/java/org/apache/kafka/common/memory/SimpleMemoryPool.java` — allocation strict/non-strict modes
- Resource-limit evasion:
    - `core/src/main/scala/kafka/network/ConnectionQuotas.scala` — per-IP, per-listener, broker-wide caps; REPLICATION exemption
    - `core/src/main/scala/kafka/server/ClientRequestQuotaManager.scala`, `ClientQuotaManager.scala` — request/produce/consume quotas with 10-second sliding window
    - `core/src/test/scala/unit/kafka/network/ConnectionQuotasTest.scala`, `DynamicConnectionQuotaTest.scala` — test evidence for enforcement
- Module system and built-in abuse:
    - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/` — PluginClassLoader, DelegatingClassLoader, ReflectionScanner
    - `connect/runtime/src/main/java/org/apache/kafka/connect/rest/` — ConnectRestExtension SPI via ServiceLoader
    - `metadata/src/main/java/org/apache/kafka/metadata/authorizer/` — StandardAuthorizer, AclMutator
    - `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/` — JwtRetriever/JwtValidator plugin interfaces
    - `storage/api/src/main/java/org/apache/kafka/server/log/remote/storage/` — RemoteStorageManager, RemoteLogMetadataManager, ClassLoaderAware wrappers
- Infinite-loop and recursion DoS:
    - Ten non-test Pattern.compile call sites enumerated in reconnaissance (KerberosRule, KerberosName, KerberosShortNamer, JmxReporter, ConfigDef, ConfigTransformer, EnvVarConfigProvider, ServerConnectionId, ApiVersionsRequest, OAuthBearerClientInitialResponse)
    - `clients/src/main/java/org/apache/kafka/common/utils/SafeObjectInputStream.java` — recursion-bounded deserialization blocklist
- Network and subprocess access:
    - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServer.java` — CrossOriginHandler (lines 274–284), listener wiring
    - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java` — CORS defaults (lines 72–82)
    - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestClient.java` — outbound Authorization header forwarding
    - `connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/` — JaasBasicAuthFilter, BasicAuthSecurityRestExtension, PropertyFileLoginModule
    - `raft/src/main/java/org/apache/kafka/raft/KafkaRaftClient.java` — VOTE, BEGIN/END_QUORUM_EPOCH, FETCH, ADD/REMOVE/UPDATE_RAFT_VOTER RPCs
    - `release/release.py`, `release/runtime.py` — subprocess execution with `shell=True`
- External function and callback misuse:
    - `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java` — production-unsuitable default
    - `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/OAuthBearerValidatorCallbackHandler.java` — unconditional SASL extension acceptance
    - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestClient.java` — propagates caller-supplied Authorization header
- Deserialization attacks:
    - `connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java` — `ALLOW_LEADING_ZEROS_FOR_NUMBERS.mappedFeature()` enabled (line 57)
    - `trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java` — `ACCEPT_SINGLE_VALUE_AS_ARRAY` enabled (line 39)
    - `clients/src/main/java/org/apache/kafka/common/utils/SafeObjectInputStream.java` — suffix-matching blocklist
    - `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/secured/BrokerJwtValidator.java`, `ClientJwtValidator.java` — JWT parsing dual architecture
- Information leakage:
    - `clients/src/main/java/org/apache/kafka/common/config/types/Password.java` — `HIDDEN = "[hidden]"`
    - Connect `RecordRedactor` — "(redacted)"
    - Metadata `ConfigurationImageNode` — "[redacted]"
    - `clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java` — toString masks HMAC
    - JMX metrics registration across `JmxReporter`, `KafkaYammerMetrics`, Connect metrics
- Public API developer misuse (insecure defaults):
    - `clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java` — SSL default constants
    - `clients/src/main/java/org/apache/kafka/clients/CommonClientConfigs.java` — PLAINTEXT default
    - `clients/src/main/java/org/apache/kafka/common/config/SaslConfigs.java` — SASL mechanism defaults
    - `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java` — empty `access.control.allow.origin` default

Related documentation found that provides context:
- `docs/security.html` (Apache Kafka security documentation) — describes SSL/SASL configuration but does not enumerate threat surfaces
- `docs/ops.html` — operational guidance, touches on JMX exposure
- KIP references for KRaft (KIP-500, KIP-631, KIP-853) and OAuth (KIP-768)

### 0.2.3 Web Search Research Conducted

No live web searches are required because all vulnerability assessment conclusions derive from in-repository evidence. The following knowledge areas were applied from static analysis alone, cross-referenced against the repository's dependency manifest (`gradle/dependencies.gradle`):

- Best practices for security-vulnerability classification: CVSS v3.1 base metrics (attack vector, attack complexity, privileges required, user interaction, scope, confidentiality/integrity/availability impact) are applied conceptually to each finding
- Documentation structure conventions for security assessments: OWASP Top Ten structural pattern (one section per category, evidence + severity + remediation) adapted to the user's ten-category list
- Recommended diagram types for security threat models: STRIDE-style data-flow diagrams with trust-boundary annotations, attack-surface component maps, and authentication/authorization decision graphs — all rendered in Mermaid per the "Visual Architecture Documentation" user rule
- Tools and techniques for maintaining documentation: Markdown + Mermaid inline, reveal.js for executive slides — matches the "Executive Presentation" user rule

Explicit validation performed against the Kafka repository's `gradle/dependencies.gradle`:
- Jackson 2.19.0 — confirmed (line 66)
- Jose4j 0.9.6 — confirmed (line 81)
- Jetty 12.0.22 — confirmed (line 69)
- Jersey 3.1.10 — confirmed (line 70)
- Log4j2 2.25.1 — confirmed (line 108)
- LZ4-java 1.8.0 — confirmed (line 110)
- RocksDB 10.1.3 — confirmed (line 118)
- snappy-java 1.1.10.7 — confirmed (line 125)
- zstd-jni 1.5.6-10 — confirmed (line 131)
- Gradle 9.1.0 — confirmed (line 63)
- Scala 2.13.x — default via `defaultScala213Version` (line 29)
- Bouncy Castle bcpkix 1.80 — confirmed (line 56)
- Mockito 5.20.0 — confirmed (line 113) (test-only)


## 0.3 Documentation Scope Analysis

### 0.3.1 Code-to-Documentation Mapping

Every Kafka subsystem below is documented in the audit deliverables. The table in Section 0.5 links each documentation file to its evidentiary sources.

- **Connect REST runtime (HTTP trust-boundary surface)**:
    - Public APIs: REST handler classes under `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/resources/` and the `ConnectRestExtension` SPI
    - Documentation needed: authentication & authorization architecture, CORS configuration, SSRF vector analysis in `RestClient`, Basic-auth internal-request bypass
    - Current in-repo documentation: partial — `docs/connect.html` describes the API surface but does not enumerate the `JaasBasicAuthFilter` bypass or warn about the `PropertyFileLoginModule` default
- **OAuth/OIDC SASL stack**:
    - Public APIs: `JwtValidator`, `JwtRetriever`, `AuthenticateCallbackHandler`
    - Documentation needed: dual-validator architecture (`BrokerJwtValidator` jose4j with `DISALLOW_NONE` vs. `ClientJwtValidator` structural-only), unsecured validator's `alg:none` acceptance, SASL extension unconditional acceptance
    - Current in-repo documentation: minimal — `SaslConfigs.java` documents configuration keys but the security posture of defaults is not consolidated
- **StandardAuthorizer (KRaft)**:
    - Public APIs: `Authorizer`, `ClusterMetadataAuthorizer`, `AclMutator`
    - Documentation needed: copy-on-write `StandardAuthorizerData`, DENY-over-ALLOW precedence, literal-only resource pattern matching, `AuthorizerNotReadyException` semantics, `MAX_RECORDS_PER_USER_OP` bounded-list guard
    - Current in-repo documentation: Javadoc on `Authorizer` but no threat-model view of ACL cache integrity
- **KRaft controller / Raft quorum**:
    - Public APIs: `KafkaRaftClient`, `QuorumState`, `VoterSet`, `UpdateVoterHandler`
    - Documentation needed: cluster-id + topic-partition + voter-key consistency validation, leader-epoch fencing, `VoterSet.hasOverlappingMajority` safety check for reconfiguration, `CLUSTER_AUTHORIZATION_FAILED` propagation
    - Current in-repo documentation: KIP-500/595/853 but no security-surface view
- **Transaction coordinator**:
    - Public APIs: `TransactionCoordinator`, `AddPartitionsToTxnManager`, `FenceProducersHandler`
    - Documentation needed: 2PC-disabled path rejecting with `TRANSACTIONAL_ID_AUTHORIZATION_FAILED`, epoch-based fencing (`PRODUCER_FENCED` → `INVALID_PRODUCER_EPOCH`), `unclean.leader.election` blocked for transactional topics
    - Current in-repo documentation: limited — KIP-98 describes EOS but security-error mapping is scattered
- **MirrorMaker 2 cross-cluster**:
    - Public APIs: `MirrorSourceConnector`, `MirrorClientConfig`, `MirrorMakerConfig`
    - Documentation needed: `syncTopicAcls` downgrades `ALLOW ALL` → `ALLOW READ` (security hardening), eager vs lazy secret resolution (`MirrorClientConfig` eagerly materializes, `connectorBaseConfig` preserves placeholders), `FORWARDING_ADMIN_CLASS` plugin risk
    - Current in-repo documentation: KIP-382 + `docs/connect-mirror-maker.html` but without the secret-resolution timing analysis
- **Client network / quotas**:
    - Public APIs: `ConnectionQuotas`, `ClientRequestQuotaManager`, `SimpleMemoryPool`
    - Documentation needed: REPLICATION listener exemption from broker-wide caps, percentage-based request quota with 10-second sliding window, non-strict memory pool allowing temporary over-allocation
    - Current in-repo documentation: `docs/ops.html` references quota configuration but does not cover the DoS-resistance properties
- **Native compression**:
    - Public APIs: `ZstdCompression`, `SnappyCompression`, `Lz4Compression`
    - Documentation needed: zstd-jni integration with Kafka-supplied `BufferSupplier` (avoiding zstd-jni's global soft-reference pools), bounded decompression chunk size (16 KB), `KafkaException` wrapping for all `Throwable`s
    - Current in-repo documentation: Javadoc on compression types but no native-boundary threat surface
- **Delegation tokens**:
    - Public APIs: `DelegationToken`, `DelegationTokenManager`
    - Documentation needed: `MessageDigest.isEqual` constant-time HMAC comparison (accepted mitigation), `toString()` HMAC placeholder masking, final-field immutability
    - Current in-repo documentation: KIP-48 introduces delegation tokens; security properties of the value object are not consolidated
- **Release tooling**:
    - Public APIs: `release/release.py`, `release/runtime.py`
    - Documentation needed: `shell=True` with f-string interpolation at lines 334–362 (`./gradlew` build/publish, `cp` of distribution artifacts, `gpg --print-md`, `mvn deploy`) — release-engineer privilege context only
    - Current in-repo documentation: `release/README.md` describes the flow but not the command-injection posture

Configuration options requiring documentation (security-relevant subset):
- Config file: `clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java`
- Options documented: all keys (26 constants) are Javadoc-documented
- Missing documentation: consolidated security-posture view across `ssl.endpoint.identification.algorithm` (default `https`), `ssl.client.auth` (default `none`), `ssl.enabled.protocols` (default `TLSv1.2,TLSv1.3`), `ssl.protocol` (default `TLSv1.3`), `SSL_ALLOW_DN_CHANGES_CONFIG`, `SSL_ALLOW_SAN_CHANGES_CONFIG`
- Additional configs with insecure-by-default posture requiring narrative documentation:
    - `access.control.allow.origin` (Connect REST) — empty default (secure — must be documented as such)
    - `allow.everyone.if.no.acl.found` — false default (secure)
    - `auto.create.topics.enable` — true by default (accessibility/DoS consideration)
    - `unclean.leader.election.enable` — false default (safe for transactions)
    - `sasl.enabled.mechanisms` — defaults to `GSSAPI` only (Kerberos-only posture)
    - `controller.quorum.auto.join.enable` — false default (security posture)

Features requiring user guides (security-audit perspective):
- Feature: **Secure defaults and insecure-by-default watchlist**
    - Current coverage: fragmented across individual configuration docs
    - Gaps: consolidated matrix of every default that affects security posture, with operator checklist
- Feature: **Authentication bypass surfaces**
    - Current coverage: none
    - Gaps: enumeration of super-user bypass, `allow.everyone.if.no.acl.found`, `INTERNAL_REQUEST_MATCHERS`, `OAuthBearerUnsecuredValidatorCallbackHandler`, JMX auth-disabled test defaults, transaction-coordinator 2PC-disabled path
- Feature: **Deserialization attack surface**
    - Current coverage: scattered warnings in Javadoc
    - Gaps: consolidated inventory with explicit JSON feature flags enabled, Jackson version, suffix-matching blocklist limitations
- Feature: **Dependency supply chain**
    - Current coverage: `LICENSE-binary` and `NOTICE-binary` list dependencies; OWASP Dependency Check (12.1.8) and Trivy are configured in CI
    - Gaps: operator-facing cross-reference between Kafka version and known-good upstream dependency versions, and the `ServiceLoader` discovery attack surface they collectively expose

### 0.3.2 Documentation Gap Analysis

Given the requirements and repository analysis, documentation gaps include:

- **Undocumented public threat surface**:
    - `JaasBasicAuthFilter.INTERNAL_REQUEST_MATCHERS` — permits unauthenticated `POST /connectors/{name}/tasks` and `PUT /connectors/{name}/fence`; not surfaced in any operator-facing guide
    - `RestClient` forwarding inbound `Authorization` headers to outbound URLs when connecting worker-to-worker — SSRF / token-leak vector
    - `JmxTool` authentication disabled in integration-test defaults — not an operator default but warrants documentation
- **Missing security posture guides**:
    - Consolidated "insecure-by-default watchlist" (PLAINTEXT listener, GSSAPI, `ALLOW_LEADING_ZEROS_FOR_NUMBERS`, `PropertyFileLoginModule`, `OAuthBearerUnsecuredValidatorCallbackHandler`, `SSL_ALLOW_DN_CHANGES`/`SAN_CHANGES`)
    - Operator checklist for hardening a KRaft cluster prior to production exposure
    - Supply-chain advisory walkthrough (dependency manifest → upstream advisory lookup pathway)
- **Incomplete architecture documentation**:
    - Threat-model diagram showing data flow across producer → broker → KRaft controller → consumer boundaries with trust-zone annotations
    - Attack-surface map overlaying the ten vulnerability categories onto Kafka modules
    - Authorization decision flow for `StandardAuthorizer` including super-user bypass, literal-pattern enforcement, DENY precedence, and `AclCache` consistency invariants
    - KRaft quorum reconfiguration safety (overlapping-majority constraint, pre-vote semantics, epoch monotonicity)
- **Outdated / implicit documentation**:
    - `Password.HIDDEN` redaction marker ("[hidden]") diverges from `RecordRedactor` "(redacted)" and `ConfigurationImageNode` "[redacted]" — inconsistent across subsystems; worth documenting for log-parsing integrators even though the audit proposes no code change
    - `DelegationToken` security properties (`MessageDigest.isEqual`, toString masking) — mitigations implemented but under-documented


## 0.4 Documentation Implementation Design

### 0.4.1 Documentation Structure Planning

All audit artifacts are isolated under a dedicated `docs/security-audit/` tree created specifically for this assessment. This isolation satisfies the "Audit Only" rule — the tree is introduced purely as analysis output and contains no modifications to existing Kafka documentation, source code, tests, build files, or comments.

```
docs/security-audit/
├── README.md                                   (audit overview and navigation)
├── executive-summary.html                      (reveal.js HTML slide deck)
├── findings/
│   ├── 01-filesystem-access-path-traversal.md
│   ├── 02-low-level-code-safety.md
│   ├── 03-resource-limit-evasion.md
│   ├── 04-module-system-builtin-abuse.md
│   ├── 05-infinite-loop-recursion-dos.md
│   ├── 06-network-subprocess-access.md
│   ├── 07-external-function-callback-misuse.md
│   ├── 08-deserialization-attacks.md
│   ├── 09-information-leakage.md
│   └── 10-public-api-developer-misuse.md
├── diagrams/
│   ├── threat-model-overview.md                (Mermaid: trust boundaries + data flow)
│   ├── attack-surface-map.md                   (Mermaid: ten-category × module matrix)
│   ├── authorization-decision-flow.md          (Mermaid: StandardAuthorizer flowchart)
│   ├── kraft-quorum-safety.md                  (Mermaid: voter-set reconfig + epoch fencing)
│   ├── connect-rest-trust-boundary.md          (Mermaid: REST + JaasBasicAuthFilter)
│   ├── oauth-jwt-validation-paths.md           (Mermaid: broker vs client validator)
│   └── native-compression-boundary.md          (Mermaid: JVM ↔ JNI buffer ownership)
├── severity-matrix.md                          (tabular Critical/High/Medium/Low with business impact)
├── remediation-roadmap.md                      (recommended future actions — NO code changes now)
├── accepted-mitigations.md                     (existing protections: MessageDigest.isEqual, DISALLOW_NONE, etc.)
├── dependency-inventory.md                     (version table + supply-chain surface)
├── no-change-verification.md                   (git diff evidence confirming zero source changes)
└── references.md                               (consolidated bibliography of file citations)
```

Rationale for the structure:

- The `findings/` tree has exactly ten files, one per user-specified vulnerability category, numbered `01`–`10` in the exact order the user supplied — preserving the verbatim enumeration from the "USER EXAMPLE — Vulnerability Categories" directive
- `diagrams/` collects every Mermaid diagram in standalone markdown fragments so each diagram is a self-contained reviewable unit; the main findings documents reference these by name ("see `diagrams/threat-model-overview.md`") per the "Visual Architecture Documentation" user rule
- `executive-summary.html` is the single reveal.js artifact satisfying the "Executive Presentation" user rule and embeds Mermaid diagrams directly
- `no-change-verification.md` holds the `git diff --name-status` evidence proving the "Audit Only" rule was honored — only new files under `docs/security-audit/` appear in the diff

### 0.4.2 Content Generation Strategy

Information Extraction Approach:

- Extract ten-category mapping from the reconnaissance inventory already compiled during Phase 3 (see section 0.3.1)
- Cite every finding with an exact file path and line range using the format `Source: path/to/file.java:L<start>-L<end>` as inline references within each finding
- Generate examples by referencing existing integration tests (for example `AuthorizerIntegrationTest.scala`, `DynamicConnectionQuotaTest.scala`, `MirrorConnectorsIntegrationSSLTest.java`) — no new test code is authored; examples are read-only citations
- Create diagrams by mapping the component relationships discovered in reconnaissance: Connect REST → `JaasBasicAuthFilter` → `INTERNAL_REQUEST_MATCHERS` bypass; KRaft `KafkaRaftClient` → `QuorumState` → `VoterSet` → election state persistence; OAuth `OAuthBearerLoginCallbackHandler` → `JwtRetriever` → `JwtValidator` with dual broker/client split

Template Application:

- Each of the ten findings documents follows an identical structure: **Category** → **Definition** → **Kafka Surface Inventory** → **Evidence (file-path + line-range citations)** → **Attack Vector** → **Severity (Critical/High/Medium/Low)** → **Business Impact** → **Accepted Mitigations Already Present** → **Recommended Future Remediation (no changes in this run)**
- The reveal.js deck follows the user's explicit "Executive Presentation" scope: what was done, why, what architectural risk surfaces exist, how the team onboards, and how mitigations are structured — scoped to the work performed (an audit, so single-state view; no before/after)
- Every slide carries at least one visual element (Mermaid diagram, icon, or matrix) — honoring the "every slide MUST include at least one visual element — no text-only slides" user rule

Documentation Standards:

- Markdown formatting with `#`, `##`, `###` headers, consistent depth across findings
- Mermaid diagrams integrated using ` ```mermaid ` fenced blocks with descriptive titles (`title`) and legends rendered as subgraph clusters or inline annotations per the "Visual Architecture Documentation" user rule
- Code excerpts use fenced ` ```java `, ` ```scala `, or ` ```python ` blocks with syntax highlighting; excerpts are kept to 2–3 lines each to minimize repository-copyright exposure and maintain clarity
- Source citations inline: `Source: clients/src/main/java/org/apache/kafka/common/utils/SafeObjectInputStream.java:L42-L58`
- Tables for parameter descriptions, severity, dependency versions, and coverage matrices
- Consistent terminology: "finding" (a reported issue), "mitigation" (an existing protection), "vector" (an attack path), "surface" (an attackable component)

### 0.4.3 Diagram and Visual Strategy

Mermaid diagrams produced (each with descriptive title and legend per user rule):

- **Threat Model Overview** (`diagrams/threat-model-overview.md`):
    - Shows producers, consumers, brokers, KRaft controllers, MirrorMaker 2, Connect workers, ZooKeeper (legacy, not applicable to 4.2), external auth providers (SASL/OAuth), SSL/TLS boundaries
    - Trust-boundary annotations between untrusted clients, semi-trusted Connect plugins, and the trusted broker cluster
    - Legend distinguishes transport boundaries (solid), trust boundaries (dashed), plugin extension points (dotted)
- **Attack Surface Map** (`diagrams/attack-surface-map.md`):
    - Component diagram cross-referencing ten vulnerability categories against Kafka modules (clients, core, connect, raft, metadata, coordinator-*, storage, server-common, tools, trogdor, release)
    - Legend encodes severity by color: red=Critical, orange=High, yellow=Medium, green=Low
- **Authorization Decision Flow** (`diagrams/authorization-decision-flow.md`):
    - Flowchart for `StandardAuthorizer.authorize`: super-user bypass → `loadingComplete` check → `AclCache` lookup via `MatchingRuleBuilder` → DENY precedence → ALLOW implication rules → audit-log emission
    - Legend identifies deny paths, allow paths, and audit-only paths
- **KRaft Quorum Safety** (`diagrams/kraft-quorum-safety.md`):
    - Sequence + state diagram covering `QuorumState` transitions, `VoterSet.hasOverlappingMajority` enforcement during `AddVoter`/`RemoveVoter`/`UpdateVoter`, leader-epoch monotonicity, pre-vote semantics
    - Legend distinguishes durable transitions (solid) from in-memory transitions (dashed)
- **Connect REST Trust Boundary** (`diagrams/connect-rest-trust-boundary.md`):
    - Sequence diagram for an inbound REST request: reverse proxy → Jetty `CrossOriginHandler` → `JaasBasicAuthFilter` (with `INTERNAL_REQUEST_MATCHERS` escape path) → resource handler → `RestClient` forwarding call with `Authorization` header
    - Legend marks the bypass and the forwarding hazards
- **OAuth JWT Validation Paths** (`diagrams/oauth-jwt-validation-paths.md`):
    - Flowchart distinguishing `BrokerJwtValidator` (jose4j with `DISALLOW_NONE`) from `ClientJwtValidator` (structural only), plus the `OAuthBearerUnsecuredValidatorCallbackHandler` legacy path accepting `alg:none`
    - Legend identifies signed vs unsigned paths
- **Native Compression Boundary** (`diagrams/native-compression-boundary.md`):
    - Component diagram showing JVM-side `BufferSupplier` + `ChunkedBytesStream` interacting with zstd-jni via `RecyclingBufferPool`; explicit 16 KB chunk-size limit
    - Legend identifies Kafka-owned resources vs. JNI-owned resources

Screenshot/image requirements:

- No screenshots are required because the audit is purely code-grounded
- Professional icons in reveal.js slides: use SVG icon fonts (Font Awesome via CDN or embedded as inline SVG). No emojis per the "Executive Presentation" user rule

Architecture diagram specifications:

- Because the deliverable modifies no architecture, only the current-state view is shown — explicitly honoring the conditional in the "Visual Architecture Documentation" rule ("If the deliverable modifies an existing architecture, both states MUST be shown — never target-state alone")
- No before/after views are produced because there is no "before" and there will be no "after" within this run


## 0.5 Documentation File Transformation Mapping

### 0.5.1 File-by-File Documentation Plan

The table below enumerates EVERY documentation file to be created during this audit. Consistent with the "Audit Only" user rule, only CREATE operations appear — no existing documentation or source files are updated, deleted, or modified. The transformation modes used are:

- **CREATE** — Create a new documentation file under `docs/security-audit/`
- **REFERENCE** — Cite an existing source code or existing docs file as evidence (read-only)

No UPDATE or DELETE operations exist in this audit because that would violate the "Audit Only" and "Minimal Change Clause" user directives.

| Target Documentation File | Transformation | Source Code / Docs (Evidence) | Content / Changes |
|---------------------------|----------------|-------------------------------|-------------------|
| docs/security-audit/README.md | CREATE | N/A (navigation index) | Audit scope, methodology, audience, ten-category enumeration, navigation to all other audit artifacts, Audit Only rule statement |
| docs/security-audit/executive-summary.html | CREATE | All findings documents | reveal.js HTML deck covering what was audited, why, what risks exist, how mitigations are structured, onboarding, continued development. Embeds Mermaid. Every slide has at least one visual element. Professional SVG icons, no emojis. |
| docs/security-audit/findings/01-filesystem-access-path-traversal.md | CREATE | clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java, DirectoryConfigProvider.java, EnvVarConfigProvider.java; core/src/main/scala/kafka/log/LogManager.scala; storage/src/main/java/org/apache/kafka/storage/internals/log/LogDirFailureChannel.java; connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java; core/src/main/scala/kafka/metrics/KafkaCSVMetricsReporter.scala; clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/secured/FileJwtRetriever.java, JwtBearerJwtRetriever.java | Category 1 finding: on-disk path resolvers, allow-list semantics, directory deletion surface, JWT file reads. Per-finding template: Definition → Kafka Surface → Evidence (file:line) → Attack Vector → Severity → Business Impact → Accepted Mitigations → Recommended Future Remediation. |
| docs/security-audit/findings/02-low-level-code-safety.md | CREATE | clients/src/main/java/org/apache/kafka/common/compress/ZstdCompression.java; clients/src/main/java/org/apache/kafka/common/memory/SimpleMemoryPool.java; streams/src/main/java/org/apache/kafka/streams/state/internals/RocksDBStore.java; gradle/dependencies.gradle (zstd-jni 1.5.6-10, snappy-java 1.1.10.7, lz4-java 1.8.0, rocksdbjni 10.1.3) | Category 2 finding: native JNI surfaces, buffer ownership trust boundary, KafkaException wrapping, memory-pool allocation modes. |
| docs/security-audit/findings/03-resource-limit-evasion.md | CREATE | core/src/main/scala/kafka/network/ConnectionQuotas.scala; core/src/main/scala/kafka/server/ClientRequestQuotaManager.scala, ClientQuotaManager.scala; clients/src/main/java/org/apache/kafka/common/memory/SimpleMemoryPool.java | Category 3 finding: per-IP/per-listener/broker-wide connection caps, REPLICATION exemption, percentage-based request throttling with 10-second window, 1000 ms spike throttle behavior, non-strict memory pool over-allocation. |
| docs/security-audit/findings/04-module-system-builtin-abuse.md | CREATE | connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginClassLoader.java, DelegatingClassLoader.java; connect/runtime/src/main/java/org/apache/kafka/connect/rest/ConnectRestExtension.java; storage/api/src/main/java/org/apache/kafka/server/log/remote/storage/RemoteStorageManager.java, RemoteLogMetadataManager.java; metadata/src/main/java/org/apache/kafka/metadata/authorizer/ClusterMetadataAuthorizer.java, AclMutator.java; clients/src/main/java/org/apache/kafka/common/security/oauthbearer/JwtValidator.java, JwtRetriever.java | Category 4 finding: ServiceLoader discovery points, URLClassLoader isolation model, plugin.path resolution, reflective instantiation in SslEngineFactory. |
| docs/security-audit/findings/05-infinite-loop-recursion-dos.md | CREATE | clients/src/main/java/org/apache/kafka/common/security/kerberos/KerberosRule.java (4× Pattern.compile); KerberosName.java, KerberosShortNamer.java; clients/src/main/java/org/apache/kafka/common/metrics/JmxReporter.java (2× Pattern.compile); clients/src/main/java/org/apache/kafka/common/config/ConfigDef.java, ConfigTransformer.java; clients/src/main/java/org/apache/kafka/common/config/provider/EnvVarConfigProvider.java; clients/src/main/java/org/apache/kafka/common/network/ServerConnectionId.java; clients/src/main/java/org/apache/kafka/common/requests/ApiVersionsRequest.java; clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/OAuthBearerClientInitialResponse.java; clients/src/main/java/org/apache/kafka/common/utils/SafeObjectInputStream.java | Category 5 finding: ten Pattern.compile sites inventoried for ReDoS potential, SafeObjectInputStream blocklist-based unbounded-depth mitigation, recursion boundaries. |
| docs/security-audit/findings/06-network-subprocess-access.md | CREATE | connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServer.java (lines 260-300); RestServerConfig.java (lines 60-100); RestClient.java; connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/JaasBasicAuthFilter.java; raft/src/main/java/org/apache/kafka/raft/KafkaRaftClient.java; raft/src/main/java/org/apache/kafka/raft/internals/UpdateVoterHandler.java; release/release.py (lines 334-362); release/runtime.py | Category 6 finding: Connect REST trust-boundary, CrossOriginHandler with secure default, JaasBasicAuthFilter INTERNAL_REQUEST_MATCHERS bypass, RestClient Authorization forwarding SSRF vector, KRaft RPCs with cluster-id validation, release tooling subprocess with shell=True and f-string interpolation. |
| docs/security-audit/findings/07-external-function-callback-misuse.md | CREATE | clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java; clients/src/main/java/org/apache/kafka/common/security/oauthbearer/OAuthBearerValidatorCallbackHandler.java; connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestClient.java; connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginUtils.java | Category 7 finding: unsecured callback accepting alg:none, unconditional SASL-extension acceptance, Authorization header forwarding, plugin ServiceLoader discovery. |
| docs/security-audit/findings/08-deserialization-attacks.md | CREATE | connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L57 (ALLOW_LEADING_ZEROS_FOR_NUMBERS); trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L39 (ACCEPT_SINGLE_VALUE_AS_ARRAY); clients/src/main/java/org/apache/kafka/common/utils/SafeObjectInputStream.java; clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/secured/BrokerJwtValidator.java, ClientJwtValidator.java; streams/src/main/java/org/apache/kafka/streams/processor/internals/Checkpoint.java | Category 8 finding: JSON feature flags enabled, Jackson 2.19.0 pinning, SafeObjectInputStream suffix-matching blocklist limitations, dual JWT validator architecture, Checkpoint.deserializeRecord, Raft control records. |
| docs/security-audit/findings/09-information-leakage.md | CREATE | clients/src/main/java/org/apache/kafka/common/config/types/Password.java (HIDDEN = "[hidden]"); connect/runtime/src/main/java/org/apache/kafka/connect/runtime/RecordRedactor.java ("(redacted)"); metadata/src/main/java/org/apache/kafka/image/node/ConfigurationImageNode.java ("[redacted]"); clients/src/main/java/org/apache/kafka/common/security/token/delegation/DelegationToken.java (toString masking); clients/src/main/java/org/apache/kafka/common/metrics/JmxReporter.java | Category 9 finding: redaction marker inconsistency, DelegationToken HMAC masking (accepted mitigation), JMX metric exposure, DEBUG-level JWT claim logging. |
| docs/security-audit/findings/10-public-api-developer-misuse.md | CREATE | clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java; SaslConfigs.java; clients/src/main/java/org/apache/kafka/clients/CommonClientConfigs.java; connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java (access.control.allow.origin empty default); connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java; core/src/main/scala/kafka/server/KafkaConfig.scala | Category 10 finding: PLAINTEXT default, GSSAPI default, SSL_ALLOW_DN_CHANGES/SAN_CHANGES, PropertyFileLoginModule production-unsuitable, allow.everyone.if.no.acl.found=false secure default, unclean.leader.election.enable=false secure default, ACCESS_CONTROL_ALLOW_ORIGIN empty=secure default. |
| docs/security-audit/diagrams/threat-model-overview.md | CREATE | Synthesized from reconnaissance | Mermaid data-flow with trust boundaries, descriptive title, legend (transport solid, trust dashed, plugin dotted). |
| docs/security-audit/diagrams/attack-surface-map.md | CREATE | Synthesized across 10 categories × Kafka modules | Mermaid component diagram, severity color legend. |
| docs/security-audit/diagrams/authorization-decision-flow.md | CREATE | metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java | Mermaid flowchart with super-user bypass, loadingComplete gate, MatchingRuleBuilder DENY precedence, ALLOW implication rules, audit-log edge. |
| docs/security-audit/diagrams/kraft-quorum-safety.md | CREATE | raft/src/main/java/org/apache/kafka/raft/QuorumState.java, VoterSet.java, KafkaRaftClient.java, UpdateVoterHandler.java | Mermaid state + sequence diagrams for durable transitions, VoterSet.hasOverlappingMajority, epoch monotonicity, pre-vote. |
| docs/security-audit/diagrams/connect-rest-trust-boundary.md | CREATE | connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServer.java, RestClient.java; connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/JaasBasicAuthFilter.java | Mermaid sequence: inbound request path + INTERNAL_REQUEST_MATCHERS escape + RestClient Authorization forwarding. |
| docs/security-audit/diagrams/oauth-jwt-validation-paths.md | CREATE | clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/secured/BrokerJwtValidator.java, ClientJwtValidator.java; clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java | Mermaid flowchart: broker (jose4j DISALLOW_NONE) vs client (structural only) vs unsecured (alg:none). |
| docs/security-audit/diagrams/native-compression-boundary.md | CREATE | clients/src/main/java/org/apache/kafka/common/compress/ZstdCompression.java | Mermaid component diagram: BufferSupplier + ChunkedBytesStream + zstd-jni RecyclingBufferPool; 16 KB chunk limit. |
| docs/security-audit/severity-matrix.md | CREATE | All findings documents | Tabular Critical/High/Medium/Low matrix with business-impact and category cross-reference. |
| docs/security-audit/remediation-roadmap.md | CREATE | All findings documents | Recommended future-state actions — explicitly NO code changes applied in this run. |
| docs/security-audit/accepted-mitigations.md | CREATE | DelegationToken.java (MessageDigest.isEqual), BrokerJwtValidator.java (DISALLOW_NONE), ConnectionQuotas.scala (REPLICATION exemption), StandardAuthorizerData.java (DENY precedence, literal-only patterns), AclControlManager.java (MAX_RECORDS_PER_USER_OP) | Catalog of existing positive-security controls discovered during reconnaissance. |
| docs/security-audit/dependency-inventory.md | CREATE | gradle/dependencies.gradle | Version matrix of runtime-affecting dependencies; supply-chain surface. |
| docs/security-audit/no-change-verification.md | CREATE | git diff --name-status output | Evidence confirming zero source-code modifications per the Audit Only rule. |
| docs/security-audit/references.md | CREATE | Consolidated from 0.10 References | Full bibliography of file citations with absolute paths. |

- Ensure that every documentation file above is produced. No file is marked "to be discovered" — the Phase 3 reconnaissance is complete and the scope of each file is known.
- The table uses no wildcard patterns in target paths — each target file is explicitly listed.
- No file under `docs/security-audit/` overlaps any existing path in the Kafka repository, guaranteeing the "Audit Only" rule is honored at path-conflict resolution time.

### 0.5.2 New Documentation Files Detail

For each new documentation file, the following detail applies. Files are listed in deliverable priority (README and executive summary first; findings in user-specified order; diagrams supporting findings; summary matrices last).

```
File: docs/security-audit/README.md
Type: Audit Overview and Navigation Index
Source Code: N/A (meta-document)
Sections:
    - Audit Scope (explicit ten-category enumeration)
    - Methodology (static code review, no execution)
    - Audit Only Rule Statement (verbatim preservation of user rule)
    - Artifact Navigation (links to every file in docs/security-audit/)
    - Severity Legend (Critical/High/Medium/Low)
    - How to Read a Finding (template explanation)
Key Citations: Ten findings documents, executive summary, diagrams
```

```
File: docs/security-audit/executive-summary.html
Type: reveal.js HTML presentation
Source Code: All findings documents synthesized
Slides (minimum, every slide has at least one visual element — no text-only):
    - Title slide with professional SVG icon and audit scope one-liner
    - What was done (audit scope) — visual: attack-surface map Mermaid
    - Why (business rationale) — visual: threat-model overview Mermaid
    - Ten categories at a glance — visual: severity heatmap
    - Critical findings (if any) — visual: per-finding Mermaid or diagram excerpt
    - High findings — visual: Mermaid excerpts per surface
    - Medium / Low findings — visual: tabular summary with icons
    - Accepted mitigations already in place — visual: authorization-decision-flow Mermaid
    - Supply-chain / dependency posture — visual: dependency-inventory table with version icons
    - Onboarding and continued development — visual: remediation-roadmap Mermaid timeline (future-state suggestions only, no code changes)
    - No-change verification — visual: git diff statistics badge
    - Contact / reviewers — visual: professional icon
Diagrams: All diagrams from docs/security-audit/diagrams/ embedded via Mermaid blocks or SVG exports
Key Citations: All ten findings files
```

```
File: docs/security-audit/findings/01-filesystem-access-path-traversal.md
Type: Vulnerability category finding
Source Code: clients/src/main/java/org/apache/kafka/common/config/provider/FileConfigProvider.java,
             DirectoryConfigProvider.java (allowed.paths),
             EnvVarConfigProvider.java (allowlist.pattern),
             connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/DelegatingClassLoader.java,
             core/src/main/scala/kafka/log/LogManager.scala (log.dirs),
             core/src/main/scala/kafka/metrics/KafkaCSVMetricsReporter.scala (directory deletion),
             clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/secured/FileJwtRetriever.java
Sections:
    - Category Definition (user-provided label)
    - Kafka Surface Inventory (ConfigProviders, log.dirs, plugin.path, CSV reporter, OAuth file readers)
    - Evidence (file:line-range citations)
    - Attack Vector (path traversal into secret files; directory-delete race; plugin-path sprawl)
    - Severity (Medium — mitigated by allowed.paths + allowlist.pattern defaults)
    - Business Impact (secret disclosure if mis-configured, plugin tampering during deploy)
    - Accepted Mitigations (DirectoryConfigProvider allowed.paths, EnvVarConfigProvider allowlist.pattern)
    - Recommended Future Remediation (no code changes in this run; guidance only)
Diagrams: None for this category (tabular inventory sufficient)
Key Citations: See Sources above
```

Remaining findings files (02 through 10) follow the same structure, populated with the citations enumerated in the transformation table (Section 0.5.1). Each finding preserves the user-specified category label verbatim, enumerates the Kafka surface, cites every file-line range discovered during reconnaissance, supplies severity (Critical/High/Medium/Low) with business-impact narrative, explicitly distinguishes existing-mitigation language from future-remediation language, and contains NO code-change proposals. Detailed per-finding scaffolds mirror the `01` structure above, with sources replaced per the transformation table.

### 0.5.3 Documentation Files to Update Detail

**No documentation files are UPDATED in this audit.** The "Audit Only" user rule explicitly prohibits modification of any existing code or documentation; only new files under `docs/security-audit/` are created. This section intentionally remains empty except for this explicit affirmation of compliance.

### 0.5.4 Documentation Configuration Updates

**No configuration files are modified.** The audit deliverables are self-contained markdown and HTML under `docs/security-audit/` and do not require changes to any documentation generator configuration, navigation manifest, or build script. Specifically:

- `docs/` Apache Kafka docs site Jekyll/HTML build configuration: not modified
- Gradle `javadoc` task configuration: not modified
- `build.gradle` and `gradle/dependencies.gradle`: not modified
- Any README or index at the repository root: not modified

This posture ensures that the existing Kafka documentation build pipeline continues to produce the same artifacts it produced before the audit, and that the audit deliverables are simply additional files that the project can choose to publish, archive, or redistribute independently.

### 0.5.5 Cross-Documentation Dependencies

- Shared content/includes: The `diagrams/*.md` files are referenced from multiple findings (for example the attack-surface map is cited in `findings/02-*` and `findings/04-*`). All cross-references use relative paths (e.g., `../diagrams/attack-surface-map.md`) so the audit tree is portable and self-contained.
- Navigation links between documents: `README.md` provides the top-level index; each findings file links back to `README.md` and to any relevant diagrams; `severity-matrix.md` links to each findings file for drill-down; `remediation-roadmap.md` links to findings by category.
- Table of contents updates required: the audit's `README.md` contains the complete TOC; no external TOC (e.g., top-level Kafka docs site index) is touched.
- Index/glossary updates needed: the audit carries its own in-line terminology; no modification of any existing glossary is performed.


## 0.6 Dependency Inventory

### 0.6.1 Documentation Dependencies

The audit produces static markdown and a single reveal.js HTML deck. No new runtime dependencies are added to the Kafka build. Documentation tooling listed below is only required if a reviewer wishes to **render** the diagrams or preview the reveal.js deck locally — none of these tools is invoked by the audit itself and none is added to `gradle/dependencies.gradle`.

| Registry | Package Name | Version | Purpose |
|----------|--------------|---------|---------|
| GitHub / CDN | mermaid (mermaid.js) | 11.4.0 | Client-side rendering of Mermaid diagrams embedded in markdown and reveal.js. Loaded via CDN when HTML is opened in a browser; no build dependency. |
| GitHub / CDN | reveal.js | 5.1.0 | Client-side HTML presentation framework used for `executive-summary.html`. Loaded via CDN; no build dependency. |
| CDN | Font Awesome (Free) | 6.6.0 | Professional SVG icon set for the reveal.js deck (user rule: "professional icons (not emojis)"). Loaded via CDN. |
| N/A (repository-native) | GitHub Markdown renderer with Mermaid support | N/A | GitHub renders both Markdown and Mermaid blocks natively; no install step needed for reviewers who use the GitHub web UI. |

**Runtime/build dependencies already present in the Kafka repository** (verified against `gradle/dependencies.gradle`, read-only citations; not modified by the audit):

| Registry | Package Name | Version | Purpose (security-audit relevance) |
|----------|--------------|---------|-------------------------------------|
| Maven Central | com.fasterxml.jackson.core:jackson-databind (and related modules) | 2.19.0 | JSON (de)serialization; category-8 surface — `JsonDeserializer` with `ALLOW_LEADING_ZEROS_FOR_NUMBERS`, Trogdor `JsonUtil` with `ACCEPT_SINGLE_VALUE_AS_ARRAY`. |
| Maven Central | org.bitbucket.b_c:jose4j | 0.9.6 | JWT parsing/verification used by `BrokerJwtValidator`; category-8 surface — `DISALLOW_NONE` enforcement. |
| Maven Central | org.eclipse.jetty:jetty-server (and ee10 servlet/servlets) | 12.0.22 | HTTP transport for Connect REST and MirrorMaker REST; category-6 surface — `CrossOriginHandler`, TLS, client-auth. |
| Maven Central | org.glassfish.jersey.containers:jersey-container-servlet + jersey-hk2 | 3.1.10 | JAX-RS implementation for Connect REST; category-6 surface. |
| Maven Central | org.apache.logging.log4j:log4j-api + log4j-1.2-api | 2.25.1 | Logging facade and bridge; category-9 surface — DEBUG-level logs, redaction markers. |
| Maven Central | org.lz4:lz4-java | 1.8.0 | LZ4 compression; category-2 surface (native/JNI). |
| Maven Central | org.rocksdb:rocksdbjni | 10.1.3 | RocksDB state store for Kafka Streams; category-2 surface (native/JNI). |
| Maven Central | org.xerial.snappy:snappy-java | 1.1.10.7 | Snappy compression; category-2 surface (native/JNI). |
| Maven Central | com.github.luben:zstd-jni | 1.5.6-10 | Zstandard compression; category-2 surface — integrates via Kafka-owned `BufferSupplier` + `ChunkedBytesStream`. |
| Maven Central | org.bouncycastle:bcpkix-jdk18on | 1.80 | PKIX parsing in test scopes and OAuth/PEM handling pathways. |
| Gradle | Gradle | 9.1.0 | Build tool; not a runtime dependency but listed for completeness of toolchain. |
| N/A | Scala standard library | 2.13.x (default `defaultScala213Version`) | Broker/core language runtime. |
| Test-scope only | org.mockito:mockito-core + mockito-junit-jupiter | 5.20.0 | Test framework; not runtime. |

- All versions above were read directly from the repository's `gradle/dependencies.gradle`. The audit does **not** modify this manifest.
- The "user-provided version" principle is honored: every version listed is exactly what appears in the manifest — no placeholder or "latest" substitution.
- The audit's own documentation does not introduce any new runtime dependency. Reviewers may render Mermaid and reveal.js artifacts using the CDN-loaded versions listed in the upper table without altering the Kafka build.

### 0.6.2 Documentation Reference Updates

- No existing documentation files contain links that need to be updated. The audit introduces only new files under `docs/security-audit/` with self-contained relative cross-references.
- Link transformation rules: **N/A** — no link rewriting is performed because no existing documentation is touched.
- Apply to: **No existing documentation files** — only the newly created audit tree carries any cross-links, and every cross-link stays within that tree.


## 0.7 Coverage and Quality Targets

### 0.7.1 Documentation Coverage Metrics

The audit measures coverage by the completeness of the vulnerability-category inventory and the depth of code-grounded evidence per finding, not by Kafka's source-code symbol coverage (which is out of scope for an audit-only engagement).

- Current coverage analysis (pre-audit baseline):
    - Consolidated security-audit narrative covering all 10 user-specified categories: **0 / 10 (0%)** — there is no pre-existing consolidated security audit in the repository
    - Accepted-mitigation catalogue (positive-security posture) in a single document: **0 / 1** — properties such as `DelegationToken.MessageDigest.isEqual` exist in code but are not consolidated
    - Ten-category attack-surface diagram with trust boundaries: **0 / 1** — not present
    - Severity matrix (Critical/High/Medium/Low cross-referenced to Kafka subsystems): **0 / 1** — not present
    - Reveal.js executive summary for non-technical leadership on Kafka security posture: **0 / 1** — not present
- Target coverage (post-audit):
    - Ten-category findings documents: **10 / 10 (100%)**
    - Accepted-mitigations catalogue: **1 / 1 (100%)**
    - Diagrams: **7 / 7 (100%)** — threat model, attack surface, authorization decision, KRaft quorum safety, Connect REST trust boundary, OAuth JWT validation paths, native compression boundary
    - Severity matrix: **1 / 1 (100%)**
    - Reveal.js executive deck: **1 / 1 (100%)** with every slide carrying at least one visual element per user rule
- Coverage gaps the audit addresses:
    - Consolidated security-audit view: currently 0%, target 100% within `docs/security-audit/`
    - Each of the ten categories: currently scattered in code comments and Javadoc, target 100% consolidated with explicit severity and business-impact framing
    - Focus areas for deepest evidence coverage: Connect REST (JaasBasicAuthFilter bypass, CrossOriginHandler, RestClient SSRF), StandardAuthorizer + AclCache invariants, KRaft quorum safety, OAuth dual-validator architecture, delegation-token timing-attack mitigation, native compression boundary, ten Pattern.compile ReDoS sites, release.py shell=True surfaces

### 0.7.2 Documentation Quality Criteria

Completeness requirements:

- Every one of the ten user-specified vulnerability categories must appear as a dedicated findings document with the same section-template structure
- Every finding must enumerate at least one Kafka surface and at least one file-line citation
- Every accepted mitigation identified during reconnaissance (e.g., `MessageDigest.isEqual`, `DISALLOW_NONE`, REPLICATION listener exemption, literal-pattern ACL enforcement, `MAX_RECORDS_PER_USER_OP`, `toString` HMAC masking, 16 KB decompression chunk) must appear in `accepted-mitigations.md`
- Every diagram must include a descriptive title and legend per the "Visual Architecture Documentation" user rule
- Every slide in the reveal.js deck must include at least one visual element per the "Executive Presentation" user rule

Accuracy validation:

- Code excerpts cited in the findings must match the exact file paths and line ranges in the repository as of the audit snapshot — no paraphrasing of code semantics without file-line evidence
- Dependency versions cited must match `gradle/dependencies.gradle` exactly (Jackson 2.19.0, Jose4j 0.9.6, Jetty 12.0.22, Jersey 3.1.10, Log4j2 2.25.1, LZ4-java 1.8.0, RocksDB 10.1.3, snappy-java 1.1.10.7, zstd-jni 1.5.6-10, Bouncy Castle bcpkix 1.80, Scala 2.13.x default, Gradle 9.1.0, Mockito 5.20.0)
- Each API signature referenced in the audit must match the current in-repository signature — auditor will cross-reference via `read_file` rather than relying on memory
- Any Mermaid diagram must render correctly in GitHub's markdown viewer and in reveal.js — syntax is kept to the commonly supported subset (`flowchart`, `sequenceDiagram`, `stateDiagram-v2`, `classDiagram`)

Clarity standards:

- Technical accuracy with accessible language: findings documents are technical, but the reveal.js deck translates each finding into business-impact language for non-technical leadership
- Progressive disclosure (simple to complex): the reveal.js deck opens with the ten-category heatmap, then drills into Critical/High before Medium/Low; findings documents lead with definition and severity before evidence
- Consistent terminology: "finding" (reported issue), "mitigation" (existing protection), "vector" (attack path), "surface" (attackable component), "Critical / High / Medium / Low" (severity tiers) — applied uniformly across every deliverable

Maintainability:

- Source citations for traceability: every finding lists explicit file:line ranges so a future auditor can re-verify
- Clear ownership / update dates: the `README.md` of the audit tree carries the audit snapshot date (the repository's `HEAD` commit at audit time) so a subsequent auditor knows the code baseline
- Template-based consistency: ten findings share the same template; seven diagrams share the title+legend convention; reveal.js slides share a consistent icon set and color palette

### 0.7.3 Example and Diagram Requirements

- Minimum examples per API method: **1 source citation with file:line range** is required for every API call or class mentioned in a finding — this is stricter than a generic example requirement because the audit is code-grounded
- Diagram types required (per the seven categorized diagrams in 0.4.3):
    - One top-level data-flow diagram with trust boundaries (threat-model overview)
    - One component / matrix diagram (attack-surface map)
    - Two decision-flow flowcharts (authorization decision, OAuth JWT validation paths)
    - One state + sequence combination (KRaft quorum safety)
    - One sequence diagram (Connect REST trust boundary)
    - One component diagram (native compression boundary)
- Code example testing: **not applicable** — the audit does not execute any Kafka code per the "Audit Only" rule; examples are cited verbatim rather than executed
- Visual content freshness: every Mermaid diagram is generated from reconnaissance findings captured in Phase 3; if a subsequent audit is performed against a later Kafka version, diagrams must be regenerated by re-walking the relevant source files cited in Section 0.5.1


## 0.8 Scope Boundaries

### 0.8.1 Exhaustively In Scope

The audit's in-scope file set is deliberately narrow because the "Audit Only" user rule forbids modification of any existing code or documentation. Only the newly created documentation tree is in scope for WRITE operations; the entire Kafka repository is in scope for READ-ONLY analysis.

- New documentation files (WRITE scope):
    - `docs/security-audit/README.md` — audit overview and navigation
    - `docs/security-audit/executive-summary.html` — reveal.js deck
    - `docs/security-audit/findings/01-filesystem-access-path-traversal.md`
    - `docs/security-audit/findings/02-low-level-code-safety.md`
    - `docs/security-audit/findings/03-resource-limit-evasion.md`
    - `docs/security-audit/findings/04-module-system-builtin-abuse.md`
    - `docs/security-audit/findings/05-infinite-loop-recursion-dos.md`
    - `docs/security-audit/findings/06-network-subprocess-access.md`
    - `docs/security-audit/findings/07-external-function-callback-misuse.md`
    - `docs/security-audit/findings/08-deserialization-attacks.md`
    - `docs/security-audit/findings/09-information-leakage.md`
    - `docs/security-audit/findings/10-public-api-developer-misuse.md`
    - `docs/security-audit/diagrams/threat-model-overview.md`
    - `docs/security-audit/diagrams/attack-surface-map.md`
    - `docs/security-audit/diagrams/authorization-decision-flow.md`
    - `docs/security-audit/diagrams/kraft-quorum-safety.md`
    - `docs/security-audit/diagrams/connect-rest-trust-boundary.md`
    - `docs/security-audit/diagrams/oauth-jwt-validation-paths.md`
    - `docs/security-audit/diagrams/native-compression-boundary.md`
    - `docs/security-audit/severity-matrix.md`
    - `docs/security-audit/remediation-roadmap.md`
    - `docs/security-audit/accepted-mitigations.md`
    - `docs/security-audit/dependency-inventory.md`
    - `docs/security-audit/no-change-verification.md`
    - `docs/security-audit/references.md`
- Documentation file updates: **NONE.** No existing documentation file is modified. This is an explicit boundary.
- Documentation configuration: **NONE.** No existing configuration file (build.gradle, gradle/dependencies.gradle, docs build, CI pipeline, Gradle plugins, module manifests) is modified.
- Documentation assets:
    - No binary images are added — all diagrams are rendered as Mermaid text so the audit remains diff-reviewable and copyright-safe
    - No style sheets are added — the reveal.js deck uses CDN-loaded default themes or an embedded minimal custom theme within the single HTML file
- Documentation generation: **NONE.** No documentation build scripts, diagram generation configurations, or API-doc generation settings are touched.

READ-ONLY scope (repository surfaces cited for evidence):

- `clients/**/*.java` — SSL/SASL/Password/DelegationToken/compression/config-provider/ReDoS surfaces, read-only
- `core/**/*.scala` — broker ConnectionQuotas, CSVMetricsReporter, LogManager, StandardAuthorizerData (metadata), read-only
- `connect/**/*.java` — REST runtime (RestServer, RestClient, JaasBasicAuthFilter), JSON converter, MirrorMaker 2, plugin isolation, read-only
- `raft/**/*.java` — KafkaRaftClient, QuorumState, VoterSet, UpdateVoterHandler, read-only
- `metadata/**/*.java` — StandardAuthorizer, AclControlManager, AclCache, StandardAcl, read-only
- `storage/**/*.java` — RemoteStorageManager/RemoteLogMetadataManager plugin loading, read-only
- `streams/**/*.java` — Checkpoint deserialization, RocksDB JNI boundary, read-only
- `trogdor/**/*.java` — JsonUtil.ACCEPT_SINGLE_VALUE_AS_ARRAY, read-only
- `server-common/**/*.java` — BrokerSecurityConfigs, SaslInternalConfigs, read-only
- `coordinator-*/**` — TransactionCoordinator, GroupCoordinator (referenced for authorization error mapping), read-only
- `tools/**/*.java` — JmxTool (test defaults), read-only
- `release/*.py` — release.py, runtime.py subprocess surface, read-only
- `gradle/dependencies.gradle` — dependency versions, read-only
- `docs/**` — existing security/ops/connect docs for context, read-only

### 0.8.2 Explicitly Out of Scope

Consistent with the "Audit Only" and "Minimal Change Clause" user rules, the following are explicitly out of scope:

- **Source code modifications of any kind** — including inline comments, Javadoc edits, whitespace changes, typo fixes, variable renames, and removal of unused imports. The "Audit Only" rule states "DO NOT modify, create, or delete any existing code in the codebase. This includes inline comments." That directive governs this audit without exception.
- **Applying any remediation**, even for findings rated Critical. The "Minimal Change Clause" states "IMPORTANT: Make no changes, even if absolutely necessary to remediate the identified security vulnerabilities. Focus specifically on identifying the security gaps without modifying code. Your goal is to find vulnerabilities and suggest a path forward for remediation in the future."
- **Test file modifications** — no test file is created, updated, or deleted. No new test runs are added to CI. Test-file paths appear only as read-only evidence citations in findings documents.
- **Dependency upgrades or downgrades** — no change to `gradle/dependencies.gradle` or any transitive dependency pinning. The audit only documents the current dependency baseline.
- **Build/CI pipeline changes** — no modification to `build.gradle`, `Jenkinsfile`, GitHub Actions workflows, `docker/`, or `docker/test/` fixtures.
- **Executing any Kafka code or build target** — the "Audit Only" rule states "Avoid executing any code in the code base, this should be a static analysis." No broker is started, no test suite is run, no Gradle task is invoked against Kafka code. (Lightweight `grep`/`find` and `git diff` are used for static inspection and verification only.)
- **Modifying existing Kafka docs** — no edits to `docs/security.html`, `docs/ops.html`, `docs/connect.html`, per-module `README.md`, or KIP references.
- **Feature additions or code refactoring** — the audit proposes NO new features and NO refactoring.
- **Deployment configuration changes** — no modification to `docker/` images, Kubernetes manifests, or release automation.
- **Unrelated documentation work** — no documentation outside `docs/security-audit/` is touched regardless of perceived improvement opportunity.
- **Anything explicitly excluded by the user instructions** — the user-supplied "Audit Only", "Visual Architecture Documentation", and "Executive Presentation" rules collectively constrain the audit to three artifact families (markdown findings, Mermaid diagrams, reveal.js deck). Anything outside those three families is out of scope by rule.


## 0.9 Execution Parameters and Rules

### 0.9.1 Execution Parameters

- **Documentation build command**: None required. All audit deliverables are plain Markdown plus a single reveal.js HTML file. GitHub renders Markdown + Mermaid natively; reveal.js renders client-side via CDN-loaded JavaScript when a reviewer opens `executive-summary.html` in a browser.
- **Documentation preview command**: `python3 -m http.server 8000` from the repository root is sufficient for a reviewer to open `http://localhost:8000/docs/security-audit/executive-summary.html` and inspect the deck locally. No Python dependency is introduced — `http.server` ships with the Python standard library. This command is for reviewer convenience only and is not invoked by the audit.
- **Diagram generation command**: None. All diagrams are authored as Mermaid text inside fenced code blocks and render in-browser. No offline `mmdc`/Mermaid CLI execution is required.
- **Documentation deployment command**: Not applicable. The audit tree is internal artifact-only and does not integrate with the Kafka docs publishing pipeline.
- **Default format**: Markdown with Mermaid diagrams for findings and diagrams; HTML with embedded Mermaid for the reveal.js executive summary.
- **Citation requirement**: Every finding, every diagram, and every executive-summary slide that references a Kafka subsystem MUST cite the source file by absolute repository path and line range in the format `Source: <path>:L<start>-L<end>`.
- **Style guide to follow**: Use Kafka's existing documentation tone (terse, declarative, engineering-grade) for the findings; use executive-grade plain English for the reveal.js deck; no emojis anywhere — professional SVG icons only per the "Executive Presentation" user rule.
- **Documentation validation**: Markdown and HTML are not linted by an external tool because the audit introduces no linter dependency. Reviewers should verify visually that: (a) every Mermaid block renders, (b) every cited file path is resolvable in the current repository, (c) the git differential after the audit shows only additions under `docs/security-audit/` and no modifications to any other path.

### 0.9.2 Rules for Documentation

The following user-specified rules govern every deliverable in this audit and are restated here verbatim so the downstream Blitzy generation agents cannot diverge from them:

- **Audit Only** (verbatim from user input): "This run should serve as a dry run for potential changes, research, or documentation. DO NOT modify, create, or delete any existing code in the codebase. Avoid executing any code in the code base, this should be a static analysis. Every deliverable MUST include a markdown file summarizing security vulnerabilities, potential exploits, bugs in the codebase, perofrmace considerations, and remediation recommendations. Verify the NO CHANGES clause by confirming no changes to existing codebase featured in the git differential. Markdown files explicitly related to the analysis performed in this run are permitted."

- **Visual Architecture Documentation** (verbatim from user input): "All visual documentation MUST use Mermaid diagrams. Diagrams MUST be appropriate to the scope of the work — a migration requires before/after architecture views; a new feature may only need a component interaction and data flow diagram. Every diagram MUST have a descriptive title and legend. Diagrams MUST be referenced by name in accompanying documentation. Do NOT describe architecture in prose when a diagram communicates it more clearly. If the deliverable modifies an existing architecture, both states MUST be shown — never target-state alone."

- **Executive Presentation** (verbatim from user input): "Every deliverable MUST include an executive summary as a reveal.js HTML artifact using any existing style guides found within the codebase and professional icons (not emojis). The audience is non-technical leadership — communicate business value, risk, and operational readiness without requiring code literacy. Cover what was done, why it was done, what changed architecturally, what risks exist and how they are mitigated, and how the team onboards and continues development. Embed Mermaid diagrams directly in the reveal.js slides. Every slide MUST include at least one visual element — no text-only slides. Scope the presentation to the work performed. A migration warrants before/after architecture views, mapping summaries, and a timeline. A new feature may only need a component diagram and a risk assessment."

Derived operational rules that follow from the above user rules:

- Follow existing documentation style and structure insofar as the Kafka docs use Markdown + HTML; the audit uses the same file formats but places artifacts under a new dedicated `docs/security-audit/` subtree
- Include Mermaid diagrams for every architectural relationship that a diagram communicates more clearly than prose — specifically the seven diagrams identified in Section 0.4.3
- Do not provide working code examples that execute against Kafka — cite file paths and line ranges as read-only evidence instead; this respects the "Avoid executing any code in the code base" constraint
- Maintain minimal changes to the repository: the audit introduces only new files under `docs/security-audit/` and produces a `no-change-verification.md` artifact that captures `git diff --name-status` proving every non-audit path is untouched
- Use provided user text EXACTLY as specified for the three user rules — reproduced verbatim in Section 0.1.2 and in this section
- Document every configuration default that affects security posture in table format within `findings/10-public-api-developer-misuse.md`
- Include a "Business Impact" section in every finding and in every executive-summary slide — communicates operational risk to non-technical leadership per the "Executive Presentation" rule
- Add source code citations for every technical detail — enforced by the "Citation requirement" in Section 0.9.1
- Keep documentation self-contained and forward-compatible: since the audit does not modify code, a subsequent upgrade of Kafka may make some findings stale. The audit tree carries the repository snapshot commit hash in `README.md` so future reviewers know which baseline the audit was performed against
- Use consistent terminology across every artifact: "finding", "surface", "vector", "mitigation", "Critical / High / Medium / Low" as defined in Section 0.7.2
- Professional iconography: Font Awesome or equivalent SVG icon set in the reveal.js deck; no emojis in any artifact


## 0.10 References

### 0.10.1 Repository Files and Folders Searched

The following files and folders were inspected during Phase 3 reconnaissance to derive every conclusion in this Agent Action Plan. Paths are listed by subsystem to aid future re-verification.

**Root and build configuration**
- `build.gradle` — build orchestration
- `gradle/dependencies.gradle` — canonical source of every dependency version cited in Section 0.6

**Clients module** (`clients/src/main/java/org/apache/kafka/`)
- `common/config/provider/FileConfigProvider.java` — file-based config read
- `common/config/provider/DirectoryConfigProvider.java` — directory-based config read, `allowed.paths` allow-list
- `common/config/provider/EnvVarConfigProvider.java` — env-var read, `allowlist.pattern`
- `common/config/ConfigDef.java` — configuration schema; Pattern.compile site
- `common/config/ConfigTransformer.java` — config variable substitution; Pattern.compile site
- `common/config/SslConfigs.java` — SSL default constants and helper
- `common/config/SaslConfigs.java` — SASL default constants
- `common/config/types/Password.java` — `HIDDEN = "[hidden]"` masking
- `common/compress/ZstdCompression.java` — zstd-jni integration, `BufferSupplier`, `ChunkedBytesStream`, 16 KB chunk
- `common/memory/SimpleMemoryPool.java` — strict / non-strict allocation, `oomTimeSensor`
- `common/metrics/JmxReporter.java` — INCLUDE_CONFIG / EXCLUDE_CONFIG regex filters (2× Pattern.compile)
- `common/network/ServerConnectionId.java` — Pattern.compile site
- `common/requests/ApiVersionsRequest.java` — Pattern.compile site
- `common/security/auth/SslEngineFactory.java` — pluggable SSL factory interface
- `common/security/kerberos/KerberosRule.java` — 4× Pattern.compile (ReDoS hot spot)
- `common/security/kerberos/KerberosName.java` — Pattern.compile site
- `common/security/kerberos/KerberosShortNamer.java` — Pattern.compile site
- `common/security/oauthbearer/JwtValidator.java`, `JwtRetriever.java` — pluggable SPI interfaces
- `common/security/oauthbearer/internals/secured/BrokerJwtValidator.java` — jose4j with DISALLOW_NONE
- `common/security/oauthbearer/internals/secured/ClientJwtValidator.java` — structural-only validation
- `common/security/oauthbearer/internals/secured/FileJwtRetriever.java` — on-disk JWT read
- `common/security/oauthbearer/internals/secured/JwtBearerJwtRetriever.java` — assertion/private-key file read
- `common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java` — accepts `alg:none`
- `common/security/oauthbearer/OAuthBearerValidatorCallbackHandler.java` — unconditional SASL-extension acceptance
- `common/security/oauthbearer/internals/OAuthBearerClientInitialResponse.java` — Pattern.compile site
- `common/security/ssl/DefaultSslEngineFactory.java` — SSL engine construction
- `common/security/ssl/SslFactory.java` — dynamic reconfiguration + CertificateEntries compatibility
- `common/security/token/delegation/DelegationToken.java` — `MessageDigest.isEqual`, `toString` masking
- `common/utils/SafeObjectInputStream.java` — suffix-matching blocklist
- `common/utils/Utils.java` — general utilities

**Core module** (`core/src/main/scala/kafka/`)
- `log/LogManager.scala`, `log/Log.scala` — `log.dirs` + locking
- `metrics/KafkaCSVMetricsReporter.scala` — directory deletion
- `metrics/KafkaYammerMetrics.scala` — JVM shutdown hook
- `network/ConnectionQuotas.scala` — per-IP/per-listener/broker-wide caps, REPLICATION exemption
- `server/ClientQuotaManager.scala`, `ClientRequestQuotaManager.scala` — request quota with 10-second window
- `server/DynamicBrokerReconfigurationTest.scala` (test) — dynamic SSL/SASL reconfig evidence

**Connect runtime** (`connect/runtime/src/main/java/org/apache/kafka/connect/`)
- `rest/RestServer.java` (lines 260-300 inspected) — `CrossOriginHandler` instantiation
- `rest/RestServerConfig.java` (lines 60-100 inspected) — CORS defaults (`access.control.allow.origin` = "")
- `rest/RestClient.java` — outbound `Authorization` header forwarding
- `rest/util/SSLUtils.java` — Jetty `SslContextFactory` wiring, `COMMA_WITH_WHITESPACE` Pattern.compile
- `rest/ConnectRestExtension.java` — SPI for REST extensions (ServiceLoader)
- `isolation/PluginClassLoader.java`, `DelegatingClassLoader.java`, `PluginUtils.java`, `ReflectionScanner.java` — plugin isolation
- `runtime/RecordRedactor.java` — "(redacted)" marker

**Connect basic-auth-extension** (`connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/`)
- `JaasBasicAuthFilter.java` — Basic auth + `INTERNAL_REQUEST_MATCHERS` bypass
- `BasicAuthSecurityRestExtension.java` — extension registration
- `PropertyFileLoginModule.java` — plaintext credentials; production-unsuitable default

**Connect JSON** (`connect/json/src/main/java/org/apache/kafka/connect/json/`)
- `JsonDeserializer.java` (line 57) — `ALLOW_LEADING_ZEROS_FOR_NUMBERS.mappedFeature()` enabled
- `JsonConverter.java` — Jackson pipeline

**Connect MirrorMaker 2** (`connect/mirror/src/main/java/org/apache/kafka/connect/mirror/`)
- `MirrorMakerConfig.java`, `MirrorClientConfig.java`, `MirrorConnectorConfig.java`, `MirrorSourceConnector.java` — cross-cluster security, `syncTopicAcls` ACL downgrade, eager vs lazy secrets
- `MirrorConnectorsIntegrationSSLTest.java` (test) — SSL integration evidence

**Raft** (`raft/src/main/java/org/apache/kafka/raft/`)
- `KafkaRaftClient.java` — central Raft client, RPCs
- `QuorumState.java` — state machine, durable / memory transitions
- `VoterSet.java` — immutable voter set, `hasOverlappingMajority`
- `ElectionState.java` — persisted election metadata
- `QuorumConfig.java` — `controller.quorum.*` defaults, `NON_ROUTABLE_HOST`
- `internals/UpdateVoterHandler.java` — leader-side update voter processing
- `KafkaRaftClientClusterAuthTest.java`, `KafkaRaftClientReconfigTest.java`, `CandidateStateTest.java`, `ProspectiveStateTest.java`, `KafkaRaftClientPreVoteTest.java` (tests)

**Metadata** (`metadata/src/main/java/org/apache/kafka/metadata/authorizer/` and `metadata/src/main/java/org/apache/kafka/image/node/`)
- `StandardAuthorizer.java` — KRaft authorizer
- `StandardAuthorizerData.java` — copy-on-write ACL data, DENY-over-ALLOW, literal-pattern-only
- `ClusterMetadataAuthorizer.java` — interface, async ACL mutations
- `AclMutator.java` — async mutator interface
- `AclCache.java` — ImmutableNavigableSet + ImmutableMap
- `StandardAcl.java` — immutable record with reverse lexicographic order
- `StandardAclWithId.java` — persisted form
- `AclControlManager.java` (controller) — `MAX_RECORDS_PER_USER_OP`, UUID generation
- `image/node/ConfigurationImageNode.java` — "[redacted]" marker

**Storage** (`storage/api/src/main/java/org/apache/kafka/server/log/remote/storage/` and `storage/src/main/java/org/apache/kafka/storage/internals/log/`)
- `RemoteStorageManager.java`, `RemoteLogMetadataManager.java` — Tiered Storage plugin interfaces
- `ClassLoaderAware` wrapper classes — isolation model
- `LogDirFailureChannel.java` — log dir failure handling

**Streams** (`streams/src/main/java/org/apache/kafka/streams/`)
- `processor/internals/Checkpoint.java` — `deserializeRecord`
- `state/internals/RocksDBStore.java` — RocksDB JNI boundary

**Coordinator modules**
- `coordinator/transaction/src/main/java/org/apache/kafka/coordinator/transaction/TransactionCoordinator.java` — 2PC disabled path
- `coordinator/transaction/src/main/java/org/apache/kafka/coordinator/transaction/FenceProducersHandler.java` — epoch fencing
- `core/src/main/scala/kafka/server/AddPartitionsToTxnManager.scala` — CLUSTER_AUTHORIZATION_FAILED mapping

**Server-common** (`server-common/src/main/java/org/apache/kafka/server/config/`)
- `BrokerSecurityConfigs.java`, `SaslInternalConfigs.java`, `ReplicationConfigs.java`

**Tools** (`tools/src/main/java/org/apache/kafka/tools/`)
- `JmxTool.java` — test defaults with auth disabled

**Trogdor** (`trogdor/src/main/java/org/apache/kafka/trogdor/`)
- `common/JsonUtil.java` (line 39) — `ACCEPT_SINGLE_VALUE_AS_ARRAY` enabled

**Release tooling** (`release/`)
- `release.py` (lines 334-362 inspected) — `shell=True` with f-string interpolation
- `runtime.py` — subprocess `execute` wrapper
- `gpg.py`, `svn.py` — additional subprocess surfaces

**Tests (referenced only as read-only evidence for mitigation invariants)**
- `clients/src/test/java/org/apache/kafka/common/network/SslTransportLayerTest.java` — SSL handshake, dynamic update
- `clients/src/test/java/org/apache/kafka/common/security/ssl/DefaultSslEngineFactoryTest.java` — PEM handling
- `clients/src/test/java/org/apache/kafka/common/security/ssl/SslFactoryTest.java` — reconfiguration semantics
- `connect/runtime/src/test/java/org/apache/kafka/connect/runtime/rest/util/SSLUtilsTest.java` — Connect SSL
- `connect/runtime/src/test/java/org/apache/kafka/connect/runtime/standalone/StandaloneConfigTest.java` — SSL listener config
- `connect/mirror/src/test/java/org/apache/kafka/connect/mirror/integration/MirrorConnectorsIntegrationSSLTest.java` — MM2 SSL
- `core/src/test/scala/unit/kafka/network/ConnectionQuotasTest.scala` — connection quota enforcement
- `core/src/test/scala/unit/kafka/server/ClientRequestQuotaManagerTest.scala` — request quota
- `core/src/test/scala/integration/kafka/server/DynamicBrokerReconfigurationTest.scala` — dynamic reconfig
- `core/src/test/scala/integration/kafka/server/DynamicConnectionQuotaTest.scala` — dynamic quotas
- `core/src/test/scala/kafka/server/AuthorizerIntegrationTest.scala`, `SslAdminIntegrationTest.scala`, `DescribeAuthorizedOperationsTest.java` — authorization evidence
- `metadata/src/test/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerTest.java`, `AuthorizerTest.scala`, `AbstractAuthorizerIntegrationTest.scala`, `MockAclMutator.java` — authorizer tests
- `raft/src/test/java/org/apache/kafka/raft/KafkaRaftClientClusterAuthTest.java`, `KafkaRaftClientReconfigTest.java`, `CandidateStateTest.java`, `ProspectiveStateTest.java`, `KafkaRaftClientPreVoteTest.java` — Raft tests
- `tests/kafkatest/tests/core/authorizer_test.py` — ducktape integration for KRaft ACL authorizer
- `tests/kafkatest/services/security/security_config.py`, `minikdc.py`, `verifiable_client.py` — security test harness
- `docker/test/fixtures/secrets/client-ssl.properties`, `docker/examples/fixtures/client-secrets/client-ssl.properties` — fixture SSL credentials

**Technical specification sections consulted** (via `get_tech_spec_section` during reconnaissance)
- `1.1 Executive Summary`, `1.2 System Overview`, `1.3 Scope`
- `3.2 FRAMEWORKS & LIBRARIES`, `3.3 OPEN SOURCE DEPENDENCIES`
- `5.4 CROSS-CUTTING CONCERNS`
- `6.3 Integration Architecture`, `6.4 Security Architecture`

### 0.10.2 Attachments

**Zero attachments were provided by the user** for this audit. The user's prompt stated "User attached 0 environments to this project" and "No attachments found for this project."

No environment variables and no secrets were provided; both lists were explicitly empty. No setup instructions were provided; the user's directive states "None provided" for setup instructions.

### 0.10.3 Figma References

**Zero Figma references were provided by the user** for this audit. No Figma frames, URLs, or design files are in scope. The audit is a code-grounded security assessment and does not reference or depend on any Figma material.

### 0.10.4 Design System References

**No design system is specified for this audit.** The reveal.js executive deck uses professional SVG icons from a widely available icon font (Font Awesome 6.6.0 via CDN) and standard reveal.js 5.1.0 themes. No proprietary design system catalog is built or referenced — the "Design System Compliance" protocol is not applicable to this documentation-only audit deliverable because the reveal.js deck is a presentation artifact, not a product UI governed by a component library.


