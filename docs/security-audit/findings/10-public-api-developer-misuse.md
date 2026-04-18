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

# Finding 10 — Public API Developer Misuse (Insecure Defaults Watchlist)

> Navigation: [Audit Overview](../README.md) • [Severity Matrix](../severity-matrix.md) • [Remediation Roadmap](../remediation-roadmap.md) • [Accepted Mitigations](../accepted-mitigations.md)

> AUDIT-ONLY STATEMENT — This finding documents observed configuration defaults, code paths, and Javadoc warnings that affect security posture. NO code, configuration, test, or build-file change is applied by this audit. Every recommendation in Section 9 is future-state only and requires formal engineering review (e.g., a Kafka Improvement Proposal) before any action.

---

## 1. Category

**Public API developer misuse** (enumeration position 10 of 10 in the user-specified vulnerability taxonomy).

This category covers security-relevant *defaults* in the public Kafka API surface — broker, Connect, MirrorMaker 2, OAuth/SASL, SSL — where the out-of-the-box behavior either (a) leaves operators exposed unless they actively harden the configuration ("insecure defaults") or (b) already chooses a conservative posture that must be preserved against future regression ("secure defaults"). Both directions are catalogued here because the audit's role is not just to surface risks but also to pin down existing positive-posture decisions so they are not inadvertently inverted by a later change.

---

## 2. Definition

Kafka exposes hundreds of configuration keys across `KafkaConfig`, `ConnectConfig`, client configs, `SaslConfigs`, `SslConfigs`, and per-module config classes. A subset of those defaults has direct security implications:

- Several defaults are **insecure by design** to preserve backward compatibility (the historical broker shipped with a PLAINTEXT listener), to ease getting-started flows (`auto.create.topics.enable = true`), or to match legacy SASL ecosystems (`DEFAULT_SASL_MECHANISM = GSSAPI`).
- Several defaults are **secure by design** — `allow.everyone.if.no.acl.found = false`, `unclean.leader.election.enable = false`, `access.control.allow.origin = ""`, `ssl.allow.dn.changes = false`, `ssl.allow.san.changes = false`, `ssl.endpoint.identification.algorithm = "https"`. These secure defaults are enumerated here so reviewers of future changes know they are security-critical invariants and so they do not silently regress.
- Kafka also ships **production-unsuitable reference implementations** — `PropertyFileLoginModule` (Connect Basic Auth extension, plaintext credential file) and `OAuthBearerUnsecuredValidatorCallbackHandler` (accepts `alg:none` JWTs). Both carry explicit Javadoc warnings against production use, yet each is the path-of-least-resistance for an operator skimming Connect or OAuth quickstart material.

This finding is the consolidated watchlist across all three directions. It is paired with [`accepted-mitigations.md`](../accepted-mitigations.md) (which catalogs the secure-default half in full) and [`remediation-roadmap.md`](../remediation-roadmap.md) (which suggests a hardening order). The audit proposes no code change here — the deliverable is the watchlist itself.

---

## 3. Kafka Surface Inventory

The finding enumerates **nine sub-findings** across four postures: four INSECURE defaults (or production-unsuitable reference implementations), four SECURE defaults (accepted mitigations), and one operator-confusion surface. Each sub-finding is tagged inline so a reviewer can distinguish regression-risk items from positive-posture items at a glance.

| # | Title | Posture | Severity |
| --- | --- | --- | --- |
| 10.1 | PLAINTEXT listener protocol as broker default | Insecure Default | High |
| 10.2 | `sasl.mechanism = GSSAPI` (Kerberos) as default when SASL enabled | Operator Confusion | Low |
| 10.3 | `PropertyFileLoginModule` ships as Connect Basic Auth login module | Production-Unsuitable Reference Implementation | High |
| 10.4 | `OAuthBearerUnsecuredValidatorCallbackHandler` accepts `alg:none` | Production-Unsuitable Reference Implementation | High |
| 10.5 | `ssl.allow.dn.changes` / `ssl.allow.san.changes` knobs exist (defaults both `false`, SECURE) | Knob Exists | Medium |
| 10.6 | `access.control.allow.origin = ""` — Connect REST CORS empty default | Secure Default (Accepted Mitigation) | Low |
| 10.7 | `allow.everyone.if.no.acl.found = false` authorizer default | Secure Default (Accepted Mitigation) | Low |
| 10.8 | `unclean.leader.election.enable = false` broker default | Secure Default (Accepted Mitigation) | Low |
| 10.9 | `auto.create.topics.enable = true` broker default | Insecure Default | Medium |

---

## 4. Evidence

Every citation below was verified against the live repository files during Phase 3 reconnaissance. All paths are absolute from the Kafka repository root; all line ranges correspond to the Apache Kafka 4.2.0-SNAPSHOT snapshot.

### 10.1 PLAINTEXT listener protocol as broker default

The out-of-the-box listener configuration for a fresh broker resolves to `PLAINTEXT://:9092` — no TLS, no SASL. Three layers encode this default:

- The canonical fallback is defined in `SocketServerConfigs`:
  - `Source: server/src/main/java/org/apache/kafka/network/SocketServerConfigs.java:L63` — `public static final String LISTENERS_CONFIG = "listeners";`
  - `Source: server/src/main/java/org/apache/kafka/network/SocketServerConfigs.java:L64` — `public static final String LISTENERS_DEFAULT = "PLAINTEXT://:9092";` (the insecure fallback literal)
  - `Source: server/src/main/java/org/apache/kafka/network/SocketServerConfigs.java:L156` — ConfigDef registration binds `LISTENERS_CONFIG` to `LISTENERS_DEFAULT` at broker startup
- The broker reads the resolved listener list via `KafkaConfig`:
  - `Source: core/src/main/scala/kafka/server/KafkaConfig.scala:L440-L441` — `def listeners: Seq[Endpoint] = CoreUtils.listenerListToEndPoints(getList(SocketServerConfigs.LISTENERS_CONFIG), effectiveListenerSecurityProtocolMap)`
- Clients inherit the same disposition via `CommonClientConfigs`:
  - `Source: clients/src/main/java/org/apache/kafka/clients/CommonClientConfigs.java:L135` — `SECURITY_PROTOCOL_CONFIG = "security.protocol"`
  - `Source: clients/src/main/java/org/apache/kafka/clients/CommonClientConfigs.java:L136` — documentation ("Protocol used to communicate with brokers")
  - `Source: clients/src/main/java/org/apache/kafka/clients/CommonClientConfigs.java:L137` — `DEFAULT_SECURITY_PROTOCOL = "PLAINTEXT"`

An operator who never overrides `listeners=` or `security.protocol=` runs an unauthenticated, unencrypted broker listening on port 9092. A counter-secure default does exist for hostname verification when TLS *is* enabled — `ssl.endpoint.identification.algorithm = "https"` — so operators who opt in to TLS inherit endpoint verification by default:

- `Source: clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java:L111-L113` — `SSL_ENDPOINT_IDENTIFICATION_ALGORITHM_CONFIG` + documentation + `DEFAULT_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM = "https"` (SECURE default, opt-in path)

Narrative: Kafka ships with a PLAINTEXT listener to preserve the historical quickstart flow. Any operator who launches `kafka-server-start.sh` against a minimal `server.properties` — without setting `listeners`, without setting `security.protocol`, without setting `sasl.enabled.mechanisms` — inherits a broker that any network observer can read from and write to. The complementary SECURE default (`ssl.endpoint.identification.algorithm = "https"`) only activates after the operator has explicitly opted into TLS; it is not a mitigation for the PLAINTEXT listener itself. Pair with the recommendation in [`remediation-roadmap.md`](../remediation-roadmap.md) to require operators enable TLS + SASL before exposing any broker to an untrusted network.

### 10.2 `sasl.mechanism = GSSAPI` (Kerberos) as default when SASL is enabled

When SASL is enabled but no explicit mechanism is named, Kafka selects Kerberos (`GSSAPI`). Three layers encode this:

- Client-side default:
  - `Source: clients/src/main/java/org/apache/kafka/common/config/SaslConfigs.java:L32` — `SASL_MECHANISM = "sasl.mechanism"`
  - `Source: clients/src/main/java/org/apache/kafka/common/config/SaslConfigs.java:L33` — `SASL_MECHANISM_DOC` (describes the option)
  - `Source: clients/src/main/java/org/apache/kafka/common/config/SaslConfigs.java:L34` — `GSSAPI_MECHANISM = "GSSAPI"` (the literal)
  - `Source: clients/src/main/java/org/apache/kafka/common/config/SaslConfigs.java:L35` — `DEFAULT_SASL_MECHANISM = GSSAPI_MECHANISM`
- Broker inter-broker default:
  - `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L133` — `SASL_MECHANISM_INTER_BROKER_PROTOCOL_CONFIG = "sasl.mechanism.inter.broker.protocol"`
  - `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L134` — `SASL_MECHANISM_INTER_BROKER_PROTOCOL_DOC` (explicitly "Default is GSSAPI")
  - `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L176` — ConfigDef registration that wires `SaslConfigs.DEFAULT_SASL_MECHANISM` as the default

Narrative: An operator who enables SASL but omits `sasl.mechanism=` inherits Kerberos, which requires a KDC. Operators who intended `SASL/SCRAM-SHA-512` or `SASL/PLAIN-over-TLS` but did not spell out the mechanism may be surprised by authentication failures at startup, and — more subtly — may retry by relaxing other security settings to debug the Kerberos error rather than re-read the default. No attacker-exploitable pathway exists; severity is Low because this is operator confusion only and operators who deliberately enable SASL typically also deliberately select a mechanism.

### 10.3 `PropertyFileLoginModule` — Connect Basic Auth production-unsuitable reference implementation

The Connect Basic Auth extension ships a JAAS login module that reads username:password pairs from a properties file and compares submitted passwords against the file in plaintext. The class explicitly warns in its Javadoc that it is NOT intended for production:

- Class-level warning:
  - `Source: connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java:L42-L49` — class Javadoc
  - `Source: connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java:L47-L48` — the explicit warning text stating that the module is NOT intended to be used in production because the credentials are stored in PLAINTEXT in the properties file
- Implementation anchors:
  - `Source: connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java:L50` — class declaration (`public class PropertyFileLoginModule implements LoginModule`)
  - `Source: connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java:L52` — `FILE_OPTIONS = "file"` (the JAAS option key that points at the credentials file)
  - `Source: connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java:L71` — file open via `Files.newInputStream(Paths.get(fileName))`
  - `Source: connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java:L73` — `credentialProperties.load(inputStream)` (loads the property file into memory)
  - `Source: connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java:L114` — the plaintext equality comparison `password.equals(credentialProperties.get(username))` inside the `login()` method (the actual credential check)

Narrative: `PropertyFileLoginModule` is the only login module that ships inside `connect-basic-auth-extension`. Operators who enable the Connect Basic Auth extension use this module unless they supply a custom JAAS configuration referencing an LDAP or JDBC login module — which requires non-trivial JAAS literacy. Two exploit consequences follow: (1) a file-system reader of the credentials file recovers all Connect REST passwords in plaintext; (2) the plaintext `String.equals` at L114 is not constant-time, though the timing signal is bounded by the length of the username lookup.

### 10.4 `OAuthBearerUnsecuredValidatorCallbackHandler` accepts `alg:none` JWTs

The unsecured OAuth validator callback handler carries a Javadoc warning flagging production unsuitability. It accepts JWT `alg:none` tokens — i.e., JWTs with no signature at all:

- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java:L38-L81` — class Javadoc
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java:L79-L80` — the explicit warning text stating that this handler is not suitable for production use due to its reliance on unsecured JWT tokens
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java:L82` — class declaration

Cross-reference: this same surface is documented in [`07-external-function-callback-misuse.md#071`](./07-external-function-callback-misuse.md) from the callback-misuse angle. It appears here in the insecure-defaults watchlist because the mere availability of the unsecured handler — combined with operator-facing OAuth quickstart material — places it in the path-of-least-resistance for a first-time OAuth deployment. A counter-mitigation (`BrokerJwtValidator` with `DISALLOW_NONE`) is documented as an accepted mitigation in [`../accepted-mitigations.md`](../accepted-mitigations.md) and from the deserialization angle in [`08-deserialization-attacks.md#084-oauth-asymmetry`](./08-deserialization-attacks.md).

### 10.5 `ssl.allow.dn.changes` / `ssl.allow.san.changes` — SECURE defaults with a dangerous knob

Two knobs permit broker operators to disable cert-identity stability checks during dynamic SSL reconfiguration. Both default to `false` (SECURE), but the existence of the knob means operator misuse can convert a routine certificate rotation into an identity change:

- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L123` — `SSL_ALLOW_DN_CHANGES_CONFIG = "ssl.allow.dn.changes"`
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L124` — `DEFAULT_SSL_ALLOW_DN_CHANGES_VALUE = false` (SECURE default)
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L125-L126` — DOC string explaining the knob
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L128` — `SSL_ALLOW_SAN_CHANGES_CONFIG = "ssl.allow.san.changes"`
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L129` — `DEFAULT_SSL_ALLOW_SAN_CHANGES_VALUE = false` (SECURE default)
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L130-L131` — DOC string for the SAN knob
- `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java` — package declared at L17 as `org.apache.kafka.common.config.internals` (note the canonical path is inside the `clients/` module and the `common.config.internals` package, not the `server-common` module — an important disambiguation for reviewers navigating the code)

Narrative: The default posture is conservative — a dynamic certificate rotation that changes the Distinguished Name (DN) or Subject Alternative Name (SAN) is rejected by default, which prevents a rotated certificate from silently assuming a different identity. The reason this knob is listed as *Medium* rather than *Low (Accepted)* is that its existence is a security-relevant foot-gun: an operator who flips either knob to `true` — perhaps to work around a certificate-rotation incident — permits certificate-based identity substitution. A rotated cert with a new DN could impersonate a different SASL principal on `PrincipalBuilder`-backed listeners; a rotated cert with new SANs could defeat hostname verification on intra-cluster replication channels. The knob is flagged here so it is documented as SECURITY-SENSITIVE and does not regress to a permissive default in a future PR.

### 10.6 `access.control.allow.origin = ""` — Connect REST CORS empty default (SECURE)

The Connect REST API ships with CORS disabled by default. Any cross-origin browser request is rejected unless the operator explicitly configures an origin allow-list:

- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java:L70` — `ACCESS_CONTROL_ALLOW_ORIGIN_CONFIG = "access.control.allow.origin"`
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java:L71-L75` — documentation describing the CORS behavior
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java:L76` — `ACCESS_CONTROL_ALLOW_ORIGIN_DEFAULT = ""` (empty string — SECURE default, no cross-origin permitted)

Narrative: This is a SECURE default (accepted mitigation). Documented here in the insecure-defaults watchlist precisely because a future change that flips the default to `"*"` (or any wildcard) would expose the Connect REST API cross-origin — losing the current browser-level protection against CSRF-style attacks on Connect. Cross-reference [`06-network-subprocess-access.md#063-crossoriginhandler`](./06-network-subprocess-access.md) for the network-angle evidence.

### 10.7 `allow.everyone.if.no.acl.found = false` — KRaft authorizer SECURE default

The KRaft `StandardAuthorizer` fails CLOSED when no ACL matches an authorization request. The config key and default-resolution logic live in `StandardAuthorizer`:

- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L18` — package declaration (`org.apache.kafka.metadata.authorizer`)
- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L54-L56` — class Javadoc ("Built-in authorizer implementation that stores ACLs in the metadata log")
- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L57` — class declaration (`public class StandardAuthorizer implements ClusterMetadataAuthorizer, Monitorable`)
- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L58` — `SUPER_USERS_CONFIG = "super.users"` (companion key)
- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L60` — `ALLOW_EVERYONE_IF_NO_ACL_IS_FOUND_CONFIG = "allow.everyone.if.no.acl.found"`
- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L210` — `static AuthorizationResult getDefaultResult(Map<String, ?> configs)` method signature
- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L211` — `Object configValue = configs.get(ALLOW_EVERYONE_IF_NO_ACL_IS_FOUND_CONFIG);`
- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L212` — `if (configValue == null) return DENIED;` (the SECURE default branch — config absent means DENIED)
- `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L213` — `return Boolean.parseBoolean(configValue.toString().trim()) ? ALLOWED : DENIED;`

Narrative: SECURE default (accepted mitigation). When an authorization decision reaches the "no ACL matched" terminal branch, the authorizer returns DENIED. A future change flipping the default to `true` would turn Kafka into an open system for unmapped resources. The complementary DENY-over-ALLOW precedence in `StandardAuthorizerData` is documented separately in [`../accepted-mitigations.md`](../accepted-mitigations.md); see also [`../diagrams/authorization-decision-flow.md`](../diagrams/authorization-decision-flow.md).

### 10.8 `unclean.leader.election.enable = false` — broker SECURE default

Unclean leader election (allowing an out-of-sync replica to be elected leader) is disabled by default. The broker-side consumer of this config lives in `KafkaConfig`:

- `Source: core/src/main/scala/kafka/server/KafkaConfig.scala:L358` — `def uncleanLeaderElectionEnable: java.lang.Boolean = getBoolean(ReplicationConfigs.UNCLEAN_LEADER_ELECTION_ENABLE_CONFIG)` (the getter that reads the value the operator has set — default resolution happens via `ReplicationConfigs`, which ships `false` as the default)

Narrative: SECURE default (accepted mitigation). The transaction coordinator and exactly-once semantics rely on this default — an out-of-sync replica elected leader can truncate log entries that were already committed to the ISR, breaking idempotent-producer and transactional guarantees. A future change flipping the default to `true` would re-open this class of truncation risks without operator consent. Documented here so the default is visible as a regression-guard invariant.

### 10.9 `auto.create.topics.enable = true` — broker INSECURE default

Kafka brokers auto-create a topic when a producer or consumer references an unknown topic name, subject to authorization. The config is declared in `ServerLogConfigs` and consumed in `KafkaConfig`:

- `Source: server-common/src/main/java/org/apache/kafka/server/config/ServerLogConfigs.java:L134` — `AUTO_CREATE_TOPICS_ENABLE_CONFIG = "auto.create.topics.enable"`
- `Source: server-common/src/main/java/org/apache/kafka/server/config/ServerLogConfigs.java:L135` — `AUTO_CREATE_TOPICS_ENABLE_DEFAULT = true` (the INSECURE default)
- `Source: server-common/src/main/java/org/apache/kafka/server/config/ServerLogConfigs.java:L136` — `AUTO_CREATE_TOPICS_ENABLE_DOC = "Enable auto creation of topic on the server."`
- `Source: core/src/main/scala/kafka/server/KafkaConfig.scala:L304` — `/** ********* Log Configuration ***********/` (section marker)
- `Source: core/src/main/scala/kafka/server/KafkaConfig.scala:L305` — `val autoCreateTopicsEnable = getBoolean(ServerLogConfigs.AUTO_CREATE_TOPICS_ENABLE_CONFIG)` (broker consumption site)

Narrative: With the default `true`, any producer or consumer able to clear the authorization check can cause an unmapped topic to be created. The interaction with 10.7 is critical: on ACL-enabled clusters where `allow.everyone.if.no.acl.found = false`, ACLs gate auto-creation so this default is well-contained. On PLAINTEXT clusters without ACLs — a posture attainable by combining the insecure defaults in 10.1 + not configuring an authorizer — any network client can trigger creation of thousands of topics, polluting the namespace, consuming partition resource budgets, and eventually degrading the cluster's control-plane performance.

---

## 5. Attack Vector

For each sub-finding, the attack vector is characterized below. Severity distinguishes whether the vector is reachable from a network attacker (`External`), requires operator misconfiguration (`Op-Mis`), or is purely a regression-risk (`Reg-Risk` — a future code change would introduce the vulnerability).

- **10.1 PLAINTEXT listener** `[External]`: A network attacker who can observe or inject packets on any link between a client and the broker (enterprise LAN, untrusted VLAN, misconfigured peering, cross-datacenter link) reads all traffic in the clear — including SASL/PLAIN credentials submitted on top of PLAINTEXT, PII in message payloads, topic metadata, and consumer offsets. Exploitation is trivial (`tcpdump` suffices). Write-path attack: the attacker forges produce requests (no TLS binding, no authentication). This is the single highest-impact default in the watchlist.
- **10.2 GSSAPI default** `[Op-Mis]`: No direct attacker exploit. Operator sees authentication failures after enabling SASL without spelling out the mechanism, may relax other security controls while debugging. Indirect risk only.
- **10.3 PropertyFileLoginModule** `[External + Op-Mis]`: An attacker with file-system read access (compromised sidecar, log-scrape pipeline, shared volume, misconfigured container) recovers every Connect REST credential in plaintext. The plaintext equality at L114 also carries a (bounded) timing signal because `String.equals` is not constant-time.
- **10.4 Unsecured OAuth validator** `[External]`: An attacker forges a JWT with `alg: "none"` and a valid-looking body; the unsecured handler accepts it without signature verification, yielding a fully-authenticated SASL/OAUTHBEARER session. See [`07-external-function-callback-misuse.md#071`](./07-external-function-callback-misuse.md) for the full exploit chain.
- **10.5 SSL_ALLOW_DN/SAN_CHANGES knobs** `[Op-Mis → External]`: The default is SECURE. However, an operator who flips either knob to `true` while rotating a certificate allows a cert with a different DN or SAN to assume a different identity on the listener. Attack path: a certificate issued (legitimately or via a compromised CA) with a different DN is rotated into the broker's keystore; the dynamic reconfiguration pipeline accepts it; subsequent SASL/SSL sessions authenticate as the new DN's principal.
- **10.6 CORS empty default** `[Reg-Risk]`: No attack vector against the current default. A future change to a permissive CORS default would re-enable browser-based cross-origin access to the Connect REST API.
- **10.7 `allow.everyone.if.no.acl.found = false`** `[Reg-Risk]`: No attack vector against the current default. A future change to `true` would fail-open the authorizer on unmapped resources.
- **10.8 `unclean.leader.election.enable = false`** `[Reg-Risk]`: No attack vector against the current default. A future change to `true` would re-enable log-truncation from non-ISR replica election; destroys exactly-once-semantics invariants.
- **10.9 `auto.create.topics.enable = true`** `[External on PLAINTEXT clusters]`: On clusters where 10.1 is combined with an absence of authorization, any network client (no authentication required) produces to a nonexistent topic name and the broker auto-creates it. A distributed attacker produces to `$(uuid)` names millions of times, exhausting metadata partitions and operator patience.

---

## 6. Severity

| Sub-finding | Severity | Rationale |
| --- | --- | --- |
| 10.1 PLAINTEXT listener default | High | Default exposure of unauthenticated, unencrypted broker |
| 10.2 GSSAPI default | Low | Operator opts into SASL intentionally |
| 10.3 PropertyFileLoginModule | High | Production-unsuitable default for Connect Basic Auth |
| 10.4 Unsecured validator | High | See 07.1 |
| 10.5 SSL_ALLOW_DN/SAN_CHANGES | Medium | Secure default; knob exists |
| 10.6 CORS empty default | Low (Accepted) | Secure default |
| 10.7 allow.everyone.if.no.acl.found | Low (Accepted) | Secure default |
| 10.8 unclean.leader.election.enable | Low (Accepted) | Secure default |
| 10.9 auto.create.topics.enable | Medium | Insecure default for namespace pollution / DoS |

Severity classifications follow the four-tier model defined in [`../README.md`](../README.md): **High** requires operator misconfiguration or privileged-context exploitation; **Medium** requires specific operator action or narrow prerequisites; **Low** is a defense-in-depth observation (for insecure-leaning items) or a SECURE default worth documenting as a regression-guard (for the Accepted-Mitigation items). No Critical rating applies here because no sub-finding permits unconditional remote bypass against a broker configured per Kafka's security documentation; every exploit either requires an operator opt-out of a secure default or relies on the historical defaults being untouched.

---

## 7. Business Impact

The insecure-default half of this watchlist translates directly into operational risk categories a non-technical audience can evaluate:

- **10.1 + 10.3 + 10.4** (the High-severity cluster): Each of these alone enables an unauthenticated data-plane or control-plane access path. An attacker who reaches the broker network port on a PLAINTEXT listener (10.1) reads all topic data in the clear; an attacker who reaches Connect REST on a deployment that kept the default `PropertyFileLoginModule` (10.3) recovers all Connect REST passwords from a credentials file; an attacker who reaches a broker running `OAuthBearerUnsecuredValidatorCallbackHandler` (10.4) forges SASL/OAUTHBEARER tokens. Together, they define the three most common production-incident patterns for misconfigured Kafka deployments. Confidentiality, integrity, and availability are simultaneously at risk.
- **10.9** (Medium): `auto.create.topics.enable = true` combined with 10.1 on an un-ACL'd cluster enables a namespace-pollution DoS — not catastrophic, but operationally expensive to recover from (topic deletion, partition-budget reclamation, metadata-log compaction).
- **10.5** (Medium): On a cluster that relied on certificate-pinned identities, an operator's expedient flip of the DN/SAN-change knob trades off a well-scoped security property for a quick operational fix; the regression becomes invisible until the replacement certificate is used to impersonate a principal.
- **The Accepted-Mitigation defaults (10.6, 10.7, 10.8)**: These carry business value by NOT being exploitable today. Their presence in this watchlist is intentional: a future PR that inverts any of these defaults re-enables a class of attack that the audit currently rates as Low. Documenting them here protects the cluster operator's existing security posture from silent regression.

The non-technical takeaway: today's Kafka deployment is exposed mainly through *what operators did not configure* (10.1, 10.3, 10.4, 10.9). Today's Kafka deployment is protected partly through *what Kafka's defaults already chose* (10.5, 10.6, 10.7, 10.8). The audit recommends documentation and opt-in-to-secure changes in future work — it proposes no code change now.

---

## 8. Accepted Mitigations Already Present

The following SECURE defaults and existing Javadoc warnings are mitigations already encoded in the codebase. They are catalogued in depth in [`../accepted-mitigations.md`](../accepted-mitigations.md); the cross-references below tie them back to the sub-finding they protect.

- **`ssl.endpoint.identification.algorithm = "https"`** — SECURE default ensures hostname verification whenever TLS is enabled. Defends the TLS-enabled path that is the recommended escape from 10.1.
  - `Source: clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java:L111-L113`
- **`access.control.allow.origin = ""`** — SECURE default. Connect REST does not permit cross-origin access by default (sub-finding 10.6).
  - `Source: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java:L70-L76`
- **`allow.everyone.if.no.acl.found = false`** — SECURE default. The KRaft authorizer fails closed for unmapped resources (sub-finding 10.7).
  - `Source: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:L60, L211-L213`
- **`unclean.leader.election.enable = false`** — SECURE default. Preserves exactly-once-semantics guarantees by preventing leader election from out-of-sync replicas (sub-finding 10.8).
  - `Source: core/src/main/scala/kafka/server/KafkaConfig.scala:L358` (consumption site; ReplicationConfigs ships the `false` default)
- **`ssl.allow.dn.changes = false` / `ssl.allow.san.changes = false`** — SECURE defaults for dynamic certificate rotation (sub-finding 10.5).
  - `Source: clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java:L123-L131`
- **Explicit Javadoc warning on `PropertyFileLoginModule`** — a documentation-level mitigation (not a default-posture mitigation) that an attentive operator reads before deploying (sub-finding 10.3).
  - `Source: connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java:L42-L49`
- **Explicit Javadoc warning on `OAuthBearerUnsecuredValidatorCallbackHandler`** — likewise a documentation-level mitigation (sub-finding 10.4).
  - `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java:L38-L81`
- **`BrokerJwtValidator` enforces `DISALLOW_NONE`** — a code-level mitigation that blocks `alg:none` JWTs *when the broker is configured to use `BrokerJwtValidator` instead of the unsecured handler.* Documented in depth in [`08-deserialization-attacks.md#084-oauth-asymmetry`](./08-deserialization-attacks.md) and listed among accepted mitigations in [`../accepted-mitigations.md`](../accepted-mitigations.md).

These mitigations are the reason none of the Medium/Low sub-findings above escalate to a higher severity. A future PR touching any of these files must re-read this section to avoid inadvertently regressing the default.

---

## 9. Recommended Future Remediation (No Changes in This Run)

> The items below are future-state suggestions. The audit proposes NO code, configuration, or documentation change against the existing Kafka repository in this run. Every item requires formal engineering review — typically a Kafka Improvement Proposal (KIP) — before any action. Reviewers MUST verify the "No Changes" clause via [`../no-change-verification.md`](../no-change-verification.md) before considering any recommendation for implementation.

1. **Future KIP: change `listeners` default away from PLAINTEXT.** Consider a future KIP that either makes the default `SASL_SSL` (breaking change) or requires operators to opt in to PLAINTEXT with an explicit acknowledgement flag. The KIP would need to address backward compatibility with the historical quickstart material and all testing fixtures that rely on the current default.
2. **Future KIP: deprecate `PropertyFileLoginModule` shipping in `connect-basic-auth-extension`.** The module could continue to exist as a reference implementation in a separate example module while the Connect Basic Auth extension's default pointer moves to a recommended production module (e.g., a new JDBC or LDAP login module bundled with Connect). Alternatively, the existing Javadoc warning could be promoted to a startup-time log line so operators see the warning at runtime rather than only in the source.
3. **Future KIP: deprecate `OAuthBearerUnsecuredValidatorCallbackHandler` or gate it behind an explicit `allow.unsecured.token = true` broker flag.** The current availability of the unsecured handler is a path-of-least-resistance for first-time OAuth deployments; an explicit opt-in flag would force operators to acknowledge the risk. A stricter alternative would remove the unsecured handler entirely after a deprecation cycle.
4. **Future KIP: change `auto.create.topics.enable` default to `false`.** The interaction with 10.1 on PLAINTEXT, un-ACL'd clusters motivates making topic creation explicit at deploy time. The KIP would need to address ecosystem integrations that rely on implicit topic creation for quickstart examples.
5. **Operator runbook (documentation-only, no code change):** a hardening checklist that an operator follows before exposing any broker to an untrusted network — enable TLS (`listeners=SSL://...` or `SASL_SSL://...`), enable SASL with a non-GSSAPI mechanism where appropriate (SCRAM-SHA-512 over TLS), configure an authorizer (`authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer`), disable auto-creation (`auto.create.topics.enable=false`), keep the DN/SAN-change knobs at `false`, configure explicit ACLs with DENY-first semantics, pin `ssl.endpoint.identification.algorithm=https`, set `unclean.leader.election.enable=false`, and keep `allow.everyone.if.no.acl.found=false`.
6. **Regression-guard documentation:** Cross-reference every SECURE default in this watchlist from [`../accepted-mitigations.md`](../accepted-mitigations.md) so that a future PR touching any of the five SECURE defaults (10.5, 10.6, 10.7, 10.8, plus the TLS endpoint-identification algorithm) surfaces the security implication in code review.

**Closing.** No code changes are applied in this audit run per the Audit Only rule. Every recommendation above is a forward-looking guidance item for the Kafka community to evaluate in subsequent KIP proposals, operator runbook updates, or code-review exercises.

---

## 10. Cross-References

- [`../accepted-mitigations.md`](../accepted-mitigations.md) — full catalog of secure defaults, including 10.5, 10.6, 10.7, 10.8 and the `ssl.endpoint.identification.algorithm = "https"` mitigation paired with 10.1.
- [`../remediation-roadmap.md`](../remediation-roadmap.md) — suggested hardening order across the four phases (Immediate / Short-term / Medium-term / Long-term), with every item here echoed in the roadmap's future-state Gantt chart.
- [`../severity-matrix.md`](../severity-matrix.md) — tabular cross-reference of every finding in the audit, including the nine sub-findings above under Category 10.
- [`./06-network-subprocess-access.md#063-crossoriginhandler`](./06-network-subprocess-access.md) — Connect REST `CrossOriginHandler` wiring, cross-referenced from sub-finding 10.6.
- [`./07-external-function-callback-misuse.md#071`](./07-external-function-callback-misuse.md) — `OAuthBearerUnsecuredValidatorCallbackHandler` exploit chain, cross-referenced from sub-finding 10.4.
- [`./08-deserialization-attacks.md#084-oauth-asymmetry`](./08-deserialization-attacks.md) — `BrokerJwtValidator` vs `ClientJwtValidator` posture asymmetry, cross-referenced from sub-finding 10.4's counter-mitigation narrative.
- [`../diagrams/authorization-decision-flow.md`](../diagrams/authorization-decision-flow.md) — `StandardAuthorizer` flow including super-user bypass and the `allow.everyone.if.no.acl.found` terminal branch, cross-referenced from sub-finding 10.7.

---

## Validation Checklist

The following checklist items are provided so that a future auditor or reviewer can re-verify this finding against a later Apache Kafka snapshot. Every item is a read-only check that can be performed with `git`, `grep`, or file inspection — no code execution and no modification of source is required, honoring the Audit Only rule.

- [ ] **10.1 PLAINTEXT listener default:** confirm that `clients/src/main/java/org/apache/kafka/common/security/auth/SecurityProtocol.java` still declares `PLAINTEXT` as a first-class protocol and that no broker-side config in `core/src/main/scala/kafka/server/KafkaConfig.scala` or `server-common/src/main/java/org/apache/kafka/server/config/` mandates a non-PLAINTEXT default for `listeners` or `advertised.listeners`. Re-read the `ssl.endpoint.identification.algorithm = "https"` default to confirm the host-identification mitigation is still present.
- [ ] **10.2 GSSAPI-only default mechanism:** verify that `clients/src/main/java/org/apache/kafka/common/config/SaslConfigs.java` still documents `GSSAPI` as the default for `sasl.mechanism` and that the broker config in `core/src/main/scala/kafka/server/KafkaConfig.scala` still lists only `GSSAPI` as the enabled mechanism unless the operator overrides `sasl.enabled.mechanisms`.
- [ ] **10.3 `PropertyFileLoginModule` Javadoc warning:** open `connect/basic-auth-extension/src/main/java/org/apache/kafka/connect/rest/basic/auth/extension/PropertyFileLoginModule.java` and confirm the class-level Javadoc still contains the literal phrase warning that the module is "NOT intended to be used in production since credentials are stored in PLAINTEXT." Re-read the companion `JaasBasicAuthFilter` class to confirm no in-product default makes `PropertyFileLoginModule` automatically active.
- [ ] **10.4 `OAuthBearerUnsecuredValidatorCallbackHandler` availability:** confirm that `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/internals/unsecured/OAuthBearerUnsecuredValidatorCallbackHandler.java` still exists as a shipping class and that no opt-in flag gates its instantiation. Cross-verify that `BrokerJwtValidator` at `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L131` still enforces `DISALLOW_NONE` for jose4j JWT validation when the secured handler is in use (counter-mitigation also cited in accepted-mitigations Entry 3). (Note: `BrokerJwtValidator` was reorganized out of the `internals/secured/` sub-package in a prior Kafka refactor; the current canonical path is the one shown here. The Source-cited evidence entries above already use the current path — only this reviewer-facing checklist item was affected.)
- [ ] **10.5 `ssl.allow.dn.changes` / `ssl.allow.san.changes` defaults:** inspect `clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java` and confirm both `SSL_ALLOW_DN_CHANGES_CONFIG` and `SSL_ALLOW_SAN_CHANGES_CONFIG` still default to `false`. The SECURE default posture is the reason sub-finding 10.5 is rated Medium rather than High.
- [ ] **10.6 `access.control.allow.origin` empty default:** re-read `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/RestServerConfig.java` and confirm the `ACCESS_CONTROL_ALLOW_ORIGIN_CONFIG` default is the empty string (`""`). Cross-check against `RestServer.java` `CrossOriginHandler` instantiation to confirm the default behavior is no CORS headers emitted.
- [ ] **10.7 `allow.everyone.if.no.acl.found = false`:** confirm via `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java` (and supporting `StandardAuthorizerData`) that the SECURE default is preserved. Cross-reference `../diagrams/authorization-decision-flow.md` to verify the Mermaid flowchart still depicts the `allow.everyone.if.no.acl.found` branch as a terminal secure-deny by default.
- [ ] **10.8 `unclean.leader.election.enable = false`:** inspect the replication config definitions in `server/src/main/java/org/apache/kafka/server/config/ReplicationConfigs.java` and `core/src/main/scala/kafka/server/KafkaConfig.scala` to confirm the broker-wide default remains `false`. This default is the reason transactional topics remain durable under the current posture. (Note: `ReplicationConfigs.java` was relocated from the `server-common` module to the `server` module in a prior Kafka refactor; the current canonical path is the one shown here. The Source-cited evidence entries above already use the current path — only this reviewer-facing checklist item was affected.)
- [ ] **10.9 `auto.create.topics.enable = true`:** confirm that `core/src/main/scala/kafka/server/KafkaConfig.scala` still declares the default as `true`. Sub-finding 10.9 is rated Medium specifically because of the interaction with sub-finding 10.1 (PLAINTEXT) and sub-finding 10.7 (when `allow.everyone.if.no.acl.found` is overridden to `true`).
- [ ] **Severity alignment:** verify that the five SECURE defaults (10.5, 10.6, 10.7, 10.8, plus the `ssl.endpoint.identification.algorithm = "https"` companion) and the four INSECURE/UNSUITABLE defaults (10.1, 10.2, 10.3, 10.4, 10.9) match the per-row severity assigned in [`../severity-matrix.md`](../severity-matrix.md) under the Category 10 sub-table, including the three High-rated entries (10.1, 10.3, 10.4).
- [ ] **Accepted-mitigation cross-references:** confirm that [`../accepted-mitigations.md`](../accepted-mitigations.md) still catalogues each SECURE default referenced above (10.5, 10.6, 10.7, 10.8) and that every entry's Cross-Reference block points back to this finding for the watchlist framing.
- [ ] **Remediation-roadmap cross-references:** verify that [`../remediation-roadmap.md`](../remediation-roadmap.md) still contains the six future-state recommendations echoed from the Remediation section above (PLAINTEXT default change, `PropertyFileLoginModule` deprecation, unsecured OAuth handler gating, `auto.create.topics.enable` flip, operator runbook, regression-guard documentation) and that every item is worded in future-tense or conditional language consistent with the Audit Only rule.
- [ ] **No-change verification:** inspect [`../no-change-verification.md`](../no-change-verification.md) to confirm the project-wide `git diff --name-status` from the pre-audit baseline still shows only additions under `docs/security-audit/` — no modification of any Kafka source, test, comment, or build file for any of the nine defaults above.

## Key Insights

The following plain-language takeaways summarize this finding for operator consumption. They are intended to be read alongside (not in place of) the full finding above.

- **Dominant attack vector.** The combination of 10.1 (`PLAINTEXT` as an available listener default) and 10.9 (`auto.create.topics.enable = true`) is the most common "insecure quickstart" trap — an operator who follows the historical quickstart can stand up a broker that accepts unencrypted connections and implicitly creates topics on first write. 10.3 (`PropertyFileLoginModule`) and 10.4 (`OAuthBearerUnsecuredValidatorCallbackHandler`) compound this by shipping production-unsuitable reference implementations alongside the real authentication machinery, inviting copy-paste into production by operators who mistake the reference class for a production default.
- **Strongest existing mitigations.** Five SECURE defaults already narrow the risk surface materially — `ssl.allow.dn.changes = false` and `ssl.allow.san.changes = false` (10.5), `access.control.allow.origin = ""` (10.6, the Connect REST CORS empty default), `allow.everyone.if.no.acl.found = false` (10.7, the authorizer fail-closed posture), and `unclean.leader.election.enable = false` (10.8, preserving transactional durability). These are catalogued in [`../accepted-mitigations.md`](../accepted-mitigations.md) and are the reason four of the nine sub-findings sit at Low severity rather than Medium or High.
- **Primary residual risks.** The three High-severity sub-findings (10.1 PLAINTEXT default, 10.3 `PropertyFileLoginModule`, 10.4 `OAuthBearerUnsecuredValidatorCallbackHandler`) are the most likely sources of a real-world production mis-configuration. The Medium-severity sub-findings (10.5 `ssl.allow.dn.changes` knob exists even though default is secure, 10.9 `auto.create.topics.enable`) are the next tier of concern because they are easy to override inadvertently.
- **Recommended operator posture.**
    1. **Never deploy a broker with a `PLAINTEXT` listener to an untrusted network.** Configure `listeners=SSL://...` or `listeners=SASL_SSL://...` and pin `ssl.endpoint.identification.algorithm=https` so client TLS validates hostnames.
    2. **Treat `PropertyFileLoginModule` and `OAuthBearerUnsecuredValidatorCallbackHandler` as reference-only.** Neither class should appear in any production JAAS configuration. If OAuth is in use, wire `BrokerJwtValidator` (jose4j with `DISALLOW_NONE`) on the broker and a structurally-equivalent validator on clients.
    3. **Lock down topic creation.** Override `auto.create.topics.enable=false` in every production broker configuration and manage topic lifecycle via `kafka-topics.sh` or equivalent administrative tooling with explicit ACLs.
    4. **Preserve the five SECURE defaults.** Verify in code review that any PR touching `ssl.allow.dn.changes`, `ssl.allow.san.changes`, `access.control.allow.origin`, `allow.everyone.if.no.acl.found`, or `unclean.leader.election.enable` retains the SECURE default value; a regression on any of these promotes Medium/Low sub-findings toward higher severity.
- **Relationship to other categories.** Sub-finding 10.4 directly references Category 07 (external function and callback misuse — the unsecured callback handler is the same class framed from a different angle) and Category 08 (deserialization — the asymmetric `BrokerJwtValidator` vs `ClientJwtValidator` architecture). Sub-finding 10.6 connects to Category 06 (network and subprocess access — the CORS empty default is the inbound Connect REST trust-boundary posture). Sub-finding 10.7 connects to the `StandardAuthorizer` flow depicted in [`../diagrams/authorization-decision-flow.md`](../diagrams/authorization-decision-flow.md). Reviewers working on any of these categories should cross-check this watchlist to avoid regressing a default that sits on a shared code path.

---

> **End of Finding 10.** This is the final category in the audit's ten-category enumeration. For the preceding category, see [Finding 09 — Information Leakage](./09-information-leakage.md). For the audit overview, see [`../README.md`](../README.md), which indexes every finding in the canonical enumeration order.
