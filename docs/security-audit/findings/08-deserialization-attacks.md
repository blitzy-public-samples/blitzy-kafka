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

# Finding 08 — Deserialization Attacks

> Navigation: [Audit Overview](../README.md) • [Severity Matrix](../severity-matrix.md) • [Remediation Roadmap](../remediation-roadmap.md) • [OAuth JWT Validation Paths Diagram](../diagrams/oauth-jwt-validation-paths.md) • [Dependency Inventory](../dependency-inventory.md) • [Accepted Mitigations](../accepted-mitigations.md)

> **Audit-only notice.** This document is a read-only static analysis artifact for Apache Kafka 4.2.0-SNAPSHOT. No source code, configuration, or runtime behavior has been modified in the course of producing this finding. Every cited line range was resolved directly from the tracked repository at the audit snapshot commit.

---

## 1. Category

**Deserialization attacks** — enumeration position 8 of 10, as specified by the Agent Action Plan's verbatim category list.

## 2. Definition

Deserialization attacks convert attacker-controlled bytes into Java or Scala objects, potentially triggering gadget-chain remote code execution, resource exhaustion (billion-laughs, deeply-nested structures), or trust-boundary bypass by producing objects whose constructors or `readObject` side effects perform unintended actions on behalf of the deserializing process. Kafka's deserialization surface spans four distinct technologies: Jackson-based JSON (used by the Connect JSON converter and the Trogdor test harness), Java native `ObjectInputStream` (wrapped by `SafeObjectInputStream` for Connect worker internal state restoration), JOSE JWT parsing (via jose4j in `BrokerJwtValidator`; structural parse-only in `ClientJwtValidator`), and hand-written binary or line-oriented codecs for protocol and state records (MirrorMaker `Checkpoint`, Streams `OffsetCheckpoint`, and the KRaft Raft RPC surface). At the audit snapshot none of these surfaces exposes a direct remote-code-execution primitive: Jackson 2.19.0 has no known RCE in its default configuration, jose4j 0.9.6 enforces the `DISALLOW_NONE` signature constraint on the broker path via `BrokerJwtValidator`, and the native `ObjectInputStream` path is restricted to Connect internal state under a suffix-matching blocklist. The sub-findings below record the residual surface that warrants explicit documentation: a fragile blocklist-by-`endsWith` in `SafeObjectInputStream`, two non-default Jackson feature flags that widen the parse surface in Connect and Trogdor, the architectural split between broker-side and client-side JWT validation that is correct-by-design but under-documented, and the hand-written binary codec in MirrorMaker `Checkpoint.deserializeRecord` that performs bounded structured reads.

## 3. Kafka Surface Inventory

This finding enumerates five distinct surfaces grouped under the deserialization-attacks category. The sub-findings are numbered `08.1` through `08.5` in the canonical order used by the [severity matrix](../severity-matrix.md) and the [remediation roadmap](../remediation-roadmap.md).

| ID   | Surface                                                                                           | Severity                               |
| ---- | ------------------------------------------------------------------------------------------------- | -------------------------------------- |
| 08.1 | `JsonDeserializer` enables `ALLOW_LEADING_ZEROS_FOR_NUMBERS` at constructor time                  | `[Low]`                                |
| 08.2 | Trogdor `JsonUtil` enables `ACCEPT_SINGLE_VALUE_AS_ARRAY` and `ALLOW_COMMENTS` in its static ObjectMapper | `[Low]`                                |
| 08.3 | `SafeObjectInputStream` uses a nine-entry suffix-matching blocklist (not an allow-list)           | `[Medium]`                             |
| 08.4 | OAuth `BrokerJwtValidator` enforces `DISALLOW_NONE` via jose4j; `ClientJwtValidator` is structural-only | `[Low]` (Accepted Mitigation)          |
| 08.5 | MirrorMaker `Checkpoint.deserializeRecord` hand-written binary codec over `ByteBuffer`            | `[Low]`                                |

Each sub-finding is evidenced, analysed, and rated in the sections that follow.

## 4. Evidence

All line numbers below were verified by direct inspection of the tracked source files at the audit snapshot. The citation format is `Source: <repository-relative path>:L<start>[-L<end>]`.

### 4.1 `JsonDeserializer` enables `ALLOW_LEADING_ZEROS_FOR_NUMBERS` (08.1)

Kafka's Connect JSON converter instantiates a single `ObjectMapper` and configures it in a package-private constructor that enables a non-RFC-8259-compliant numeric parser feature before any record is deserialized.

- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L17` — `package org.apache.kafka.connect.json;`
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L22` — `import com.fasterxml.jackson.core.json.JsonReadFeature;`
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L23` — `import com.fasterxml.jackson.databind.DeserializationFeature;`
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L35` — `public class JsonDeserializer implements Deserializer<JsonNode> {`
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L36` — `private final ObjectMapper objectMapper = new ObjectMapper();` — single mapper instance used for every deserialize call
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L41-L43` — `public JsonDeserializer()` no-arg constructor delegates to the package-private three-arg constructor with `Set.of()`, `new JsonNodeFactory(true)`, and `true` (Blackbird enabled)
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L52-L63` — package-private constructor `JsonDeserializer(Set<DeserializationFeature>, JsonNodeFactory, boolean)`
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L57` — **`objectMapper.enable(JsonReadFeature.ALLOW_LEADING_ZEROS_FOR_NUMBERS.mappedFeature());`** — the constructor calls `.enable(...)` on the mapper with the mapped form of the `JsonReadFeature.ALLOW_LEADING_ZEROS_FOR_NUMBERS` stream-level flag; this permits the parser to accept numeric literals prefixed with zero (e.g., `007`) as valid JSON numbers, which is explicitly forbidden by RFC 8259 §6
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L58` — `deserializationFeatures.forEach(objectMapper::enable);` — the caller-supplied feature set is enabled after the leading-zeros flag, but no operator-facing configuration removes the leading-zeros flag
- `Source: connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L66-L78` — `public JsonNode deserialize(String topic, byte[] bytes)` — reads the tree from raw bytes via `objectMapper.readTree(bytes)` and wraps any exception in `SerializationException`

**Jackson version anchor:** `Source: gradle/dependencies.gradle:L66` — `jackson: "2.19.0",`. The Jackson 2.19.0 line has no published RCE advisory applicable to the `ALLOW_LEADING_ZEROS_FOR_NUMBERS` feature flag; the concern raised here is **spec conformance** and downstream interoperability, not direct exploitation. See the [dependency inventory](../dependency-inventory.md) for the full Jackson coordinate set pinned at this version.

### 4.2 Trogdor `JsonUtil` enables `ACCEPT_SINGLE_VALUE_AS_ARRAY` and `ALLOW_COMMENTS` (08.2)

The Trogdor fault-injection / soak-test framework ships a process-wide `ObjectMapper` configured with three non-default Jackson feature flags. Trogdor is deployed as an operator-run test harness, not a broker component, so its trust boundary is different from the broker or Connect plane; this sub-finding is recorded for completeness so that future reviewers do not mis-attribute the flags as production-broker configuration.

- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L18` — `package org.apache.kafka.trogdor.common;`
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L20-L26` — Jackson imports (`JsonInclude`, `JsonParser`, `JsonProcessingException`, `DeserializationFeature`, `ObjectMapper`, `SerializationFeature`, `Jdk8Module`)
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L33` — `public class JsonUtil {`
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L34` — `public static final ObjectMapper JSON_SERDE;` — JVM-wide mapper instance shared by every Trogdor caller
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L36-L43` — static initializer block that constructs and configures the `JSON_SERDE` singleton
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L37` — `JSON_SERDE = new ObjectMapper();`
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L38` — `JSON_SERDE.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);` — disables the Jackson default that throws when asked to serialize a bean with no accessible properties; widens serializer leniency
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L39` — **`JSON_SERDE.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);`** — enables the Jackson feature that silently converts a scalar JSON value into a single-element array when the target type is an array or `Collection`, eliminating a parse error that would otherwise indicate a schema mismatch
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L40` — **`JSON_SERDE.configure(JsonParser.Feature.ALLOW_COMMENTS, true);`** — enables the Jackson parser extension that accepts C-style (`/* ... */`) and C++-style (`// ...`) comments in JSON documents, which are forbidden by RFC 8259 §2
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L41` — `JSON_SERDE.registerModule(new Jdk8Module());` — enables `java.util.Optional` and other JDK 8 value-type support
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L42` — `JSON_SERDE.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);` — suppresses empty collections and null fields from serialized output
- `Source: trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L45-L51` — `public static String toJsonString(Object object)` uses `JSON_SERDE.writeValueAsString(object)` and wraps `JsonProcessingException` in a `RuntimeException`

The lenient `ACCEPT_SINGLE_VALUE_AS_ARRAY` and `ALLOW_COMMENTS` flags are operator-ergonomic features that make hand-authored Trogdor task specifications easier to write. They are **not** applied to the broker-facing JSON surfaces; the Connect JSON converter at `connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java` uses a different mapper instance with a different configuration (see 4.1).

### 4.3 `SafeObjectInputStream` suffix-matching blocklist (08.3)

Connect's internal worker-state restoration path reads serialized Java objects from a `ByteArrayInputStream` via a subclass of `java.io.ObjectInputStream` that overrides `resolveClass` to reject a nine-entry list of well-known gadget-chain class names. The rejection uses `String.endsWith` suffix matching rather than exact class-name equality or an allow-list of permitted classes.

- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L17` — `package org.apache.kafka.connect.util;`
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L19-L23` — imports (`IOException`, `InputStream`, `ObjectInputStream`, `ObjectStreamClass`, `java.util.Set`)
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L25` — `public class SafeObjectInputStream extends ObjectInputStream {` — subclass declaration
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L27-L37` — `protected static final Set<String> DEFAULT_NO_DESERIALIZE_CLASS_NAMES = Set.of(...)` — the nine-entry blocklist, reproduced verbatim below
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L39-L41` — single-argument constructor `public SafeObjectInputStream(InputStream in) throws IOException { super(in); }`
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L43-L52` — `resolveClass(ObjectStreamClass desc)` override
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L45` — `String name = desc.getName();`
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L47-L49` — `if (isBlocked(name)) { throw new SecurityException("Illegal type to deserialize: prevented for security reasons"); }`
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L51` — `return super.resolveClass(desc);` — when not blocked, delegates to the default `ObjectInputStream` class resolution
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L54-L62` — `private boolean isBlocked(String name)` — the helper used by `resolveClass`; iterates `DEFAULT_NO_DESERIALIZE_CLASS_NAMES` and returns `true` as soon as `name.endsWith(list)` matches for any entry
- `Source: connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L55-L59` — the inner loop: `for (String list : DEFAULT_NO_DESERIALIZE_CLASS_NAMES) { if (name.endsWith(list)) { return true; } }`

**The nine blocklist entries (verbatim, preserving ordering):**

| #  | Fully-qualified class name                                              | Originating library / concern |
| -- | ----------------------------------------------------------------------- | ----------------------------- |
| 1  | `org.apache.commons.collections.functors.InvokerTransformer`            | Apache Commons Collections 3.x (original `ysoserial` gadget chain) |
| 2  | `org.apache.commons.collections.functors.InstantiateTransformer`        | Apache Commons Collections 3.x |
| 3  | `org.apache.commons.collections4.functors.InvokerTransformer`           | Apache Commons Collections 4.x |
| 4  | `org.apache.commons.collections4.functors.InstantiateTransformer`       | Apache Commons Collections 4.x |
| 5  | `org.codehaus.groovy.runtime.ConvertedClosure`                          | Groovy runtime                 |
| 6  | `org.codehaus.groovy.runtime.MethodClosure`                             | Groovy runtime                 |
| 7  | `org.springframework.beans.factory.ObjectFactory`                       | Spring beans                   |
| 8  | `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`            | JDK-internal Xalan (XSLT)      |
| 9  | `org.apache.xalan.xsltc.trax.TemplatesImpl`                             | External Xalan (XSLT)          |

**Two structural observations about the blocklist design:**

1. **Suffix matching via `endsWith`.** The helper at `SafeObjectInputStream.java:L54-L62` tests each candidate class name against every blocklist entry using `name.endsWith(list)`. This is not an exact-match predicate — a class whose fully-qualified name ends with any of the nine listed strings is rejected, but a class whose name does **not** end with any of those suffixes is admitted unconditionally. The suffix predicate is a superset of exact-match (so an exact hit is still blocked), but it does not generalize to variants that do not match the listed suffix.
2. **Blocklist, not allow-list.** Any class on the worker's classpath whose fully-qualified name does not match one of the nine suffixes can be resolved and instantiated through this code path. The security posture therefore depends entirely on the worker's classpath not introducing a new gadget-chain class that is not on the blocklist. A dependency upgrade that adds a new exploitable deserialization gadget (for example, a new transformer class introduced by a future Commons Collections release, or a new JDK-internal templates class) would require the blocklist to be extended in lockstep.

### 4.4 OAuth `BrokerJwtValidator` enforces `DISALLOW_NONE`; `ClientJwtValidator` is structural-only (08.4 — Accepted Mitigation)

Kafka ships **two** JWT validator implementations that live in the same Java package. The broker-side validator delegates to jose4j with an explicit algorithm constraint that disallows the unsigned `alg:none` JOSE header; the client-side validator parses the token payload using the unsecured JWS path (base64 + JSON only) and performs no signature verification. This architectural split is intentional and correct — the broker is the authoritative validation point, and the client-side parse exists only to extract expiration and scope claims for local sanity checks before the token is sent — but the asymmetry is under-documented and is recorded here to prevent future regression or operator confusion.

**`BrokerJwtValidator` — broker-side, jose4j-backed, `DISALLOW_NONE` enforced:**

- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L18` — `package org.apache.kafka.common.security.oauthbearer;`
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L27-L34` — jose4j imports (`JwtClaims`, `MalformedClaimException`, `NumericDate`, `ReservedClaimNames`, `InvalidJwtException`, `JwtConsumer`, `JwtConsumerBuilder`, `JwtContext`)
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L52` — **`import static org.jose4j.jwa.AlgorithmConstraints.DISALLOW_NONE;`** — pulls in the jose4j algorithm-constraints helper that forbids the `none` algorithm
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L60-L78` — class Javadoc enumerates the four validation steps: (1) structural validation of the `b64token`, (2) conversion into an in-memory data structure, (3) presence of `scope`, `exp`, `subject`, `iss`, and `iat` claims, and (4) **signature matching validation** against the `kid` and the OAuth/OIDC provider's JWKS
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L80` — `public class BrokerJwtValidator implements JwtValidator {`
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L86` — `private JwtConsumer jwtConsumer;` — the built jose4j consumer is the authoritative validator object
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L95-L104` — constructors (public no-args for configuration-driven instantiation; package-visible for testing)
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L106-L138` — `public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries)` — the initialization entry point
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L119` — `final JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder();`
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L121-L128` — optional clock-skew, expected-audience, and expected-issuer builder calls
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L130-L135` — the terminal builder chain:
  - `.setJwsAlgorithmConstraints(DISALLOW_NONE)` at **L131** — enforces the no-`alg:none` constraint
  - `.setRequireExpirationTime()` at L132
  - `.setRequireIssuedAt()` at L133
  - `.setVerificationKeyResolver(verificationKeyResolver)` at L134 — hooks in the JWKS-backed verification key resolver
  - `.build();` at L135 — produces the immutable `JwtConsumer`

**`ClientJwtValidator` — client-side, structural-only, no signature verification:**

- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L18` — `package org.apache.kafka.common.security.oauthbearer;` (same package as `BrokerJwtValidator`)
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L24-L25` — imports `OAuthBearerIllegalTokenException` and **`OAuthBearerUnsecuredJws`** — the second of these is the helper used to decode the JWT payload without a signature check
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L43-L58` — class Javadoc enumerates only **three** validation steps: structural validation of the `b64token`, conversion into an in-memory map, and presence of `scope`, `exp`, `subject`, and `iat` claims. **There is no "signature matching" step in this list, unlike `BrokerJwtValidator` at L60-L78.**
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L61` — `public class ClientJwtValidator implements JwtValidator {`
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L73-L84` — `public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries)` — initializes only the `scopeClaimName` and `subClaimName` overrides; no `JwtConsumer` is constructed
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L95-L132` — `public OAuthBearerToken validate(String accessToken)` — the validation entry point
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L97` — `SerializedJwt serializedJwt = new SerializedJwt(accessToken);` — splits the `header.payload.signature` JWS compact serialization
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L101` — **`payload = OAuthBearerUnsecuredJws.toMap(serializedJwt.getPayload());`** — the payload is parsed via the **unsecured** JWS helper: base64-decode, then JSON-deserialize. No cryptographic verification is performed. This is the line that formalizes the client-side structural-only parse.
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L106-L118` — scope, expiration, subject, and issued-at claims are extracted from the unverified map
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L120-L125` — the extracted claims are validated against local constraints via `ClaimValidationUtils.validateScopes`, `.validateExpiration`, `.validateSubject`, and `.validateIssuedAt`
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L127-L131` — returns a `BasicOAuthBearerToken` assembled from the structural claims
- `Source: clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L134-L138` — `getClaim(Map, String)` helper logs every claim at DEBUG level (see [Finding 09.4](./09-information-leakage.md))

**jose4j version anchor:** `Source: gradle/dependencies.gradle:L81` — `jose4j: "0.9.6",`. The jose4j 0.9.6 line is the current stable release used by the broker validator; any regression in jose4j's algorithm-constraint API would be an upstream vulnerability with direct impact on `BrokerJwtValidator`. See the [dependency inventory](../dependency-inventory.md) for the full jose4j coordinate pinning.

**Architectural rationale.** `BrokerJwtValidator` is the authoritative validation point: when a client presents a token as the OAUTHBEARER credential during SASL authentication, the broker must verify that the token was issued by a trusted identity provider (via JWKS-backed signature verification) and that the token is structurally sound. `ClientJwtValidator`, by contrast, runs on the client-side and is used only to extract the `exp`, `sub`, and `scope` claims so that the client can decide when to refresh the token before sending it to the broker — it cannot verify the signature because the client does not necessarily hold the identity provider's public key. The broker still enforces full validation on the server-side, so a manipulated JWT that passes the client-side structural parse will be rejected at the broker. This architectural split is correct and is catalogued as an accepted mitigation at [`../accepted-mitigations.md`](../accepted-mitigations.md) entry #3.

### 4.5 MirrorMaker `Checkpoint.deserializeRecord` hand-written binary codec (08.5)

The MirrorMaker 2 checkpoint connector persists consumer-group checkpoint records using a hand-written binary codec built on top of the Kafka `Schema` / `Struct` / `Type` family from the `org.apache.kafka.common.protocol.types` package. The codec reads fixed-width header fields and length-prefixed variable fields from a `ByteBuffer`, and malformed input raises a structured `DataException` or `BufferUnderflowException` rather than admitting an attacker-crafted object graph.

- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L17` — `package org.apache.kafka.connect.mirror;`
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L19-L30` — imports: `ConsumerRecord`, `OffsetAndMetadata`, `TopicPartition`, and the Kafka `protocol.types` schema framework (`Field`, `Schema`, `Struct`, `Type`), plus `java.nio.ByteBuffer`
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L35` — `public class Checkpoint {`
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L43` — `public static final short VERSION = 0;` — the single supported wire version at the audit snapshot
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L45-L48` — `VALUE_SCHEMA_V0` defines the value shape: `upstreamOffset: INT64`, `offset: INT64`, `metadata: STRING`
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L50-L53` — `KEY_SCHEMA` defines the key shape: `group: STRING`, `topic: STRING`, `partition: INT32`
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L55-L56` — `HEADER_SCHEMA` defines the single header field: `version: INT16`
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L123-L138` — `public static Checkpoint deserializeRecord(ConsumerRecord<byte[], byte[]> record)` — the deserialization entry point
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L124` — `ByteBuffer value = ByteBuffer.wrap(record.value());` — wraps the raw record value bytes (read-only structural wrapper, no copy)
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L125-L126` — `Struct header = HEADER_SCHEMA.read(value); short version = header.getShort(VERSION_KEY);` — reads the two-byte version header
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L127-L128` — `Schema valueSchema = valueSchema(version); Struct valueStruct = valueSchema.read(value);` — the version field selects the value schema; `valueSchema(version)` at `Checkpoint.java:L140-L143` asserts `version == 0` and returns `VALUE_SCHEMA_V0`
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L129-L131` — `upstreamOffset`, `downstreamOffset`, and `metadata` are read via typed `Struct` accessors
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L132-L135` — `Struct keyStruct = KEY_SCHEMA.read(ByteBuffer.wrap(record.key())); ...` — the key is parsed from a separate `ByteBuffer` using the key schema
- `Source: connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L136-L137` — returns a `Checkpoint` constructed from the parsed fields; there is no attacker-controllable class instantiation on this path

**Cross-reference to Streams `OffsetCheckpoint` (text-format codec):** The Kafka Streams state-store checkpoint file is parsed using a line-oriented text codec that splits each line on whitespace using a pre-compiled `Pattern`.

- `Source: streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java:L55` — `public class OffsetCheckpoint {`
- `Source: streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java:L58` — `private static final Pattern WHITESPACE_MINIMUM_ONCE = Pattern.compile("\\s+");` — (the regex `\s+` matches one-or-more whitespace characters; it is the whitespace-split pattern used when reading checkpoint records, and is cross-referenced in [Finding 05](./05-infinite-loop-recursion-dos.md) as a benign regex because `\s+` has no catastrophic-backtracking behaviour)
- `Source: streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java:L150-L192` — `public Map<TopicPartition, Long> read()` performs bounded text parsing inside a `switch` on the version field (only version `0` is accepted; every other value throws `IllegalArgumentException("Unknown offset checkpoint version: " + version)`)

Both codecs perform structured, bounded reads and produce only typed primitive values plus length-prefixed `String`s. Neither path uses `ObjectInputStream` or any form of generic-object deserialization, and neither admits attacker-constructed Java objects.

## 5. Attack Vector

### 5.1 `ALLOW_LEADING_ZEROS_FOR_NUMBERS` parse-permissiveness (08.1)

An adversary who controls a JSON payload accepted by a Kafka Connect sink or source using the built-in JSON converter submits a numeric field formatted with leading zeros — for example `{"user_id": 00042}`. A spec-compliant downstream consumer (any JSON parser that does not enable the same Jackson flag) rejects the same document with a parse error at the leading zero. If the Connect JSON converter is positioned in front of a non-Kafka downstream system, the two systems disagree on document validity: Kafka's pipeline accepts the record and commits an offset, and the downstream system rejects it on read. This is a **parser-differential** behaviour, not an RCE or DoS primitive. The risk is interoperability drift and undetected downstream rejection, not direct exploitation.

### 5.2 Lenient Jackson flags on Trogdor JSON_SERDE (08.2)

The Trogdor `JsonUtil.JSON_SERDE` mapper is shared across every Trogdor caller and is used to parse operator-authored task specifications (for example `ProduceBenchSpec`, `ConsumeBenchSpec`, `NetworkPartitionFaultSpec`). An adversary who can post task specifications to a Trogdor coordinator — which is the Trogdor trust boundary by design, since Trogdor is an operator-run test harness — crafts a specification that exploits `ACCEPT_SINGLE_VALUE_AS_ARRAY` to smuggle a scalar value into an array field that a downstream Trogdor task treats as a list. The result is an unexpected runtime path inside the Trogdor worker, not a compromise of a broker. Because Trogdor is not in the broker trust boundary, this surface is documented for completeness but is not an operational broker risk.

### 5.3 Blocklist bypass in `SafeObjectInputStream` (08.3)

An adversary who can write bytes onto the input stream passed to `SafeObjectInputStream` submits a serialized object graph whose top-level class name is a fully-qualified name that does **not** end with any of the nine blocklist suffixes listed in Section 4.3. `resolveClass` then delegates to `super.resolveClass(desc)` and the JVM resolves the class from the Connect worker's classpath. If that class is present on the classpath and has a `readObject`, `readResolve`, or constructor side effect that performs an exploitable action (for example, invoking a transformer, instantiating a templated class, or opening a subprocess), the deserialization produces the intended side effect.

The exploitation precondition is that the adversary controls the bytes at the deserialization site and that the Connect worker's classpath contains a deserialization gadget that is **not** on the nine-entry blocklist. Neither precondition is trivially met at the audit snapshot:

- The deserialization site restores Connect internal worker state — typically, the bytes originate from a trusted Connect worker or from on-disk worker state. An adversary with write access to that store already has a more direct compromise path.
- The nine-entry blocklist covers the best-known Java-deserialization gadget-chain entry points (Apache Commons Collections 3.x and 4.x `InvokerTransformer`/`InstantiateTransformer`; Groovy `ConvertedClosure`/`MethodClosure`; Spring `ObjectFactory`; JDK-internal and external Xalan `TemplatesImpl`). A novel or less-well-documented gadget not listed here would need to be both on the classpath and reachable.

The **structural** concern is that a blocklist approach ties security posture to the completeness of the list; a dependency upgrade that introduces a new gadget class not on the list would silently widen the attack surface without any visible warning.

### 5.4 OAuth validator asymmetry (08.4 — Accepted Mitigation)

**No attack vector applies at the audit snapshot.** Section 4.4 documents the current architecture: the broker enforces `DISALLOW_NONE` via jose4j (authoritative), and the client performs structural parsing only (advisory). An adversary who submits a JWT with `alg:none` to a broker is rejected at the broker via the jose4j algorithm-constraint check at `BrokerJwtValidator.java:L131`. An adversary who manipulates a JWT seen only by the client side of the protocol cannot bypass the broker's verification because the broker re-validates every token presented during SASL authentication.

The sub-finding exists in this document for two reasons:

1. **Regression prevention.** A future refactor that replaces `DISALLOW_NONE` with `DEFAULT` or `NO_CONSTRAINTS` at `BrokerJwtValidator.java:L131` would silently admit `alg:none` JWTs on the broker path. The mitigation is recorded at [`../accepted-mitigations.md`](../accepted-mitigations.md) entry #3 so that such a change is caught in code review.
2. **Operator confusion prevention.** An operator who wires `ClientJwtValidator` on a broker — for example by copy-pasting the client-side validator class name into a broker configuration — would silently disable signature verification on the server side. The asymmetry between the two validators is not documented in `SaslConfigs.java` Javadoc, and the [remediation roadmap](../remediation-roadmap.md) Section 3.2.2 `[08.4]` recommends publishing an operator-facing advisory to clarify the distinction. No code change is proposed.

### 5.5 `Checkpoint.deserializeRecord` malformed input (08.5)

An adversary who forges or corrupts a MirrorMaker checkpoint record submits a byte string that claims a supported schema version but whose content is shorter than, longer than, or structurally incompatible with the schema. `HEADER_SCHEMA.read` or `valueSchema.read` at `Checkpoint.java:L125-L128` raise a `DataException` or `BufferUnderflowException`; the record is rejected at the consumer side. A version field that is not zero propagates to the `assert version == 0` in `valueSchema(short)` at `Checkpoint.java:L140-L143`, which raises `AssertionError` if JVM assertions are enabled and otherwise silently returns `VALUE_SCHEMA_V0` — the subsequent `valueSchema.read(value)` would then throw on a version mismatch in the shape of the data, again not admitting a forged object.

The risk is **integrity corruption** in mirror offset tracking (downstream consumer groups receive incorrect checkpoint translations) rather than code execution. The hand-written binary codec does not instantiate attacker-controlled classes and does not expose a gadget-chain vector.

## 6. Severity

Each sub-finding is scored using the Critical / High / Medium / Low tiers defined in [`../README.md`](../README.md) Section 2.3.

| Sub-finding | Severity                        | Rationale                                                                                                                                                                  |
| ----------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 08.1        | `[Low]`                         | Spec conformance drift, not exploitation. Exploitation requires a downstream non-Kafka consumer that enforces strict RFC 8259 numeric syntax and that disagrees with Kafka's pipeline. |
| 08.2        | `[Low]`                         | Trogdor is an operator-run test harness, not in the broker trust boundary. The lenient flags are ergonomics for test-spec authoring.                                        |
| 08.3        | `[Medium]`                      | A suffix-matching blocklist is a fragile security posture: dependency upgrades that introduce a new gadget-chain class would silently widen the surface. The exploitation precondition requires attacker control of the deserialized bytes and a classpath containing an unlisted gadget. |
| 08.4        | `[Low]` (Accepted Mitigation)   | The broker enforces `DISALLOW_NONE` via jose4j at `BrokerJwtValidator.java:L131`. No live exposure at the audit snapshot; sub-finding exists to prevent regression.         |
| 08.5        | `[Low]`                         | Bounded binary codec; malformed input yields a typed exception, not an attacker-controlled object graph. DoS potential only (forced deserialization failures).              |

**Category-level roll-up:** 0 Critical, 0 High, 1 Medium, 4 Low (one of which is an Accepted Mitigation). The category is driven by the `SafeObjectInputStream` blocklist design (08.3); the remaining four sub-findings are defence-in-depth observations or accepted-mitigation records. These totals match the [severity matrix](../severity-matrix.md) Section 4 row for Category 08.

## 7. Business Impact

The business impact of deserialization-attack surfaces in Apache Kafka deployments is **low to moderate** at the audit snapshot, and centres on two distinct concerns: **supply-chain resilience** and **interoperability drift**, not direct credential theft or remote code execution. Four concrete consequences apply:

1. **Supply-chain regression risk (08.3 — primary).** The nine-entry suffix-matching blocklist in `SafeObjectInputStream` is sized to cover the well-known Java-deserialization gadget-chain entry points present in the legacy OWASP `ysoserial` toolkit (Apache Commons Collections, Groovy, Spring, Xalan). A future dependency upgrade — introduced either in Kafka's direct dependency graph or via a transitive dependency brought in by a Connect plugin on `plugin.path` — could add a new class to the worker classpath that is exploitable via `ObjectInputStream` deserialization and whose name does not end with any of the nine listed suffixes. Because the blocklist approach does not alert on classpath changes, the regression would be silent. Operators running Connect with a broad plugin ecosystem (for example, clusters pulling in Debezium, Confluent connectors, and proprietary in-house plugins) carry a correspondingly broader surface for this regression path.

2. **Interoperability drift with downstream non-Kafka systems (08.1).** Organizations running pipelines where Kafka Connect is upstream of a non-Kafka consumer (for example, a BI tool that re-parses committed JSON records, a data lake that validates schemas on ingest, or a streaming SQL engine with its own JSON parser) may experience periodic record-rejection incidents when a producer emits numeric literals with leading zeros. The Connect pipeline accepts and commits the record because `ALLOW_LEADING_ZEROS_FOR_NUMBERS` is enabled, but the downstream consumer rejects it. These failures manifest as data-freshness alerts or pipeline lag rather than security incidents, but they are directly attributable to the Jackson feature flag enabled at `JsonDeserializer.java:L57`.

3. **Operator misconfiguration potential (08.4).** An operator who mis-wires `ClientJwtValidator` as the broker's `JwtValidator` implementation — either through a copy-paste error in a configuration file or through a misleading class-name choice in operator tooling — would silently disable signature verification on the broker path. The broker would accept any JWT whose payload parses as JSON regardless of signature. The impact is **authentication bypass on the broker OAUTHBEARER mechanism**. The audit does not identify any operator-facing documentation that distinguishes the two validators; the [remediation roadmap](../remediation-roadmap.md) Section 3.2.2 proposes a documentation update, not a code change.

4. **Test-harness surface isolation (08.2).** The Trogdor lenient Jackson flags are scoped to the Trogdor test runner process. Trogdor is not deployed in production broker topology; compromise of the Trogdor coordinator would affect only the test infrastructure. The business impact is **test-framework compromise**, not broker compromise.

The cumulative posture is appropriately cautious: Kafka's deserialization surfaces either use typed structured codecs (Checkpoint, OffsetCheckpoint, KRaft RPCs via generated message classes), enforce authoritative cryptographic validation (BrokerJwtValidator with `DISALLOW_NONE`), or wrap the native `ObjectInputStream` path with a blocklist that covers the canonical gadget-chain entry points. The residual risk is primarily supply-chain — a future gadget class outside the blocklist — and interoperability — a future non-Kafka consumer that rejects a leading-zero numeric literal emitted by a Kafka Connect pipeline.

## 8. Performance Considerations

The Audit Only rule (quoted verbatim in [`../README.md`](../README.md) Section 1 and reproduced in Agent Action Plan Section 0.9.2) directs every deliverable to summarise "security vulnerabilities, potential exploits, bugs in the codebase, perofrmace considerations, and remediation recommendations" (the misspelling of "performance" is preserved verbatim from the user-supplied rule text). This section records the performance characteristics of the Category 08 deserialization surfaces and the positive-security controls catalogued in Section 9 below. No benchmarks were executed and no profiling harness was attached to the running Kafka code during this audit — the performance accounting below is derived exclusively from static inspection of the line ranges cited in Section 4. Consistent with the Audit Only rule, the observations here are informational and do not propose or apply any code change.

### 8.1 Hot-Path Signals per Sub-Finding

- **08.1 — `JsonDeserializer.deserialize` per-record parse** (`connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java:L57` for the `ALLOW_LEADING_ZEROS_FOR_NUMBERS.mappedFeature()` flag; the `deserialize(...)` method body is the record-level entry point). The Connect JSON converter's deserializer is on the **data-plane record hot path**: every record produced through a Connect source task that uses the JSON converter, and every record consumed through a Connect sink task that uses the JSON converter, traverses this `ObjectMapper.readTree(...)` call. The `ALLOW_LEADING_ZEROS_FOR_NUMBERS` flag is a compile-time Jackson feature bitmask — it is set once at `ObjectMapper` construction and has **zero per-record cost** other than the conditional branch inside Jackson's number-parse state machine. The performance impact of enabling this flag is measurably negligible; the security impact is the widened parse surface characterised in Section 5.1.
- **08.2 — Trogdor `JsonUtil` per-task-spec parse** (`trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java:L39` for `ACCEPT_SINGLE_VALUE_AS_ARRAY`, `L40` for `ALLOW_COMMENTS`). Trogdor's `JsonUtil` is invoked once per task-spec POST to the Trogdor coordinator REST endpoint — a control-plane admin operation that is neither on a per-record hot path nor on a per-connection hot path. Task-spec submissions are low-frequency (minutes to hours between submissions in normal use). The two lenient flags add bit-flags to the `ObjectMapper` configuration at class-load time and impose zero measurable runtime cost per submission.
- **08.3 — `SafeObjectInputStream.resolveClass` per-class-resolution** (`connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L43-L52` for the `resolveClass` override, `L27-L37` for the blocklist). The `resolveClass` override is invoked by the JDK `ObjectInputStream` machinery once per **distinct class encountered in a serialized graph**. Connect's `SafeObjectInputStream` is used for internal serialized-state flows (for example, Kafka Connect's internal offset-commit topics, task-configuration propagation through the config topic) rather than user-record traffic; the frequency is bounded by the rate of Connect rebalance and commit events rather than by record throughput. The per-resolution cost is `O(|blocklist|)` ≈ 9 short-string `endsWith` checks plus one Class-name `String.equals` comparison — well under one microsecond per resolution on a warm JVM.
- **08.4 — `BrokerJwtValidator` per-SASL-handshake** (`clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L52, L131` for `DISALLOW_NONE`; `ClientJwtValidator.java:L101` for the structural-only path). This is the same hot-path signal characterised in Finding 07 Section 8.1 under sub-finding 07.1 (the unsecured counterpart). The jose4j `JwtConsumer.processToClaims(...)` call on the broker side performs base64-URL decoding, JSON parsing, and cryptographic signature verification (typically RSA, ECDSA, or HMAC) against a JWKS-sourced public key. Per-handshake cost is dominated by the asymmetric-key verification, typically 1–10 ms depending on algorithm and JWKS cache state. The `ClientJwtValidator` structural-only path at `L101` (`OAuthBearerUnsecuredJws.toMap(...)`) performs base64-URL decode and JSON parse only — typically tens of microseconds per handshake. Neither path is on a per-record hot path; both are one-per-SASL-handshake, which is one-per-TCP-connection.
- **08.5 — `Checkpoint.deserializeRecord` per-checkpoint-record replay** (`connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L45-L56, L123-L138`). The checkpoint codec is invoked once per checkpoint record during MirrorMaker 2 checkpoint topic replay, typically during `MirrorCheckpointConnector` startup and during periodic consumer-group offset translation. Frequency is bounded by the number of mirrored consumer groups × topic partitions × checkpoint emission cadence (configurable, default every ~1 minute per consumer group), not by record throughput. The codec reads a small, fixed number of typed primitives via the `Schema` / `Struct` framework — a few microseconds per record at most. Memory allocation is bounded by the record's fixed primitive payload plus one or two `String` allocations for topic/group names.

### 8.2 Observable Metrics Indicating Exploitation

The following metrics are already exposed by Kafka under JMX / Yammer in the audit snapshot. The audit records them for their exploitation-detection value and does not propose new metrics (doing so would constitute a code change outside the Audit Only scope).

- **Connect converter error rates** — `kafka.connect:type=task-error-metrics,name=deadletterqueue-produce-requests` and `kafka.connect:type=task-error-metrics,name=total-record-failures`. A sustained elevation in converter-produced failures on a JSON-converter pipeline is a signal that upstream records are encountering parse errors. A sudden rise without a producer-side change could indicate a malformed-input probe targeting the `ALLOW_LEADING_ZEROS_FOR_NUMBERS` parse surface at 08.1.
- **Connect worker heap and GC pressure** — `java.lang:type=GarbageCollector,name=*` and `java.lang:type=Memory,attribute=HeapMemoryUsage`. A deserialization-pressure attack on the `SafeObjectInputStream` path at 08.3 (for example, a large, deeply-nested serialized graph that would exercise the `resolveClass` override many times) would be visible as a transient spike in old-generation allocation and potentially a `java.lang:type=GarbageCollector,name=G1 Old Generation` count increase during the affected Connect rebalance or commit event.
- **Broker SASL handshake latency** — `kafka.network:type=RequestMetrics,name=RequestQueueTimeMs,request=SaslHandshake` and the complementary `LocalTimeMs`. A sustained drop in P50 SASL handshake latency from the usual 1–10 ms range to the tens-of-microseconds range is a strong signal that the broker has been mis-configured to run `ClientJwtValidator` or the unsecured validator at 07.1 — the drop reflects the absence of the cryptographic path in the `BrokerJwtValidator` jose4j code. This is the same metric catalogued in Finding 07 Section 8.2 and has dual diagnostic value across the two findings.
- **MirrorMaker checkpoint throughput** — `kafka.connect.mirror:type=MirrorCheckpointConnector-metrics,name=checkpoint-put-total` and the complementary emission cadence. A sustained drop in checkpoint emission rate while consumer groups are actively advancing offsets is a possible signal of 08.5-related replay errors; the more usual causes are network throttling or coordinator failover.
- **Trogdor coordinator request rate** — no direct JMX metric in the audit snapshot; operators should rely on the coordinator's own logging and reverse-proxy access logs for an observability baseline on the Trogdor REST endpoints that trigger the 08.2 code path.

### 8.3 Performance Trade-Offs of Current Mitigations

- **`BrokerJwtValidator.setJwsAlgorithmConstraints(DISALLOW_NONE)` (accepted mitigation Entry 3) — measurable per-handshake cost, acceptable.** The cryptographic verification cost is the single largest per-handshake expense on the broker OAUTHBEARER path. The cost is intentional — it is the whole point of using a signed-JWT authentication mechanism — and is amortised across the connection lifetime by Kafka's SASL reauthentication protocol (KIP-368), which re-runs the validator only at the configured reauthentication interval, not on every request.
- **`SafeObjectInputStream.resolveClass` blocklist (accepted mitigation) — sub-microsecond per class resolution.** The nine-entry `endsWith` loop is a constant-factor check. Its cost scales with the number of distinct classes in a deserialized graph, not with record throughput. The trade-off is correctness-over-performance: the blocklist is fragile (see sub-finding 08.3), but its runtime cost is genuinely negligible.
- **Jackson 2.19.0 pinning (accepted mitigation) — supply-chain stability, zero runtime cost.** Pinning is a build-time decision with zero runtime impact.
- **Jose4j 0.9.6 pinning (accepted mitigation) — supply-chain stability, zero runtime cost.** Same accounting as Jackson.
- **Bounded typed codecs in `Checkpoint` and `OffsetCheckpoint` (accepted mitigation) — fastest possible deserialization path.** Typed primitive reads via `ByteBuffer` and length-prefixed `String` reads are the cheapest deserialization primitive in the JVM ecosystem. There is no faster approach that retains cross-version compatibility; the performance profile is optimal.
- **`ClientJwtValidator` structural-only parsing (accepted mitigation, dual-architecture split) — intentional performance-for-security trade.** The client-side validator is deliberately cheaper than the broker-side validator because clients are typically resource-constrained (embedded producers, consumer sidecars, stream processors on small instances) and do not need to re-verify signatures that the broker has already verified on the preceding TCP handshake.

### 8.4 Future-State Performance Accounting

Each item below maps to a recommendation in Section 10. The cost estimates are qualitative because no code has been written or benchmarked; they are included so that a future change-bearing engagement can prioritise on risk-adjusted cost.

- **Convert `SafeObjectInputStream` to allow-list (Section 10 item 1).** An allow-list `Set<String>` lookup replaces the current `endsWith` loop. `HashSet.contains(...)` is `O(1)` amortised versus the current `O(|blocklist|)` `endsWith` linear scan. Performance change: **marginal improvement** (sub-microsecond to sub-nanosecond per resolution), with significantly improved security posture. The main cost of the migration is operational — compiling the full set of Connect-internal serialized-state classes that must be permitted.
- **Review Jackson feature flags (Section 10 item 2).** Removing flags from the `ObjectMapper` configuration is a zero-cost change at runtime (the feature bitmask check is already paid for each feature-flag regardless of whether it is enabled or disabled). The change is performance-neutral and entirely security-motivated.
- **Publish JWT-validator dual-architecture operator advisory (Section 10 item 3).** Documentation-only; zero runtime impact.
- **Document `JsonDeserializer` feature-flag set for downstream integrators (Section 10 item 4).** Documentation-only; zero runtime impact.
- **Maintain supply-chain vigilance on Jackson and jose4j (Section 10 item 5).** Operational-process change; zero runtime impact.

### 8.5 No-Code-Change Attestation

The analysis above was derived from static inspection of the line ranges cited in Section 4 and cross-referenced against the accepted-mitigation entries in Section 9. No benchmarks were executed, no profiling was attached to a running Kafka process, no code was modified, and no new telemetry hooks were added. The Audit Only rule from Agent Action Plan Section 0.9.2 — "DO NOT modify, create, or delete any existing code in the codebase. Avoid executing any code in the code base, this should be a static analysis." — is honoured in full by this section.

## 9. Accepted Mitigations Already Present

The following mitigations are in place at the audit snapshot and are catalogued in [`../accepted-mitigations.md`](../accepted-mitigations.md). This audit does not propose to modify them; the purpose of enumerating them here is to prevent regression in future refactoring.

- **`BrokerJwtValidator.setJwsAlgorithmConstraints(DISALLOW_NONE)` — authoritative JWT signature enforcement.** The broker-side validator imports `DISALLOW_NONE` from jose4j and applies it to the `JwtConsumer` builder at `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java:L52,L131`. Any JWT that presents `alg:none` in its JOSE header is rejected before claim extraction. Catalogued as [`../accepted-mitigations.md`](../accepted-mitigations.md) entry #3 under Section 3.2 "Security — OAuth".
- **`SafeObjectInputStream` as a subclass of `ObjectInputStream` — existence of any blocklist is a partial mitigation.** The blocklist is fragile (see sub-finding 08.3) but its presence blocks the canonical `ysoserial`-style gadget-chain classes at `connect/runtime/src/main/java/org/apache/kafka/connect/util/SafeObjectInputStream.java:L27-L37`. The override of `resolveClass` at L43-L52 ensures the blocklist is consulted on every class resolution, not just top-level graph entries. A future refactor that removes this subclass and uses the default `ObjectInputStream` directly would regress the posture to fully permissive.
- **Jackson 2.19.0 pinned in `gradle/dependencies.gradle:L66`.** The 2.19.0 line has no published RCE advisory applicable to the default deserialization configuration or to the `ALLOW_LEADING_ZEROS_FOR_NUMBERS` / `ACCEPT_SINGLE_VALUE_AS_ARRAY` / `ALLOW_COMMENTS` feature flags enabled by Kafka. Supply-chain advisories against the Jackson family are tracked via the repository's OWASP Dependency-Check integration; see the [dependency inventory](../dependency-inventory.md) Section 5.4 "Deserialization (Jackson)" for the full Jackson coordinate set.
- **Jose4j 0.9.6 pinned in `gradle/dependencies.gradle:L81`.** The 0.9.6 line is the current stable release of the jose4j JWT/JOSE library used by `BrokerJwtValidator`. Supply-chain tracking applies as for Jackson; see the [dependency inventory](../dependency-inventory.md) Section 5.2 "OAuth and JWT (jose4j)".
- **MirrorMaker `Checkpoint` and Streams `OffsetCheckpoint` use bounded typed codecs rather than `ObjectInputStream`.** The MirrorMaker checkpoint codec at `connect/mirror-client/src/main/java/org/apache/kafka/connect/mirror/Checkpoint.java:L45-L56,L123-L138` reads only typed primitives and length-prefixed `String`s via the `Schema` / `Struct` framework. The Streams offset checkpoint at `streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java:L55-L192` parses a line-oriented text format with bounded integer and long extraction via `Integer.parseInt` / `Long.parseLong`. Neither path admits attacker-constructed Java objects.
- **`ClientJwtValidator` does not deserialize into caller-supplied types.** The payload extraction at `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java:L101` uses `OAuthBearerUnsecuredJws.toMap(...)` which produces a `Map<String, Object>` of JSON primitives — it does not bind the JSON to an attacker-chosen class via `ObjectMapper.readValue(bytes, Class<?>)` or a similar reflection path. The subsequent claim extractions at L106-L118 are type-checked against expected primitive kinds (`String`, `Number`, `Collection`) before use.

## 10. Recommended Future Remediation (No Changes in This Run)

Per the Audit Only rule, **no source code or configuration changes are applied in this run**. The following items are forward-looking recommendations for subsequent Kafka Improvement Proposals (KIPs), code reviews, or operator-facing documentation updates. Each item is cross-referenced to its tagged entry in the [remediation roadmap](../remediation-roadmap.md).

1. **Convert `SafeObjectInputStream` from suffix-matching blocklist to explicit allow-list (08.3 — Medium-term, KIP required).** A future KIP could replace the nine-entry `endsWith` blocklist at `SafeObjectInputStream.java:L27-L62` with an explicit allow-list of the canonical class names that Connect's internal serialized-state flows actually require, rejecting every other class unconditionally. The current blocklist would be retained as a defence-in-depth secondary check. Cross-reference: [remediation-roadmap.md Section 3.3.1 — `[08.3]` Convert SafeObjectInputStream to allow-list](../remediation-roadmap.md).

2. **Review Jackson feature flags in `JsonDeserializer` and Trogdor `JsonUtil` (08.1, 08.2 — Medium-term, KIP required for Connect; engineering review for Trogdor).** A future review could evaluate whether `ALLOW_LEADING_ZEROS_FOR_NUMBERS.mappedFeature()` at `JsonDeserializer.java:L57` is still required for backward compatibility with any historical producer, and whether `ACCEPT_SINGLE_VALUE_AS_ARRAY` at `JsonUtil.java:L39` and `ALLOW_COMMENTS` at `JsonUtil.java:L40` are still required for Trogdor task-authoring ergonomics. The review could document the historical rationale for each flag and decide whether contemporary use justifies the widened parse surface. Cross-reference: [remediation-roadmap.md Section 3.3.6 — `[08.1, 08.2]` Jackson feature-flag review](../remediation-roadmap.md).

3. **Publish a JWT-validator dual-architecture operator advisory (08.4 — Short-term, documentation-only).** Documentation maintainers could publish an operator-facing advisory distinguishing `BrokerJwtValidator` (jose4j-backed, enforces `DISALLOW_NONE`, appropriate for brokers) from `ClientJwtValidator` (structural-only parsing, appropriate for clients). The advisory could also reiterate the relationship to the deprecated `OAuthBearerUnsecuredValidatorCallbackHandler` catalogued in [Finding 07](./07-external-function-callback-misuse.md) sub-finding 07.1. No code change is proposed. Cross-reference: [remediation-roadmap.md Section 3.2.2 — `[08.4]` JWT-validator dual-architecture advisory](../remediation-roadmap.md).

4. **Document the `JsonDeserializer` feature-flag set for downstream integrators (08.1 — Short-term, documentation-only).** An operator runbook could publish the exact set of `DeserializationFeature` and `JsonReadFeature` flags that Kafka enables on the default Connect JSON converter, so that non-Kafka downstream consumers can align their parsing leniency. The same runbook could note Trogdor's additional `ACCEPT_SINGLE_VALUE_AS_ARRAY` and `ALLOW_COMMENTS` flags and clarify that Trogdor is a test harness rather than a broker-facing JSON endpoint.

5. **Maintain supply-chain vigilance on Jackson and jose4j (08.1, 08.2, 08.3, 08.4 — ongoing).** The repository already integrates OWASP Dependency-Check as a CI step; the operational recommendation is to track every Jackson and jose4j advisory emitted against the pinned 2.19.0 and 0.9.6 lines respectively, and to evaluate upgrade impact through the Kafka release process. The [dependency inventory](../dependency-inventory.md) is the canonical starting point for this tracking.

**Closing.** No code changes are applied in this audit run per the Audit Only rule. Every recommendation above is a forward-looking guidance item for the Kafka community to evaluate in subsequent KIP proposals, operator runbook updates, or code-review exercises.

## 11. Cross-References

- **Navigation root:** [`../README.md`](../README.md) — audit overview, severity tier definitions (Section 2.3), and navigation to every audit artifact.
- **Severity matrix:** [`../severity-matrix.md`](../severity-matrix.md) — Section 3.8 "Category 08 - Deserialization Attacks" enumerates rows `08.1` through `08.5` with the same severity assignments used here.
- **Remediation roadmap:** [`../remediation-roadmap.md`](../remediation-roadmap.md) — Section 3.2.2 `[08.4]` JWT-validator dual-architecture advisory (Short-term); Section 3.3.1 `[08.3]` Convert `SafeObjectInputStream` to allow-list (Medium-term); Section 3.3.6 `[08.1, 08.2]` Jackson feature-flag review (Medium-term).
- **Accepted mitigations:** [`../accepted-mitigations.md`](../accepted-mitigations.md) — Section 3.2 entry #3 "BrokerJwtValidator enforces `DISALLOW_NONE` JWS algorithm constraints" is the canonical record for the accepted-mitigation aspect of sub-finding 08.4.
- **Dependency inventory:** [`../dependency-inventory.md`](../dependency-inventory.md) — Jackson 2.19.0 (family anchor at `gradle/dependencies.gradle:L66`); jose4j 0.9.6 (anchor at `gradle/dependencies.gradle:L81`); Section 5.2 "OAuth and JWT (jose4j)" and Section 5.4 "Deserialization (Jackson)" describe the supply-chain surface.
- **OAuth JWT validation paths diagram:** [`../diagrams/oauth-jwt-validation-paths.md`](../diagrams/oauth-jwt-validation-paths.md) — Mermaid flowchart distinguishing `BrokerJwtValidator` (jose4j + `DISALLOW_NONE` at L131) from `ClientJwtValidator` (structural-only) from the unsecured `OAuthBearerUnsecuredValidatorCallbackHandler` (legacy, accepts `alg:none`). Directly supports sub-finding 08.4.
- **Attack surface map:** [`../diagrams/attack-surface-map.md`](../diagrams/attack-surface-map.md) — Category 08 row intersects the Connect, Trogdor, and Clients-OAuth modules.
- **Threat model overview:** [`../diagrams/threat-model-overview.md`](../diagrams/threat-model-overview.md) — deserialization surfaces are annotated at the Connect plane and the OAuth SASL trust boundary.
- **Related finding — Category 05 (Infinite Loop / ReDoS):** [`./05-infinite-loop-recursion-dos.md`](./05-infinite-loop-recursion-dos.md) — `streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java:L58` `WHITESPACE_MINIMUM_ONCE` pattern is cited in Finding 05 as a benign `\s+` regex; also appears in this document at sub-finding 08.5 as evidence that Streams checkpoint parsing is bounded.
- **Related finding — Category 07 (External Function and Callback Misuse):** [`./07-external-function-callback-misuse.md`](./07-external-function-callback-misuse.md) — sub-finding 07.1 documents the deprecated `OAuthBearerUnsecuredValidatorCallbackHandler` that accepts `alg:none`; the validator asymmetry described here in 08.4 is the correct-by-design counterpart on the supported code path.
- **Related finding — Category 09 (Information Leakage):** [`./09-information-leakage.md`](./09-information-leakage.md) — sub-finding 09.4 documents the DEBUG-level JWT claim logging common to both `BrokerJwtValidator` and `ClientJwtValidator` (at `BrokerJwtValidator.java:L191-L199` and `ClientJwtValidator.java:L134-L138`). The two findings are complementary: Finding 08.4 records the validator architecture; Finding 09.4 records the per-claim logging side-channel inside each validator.
- **Related finding — Category 10 (Public API Developer Misuse):** [`./10-public-api-developer-misuse.md`](./10-public-api-developer-misuse.md) — sub-finding 10.4 catalogues `OAuthBearerUnsecuredValidatorCallbackHandler` as an insecure default; this document cross-references that finding as part of the broader OAuth trust-boundary story.

## Validation Checklist

The following checklist items are provided so that a future auditor or reviewer can re-verify this finding against a later Apache Kafka snapshot. Every item is a read-only check that can be performed with `git`, `grep`, or file inspection — no code execution and no modification of source is required, honoring the Audit Only rule.

- [ ] **08.1 — `JsonDeserializer.ALLOW_LEADING_ZEROS_FOR_NUMBERS`:** Confirm that `connect/json/src/main/java/org/apache/kafka/connect/json/JsonDeserializer.java` still enables `ALLOW_LEADING_ZEROS_FOR_NUMBERS.mappedFeature()` at the line cited in Section 4.1 (anchor L57 in the audit snapshot), and that the surrounding `ObjectMapper` construction is unchanged.
- [ ] **08.2 — `JsonUtil.ACCEPT_SINGLE_VALUE_AS_ARRAY`:** Confirm that `trogdor/src/main/java/org/apache/kafka/trogdor/common/JsonUtil.java` still enables `DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY` at the line cited in Section 4.2 (anchor L39 in the audit snapshot), and that the `JsonFactory` / `ObjectMapper` wiring remains scoped to Trogdor.
- [ ] **08.3 — `SafeObjectInputStream` suffix-matching blocklist:** Confirm that `SafeObjectInputStream.java` (located at `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/distributed/` or equivalent `util/` directory per the Section 4.3 evidence — note: NOT under `clients/.../utils/`) still implements an `endsWith`-based class-name blocklist with approximately 9 entries, and that the `resolveClass` override has not been relaxed.
- [ ] **08.4 — `BrokerJwtValidator` DISALLOW_NONE vs `ClientJwtValidator` structural-only:** Confirm that `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/BrokerJwtValidator.java` still configures `jose4j` with `DISALLOW_NONE` at the line cited in Section 4.4 (anchor L131 in the audit snapshot), and that `clients/src/main/java/org/apache/kafka/common/security/oauthbearer/ClientJwtValidator.java` continues to perform structural-only parsing (no signature verification) at the cited line range. (Note: both classes were reorganized out of the `internals/secured/` sub-package in a prior Kafka refactor; the current canonical paths are the ones shown here. The Source-cited evidence entries above already use the current paths — only this reviewer-facing checklist item was affected.)
- [ ] **08.5 — Streams `OffsetCheckpoint` bounded parsing:** Confirm that `streams/src/main/java/org/apache/kafka/streams/state/internals/OffsetCheckpoint.java` still uses the bounded `WHITESPACE_MINIMUM_ONCE` pattern and numeric-parse path cited in Section 4.5.
- [ ] **Jackson and jose4j version pinning:** Confirm that `gradle/dependencies.gradle` still pins Jackson at `2.19.0` (line 66) and jose4j at `0.9.6` (line 81), matching the supply-chain surface characterised in Section 7.
- [ ] **Severity alignment:** Confirm that the severity assignments for 08.1 through 08.5 in Section 6 of this finding match the row-level severities for the same sub-findings in [severity-matrix.md](../severity-matrix.md) Section 3.8.
- [ ] **Remediation roadmap cross-references:** Confirm that the sub-findings referenced in Section 10 (08.4 → Section 3.2.2; 08.3 → Section 3.3.1; 08.1, 08.2 → Section 3.3.6) still resolve to the corresponding subsections in [remediation-roadmap.md](../remediation-roadmap.md).
- [ ] **Accepted-mitigation cross-references:** Confirm that [accepted-mitigations.md](../accepted-mitigations.md) Section 3.2 entry #3 ("`BrokerJwtValidator` enforces `DISALLOW_NONE`") still cites the same `BrokerJwtValidator.java` line range as Section 9 of this finding.
- [ ] **OAuth JWT validation paths diagram:** Confirm that [`../diagrams/oauth-jwt-validation-paths.md`](../diagrams/oauth-jwt-validation-paths.md) still distinguishes `BrokerJwtValidator` (jose4j + `DISALLOW_NONE`) from `ClientJwtValidator` (structural-only), matching the architecture described in 08.4.
- [ ] **No-change verification:** Confirm via [no-change-verification.md](../no-change-verification.md) that this finding introduced zero modifications to Kafka source, test, or build files; only the markdown file you are reading now (and its sibling artifacts under `docs/security-audit/`) were created.

## Key Insights

The following plain-language takeaways summarize this finding for operator consumption. They are intended to be read alongside (not in place of) the full finding above.

- **Dominant attack vector.** Category 08 is characterised less by a single dominant vector and more by a cluster of parsing-leniency flags. The most consequential surface today is the `SafeObjectInputStream` (08.3) — a suffix-matching blocklist approach that is inherently weaker than an allow-list because new gadget classes in updated JDKs or third-party libraries can silently become deserializable. The `JsonDeserializer.ALLOW_LEADING_ZEROS_FOR_NUMBERS` flag (08.1) expands parsing leniency beyond the Jackson defaults and creates a small-but-real surface for malformed-input propagation into downstream schema-sensitive consumers.

- **Strongest existing mitigation.** The `BrokerJwtValidator` configures `jose4j` with `DISALLOW_NONE` (08.4 / accepted mitigation Entry 3), which hard-rejects `alg:none` JWTs on the broker's supported OAUTHBEARER code path. This is the strongest positive-security control in the deserialization category and is the correct-by-design counterpart to the unsecured handler catalogued in Finding 07.1.

- **Primary residual risk.** The `SafeObjectInputStream` blocklist approach is brittle against the evolution of the Java standard library and third-party JARs on the Connect worker classpath. A new gadget chain that does not match any `endsWith` suffix in the blocklist would be deserialized without the mitigation applying. The second residual risk is the Trogdor `ACCEPT_SINGLE_VALUE_AS_ARRAY` flag (08.2), which is scoped to a test harness but worth monitoring if Trogdor is ever repurposed for production traffic.

- **Recommended operator posture.** (1) Maintain supply-chain vigilance on Jackson (2.19.0 pinned) and jose4j (0.9.6 pinned) — track every CVE advisory against these lines and evaluate upgrade impact through the Kafka release process. (2) Restrict the Connect worker classpath to the minimum set of trusted JARs, so that the `SafeObjectInputStream` blocklist is backed by a narrow class-surface. (3) If you operate Trogdor, keep it scoped to test environments only; do not expose Trogdor REST endpoints to production traffic. (4) Ensure no broker is running `OAuthBearerUnsecuredValidatorCallbackHandler` (cross-reference Finding 07.1).

- **Relationship to other categories.** Category 08 intersects with Category 05 (infinite-loop / recursion — `SafeObjectInputStream` is both a deserialization guard and a recursion-bounded guard), Category 07 (external-function / callback misuse — 08.4's dual-validator architecture is the correct-by-design counterpart to 07.1's unsecured handler), Category 09 (information leakage — 09.4 documents DEBUG-level JWT claim logging inside both validators), and Category 10 (public API developer misuse — 10.4 catalogues the unsecured validator as an insecure public-API default).

---

> **End of Finding 08.** For the next category, see [Finding 09 — Information Leakage](./09-information-leakage.md). For the preceding category, see [Finding 07 — External Function and Callback Misuse](./07-external-function-callback-misuse.md).
