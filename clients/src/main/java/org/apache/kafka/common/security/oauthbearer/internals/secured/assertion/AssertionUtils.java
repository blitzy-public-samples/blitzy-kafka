/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.common.security.oauthbearer.internals.secured.assertion;

import org.apache.kafka.common.security.oauthbearer.internals.secured.ConfigurationUtils;
import org.apache.kafka.common.utils.Time;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_ALGORITHM;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_CLAIM_AUD;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_CLAIM_EXP_SECONDS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_CLAIM_ISS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_CLAIM_JTI_INCLUDE;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_CLAIM_NBF_SECONDS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_CLAIM_SUB;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ASSERTION_TEMPLATE_FILE;

/**
 * Set of utilities for the OAuth JWT assertion logic.
 */
// CROSS-CUTTING: Central utility and factory for the assertion pipeline. Used by
// JwtBearerJwtRetriever to build the final AssertionJwtTemplate (via
// layeredAssertionJwtTemplate) and to instantiate AssertionCreator implementations.
// Creates and wires StaticAssertionJwtTemplate, DynamicAssertionJwtTemplate,
// FileAssertionJwtTemplate into a LayeredAssertionJwtTemplate. Depends on:
// ConfigurationUtils (config validation/extraction), Time (clock abstraction),
// SaslConfigs (config key constants), JCA (KeyFactory, Signature, Cipher).
// The privateKey() and sign() methods are also used by DefaultAssertionCreator
// for JWT signing.
// Impact: Changes to layering order or algorithm mapping affect ALL jwt-bearer
// assertion flows.
public class AssertionUtils {

    public static final String TOKEN_SIGNING_ALGORITHM_RS256 = "RS256";
    public static final String TOKEN_SIGNING_ALGORITHM_ES256 = "ES256";

    /**
     * Inspired by {@code org.apache.kafka.common.security.ssl.DefaultSslEngineFactory.PemStore}, which is not
     * visible to reuse directly.
     */
    // SECURITY: (HIGH) Parses PKCS#8 private key from raw bytes, with optional PBE
    // passphrase decryption. The decoded key bytes exist as byte[] but are not
    // explicitly zeroed after use (no Arrays.fill(0) call on pkcs8EncodedBytes or
    // keySpec internals).
    // Exploit: (1) If passphrase is supplied, PBEKeySpec wraps it as char[] but the
    // passphrase String's internal char[] cannot be zeroed (String is immutable in
    // Java). (2) Memory forensics can recover the decoded PKCS#8 bytes from the JVM
    // heap. (3) The passphrase Optional<String> persists as an interned String,
    // potentially surviving multiple GC cycles.
    // Improvement: Accept passphrase as char[] instead of String to enable explicit
    // zeroing via Arrays.fill(). Zero pkcs8EncodedBytes in a finally block after
    // KeyFactory use.
    public static PrivateKey privateKey(byte[] privateKeyContents,
                                        Optional<String> passphrase) throws GeneralSecurityException, IOException {
        PKCS8EncodedKeySpec keySpec;

        // SECURITY: (MEDIUM) PBE-encrypted private key decryption using
        // EncryptedPrivateKeyInfo. The PBE algorithm is extracted from the encrypted
        // key info itself — an attacker who can tamper with the key file could specify
        // a weak PBE algorithm. The Cipher is initialized with the PBE key and the
        // algorithm parameters from the encrypted key info.
        if (passphrase.isPresent()) {
            EncryptedPrivateKeyInfo keyInfo = new EncryptedPrivateKeyInfo(privateKeyContents);
            String algorithm = keyInfo.getAlgName();
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
            SecretKey pbeKey = secretKeyFactory.generateSecret(new PBEKeySpec(passphrase.get().toCharArray()));
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, keyInfo.getAlgParameters());
            keySpec = keyInfo.getKeySpec(cipher);
        } else {
            byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(privateKeyContents);
            keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        }

        // DECISION: Uses KeyFactory.getInstance("RSA") for all keys. Alternative:
        // Detect key type (RSA vs EC) from the encoded key spec. Rationale: Currently
        // only RS256 and ES256 are supported algorithms. For ES256, the EC KeyFactory
        // should be used — this appears to be a limitation where EC keys may fail with
        // this RSA-only KeyFactory.
        // Note: Documenting existing behavior, not modifying per minimal change clause.
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // SECURITY: (MEDIUM) Algorithm allowlist — only RS256 (SHA256withRSA) and
    // ES256 (SHA256withECDSA) are supported. Unknown algorithms throw
    // NoSuchAlgorithmException (fail-closed). This prevents algorithm confusion
    // attacks where an attacker specifies a weak algorithm.
    // DECISION: Maps algorithm identifiers to JVM Signature algorithm names.
    // RS256 -> SHA256withRSA, ES256 -> SHA256withECDSA. These mappings follow the
    // JWA (RFC 7518) to JCA algorithm name mapping. Case-insensitive comparison via
    // equalsIgnoreCase() for resilience against config case variations.
    public static Signature getSignature(String algorithm) throws GeneralSecurityException {
        if (algorithm.equalsIgnoreCase(TOKEN_SIGNING_ALGORITHM_RS256)) {
            return Signature.getInstance("SHA256withRSA");
        } else if (algorithm.equalsIgnoreCase(TOKEN_SIGNING_ALGORITHM_ES256)) {
            return Signature.getInstance("SHA256withECDSA");
        } else {
            throw new NoSuchAlgorithmException(String.format("Unsupported signing algorithm: %s", algorithm));
        }
    }

    // SECURITY: (HIGH) JCA digital signature: content -> UTF-8 bytes ->
    // Signature.sign() -> Base64URL. The private key is used via
    // Signature.initSign() — the JCA provider handles the actual signing
    // operation. The signed content (JWT header.payload) is not sensitive, but
    // the signing operation is the trust anchor for the entire assertion flow.
    // Exploit: If the JCA provider is compromised (e.g., via a malicious security
    // provider registered before the default), the signature could be weakened or
    // the private key exfiltrated during sign().
    // Improvement: Pin the JCA provider explicitly (e.g., "SunRsaSign") rather
    // than using the default provider chain. Verify Signature instance algorithm
    // matches expected before signing.
    public static String sign(String algorithm, PrivateKey privateKey, String contentToSign) throws GeneralSecurityException {
        Signature signature = getSignature(algorithm);
        signature.initSign(privateKey);
        signature.update(contentToSign.getBytes(StandardCharsets.UTF_8));
        byte[] signedContent = signature.sign();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signedContent);
    }

    // DECISION: Returns Optional.empty() when no static claim configs (aud, iss,
    // sub) are present. When at least one is present, creates
    // StaticAssertionJwtTemplate with only the configured claims. This Optional
    // is added to the layered template list via ifPresent() — so the static layer
    // is entirely absent when no static claims are configured. Alternative: Always
    // include an empty StaticAssertionJwtTemplate. Rationale: Skipping the empty
    // layer avoids an unnecessary putAll(emptyMap) in LayeredAssertionJwtTemplate,
    // though the performance difference is negligible.
    public static Optional<StaticAssertionJwtTemplate> staticAssertionJwtTemplate(ConfigurationUtils cu) {
        if (cu.containsKey(SASL_OAUTHBEARER_ASSERTION_CLAIM_AUD) ||
            cu.containsKey(SASL_OAUTHBEARER_ASSERTION_CLAIM_ISS) ||
            cu.containsKey(SASL_OAUTHBEARER_ASSERTION_CLAIM_SUB)) {
            Map<String, Object> staticClaimsPayload = new HashMap<>();

            if (cu.containsKey(SASL_OAUTHBEARER_ASSERTION_CLAIM_AUD))
                staticClaimsPayload.put("aud", cu.validateString(SASL_OAUTHBEARER_ASSERTION_CLAIM_AUD));

            if (cu.containsKey(SASL_OAUTHBEARER_ASSERTION_CLAIM_ISS))
                staticClaimsPayload.put("iss", cu.validateString(SASL_OAUTHBEARER_ASSERTION_CLAIM_ISS));

            if (cu.containsKey(SASL_OAUTHBEARER_ASSERTION_CLAIM_SUB))
                staticClaimsPayload.put("sub", cu.validateString(SASL_OAUTHBEARER_ASSERTION_CLAIM_SUB));

            Map<String, Object> header = Map.of();
            return Optional.of(new StaticAssertionJwtTemplate(header, staticClaimsPayload));
        } else {
            return Optional.empty();
        }
    }

    public static Optional<FileAssertionJwtTemplate> fileAssertionJwtTemplate(ConfigurationUtils cu) {
        if (cu.containsKey(SASL_OAUTHBEARER_ASSERTION_TEMPLATE_FILE)) {
            File assertionTemplateFile = cu.validateFile(SASL_OAUTHBEARER_ASSERTION_TEMPLATE_FILE);
            return Optional.of(new FileAssertionJwtTemplate(assertionTemplateFile));
        } else {
            return Optional.empty();
        }
    }

    public static DynamicAssertionJwtTemplate dynamicAssertionJwtTemplate(ConfigurationUtils cu, Time time) {
        String algorithm = cu.validateString(SASL_OAUTHBEARER_ASSERTION_ALGORITHM);
        int expSeconds = cu.validateInteger(SASL_OAUTHBEARER_ASSERTION_CLAIM_EXP_SECONDS, true);
        int nbfSeconds = cu.validateInteger(SASL_OAUTHBEARER_ASSERTION_CLAIM_NBF_SECONDS, true);
        boolean includeJti = cu.validateBoolean(SASL_OAUTHBEARER_ASSERTION_CLAIM_JTI_INCLUDE, true);
        return new DynamicAssertionJwtTemplate(time, algorithm, expSeconds, nbfSeconds, includeJti);
    }

    // DECISION: Layering order: static base -> file-based -> dynamic. This order
    // ensures: (1) static provides config-driven claims (aud, iss, sub), (2) file
    // provides operational overrides (can be updated without restart), (3) dynamic
    // adds time-based claims (iat, exp, nbf, jti) which MUST always be fresh and
    // should never be overridden by stale file/config values. Alternative: Reverse
    // order (dynamic first, file last). Rationale: Later-wins semantics means
    // dynamic claims cannot be accidentally overridden by a file template, which is
    // the safest default for time-sensitive claims.
    public static LayeredAssertionJwtTemplate layeredAssertionJwtTemplate(ConfigurationUtils cu, Time time) {
        List<AssertionJwtTemplate> templates = new ArrayList<>();
        staticAssertionJwtTemplate(cu).ifPresent(templates::add);
        fileAssertionJwtTemplate(cu).ifPresent(templates::add);
        templates.add(dynamicAssertionJwtTemplate(cu, time));
        return new LayeredAssertionJwtTemplate(templates);
    }
}
