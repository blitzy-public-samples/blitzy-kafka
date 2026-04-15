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
package org.apache.kafka.common.security.ssl;

import org.apache.kafka.common.KafkaException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
/**
 * A wrapper around the original trust manager factory for creating common name logging trust managers.
 * These trust managers log the common name of an expired but otherwise valid (client) certificate before rejecting the connection attempt.
 * This allows to identify misconfigured clients in complex network environments, where the IP address is not sufficient.
 */
// SECURITY: (LOW) CN information leakage in logs.
// Why: Logs the Common Name (CN) of client certificates during TLS handshake for
// audit/debugging. This is primarily used to identify clients presenting expired certs.
// Exploit: If log files are accessible to unauthorized users, the CN information (which
// may contain usernames, email addresses, or hostnames) could be used for reconnaissance
// or targeted phishing attacks. Combined with certificate expiry dates from logs, an
// attacker could time social engineering campaigns around certificate renewal periods.
// Improvement: Consider making CN logging configurable (off by default in production)
// and ensuring log files have restrictive permissions. Also consider hashing the CN
// for log entries to enable correlation without exposing the actual identity.
//
// DECISION: Wraps TrustManagerFactory to add logging without modifying trust validation
// logic. Alternative: Subclass X509TrustManager directly. Rationale: Wrapping at the
// factory level ensures ALL X509TrustManager instances from the factory get CN logging,
// regardless of how many trust managers the factory produces. This is less fragile than
// individual wrapping.
class CommonNameLoggingTrustManagerFactoryWrapper {
    // CROSS-CUTTING: Instantiated by CommonNameLoggingSslEngineFactory.getTrustManagers().
    // Depends on: javax.net.ssl.TrustManagerFactory, javax.net.ssl.X509TrustManager.
    // The wrapped trust managers are passed to SSLContext.init() and participate in every
    // TLS handshake on the configured listener. Logging output goes to SLF4J (info level)
    // for the CommonNameLoggingTrustManagerFactoryWrapper category.

    private static final Logger log = LoggerFactory.getLogger(CommonNameLoggingTrustManagerFactoryWrapper.class);

    private final TrustManagerFactory origTmf;

    /**
     * Create a wrapped trust manager factory
     * @param kmfAlgorithm the algorithm
     * @throws NoSuchAlgorithmException
     */
    protected CommonNameLoggingTrustManagerFactoryWrapper(String kmfAlgorithm) throws NoSuchAlgorithmException {
        this.origTmf = TrustManagerFactory.getInstance(kmfAlgorithm);
    }
    /**
     * Factory for creating a wrapped trust manager factory
     * @param kmfAlgorithm the algorithm
     * @return A wrapped trust manager factory
     * @throws NoSuchAlgorithmException
     */
    public static CommonNameLoggingTrustManagerFactoryWrapper getInstance(String kmfAlgorithm) throws NoSuchAlgorithmException {
        return new CommonNameLoggingTrustManagerFactoryWrapper(kmfAlgorithm);
    }

    public TrustManagerFactory getOriginalTrustManagerFactory() {
        return this.origTmf;
    }

    public String getAlgorithm() {
        return this.origTmf.getAlgorithm();
    }

    public void init(KeyStore ts) throws KeyStoreException {
        this.origTmf.init(ts);
    }

    // DECISION: Wraps ONLY X509TrustManager instances, passing other TrustManager types
    // through unchanged. Rationale: CN extraction is only meaningful for X.509
    // certificate-based auth. Non-X509 trust managers (e.g., JSSE internal types) are left
    // untouched to avoid breaking any custom trust manager implementations.
    public TrustManager[] getTrustManagers() {
        TrustManager[] origTrustManagers = this.origTmf.getTrustManagers();
        TrustManager[] wrappedTrustManagers = new TrustManager[origTrustManagers.length];
        for (int i = 0; i < origTrustManagers.length; i++) {
            TrustManager tm = origTrustManagers[i];
            if (tm instanceof X509TrustManager) {
                // Wrap only X509 trust managers
                wrappedTrustManagers[i] = new CommonNameLoggingTrustManager((X509TrustManager) tm, 2000);
            } else {
                wrappedTrustManagers[i] = tm;
            }
        }
        return wrappedTrustManagers;
    }
    /**
     * A trust manager which logs the common name of an expired but otherwise valid (client) certificate before rejecting the connection attempt.
     * This allows to identify misconfigured clients in complex network environments, where the IP address is not sufficient.
     * this class wraps a standard trust manager and delegates almost all requests to it, except for cases where an invalid certificate is reported by the
     * standard trust manager. In this cases this manager checks whether the provided certificate is invalid only due to being expired and logs the common
     * name if that is the case. This trust manager will always return the results of the wrapped standard trust manager, i.e. return if the certificate is valid
     * or rethrow the original exception if it is not.
     */
    static class CommonNameLoggingTrustManager implements X509TrustManager {

        private final X509TrustManager origTm;
        final int nrOfRememberedBadCerts;
        private final LinkedHashMap<ByteBuffer, String> previouslyRejectedClientCertChains;

        public CommonNameLoggingTrustManager(X509TrustManager originalTrustManager, int nrOfRememberedBadCerts) {
            this.origTm = originalTrustManager;
            this.nrOfRememberedBadCerts = nrOfRememberedBadCerts;
            // SECURITY: (LOW) LRU cache bounded to nrOfRememberedBadCerts entries (~2000
            // default) to prevent memory exhaustion attacks. Without this bound, an attacker
            // could flood connections with unique invalid certificates, causing unbounded
            // HashMap growth and OOM. The LinkedHashMap with removeEldestEntry provides
            // O(1) eviction of oldest entries.
            // Restrict maximal size of the LinkedHashMap to avoid security attacks causing OOM
            this.previouslyRejectedClientCertChains = new LinkedHashMap<>() {
                @Override
                protected boolean removeEldestEntry(final Map.Entry<ByteBuffer, String> eldest) {
                    return size() > nrOfRememberedBadCerts;
                }
            };
        }

        public X509TrustManager getOriginalTrustManager() {
            return this.origTm;
        }

        // SECURITY: (MEDIUM) Client certificate validation with expiry-aware logging.
        // This method first checks the LRU cache for previously rejected cert chains
        // (fast-path rejection), then delegates to the original trust manager. If
        // validation fails, it re-validates with a NeverExpiringX509Certificate wrapper
        // to determine if expiry was the sole failure cause. This two-phase validation
        // approach ensures original security semantics are preserved -- the original
        // CertificateException is always rethrown regardless of the expiry check result.
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            /* COMPLEXITY: 41 lines -- Multi-phase certificate validation with caching.
             * Control flow:
             * 1. Compute SHA-256 digest of the cert chain for cache lookup
             * 2. Check LRU cache for previously rejected chains (fast-path rejection)
             * 3. Delegate to original trust manager for full validation
             * 4. On failure: Re-validate with NeverExpiringX509Certificate wrapper
             *    - If re-validation succeeds: expiry was only failure -> log CN, cache
             *    - If re-validation fails: other issues -> cache rejection for fast-path
             * 5. Always rethrow original exception if initial validation failed
             * Exit paths: (1) Cache hit -> throw cached exception,
             * (2) Validation success -> return,
             * (3) Validation failure -> log if expired, then throw original exception
             */
            CertificateException origException = null;
            ByteBuffer chainDigest = calcDigestForCertificateChain(chain);
            if (chainDigest != null) {
                String errorMessage = this.previouslyRejectedClientCertChains.get(chainDigest);
                if (errorMessage != null) {
                    // Reinsert the digest, to remember that this is the most recent digest we've seen
                    addRejectedClientCertChains(chainDigest, errorMessage, true);
                    // Then throw with the original error Message
                    throw new CertificateException(errorMessage);
                }
            }
            try {
                this.origTm.checkClientTrusted(chain, authType);
                // If the last line did not throw, the chain is valid (including that none of the certificates is expired)
            } catch (CertificateException e) {
                origException = e;
                try {
                    X509Certificate[] wrappedChain = sortChainAnWrapEndCertificate(chain);
                    this.origTm.checkClientTrusted(wrappedChain, authType);
                    // No exception occurred this time. The certificate is either not yet valid or already expired
                    Date now = new Date();
                    // Check if the certificate was valid in the past
                    if (wrappedChain[0].getNotBefore().before(now)) {
                        String commonName = wrappedChain[0].getSubjectX500Principal().toString();
                        String notValidAfter = wrappedChain[0].getNotAfter().toString();
                        log.info("Certificate with common name \"" + commonName + "\" expired on " + notValidAfter);
                        // The end certificate is expired and thus will never become valid anymore, as long as the trust store is not changed
                        addRejectedClientCertChains(chainDigest, origException.getMessage(), false);
                    }

                } catch (CertificateException innerException) {
                    // Ignore this exception as we throw the original one below
                    // Even with disabled date check, this cert chain is invalid: Remember the chain and fail faster next time we see it
                    addRejectedClientCertChains(chainDigest, origException.getMessage(), false);
                }
            }
            if (origException != null) {
                throw origException;
            }
        }

        // SECURITY: (LOW) Uses SHA-256 for cert chain fingerprinting -- collision-resistant
        // and computationally efficient. The digest is used as a cache key, not for security
        // decisions; a collision would only cause a misleading cached error message, not a
        // security bypass.
        public static ByteBuffer calcDigestForCertificateChain(X509Certificate[] chain) throws CertificateEncodingException {
            MessageDigest md;
            try {
                md = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                return null;
            }
            for (X509Certificate cert: chain) {
                md.update(cert.getEncoded());
            }
            return ByteBuffer.wrap(md.digest());
        }

        private void addRejectedClientCertChains(ByteBuffer chainDigest, String errorMessage, boolean removeIfExisting) {
            if (removeIfExisting) {
                this.previouslyRejectedClientCertChains.remove(chainDigest);
            }
            this.previouslyRejectedClientCertChains.put(chainDigest, errorMessage);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.origTm.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return this.origTm.getAcceptedIssuers();
        }
        
       /**
         * This method sorts the certificate chain from end to root certificate and wraps the end certificate to make it "never-expireing"
         * @param origChain The original (unsorted) certificate chain
         * @return The sorted and wrapped certificate chain
         * @throws CertificateException
         */
        public static X509Certificate[] sortChainAnWrapEndCertificate(X509Certificate[] origChain) throws CertificateException {
            /* COMPLEXITY: 50 lines -- Certificate chain sorting and end-entity wrapping.
             * Control flow:
             * 1. Build two maps: subject->cert and issuer->cert for chain traversal
             * 2. Detect self-signed certs (subject == issuer), validate CA constraint
             * 3. Find end certs (certs whose subject is not another cert's issuer)
             * 4. Validate exactly one end certificate exists
             * 5. Wrap end cert in NeverExpiringX509Certificate for expiry-blind check
             * 6. Build sorted chain by following issuer->subject links
             * Exit paths: (1) null/empty chain -> CertificateException,
             * (2) self-signed non-CA -> CertificateException,
             * (3) multiple end certs -> CertificateException,
             * (4) broken chain -> CertificateException,
             * (5) success -> sorted wrapped chain
             */
            if (origChain == null || origChain.length < 1) {
                throw new CertificateException("Certificate chain is null or empty");
            }
            // Find the end certificate by looking at all issuers and find the one not referred to by any other certificate
            // There might be multiple end certificates if the chain is invalid!
            // Create a map from principal to certificate
            HashMap<X500Principal, X509Certificate> principalToCertMap = new HashMap<>();
            // First, create a map from principal of issuer (!) to certificate for easily finding the right certificates
            HashMap<X500Principal, X509Certificate> issuedbyPrincipalToCertificatesMap = new HashMap<>();
            for (X509Certificate cert: origChain) {
                X500Principal principal = cert.getSubjectX500Principal();
                X500Principal issuerPrincipal = cert.getIssuerX500Principal();
                if (issuerPrincipal.equals(principal)) {
                    // self-signed certificate in chain! This should not happen
                    boolean isCA = cert.getBasicConstraints() >= 0;
                    if (!isCA) {
                        throw new CertificateException("Self-signed certificate in chain that is not a CA!");
                    }
                }
                issuedbyPrincipalToCertificatesMap.put(issuerPrincipal, cert);
                principalToCertMap.put(principal, cert);
            }
            // Thus, expect certificate chain to be broken, e.g. containing multiple enbd certificates
            Set<X509Certificate> endCertificates = new HashSet<>();
            for (X509Certificate cert: origChain) {
                X500Principal subjectPrincipal = cert.getSubjectX500Principal();
                if (!issuedbyPrincipalToCertificatesMap.containsKey(subjectPrincipal)) {
                    // We found a certificate which is not an issuer of another certificate. We consider it to be an end certificate
                    endCertificates.add(cert);
                }
            }
            // There should be exactly one end certificate, otherwise we don't know which one to wrap
            if (endCertificates.size() != 1) {
                throw new CertificateException("Multiple end certificates in chain");
            }
            X509Certificate endCertificate = endCertificates.iterator().next();
            X509Certificate[] wrappedChain = new X509Certificate[origChain.length];
            // Add the wrapped certificate as first element in the new certificate chain array
            wrappedChain[0] = new NeverExpiringX509Certificate(endCertificate);
            // Add all other (potential) certificates in order of dependencies (result will be sorted from end certificate to last intermediate/root certificate)
            for (int i = 1; i < origChain.length; i++) {
                X500Principal siblingCertificateIssuer = wrappedChain[i - 1].getIssuerX500Principal();
                if (principalToCertMap.containsKey(siblingCertificateIssuer)) {
                    wrappedChain[i] = principalToCertMap.get(siblingCertificateIssuer);
                } else {
                    throw new CertificateException("Certificate chain contains certificates not belonging to the chain");
                }
            }
            return wrappedChain;
        }
    }

    // DECISION: NeverExpiringX509Certificate overrides checkValidity() to suppress expiry
    // checks. Alternative: Use a custom TrustManager that ignores CertificateExpiredException.
    // Rationale: Wrapping the certificate preserves the original trust manager's full
    // validation pipeline (signature verification, chain building, revocation checking) --
    // only the date check is suppressed. This approach is more surgical than replacing the
    // entire trust manager.
    static class NeverExpiringX509Certificate extends X509Certificate {

        private final X509Certificate origCertificate;

        public NeverExpiringX509Certificate(X509Certificate origCertificate) {
            this.origCertificate = origCertificate;
            if (this.origCertificate == null) {
                throw new KafkaException("No X509 certificate provided in constructor NeverExpiringX509Certificate");
            }
        }

        @Override
        public Set<String> getCriticalExtensionOIDs() {
            return this.origCertificate.getCriticalExtensionOIDs();
        }

        @Override
        public byte[] getExtensionValue(String oid) {
            return this.origCertificate.getExtensionValue(oid);
        }

        @Override
        public Set<String> getNonCriticalExtensionOIDs() {
            return this.origCertificate.getNonCriticalExtensionOIDs();
        }

        @Override
        public boolean hasUnsupportedCriticalExtension() {
            return this.origCertificate.hasUnsupportedCriticalExtension();
        }

        @Override
        public void checkValidity()
                throws CertificateExpiredException, CertificateNotYetValidException {
            Date now = new Date();
            // Do nothing for certificates which are not valid anymore now
            if (this.origCertificate.getNotAfter().before(now)) {
                return;
            }
            // Check validity as usual
            this.origCertificate.checkValidity();
        }

        @Override
        public void checkValidity(Date date) {
            // We do not check validity at all.
        }

        @Override
        public int getBasicConstraints() {
            return this.origCertificate.getBasicConstraints();
        }

        @Override
        public Principal getIssuerDN() {
            return this.origCertificate.getIssuerDN();
        }

        @Override
        public boolean[] getIssuerUniqueID() {
            return this.origCertificate.getIssuerUniqueID();
        }

        @Override
        public boolean[] getKeyUsage() {
            return this.origCertificate.getKeyUsage();
        }

        @Override
        public Date getNotAfter() {
            return this.origCertificate.getNotAfter();
        }

        @Override
        public Date getNotBefore() {
            return this.origCertificate.getNotBefore();
        }

        @Override
        public BigInteger getSerialNumber() {
            return this.origCertificate.getSerialNumber();
        }

        @Override
        public String getSigAlgName() {
            return this.origCertificate.getSigAlgName();
        }

        @Override
        public String getSigAlgOID() {
            return this.origCertificate.getSigAlgOID();
        }

        @Override
        public byte[] getSigAlgParams() {
            return this.origCertificate.getSigAlgParams();
        }

        @Override
        public byte[] getSignature() {
            return this.origCertificate.getSignature();
        }

        @Override
        public Principal getSubjectDN() {
            return this.origCertificate.getSubjectDN();
        }

        @Override
        public boolean[] getSubjectUniqueID() {
            return this.origCertificate.getSubjectUniqueID();
        }

        @Override
        public byte[] getTBSCertificate() throws CertificateEncodingException {
            return this.origCertificate.getTBSCertificate();
        }

        @Override
        public int getVersion() {
            return this.origCertificate.getVersion();
        }

        @Override
        public byte[] getEncoded() throws CertificateEncodingException {
            return this.origCertificate.getEncoded();
        }

        @Override
        public PublicKey getPublicKey() {
            return this.origCertificate.getPublicKey();
        }

        @Override
        public String toString() {
            return this.origCertificate.toString();
        }

        @Override
        public void verify(PublicKey publicKey) throws CertificateException, NoSuchAlgorithmException,
                InvalidKeyException, NoSuchProviderException, SignatureException {
            this.origCertificate.verify(publicKey);
        }

        @Override
        public void verify(PublicKey publicKey, String sigProvider)
                throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
                NoSuchProviderException, SignatureException {
            this.origCertificate.verify(publicKey, sigProvider);
        }
    }
}
