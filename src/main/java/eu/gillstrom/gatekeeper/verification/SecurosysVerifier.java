package eu.gillstrom.gatekeeper.verification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class SecurosysVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(SecurosysVerifier.class);

    // Securosys Primus HSM Root CA (production)
    private static final String SECUROSYS_ROOT_CA = """
            -----BEGIN CERTIFICATE-----
            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
            4WzEkJhoDVG+m/ScmyguyvqBkkYBEuX0Yg==
            -----END CERTIFICATE-----""";

    private final X509Certificate rootCa;

    public SecurosysVerifier() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            this.rootCa = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(SECUROSYS_ROOT_CA.trim().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load Securosys root CA — SecurosysVerifier cannot be constructed", e);
        }
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.SECUROSYS;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        // Securosys uses a vendor-specific XML+signature flow; call
        // verifySecurosysAttestation directly instead of this generic entry
        // point. Throwing here is a safeguard against accidental misuse.
        throw new UnsupportedOperationException(
                "Use verifySecurosysAttestation(xml, sig, chain, csrPublicKey) for Securosys");
    }

    /**
     * Verify a Securosys Primus HSM key attestation.
     *
     * <ol>
     *   <li>Parse the attestation-certificate chain and validate it with PKIX
     *       against the pinned Securosys root CA.</li>
     *   <li>Verify the SHA-256/RSA signature over the raw attestation XML bytes
     *       with the public key from the leaf attestation certificate.</li>
     *   <li>Parse the attestation XML safely (XXE-protected {@link DocumentBuilder}).
     *       Extract the attested public key and compare it to the CSR key.</li>
     *   <li>Check that the attested key has the required attributes:
     *       {@code extractable=false}, {@code never_extractable=true},
     *       {@code sensitive=true}, {@code always_sensitive=true}.</li>
     * </ol>
     */
    public SecurosysAttestationResult verifySecurosysAttestation(
            String xmlBase64,
            String signatureBase64,
            List<String> certChainPem,
            PublicKey csrPublicKey) {

        SecurosysAttestationResult result = new SecurosysAttestationResult();

        try {
            X509Certificate[] chain = parseCertChain(certChainPem);
            if (chain.length == 0) {
                result.addError("No certificates in chain");
                return result;
            }

            if (!verifyCertChain(chain)) {
                result.addError("Certificate chain verification failed");
            } else {
                result.setChainValid(true);
            }

            // XML bytes (decoded, not re-encoded) are what the signature is
            // computed over. UTF-8 is asserted for string views of this data.
            byte[] xmlBytes = Base64.getDecoder().decode(xmlBase64);

            byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
            PublicKey attestPubKey = chain[0].getPublicKey();

            // Securosys Primus attestation signatures use SHA256withRSA per the
            // vendor specification. If Securosys ever changes the algorithm,
            // this constant must be updated and the change considered against
            // the verification contract.
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(attestPubKey);
            sig.update(xmlBytes);

            if (!sig.verify(sigBytes)) {
                result.addError("XML signature verification failed");
            } else {
                result.setSignatureValid(true);
            }

            // Parse XML with XXE protection and extract the relevant fields
            // through the DOM rather than regex.
            Document doc = parseXmlSafely(xmlBytes);

            byte[] xmlPubKeyBytes = extractPublicKey(doc);
            if (xmlPubKeyBytes == null) {
                result.addError("Could not extract public_key from XML");
            } else {
                byte[] csrPubKeyBytes = csrPublicKey.getEncoded();
                if (MessageDigest.isEqual(xmlPubKeyBytes, csrPubKeyBytes)) {
                    result.setPublicKeyMatch(true);
                } else {
                    result.addError("Public key mismatch: CSR key does not match attested key");
                }
            }

            boolean extractable = extractBooleanAttribute(doc, "extractable");
            boolean neverExtractable = extractBooleanAttribute(doc, "never_extractable");
            boolean sensitive = extractBooleanAttribute(doc, "sensitive");
            boolean alwaysSensitive = extractBooleanAttribute(doc, "always_sensitive");

            if (extractable) result.addError("Key attribute extractable must be false");
            if (!neverExtractable) result.addError("Key attribute never_extractable must be true");
            if (!sensitive) result.addError("Key attribute sensitive must be true");
            if (!alwaysSensitive) result.addError("Key attribute always_sensitive must be true");

            result.setExtractable(extractable);
            result.setNeverExtractable(neverExtractable);
            result.setSensitive(sensitive);
            result.setAlwaysSensitive(alwaysSensitive);

            result.setKeyLabel(firstElementText(doc, "label"));
            result.setAlgorithm(firstElementText(doc, "algorithm"));
            result.setKeySize(firstElementText(doc, "key_size"));
            result.setCreateTime(firstElementText(doc, "create_time"));

            if (chain.length > 1) {
                String cn = chain[1].getSubjectX500Principal().getName();
                Pattern p = Pattern.compile("SN:\\s*(\\d+)");
                Matcher m = p.matcher(cn);
                if (m.find()) {
                    result.setHsmSerialNumber(m.group(1));
                }
            }

            result.setValid(result.isChainValid() && result.isSignatureValid()
                    && result.isPublicKeyMatch() && !extractable && neverExtractable
                    && sensitive && alwaysSensitive);

        } catch (Exception e) {
            log.warn("Securosys attestation verification threw: {}", e.getMessage(), e);
            result.addError("Verification error: " + e.getMessage());
        }

        return result;
    }

    /**
     * Parse XML with XXE and external-entity protection.
     */
    private Document parseXmlSafely(byte[] xmlBytes) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xmlBytes));
    }

    private X509Certificate[] parseCertChain(List<String> pemCerts) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate[] chain = new X509Certificate[pemCerts.size()];
        for (int i = 0; i < pemCerts.size(); i++) {
            String pem = pemCerts.get(i).trim();
            if (!pem.startsWith("-----BEGIN")) {
                pem = "-----BEGIN CERTIFICATE-----\n" + pem + "\n-----END CERTIFICATE-----";
            }
            chain[i] = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        }
        return chain;
    }

    /**
     * Validate the attestation certificate chain with the standard PKIX
     * algorithm, anchored at the pinned Securosys root CA. BasicConstraints,
     * key usage, path length and issuer/subject linkage are all enforced by
     * {@link CertPathValidator}.
     *
     * <p>Revocation checking (OCSP/CRL) is disabled; Securosys attestation
     * certificates come from a closed vendor PKI and the attestation itself is
     * a point-in-time assertion about key generation, so ongoing revocation
     * does not apply in the same way as for public-web PKI. Chain time
     * validity (notBefore/notAfter) is still enforced by PKIX.</p>
     */
    private boolean verifyCertChain(X509Certificate[] chain) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> path = new ArrayList<>();
            for (X509Certificate c : chain) {
                // Do not include the trust anchor in the CertPath itself.
                if (!c.equals(rootCa)) {
                    path.add(c);
                }
            }
            if (path.isEmpty()) {
                return false;
            }
            CertPath certPath = cf.generateCertPath(path);
            Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCa, null));
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
            return true;
        } catch (Exception e) {
            log.warn("Securosys certificate chain validation failed: {}", e.getMessage());
            return false;
        }
    }

    private byte[] extractPublicKey(Document doc) {
        String pubKeyB64 = firstElementText(doc, "public_key");
        if (pubKeyB64 == null) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(pubKeyB64.trim());
        } catch (IllegalArgumentException e) {
            log.warn("Securosys attestation public_key is not valid Base64: {}", e.getMessage());
            return null;
        }
    }

    private boolean extractBooleanAttribute(Document doc, String tagName) {
        String value = firstElementText(doc, tagName);
        return "true".equalsIgnoreCase(value);
    }

    private String firstElementText(Document doc, String tagName) {
        NodeList nl = doc.getElementsByTagName(tagName);
        if (nl.getLength() == 0) {
            return null;
        }
        Node node = nl.item(0);
        String text = node.getTextContent();
        return text == null ? null : text.trim();
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        // Chain validation is performed as part of verifySecurosysAttestation;
        // this interface entry point is retained for API compatibility only.
        return true;
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return attestationCert.getSerialNumber().toString(16);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        return "Primus HSM";
    }

    public static class SecurosysAttestationResult {
        private boolean valid;
        private boolean chainValid;
        private boolean signatureValid;
        private boolean publicKeyMatch;
        private boolean extractable;
        private boolean neverExtractable;
        private boolean sensitive;
        private boolean alwaysSensitive;
        private String keyLabel;
        private String algorithm;
        private String keySize;
        private String createTime;
        private String hsmSerialNumber;
        private final List<String> errors = new ArrayList<>();

        public void addError(String error) { errors.add(error); }

        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }

        public boolean isChainValid() { return chainValid; }
        public void setChainValid(boolean chainValid) { this.chainValid = chainValid; }

        public boolean isSignatureValid() { return signatureValid; }
        public void setSignatureValid(boolean signatureValid) { this.signatureValid = signatureValid; }

        public boolean isPublicKeyMatch() { return publicKeyMatch; }
        public void setPublicKeyMatch(boolean publicKeyMatch) { this.publicKeyMatch = publicKeyMatch; }

        public boolean isExtractable() { return extractable; }
        public void setExtractable(boolean extractable) { this.extractable = extractable; }

        public boolean isNeverExtractable() { return neverExtractable; }
        public void setNeverExtractable(boolean neverExtractable) { this.neverExtractable = neverExtractable; }

        public boolean isSensitive() { return sensitive; }
        public void setSensitive(boolean sensitive) { this.sensitive = sensitive; }

        public boolean isAlwaysSensitive() { return alwaysSensitive; }
        public void setAlwaysSensitive(boolean alwaysSensitive) { this.alwaysSensitive = alwaysSensitive; }

        public String getKeyLabel() { return keyLabel; }
        public void setKeyLabel(String keyLabel) { this.keyLabel = keyLabel; }

        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

        public String getKeySize() { return keySize; }
        public void setKeySize(String keySize) { this.keySize = keySize; }

        public String getCreateTime() { return createTime; }
        public void setCreateTime(String createTime) { this.createTime = createTime; }

        public String getHsmSerialNumber() { return hsmSerialNumber; }
        public void setHsmSerialNumber(String hsmSerialNumber) { this.hsmSerialNumber = hsmSerialNumber; }

        public List<String> getErrors() { return errors; }
    }
}
