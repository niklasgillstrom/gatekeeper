package eu.gillstrom.gatekeeper.verification;

import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Component
public class YubicoVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(YubicoVerifier.class);

    // Yubico YubiHSM Root CA — genuine vendor-issued root.
    //
    // Source: https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem
    // Subject:  CN=Yubico YubiHSM Root CA
    // Issuer:   CN=Yubico YubiHSM Root CA (self-signed)
    // Validity: 2017-01-01 to 2071-10-05 (UTC)
    // SHA-256:  09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:
    //           BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24
    //
    // Operators deploying this verifier should re-verify the SHA-256 fingerprint
    // against an authoritative Yubico source before relying on it, and rotate
    // according to the operator's key-management policy.
    private static final String YUBICO_ROOT_CA = """
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----""";

    // Yubico OIDs for attestation (1.3.6.1.4.1.41482.4.x)
    private static final String YUBICO_BASE_OID = "1.3.6.1.4.1.41482.4";
    private static final String FIRMWARE_OID = YUBICO_BASE_OID + ".1";
    private static final String SERIAL_OID = YUBICO_BASE_OID + ".2";
    private static final String ORIGIN_OID = YUBICO_BASE_OID + ".3";
    private static final String CAPABILITIES_OID = YUBICO_BASE_OID + ".5";
    private static final String OBJECT_ID_OID = YUBICO_BASE_OID + ".6";
    private static final String LABEL_OID = YUBICO_BASE_OID + ".9";

    // Capabilities bits that indicate exportability
    private static final int EXPORT_WRAPPED_BIT = 12;
    private static final int EXPORTABLE_UNDER_WRAP_BIT = 16;

    private final X509Certificate rootCa;

    public YubicoVerifier() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream is = new ByteArrayInputStream(
                    YUBICO_ROOT_CA.trim().getBytes(StandardCharsets.UTF_8));
            this.rootCa = (X509Certificate) cf.generateCertificate(is);
        } catch (Exception e) {
            // Fail-closed: if the Yubico root CA cannot be loaded, the verifier cannot
            // provide its security guarantees. Refuse to construct the bean so the
            // Spring Boot application fails to start, rather than silently running
            // with a weakened (string-matching) fallback.
            throw new IllegalStateException(
                    "Failed to load Yubico root CA — YubicoVerifier cannot be constructed", e);
        }
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.YUBICO;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        try {
            // Verify the attested public key matches CSR public key
            PublicKey attestedKey = attestationCert.getPublicKey();
            return MessageDigest.isEqual(attestedKey.getEncoded(), csrPublicKey.getEncoded());
        } catch (Exception e) {
            log.warn("Yubico verifyAttestation public-key comparison failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Verify Yubico attestation:
     * 1. Verify certificate chain against Yubico root
     * 2. Verify that attestation cert public key matches CSR
     * 3. Extract key attributes from OID extensions
     */
    public YubicoAttestationResult verifyYubicoAttestation(
            List<String> certChainPem,
            PublicKey csrPublicKey) {

        YubicoAttestationResult result = new YubicoAttestationResult();

        try {
            // Parse certificate chain
            X509Certificate[] chain = parseCertChain(certChainPem);
            if (chain.length == 0) {
                result.addError("No certificates in chain");
                return result;
            }

            X509Certificate attestCert = chain[0];

            // Verify certificate chain to root
            if (!verifyCertChainToRoot(chain)) {
                result.addError("Certificate chain verification failed");
            } else {
                result.setChainValid(true);
            }

            // Verify public key match
            PublicKey attestedKey = attestCert.getPublicKey();
            if (MessageDigest.isEqual(attestedKey.getEncoded(), csrPublicKey.getEncoded())) {
                result.setPublicKeyMatch(true);
            } else {
                result.addError("Public key mismatch: CSR key does not match attested key");
            }

            // Extract attributes from OID extensions
            extractYubicoAttributes(attestCert, result);

            // Extract device serial from device cert
            if (chain.length > 1) {
                String cn = chain[1].getSubjectX500Principal().getName();
                if (cn.contains("Attestation")) {
                    // Format: YubiHSM Attestation (XXXXXXXX)
                    int start = cn.indexOf('(');
                    int end = cn.indexOf(')');
                    if (start > 0 && end > start) {
                        result.setDeviceSerial(cn.substring(start + 1, end));
                    }
                }
            }

            result.setValid(result.isChainValid() && result.isPublicKeyMatch()
                    && result.isGenerated() && !result.isKeyExportable()
                    && result.getErrors().isEmpty());

        } catch (Exception e) {
            log.warn("Yubico attestation verification threw: {}", e.getMessage(), e);
            result.addError("Verification error: " + e.getMessage());
        }

        return result;
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
     * Validate the Yubico attestation certificate chain with PKIX, anchored at
     * the pinned Yubico root CA. BasicConstraints, key usage, path length and
     * issuer/subject linkage are all enforced by {@link CertPathValidator}.
     *
     * <p>Revocation checking is disabled; Yubico attestation certificates come
     * from a closed vendor PKI hierarchy and the attestation is a point-in-time
     * assertion about key generation. Chain time validity (notBefore/notAfter)
     * is still enforced by PKIX.</p>
     */
    private boolean verifyCertChainToRoot(X509Certificate[] chain) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> path = new ArrayList<>();
            for (X509Certificate c : chain) {
                // Don't include the trust anchor itself in the CertPath.
                if (!c.equals(rootCa)) {
                    path.add(c);
                }
            }
            if (path.isEmpty()) {
                // Submitted chain contains only the root — trivially accepted
                // since it equals the pinned trust anchor.
                return true;
            }
            CertPath certPath = cf.generateCertPath(path);
            Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCa, null));
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
            return true;
        } catch (Exception e) {
            log.warn("Yubico certificate chain validation failed: {}", e.getMessage());
            return false;
        }
    }

    private void extractYubicoAttributes(X509Certificate cert, YubicoAttestationResult result) {
        try {
            for (String oid : cert.getNonCriticalExtensionOIDs()) {
                byte[] extValue = cert.getExtensionValue(oid);
                if (extValue == null)
                    continue;

                // Unwrap OCTET STRING wrapper
                ASN1OctetString octet = ASN1OctetString.getInstance(extValue);
                byte[] content = octet.getOctets();

                switch (oid) {
                    case FIRMWARE_OID -> {
                        ASN1OctetString fw = ASN1OctetString.getInstance(content);
                        byte[] fwBytes = fw.getOctets();
                        if (fwBytes.length >= 3) {
                            result.setFirmware(fwBytes[0] + "." + fwBytes[1] + "." + fwBytes[2]);
                        }
                    }
                    case SERIAL_OID -> {
                        ASN1Integer serial = ASN1Integer.getInstance(content);
                        result.setDeviceSerial(serial.getValue().toString());
                    }
                    case ORIGIN_OID -> {
                        ASN1BitString bs = ASN1BitString.getInstance(content);
                        byte[] originBytes = bs.getBytes();
                        if (originBytes.length > 0) {
                            int originBits = originBytes[0] & 0xFF;
                            result.setGenerated((originBits & 0x01) != 0);
                            result.setImported((originBits & 0x02) != 0);
                            result.setImportedWrapped((originBits & 0x10) != 0);
                        }
                    }
                    case CAPABILITIES_OID -> {
                        ASN1BitString bs = ASN1BitString.getInstance(content);
                        byte[] capBytes = bs.getBytes();
                        long caps = 0;
                        for (int i = 0; i < Math.min(capBytes.length, 8); i++) {
                            caps |= ((long) (capBytes[i] & 0xFF)) << (8 * i);
                        }
                        boolean canExportWrapped = (caps & (1L << EXPORT_WRAPPED_BIT)) != 0;
                        boolean exportableUnderWrap = (caps & (1L << EXPORTABLE_UNDER_WRAP_BIT)) != 0;
                        result.setExportableUnderWrap(exportableUnderWrap);
                        result.setCanExportWrapped(canExportWrapped);
                    }
                    case LABEL_OID -> {
                        ASN1UTF8String label = ASN1UTF8String.getInstance(content);
                        result.setKeyLabel(label.getString());
                    }
                    case OBJECT_ID_OID -> {
                        ASN1Integer objId = ASN1Integer.getInstance(content);
                        result.setKeyId(objId.getValue().intValue());
                    }
                }
            }

            // Validate key origin and exportability
            if (!result.isGenerated()) {
                result.addError("Key was not generated on HSM (origin: " + result.getKeyOrigin() + ")");
            }
            if (result.isExportableUnderWrap() || result.isCanExportWrapped()) {
                result.addError("Key has export capabilities - not allowed for signing keys");
            }

        } catch (Exception e) {
            log.warn("Failed to parse Yubico attestation extensions: {}", e.getMessage());
            result.addError("Failed to parse attestation extensions: " + e.getMessage());
        }
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        if (chain == null || chain.length == 0)
            return false;
        try {
            X509Certificate[] fullChain = new X509Certificate[chain.length + 1];
            fullChain[0] = attestationCert;
            System.arraycopy(chain, 0, fullChain, 1, chain.length);
            return verifyCertChainToRoot(fullChain);
        } catch (Exception e) {
            log.warn("Yubico verifyChain failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return attestationCert.getSerialNumber().toString(16);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        return "YubiHSM 2";
    }

    public static class YubicoAttestationResult {
        private boolean valid;
        private boolean chainValid;
        private boolean publicKeyMatch;
        private String deviceSerial;
        private String firmware;
        private String keyLabel;
        private int keyId;
        private boolean generated;
        private boolean imported;
        private boolean importedWrapped;
        private boolean exportableUnderWrap;
        private boolean canExportWrapped;
        private java.util.List<String> errors = new java.util.ArrayList<>();

        public void addError(String error) {
            errors.add(error);
        }

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public boolean isChainValid() {
            return chainValid;
        }

        public void setChainValid(boolean chainValid) {
            this.chainValid = chainValid;
        }

        public boolean isPublicKeyMatch() {
            return publicKeyMatch;
        }

        public void setPublicKeyMatch(boolean publicKeyMatch) {
            this.publicKeyMatch = publicKeyMatch;
        }

        public String getDeviceSerial() {
            return deviceSerial;
        }

        public void setDeviceSerial(String deviceSerial) {
            this.deviceSerial = deviceSerial;
        }

        public String getFirmware() {
            return firmware;
        }

        public void setFirmware(String firmware) {
            this.firmware = firmware;
        }

        public String getKeyLabel() {
            return keyLabel;
        }

        public void setKeyLabel(String keyLabel) {
            this.keyLabel = keyLabel;
        }

        public int getKeyId() {
            return keyId;
        }

        public void setKeyId(int keyId) {
            this.keyId = keyId;
        }

        public boolean isGenerated() {
            return generated;
        }

        public void setGenerated(boolean generated) {
            this.generated = generated;
        }

        public boolean isImported() {
            return imported;
        }

        public void setImported(boolean imported) {
            this.imported = imported;
        }

        public boolean isImportedWrapped() {
            return importedWrapped;
        }

        public void setImportedWrapped(boolean importedWrapped) {
            this.importedWrapped = importedWrapped;
        }

        public boolean isExportableUnderWrap() {
            return exportableUnderWrap;
        }

        public void setExportableUnderWrap(boolean exportableUnderWrap) {
            this.exportableUnderWrap = exportableUnderWrap;
        }

        public boolean isCanExportWrapped() {
            return canExportWrapped;
        }

        public void setCanExportWrapped(boolean canExportWrapped) {
            this.canExportWrapped = canExportWrapped;
        }

        public java.util.List<String> getErrors() {
            return errors;
        }

        public String getKeyOrigin() {
            if (generated)
                return "generated";
            if (importedWrapped)
                return "imported_wrapped";
            if (imported)
                return "imported";
            return "unknown";
        }

        public boolean isKeyExportable() {
            return exportableUnderWrap || canExportWrapped;
        }
    }
}
