package eu.gillstrom.gatekeeper.verification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Thales Luna Public Key Confirmation (PKC) verifier.
 *
 * <p>A PKC is a PKCS#7 certificate chain that a Luna HSM issues for one of its
 * key pairs ({@code cmu getpkc}). Thales: "A Luna HSM will issue confirmations
 * only for private keys that were created by a Luna cryptographic module and
 * that can never exist outside the security perimeter of a Luna HSM", and
 * {@code cmu getpkc} "works with non-extractable keys only". The PKC carries
 * no attribute list: the evidence that the key was generated in the HSM and
 * cannot leave it is that the HSM issued a Proof of Origin certificate for
 * it at all. Those two Thales statements were read through search excerpts of
 * thalesdocs.com, which this build cannot reach.</p>
 *
 * <p>The RSA chain follows Thales's MIT-licensed {@code luna-pkc-validator}:
 * Proof of Origin (leaf, EKU {@code 1.3.6.1.4.1.12383.1.13}), Device
 * Authentication ({@code .1.12}), Hardware Origin ({@code .1.8}), Thales Luna
 * Mfg Integrity ({@code .1.7}), signed by the Chrysalis-ITS Root
 * ({@code .1.1}). Each certificate must be signed by the next, name the next
 * as issuer, carry exactly its EKU, be a CA unless it is the leaf, and be
 * within its validity period. The root is pinned by its public key: Thales's
 * validator ships the root with serial {@code 804500000007}, the PKI
 * Consortium publishes serial {@code 80450000000D}, and both carry the same
 * key. The leaf's public key must be the CSR key. The ECC chain is not
 * supported, as signing keys are RSA.</p>
 *
 * <p>{@code attestationData} is the base64 of the DER PKC ({@code .p7b}).</p>
 */
@Component
public class ThalesLunaVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(ThalesLunaVerifier.class);

    /** SHA-256 of the Chrysalis-ITS Root's DER SubjectPublicKeyInfo. */
    static final String CHRYSALIS_ROOT_KEY_SHA256 = "5d31fc462ae8a1a5327b149ff43aa6d867a28d7e17ca1cca7e7d514cf8cdc132";

    /**
     * Chrysalis-ITS Root, serial 80450000000D, 2002-01-01 to 2032-01-01, as
     * published by the PKI Consortium's Remote Key Attestation project
     * (validation/thales-luna7.md).
     * SHA-256 69:6A:7E:E6:7B:C4:FA:CF:F6:09:11:BC:0B:24:A3:A6:BC:E7:5A:2E:F4:C4:23:18:44:8A:DD:45:01:B6:99:69
     */
    static final String CHRYSALIS_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----""";

    /** EKU of each certificate of the RSA chain, leaf first, as in Thales's validator. */
    static final List<String> RSA_CHAIN_EKUS = List.of(
            "1.3.6.1.4.1.12383.1.13", "1.3.6.1.4.1.12383.1.12", "1.3.6.1.4.1.12383.1.8",
            "1.3.6.1.4.1.12383.1.7");
    static final String OID_HSM_SERIAL = "1.3.6.1.4.1.12383.2.1";
    static final int MAX_PKC_SIZE = 64 * 1024;

    private final PublicKey rootKey;

    public ThalesLunaVerifier() {
        this(MarvellAttestation.certificate(CHRYSALIS_ROOT_PEM).getPublicKey());
        if (!CHRYSALIS_ROOT_KEY_SHA256.equals(sha256(rootKey.getEncoded()))) {
            throw new IllegalStateException("Pinned Chrysalis-ITS Root key does not match its fingerprint");
        }
    }

    /** For tests: another root key. */
    ThalesLunaVerifier(PublicKey rootKey) {
        this.rootKey = rootKey;
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.THALES;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        return false; // Use verifyLunaAttestation instead
    }

    /**
     * @param pkcBase64    base64 of the DER PKCS#7 PKC
     * @param csrPublicKey the CSR's public key
     */
    public ThalesLunaResult verifyLunaAttestation(String pkcBase64, PublicKey csrPublicKey) {
        ThalesLunaResult result = new ThalesLunaResult();
        try {
            byte[] pkc = Base64.getDecoder().decode(pkcBase64);
            if (pkc.length > MAX_PKC_SIZE) {
                result.addError("LUNA_PKC_MALFORMED: PKC exceeds " + MAX_PKC_SIZE + " bytes");
                return result;
            }
            List<X509Certificate> certs = new ArrayList<>();
            for (var c : CertificateFactory.getInstance("X.509")
                    .generateCertPath(new ByteArrayInputStream(pkc), "PKCS7").getCertificates()) {
                certs.add((X509Certificate) c);
            }
            // The chain may end with a copy of the root; it is checked by key, not trusted.
            if (!certs.isEmpty() && isRoot(certs.get(certs.size() - 1))) {
                certs.remove(certs.size() - 1);
            }
            String chainError = chainError(certs);
            if (chainError != null) {
                result.addError("LUNA_CHAIN_INVALID: " + chainError);
                return result;
            }
            result.setChainValid(true);

            X509Certificate leaf = certs.get(0);
            result.setHsmSerial(hsmSerial(leaf));
            if (csrPublicKey != null && Arrays.equals(leaf.getPublicKey().getEncoded(), csrPublicKey.getEncoded())) {
                result.setPublicKeyMatch(true);
            } else {
                result.addError("LUNA_PUBLIC_KEY_MISMATCH: the Proof of Origin certificate is for another key");
            }
            result.setKeyOrigin("generated");
            result.setExportable(false);
            result.setValid(result.isChainValid() && result.isPublicKeyMatch() && result.getErrors().isEmpty());
        } catch (Exception e) {
            result.addError("LUNA_PKC_MALFORMED: " + e.getMessage());
            log.warn("Thales Luna PKC verification failed: {}", e.getMessage());
        }
        return result;
    }

    private boolean isRoot(X509Certificate c) {
        return Arrays.equals(c.getPublicKey().getEncoded(), rootKey.getEncoded());
    }

    /** Null when {@code certs} is the RSA PKC chain below the pinned root, else the reason. */
    private String chainError(List<X509Certificate> certs) {
        if (certs.size() != RSA_CHAIN_EKUS.size()) {
            return "expected " + RSA_CHAIN_EKUS.size() + " certificates below the root, found " + certs.size();
        }
        for (int i = 0; i < certs.size(); i++) {
            X509Certificate c = certs.get(i);
            try {
                c.checkValidity();
                List<String> eku = c.getExtendedKeyUsage();
                if (eku == null || !eku.equals(List.of(RSA_CHAIN_EKUS.get(i)))) {
                    return "certificate " + i + " has EKU " + eku + ", expected " + RSA_CHAIN_EKUS.get(i);
                }
                boolean ca = c.getBasicConstraints() >= 0;
                if (ca != (i > 0)) {
                    return "certificate " + i + (ca ? " is" : " is not") + " a CA";
                }
                if (i + 1 < certs.size()) {
                    X509Certificate issuer = certs.get(i + 1);
                    if (!c.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                        return "certificate " + i + " does not name certificate " + (i + 1) + " as issuer";
                    }
                    c.verify(issuer.getPublicKey());
                } else {
                    c.verify(rootKey);
                }
            } catch (Exception e) {
                return "certificate " + i + ": " + e.getMessage();
            }
        }
        return null;
    }

    /** The HSM serial in the leaf's {@code 12383.2.1} extension, little-endian, as Thales's validator reads it. */
    static String hsmSerial(X509Certificate leaf) {
        byte[] ext = leaf.getExtensionValue(OID_HSM_SERIAL);
        if (ext == null || ext.length != 6 || ext[0] != 0x04 || ext[1] != 4) {
            return null;
        }
        return Integer.toUnsignedString(ByteBuffer.wrap(ext, 2, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
    }

    static String sha256(byte[] b) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        if (chain == null) {
            return false;
        }
        List<X509Certificate> certs = new ArrayList<>();
        certs.add(attestationCert);
        certs.addAll(Arrays.asList(chain));
        if (isRoot(certs.get(certs.size() - 1))) {
            certs.remove(certs.size() - 1);
        }
        return chainError(certs) == null;
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return hsmSerial(attestationCert);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        return "Thales Luna";
    }

    public static class ThalesLunaResult {
        private boolean valid;
        private boolean chainValid;
        private boolean publicKeyMatch;
        private boolean exportable = true;
        private String keyOrigin = "unverified";
        private String hsmSerial;
        private List<String> errors = new ArrayList<>();

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

        public boolean isExportable() {
            return exportable;
        }

        public void setExportable(boolean exportable) {
            this.exportable = exportable;
        }

        public String getKeyOrigin() {
            return keyOrigin;
        }

        public void setKeyOrigin(String keyOrigin) {
            this.keyOrigin = keyOrigin;
        }

        public String getHsmSerial() {
            return hsmSerial;
        }

        public void setHsmSerial(String hsmSerial) {
            this.hsmSerial = hsmSerial;
        }

        public List<String> getErrors() {
            return errors;
        }
    }
}
