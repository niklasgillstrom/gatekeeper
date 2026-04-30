package eu.gillstrom.gatekeeper.verification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Google Cloud HSM Key Attestation Verifier
 *
 * Client fetches attestation via:
 * gcloud kms keys versions describe [version] --key [key] --keyring [ring]
 * --location [loc] --attestation-file attestation.dat
 * gcloud kms keys versions get-certificate-chain [version] --key [key]
 * --keyring [ring] --location [loc] --output-file certs.pem
 *
 * Client must decompress attestation.dat (gzip) and extract files from bundle
 * if downloaded via Console.
 *
 * Google Cloud HSM uses Marvell (Cavium) LiquidSecurity HSMs.
 */
@Component
public class GoogleCloudHsmVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(GoogleCloudHsmVerifier.class);

    // Trust anchor for Google Cloud HSM key attestations.
    //
    // SOURCE: Marvell/Cavium LiquidSecurity Root CA, distributed by Marvell at
    //   https://www.marvell.com/content/dam/marvell/en/public-collateral/security-solutions/liquid_security_certificate.zip
    // referenced by Google Cloud HSM's open-source key-attestation verification
    // code as the trust anchor for HSM partition certificates. The Marvell
    // factory CA is the practical pinning point for cloud-deployed Marvell-
    // based HSMs (Google Cloud HSM and Azure Managed HSM both anchor here);
    // any cloud-vendor signing certs that appear in the attestation chain are
    // intermediate certs validated transitively through PKIX. AWS CloudHSM is
    // excluded from this verifier because it does not support per-key
    // attestation in the sense Google and Azure do (only cluster-level
    // identity attestation).
    //
    // CERTIFICATE METADATA:
    //   Subject:  CN=localca.liquidsecurity.cavium.com, O=Cavium, Inc.
    //   Issuer:   CN=localca.liquidsecurity.cavium.com (self-signed)
    //   Validity: 2015-11-19 to 2025-11-16 (UTC)
    //   SHA-256:  97:57:57:F0:D7:66:40:E0:3D:14:76:0F:8F:C9:E3:A5:
    //             58:26:FA:78:07:B2:C3:92:F7:80:1A:95:BD:69:CC:28
    //
    // ROTATION NOTE: this certificate expired on 2025-11-16. Marvell has
    // presumably published a successor at the same URL; deployers should
    // fetch the current certificate, verify its SHA-256 fingerprint against
    // Marvell's documentation, and replace this constant before relying on
    // chain validation for attestations created after the expiry date. The
    // PKIX validator does not check the trust anchor's own validity period
    // (anchors are trusted by definition), so an expired anchor still
    // validates structurally — but chain certs with notBefore after the
    // anchor's expiry indicate the anchor has been rotated upstream, and
    // PKIX will fail to find a path.
    //
    // VERIFICATION MODEL NOTE: Google Cloud HSM's published Python sample
    // code (`verify_chains.py`, Apache-2.0, copyright 2021, last modified
    // ~2023) verifies attestations against a **dual chain** anchored at
    // BOTH:
    //   1. The Marvell manufacturer root (this constant), proving the
    //      attestation came from genuine Marvell hardware, AND
    //   2. Google's own "Hawksbill Root v1 prod" CA (not bundled here),
    //      proving Google operates the specific HSM partition that signed
    //      the attestation.
    // This verifier validates only the manufacturer chain. For production
    // verification of Google Cloud HSM attestations, deployers should
    // additionally pin Google's owner-root certificate (currently
    // distributed at https://www.gstatic.com/cloudhsm/roots/global_1498867200.pem)
    // and validate the parallel owner chain. Because Google's published
    // sample predates 2026 and Marvell's bundled root has since expired,
    // deployers should consult current Google Cloud HSM attestation
    // documentation rather than rely on this code as the production model
    // — the verification protocol may have evolved.
    private static final String ATTESTATION_TRUST_ANCHOR = """
            -----BEGIN CERTIFICATE-----
            MIIDoDCCAogCCQDA6q30NN7cFzANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UEBhMC
            VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYD
            VQQKDAxDYXZpdW0sIEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYD
            VQQDDCFsb2NhbGNhLmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wHhcNMTUxMTE5
            MTM1NTI1WhcNMjUxMTE2MTM1NTI1WjCBkTELMAkGA1UEBhMCVVMxEzARBgNVBAgM
            CkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQKDAxDYXZpdW0s
            IEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQDDCFsb2NhbGNh
            LmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
            DwAwggEKAoIBAQDckvqQM4cvZjdyqOLGMTjKJwvfxJOhVqw6pojgUMz10VU7z3Ct
            JrwHcESwEDUxUkMxzof55kForURLaVVCjedYauEisnZwwSWkAemp9GREm8iX6BXt
            oZ8VDWoO2H0AJiHCM62qJeZVXhm8A/zWG0PyLrCINH0yz9ah6BcwdsZGLvQvkpUN
            JhwVMrb9nI9BlRmTWhoot1YSTf7jfibEkc/pN+0Ez30RFaL3MhyIaNJS22+10tny
            4sOUTsPEtXKah5mPlHpnrGcB18z5Yxgr0vDNYx+FCPGo95XGrq9NYfNMlwsSeFSr
            8D1VQ7HZmipeTB1hQTUQw/K/Rmtw5NiljkYTAgMBAAEwDQYJKoZIhvcNAQELBQAD
            ggEBAJjqbFaa3FOXEXcXPX2lCHdcyl8TwOR9f3Rq87MEfb3oeK9FarNkUCdvuGs3
            OkAWoFib/9l2F7ZgaNlJqVrwBaOvYuGguQoUpDybqttYUJVLcu9vA9eZA+UCJdhd
            P7fCyGMO+G96cnG3GTS1/SrIDU+YCnVElQ0P/73/de+ImoeMkwcqiUi2lsf3vGGR
            YXMt/DxUwjXwjIpWCs+37cwbNHAv0VKDOR/jmNf5EZf+sy4x2rJZ1NS6eDZ9RBug
            CLaN6ntybV4YlE7jDI9XIOm/tPJULZGLpLolngWVB6qtzn1RjBw1HIqpoXg+9s1g
            pLFFinSrEL1fkQR0YZQrJckktPs=
            -----END CERTIFICATE-----""";

    // Attestation attribute tags (Marvell TLV format)
    private static final int TAG_KEY_ID = 0x0102;
    private static final int TAG_KEY_TYPE = 0x0100;
    private static final int TAG_KEY_SIZE = 0x0101;
    private static final int TAG_EXTRACTABLE = 0x0162;
    private static final int TAG_PUBLIC_KEY = 0x0350;

    private final X509Certificate attestationTrustAnchor;

    public GoogleCloudHsmVerifier() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            this.attestationTrustAnchor = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(ATTESTATION_TRUST_ANCHOR.trim().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            // Fail-closed: if the attestation trust anchor cannot be loaded,
            // refuse to construct the bean so the Spring Boot application
            // fails to start.
            throw new IllegalStateException(
                    "Failed to load attestation trust anchor — GoogleCloudHsmVerifier cannot be constructed", e);
        }
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.GOOGLE;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        return false;
    }

    /**
     * Verify Google Cloud HSM attestation:
     * 1. Parse certificate chain
     * 2. Verify chain against the configured attestation trust anchor
     * 3. Verify attestation signature
     * 4. Parse attributes and verify non-extractable
     * 5. Compare public key with CSR
     *
     * @param attestationDataBase64 Base64-encoded decompressed attestation data
     * @param certChainPem          Certificate chain PEM strings
     * @param csrPublicKey          Public key from CSR to match
     */
    public GoogleAttestationResult verifyGoogleAttestation(
            String attestationDataBase64,
            List<String> certChainPem,
            PublicKey csrPublicKey) {

        GoogleAttestationResult result = new GoogleAttestationResult();

        try {
            byte[] attestationData = Base64.getDecoder().decode(attestationDataBase64);

            List<X509Certificate> certs = parseCertChain(certChainPem);
            if (certs.isEmpty()) {
                result.addError("No certificates in chain");
                return result;
            }

            if (!verifyCertChain(certs)) {
                result.addError("Certificate chain verification failed");
            } else {
                result.setChainValid(true);
            }

            if (!verifyAttestationSignature(attestationData, certs.get(0))) {
                result.addError("Attestation signature verification failed");
            } else {
                result.setSignatureValid(true);
            }

            parseAttestationAttributes(attestationData, result);

            byte[] attestedPubKey = extractPublicKeyFromAttestation(attestationData);
            if (attestedPubKey != null) {
                if (MessageDigest.isEqual(attestedPubKey, csrPublicKey.getEncoded())) {
                    result.setPublicKeyMatch(true);
                } else {
                    result.addError("Public key mismatch: CSR key does not match attested key");
                }
            }

            if (result.isExtractable()) {
                result.addError("Key is extractable - not allowed for signing keys");
            }

            result.setValid(result.isChainValid() && result.isSignatureValid()
                    && result.isPublicKeyMatch() && !result.isExtractable()
                    && result.getErrors().isEmpty());

        } catch (Exception e) {
            result.addError("Verification error: " + e.getMessage());
            log.warn("Google Cloud HSM attestation verification failed", e);
        }

        return result;
    }

    private List<X509Certificate> parseCertChain(List<String> pemCerts) throws Exception {
        List<X509Certificate> certs = new ArrayList<>();
        if (pemCerts == null)
            return certs;

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (String pem : pemCerts) {
            String trimmed = pem.trim();
            if (trimmed.isEmpty())
                continue;

            // Handle multiple certs in one PEM file
            String[] parts = trimmed.split("-----END CERTIFICATE-----");
            for (String part : parts) {
                String certPem = part.trim();
                if (certPem.isEmpty())
                    continue;
                if (!certPem.endsWith("-----END CERTIFICATE-----")) {
                    certPem += "\n-----END CERTIFICATE-----";
                }
                try {
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));
                    certs.add(cert);
                } catch (Exception e) {
                    // Log and re-throw so that a malformed certificate in the chain
                    // is treated as a verification failure rather than silently
                    // dropped — the latter would let a partial, missing-issuer chain
                    // still "verify" via the PKIX path builder if the remaining
                    // chain happens to be self-contained.
                    log.warn("Failed to parse certificate in Google Cloud HSM chain: {}", e.getMessage());
                    throw e;
                }
            }
        }
        return certs;
    }

    /**
     * Validate the Google Cloud HSM attestation chain using PKIX anchored at
     * the pinned attestation trust anchor (Google's published attestation CA
     * in production; a placeholder in this reference build).
     * BasicConstraints, key usage, path length and issuer/subject linkage are
     * enforced by {@link CertPathValidator}. Revocation checking is disabled
     * for the same reasons documented on the Securosys and Yubico verifiers.
     */
    private boolean verifyCertChain(List<X509Certificate> certs) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> path = new ArrayList<>();
            for (X509Certificate c : certs) {
                if (!c.equals(attestationTrustAnchor)) {
                    path.add(c);
                }
            }
            if (path.isEmpty()) {
                return true;
            }
            CertPath certPath = cf.generateCertPath(path);
            Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(attestationTrustAnchor, null));
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
            return true;
        } catch (Exception e) {
            log.warn("Google Cloud HSM certificate chain validation failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean verifyAttestationSignature(byte[] attestation, X509Certificate cert) {
        // NOTE: This is a simplified signature verification that assumes a specific
        // blob layout (data || signature, with fixed-length signature). The actual
        // Marvell attestation blob format is TLV-structured and the signature field
        // is embedded in a defined location — not necessarily the final bytes.
        //
        // Until this is replaced with a proper Marvell attestation parser (see
        // TODO in parseAttestationAttributes), treat signature-verification failures
        // as VERIFICATION FAILURES, not as success. Fail-closed is the correct
        // default when the parser cannot deterministically verify the signature.
        try {
            int sigLen = cert.getPublicKey().getAlgorithm().equals("RSA") ? 256 : 64;
            if (attestation.length <= sigLen)
                return false;

            byte[] data = Arrays.copyOf(attestation, attestation.length - sigLen);
            byte[] sig = Arrays.copyOfRange(attestation, attestation.length - sigLen, attestation.length);

            String algorithm = cert.getPublicKey().getAlgorithm().equals("RSA")
                    ? "SHA256withRSA"
                    : "SHA256withECDSA";
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(cert.getPublicKey());
            verifier.update(data);
            return verifier.verify(sig);
        } catch (Exception e) {
            // Fail-closed. Do NOT return true on exception; this would allow
            // unverified attestations through whenever the blob layout deviates
            // from the simplified assumption.
            return false;
        }
    }

    private void parseAttestationAttributes(byte[] attestation, GoogleAttestationResult result) {
        try {
            // Parse TLV-encoded attributes (Marvell format)
            int pos = 0;
            while (pos + 4 < attestation.length) {
                int tag = ((attestation[pos] & 0xFF) << 8) | (attestation[pos + 1] & 0xFF);
                int len = ((attestation[pos + 2] & 0xFF) << 8) | (attestation[pos + 3] & 0xFF);
                pos += 4;

                if (pos + len > attestation.length)
                    break;

                byte[] value = Arrays.copyOfRange(attestation, pos, pos + len);

                switch (tag) {
                    case TAG_KEY_ID -> result.setKeyId(bytesToHex(value));
                    case TAG_KEY_TYPE -> result.setKeyType(parseKeyType(value));
                    case TAG_KEY_SIZE -> {
                        if (value.length >= 2) {
                            result.setKeySize(((value[0] & 0xFF) << 8) | (value[1] & 0xFF));
                        }
                    }
                    case TAG_EXTRACTABLE -> result.setExtractable(value.length > 0 && value[0] != 0);
                }

                pos += len;
            }

            // Google Cloud HSM keys are non-extractable by design
            if (!result.isExtractable()) {
                result.setKeyOrigin("generated");
            }

        } catch (Exception e) {
            // TLV parse failure — do not silently default to non-extractable.
            // Mark the result as invalid so the caller's aggregated check
            // (isValid = chainValid && signatureValid && !extractable && ...) can
            // surface the parse failure rather than masking it behind a benign-
            // looking "generated/non-extractable" stub.
            log.warn("Failed to parse Google Cloud HSM attestation TLV attributes: {}", e.getMessage());
            result.addError("Failed to parse attestation attributes: " + e.getMessage());
        }
    }

    private byte[] extractPublicKeyFromAttestation(byte[] attestation) {
        try {
            int pos = 0;
            while (pos + 4 < attestation.length) {
                int tag = ((attestation[pos] & 0xFF) << 8) | (attestation[pos + 1] & 0xFF);
                int len = ((attestation[pos + 2] & 0xFF) << 8) | (attestation[pos + 3] & 0xFF);
                pos += 4;

                if (pos + len > attestation.length)
                    break;

                if (tag == TAG_PUBLIC_KEY) {
                    return Arrays.copyOfRange(attestation, pos, pos + len);
                }

                pos += len;
            }
        } catch (Exception e) {
            log.warn("Failed to extract public key from Google Cloud HSM attestation blob: {}",
                    e.getMessage());
        }
        return null;
    }

    private String parseKeyType(byte[] value) {
        if (value.length < 2)
            return "unknown";
        int type = ((value[0] & 0xFF) << 8) | (value[1] & 0xFF);
        return switch (type) {
            case 0x0000 -> "RSA";
            case 0x0003 -> "EC";
            case 0x001F -> "AES";
            default -> "type-" + type;
        };
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        return true;
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return attestationCert.getSerialNumber().toString(16);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        return "Google Cloud HSM";
    }

    public static class GoogleAttestationResult {
        private boolean valid;
        private boolean chainValid;
        private boolean signatureValid;
        private boolean publicKeyMatch;
        private boolean extractable;
        private String keyOrigin;
        private String keyId;
        private String keyType;
        private int keySize;
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

        public boolean isSignatureValid() {
            return signatureValid;
        }

        public void setSignatureValid(boolean signatureValid) {
            this.signatureValid = signatureValid;
        }

        public boolean isPublicKeyMatch() {
            return publicKeyMatch;
        }

        public void setPublicKeyMatch(boolean publicKeyMatch) {
            this.publicKeyMatch = publicKeyMatch;
        }

        public boolean isExtractable() {
            return extractable;
        }

        public void setExtractable(boolean extractable) {
            this.extractable = extractable;
        }

        public String getKeyOrigin() {
            return keyOrigin;
        }

        public void setKeyOrigin(String keyOrigin) {
            this.keyOrigin = keyOrigin;
        }

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getKeyType() {
            return keyType;
        }

        public void setKeyType(String keyType) {
            this.keyType = keyType;
        }

        public int getKeySize() {
            return keySize;
        }

        public void setKeySize(int keySize) {
            this.keySize = keySize;
        }

        public List<String> getErrors() {
            return errors;
        }
    }
}
