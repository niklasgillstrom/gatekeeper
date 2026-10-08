package eu.gillstrom.gatekeeper.verification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Google Cloud HSM key attestation verifier.
 *
 * <p>The client fetches the attestation and its certificate chains with
 * {@code gcloud kms keys versions describe ... --attestation-file
 * attestation.dat} and {@code gcloud kms keys versions get-certificate-chain
 * ... --output-file certs.pem}. {@code attestationData} is the base64 of
 * {@code attestation.dat}, gzip-compressed as delivered or already
 * decompressed; {@code attestationCertChain} holds the PEM certificates.</p>
 *
 * <p>Verification follows Google's {@code verify_attestation_chains.py}
 * (GoogleCloudPlatform/python-docs-samples, kms/attestations): a manufacturer
 * chain Marvell root → card → partition; an owner chain in which
 * "Hawksbill Root v1 prod" issued a card certificate with the manufacturer
 * card's key and a partition certificate with the manufacturer partition's
 * key; no other certificate in the bundle; and a SHA-256 PKCS#1 v1.5
 * signature over all but the last 256 bytes that verifies under both
 * partition certificates. Both roots are pinned. Google's tool fetches the
 * Marvell root from marvell.com; the Marvell roots here are the ones
 * Microsoft's validator pins ({@link MarvellAttestation#marvellRoots()}).</p>
 *
 * <p>Google's tool reads no attributes. The key's attributes and RSA key are
 * read from the decompressed blob, which for a key pair carries a public- and
 * a private-key object in Marvell's layout ({@link MarvellAttestation#evaluate});
 * that Google's blob has this form is unverified until a real attestation is
 * checked. Never valid
 * while {@link MarvellAttestation#FORMAT_CONFIRMED_BY_REAL_SAMPLE} is
 * false.</p>
 */
@Component
public class GoogleCloudHsmVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(GoogleCloudHsmVerifier.class);

    /**
     * Google's owner root, copied from {@code OWNER_ROOT_CERT_PEM} in
     * {@code verify_attestation_chains.py}. 2017-07-01 to 2030-01-01.
     * SHA-256 46:B5:FD:35:1D:56:A0:72:1C:A0:AF:CD:17:31:C0:F7:B7:4E:39:41:EB:81:8B:FD:0E:C3:6E:29:DF:0D:E0:95
     */
    static final String HAWKSBILL_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDjTCCAnWgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJVUzEL
            MAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdv
            b2dsZSBJbmMxHzAdBgNVBAMMFkhhd2tzYmlsbCBSb290IHYxIHByb2QwHhcNMTcw
            NzAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjBoMQswCQYDVQQGEwJVUzELMAkGA1UE
            CAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJ
            bmMxHzAdBgNVBAMMFkhhd2tzYmlsbCBSb290IHYxIHByb2QwggEiMA0GCSqGSIb3
            DQEBAQUAA4IBDwAwggEKAoIBAQCsLqhiiSGgcJLfsI7Dk00mONulol9rHm2obCyD
            1lua+AKg+LAW+1zauZu5i028FSbgDk8vtSBDHDF+XsFnqTbIGV7Ctai2lnaQe1UV
            TVMWEPBi1diYGceeDrJpJqPz2aXTcIghrGISeyq+IC4z25uQp7G/D8AResKYqYxN
            NqcfZlMIk0s6Eh4aPyvCXYtLl9QXD0GDJ6nz4NmC+Fw31B5d5Kg9WXxDZOYC1zU5
            9JXbdxxzeC/EJo1k1AHghto/J8edvTIl5NQ0ahOHKoUZzhhDRsVBioFmymVuwaHO
            cXTUsHe3NTkNyeLIfoFpsQQ4XcH9kjO67YXTkdCWeNYw/FYZAgMBAAGjQjBAMA8G
            A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBQx6FLf4Un4
            Ent8budOkXqXdbyorjANBgkqhkiG9w0BAQsFAAOCAQEAjxKOjnr7WYKoD+a+uAld
            F8iOwTrHpFLUDS6sqFyx9FLut8Qlmioy/JE9uima7cjeH3U5VBbRcnTglaDiQTac
            +JXCIRApEl9N0bDhoVvFeTzRI8nJdMJCWPobNXV3MHpYsgfgzewh4lFUWQghvscF
            325VgSEN0a1hgXcnPr05gd+9kTI9zF3r3vyncyYvzYincGX0NQaz1gJW4brm1W+w
            TbWVy8Y0o6c1eZm7v8sHoNSg3vIs6JsnQ8bAXK5i2qO/AXZQu25wH1aPQct8QdGw
            x2JBsjEjmWpHuBDAXPCesD5cu9UzzDgcpdwmi7Xidl74kj3f/HgrOeimRdOb8lG5
            /A==
            -----END CERTIFICATE-----""";

    private final List<X509Certificate> marvellRoots;
    private final X509Certificate ownerRoot;
    private final boolean formatConfirmed;

    public GoogleCloudHsmVerifier() {
        this(MarvellAttestation.marvellRoots(), MarvellAttestation.certificate(HAWKSBILL_ROOT_PEM),
                MarvellAttestation.FORMAT_CONFIRMED_BY_REAL_SAMPLE);
    }

    /** For tests: other roots, and the format gate opened or closed. */
    GoogleCloudHsmVerifier(List<X509Certificate> marvellRoots, X509Certificate ownerRoot, boolean formatConfirmed) {
        this.marvellRoots = List.copyOf(marvellRoots);
        this.ownerRoot = ownerRoot;
        this.formatConfirmed = formatConfirmed;
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.GOOGLE;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        return false; // Use verifyGoogleAttestation instead
    }

    /**
     * @param attestationDataBase64 base64 of {@code attestation.dat}, compressed or not
     * @param certChainPem          the PEM certificates from {@code get-certificate-chain}
     * @param csrPublicKey          the CSR's public key
     */
    public GoogleAttestationResult verifyGoogleAttestation(
            String attestationDataBase64, List<String> certChainPem, PublicKey csrPublicKey) {

        GoogleAttestationResult result = new GoogleAttestationResult();
        try {
            List<X509Certificate> bundle = new ArrayList<>();
            if (certChainPem != null) {
                for (String pem : certChainPem) {
                    if (pem != null && !pem.isBlank()) {
                        bundle.addAll(MarvellAttestation.parsePemBundle(pem));
                    }
                }
            }
            if (bundle.isEmpty()) {
                result.addError("No certificates in chain");
                return result;
            }
            Chains chains = chains(bundle);
            if (chains == null) {
                result.addError("MARVELL_CHAIN_INVALID: the bundle does not hold the manufacturer chain "
                        + "under a pinned Marvell root and the owner chain under Hawksbill Root v1 prod, "
                        + "with matching card and partition keys and no other certificate");
                return result;
            }
            result.setChainValid(true);

            byte[] blob = MarvellAttestation.gunzipIfCompressed(Base64.getDecoder().decode(attestationDataBase64));
            MarvellAttestation.Parsed parsed = MarvellAttestation.parse(blob);
            if (!MarvellAttestation.signedPkcs1Sha256(parsed, chains.manufacturerPartition())
                    || !MarvellAttestation.signedPkcs1Sha256(parsed, chains.ownerPartition())) {
                result.addError("MARVELL_SIGNATURE_INVALID: the attestation is not signed by both "
                        + "partition certificates");
                return result;
            }
            result.setSignatureValid(true);

            MarvellAttestation.KeyEvidence evidence = MarvellAttestation.evaluate(List.of(parsed), csrPublicKey);
            result.setExtractable(evidence.extractable());
            result.setKeyOrigin(evidence.keyOrigin());
            result.setPublicKeyMatch(evidence.publicKeyMatch());
            result.setKeyId(evidence.keyId());
            result.setKeyType("RSA");
            result.setKeySize(evidence.keyBits());
            evidence.errors().forEach(result::addError);

            if (!formatConfirmed) {
                result.addError(MarvellAttestation.FORMAT_UNCONFIRMED_ERROR);
            }
            result.setValid(result.isChainValid() && result.isSignatureValid()
                    && result.isPublicKeyMatch() && !result.isExtractable()
                    && result.getErrors().isEmpty());
        } catch (Exception e) {
            result.addError("MARVELL_ATTESTATION_MALFORMED: " + e.getMessage());
            log.warn("Google Cloud HSM attestation verification failed: {}", e.getMessage());
        }
        return result;
    }

    private record Chains(X509Certificate manufacturerPartition, X509Certificate ownerPartition) {
    }

    private Chains chains(List<X509Certificate> bundle) {
        MarvellAttestation.ManufacturerChain mfr = MarvellAttestation.manufacturerChain(bundle, marvellRoots);
        if (mfr == null) {
            return null;
        }
        X509Certificate ownerCard = issuedWithKey(bundle, mfr.card());
        X509Certificate ownerPartition = issuedWithKey(bundle, mfr.partition());
        if (ownerCard == null || ownerPartition == null || ownerCard.equals(ownerPartition)) {
            return null;
        }
        List<X509Certificate> rest = new ArrayList<>(bundle);
        rest.removeAll(List.of(mfr.card(), mfr.partition(), ownerCard, ownerPartition));
        rest.removeAll(marvellRoots);
        rest.remove(ownerRoot);
        return rest.isEmpty() ? new Chains(mfr.partition(), ownerPartition) : null;
    }

    /** The certificate the owner root issued for the same key as {@code manufacturerCert}. */
    private X509Certificate issuedWithKey(List<X509Certificate> bundle, X509Certificate manufacturerCert) {
        for (X509Certificate c : MarvellAttestation.issuedBy(ownerRoot, bundle)) {
            if (Arrays.equals(c.getPublicKey().getEncoded(), manufacturerCert.getPublicKey().getEncoded())) {
                return c;
            }
        }
        return null;
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            return false;
        }
        List<X509Certificate> bundle = new ArrayList<>(List.of(chain));
        bundle.add(attestationCert);
        Chains found = chains(bundle);
        return found != null && found.manufacturerPartition().equals(attestationCert);
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
        private boolean extractable = true;
        private String keyOrigin = "unverified";
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
