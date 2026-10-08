package eu.gillstrom.gatekeeper.verification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Key attestation verifier for physical Marvell LiquidSecurity HSMs, the
 * hardware that Azure Managed HSM and Google Cloud HSM run on.
 *
 * <p>Marvell: "When you create a key on a Marvell HSM, you can optionally
 * request an attestation statement to provide evidence that the key is
 * HSM-protected. The statement is a token that is cryptographically signed
 * directly by the physical hardware and can be verified by the user." The
 * attestation is produced when the key is generated (for example with
 * Cfm2Util); a financial entity that wants to show DORA Art. 9.3 d met keeps
 * it from then on.</p>
 *
 * <p>{@code attestationData} is the base64 of {@code attest.dat}, gzip or
 * not; {@code attestationCertChain} holds the partition and card
 * certificates. The chain is the manufacturer chain alone (pinned Marvell
 * root → card → partition): no cloud operator stands between the entity and
 * the hardware, so there is no owner chain. The signature scheme follows the
 * layout ({@link MarvellAttestation#signedBy}), and the key evidence is read
 * as for the cloud verifiers ({@link MarvellAttestation#evaluate}). Never
 * valid while {@link MarvellAttestation#FORMAT_CONFIRMED_BY_REAL_SAMPLE} is
 * false.</p>
 */
@Component
public class MarvellHsmVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(MarvellHsmVerifier.class);

    private final List<X509Certificate> marvellRoots;
    private final boolean formatConfirmed;

    public MarvellHsmVerifier() {
        this(MarvellAttestation.marvellRoots(), MarvellAttestation.FORMAT_CONFIRMED_BY_REAL_SAMPLE);
    }

    /** For tests: other roots, and the format gate opened or closed. */
    MarvellHsmVerifier(List<X509Certificate> marvellRoots, boolean formatConfirmed) {
        this.marvellRoots = List.copyOf(marvellRoots);
        this.formatConfirmed = formatConfirmed;
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.MARVELL;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        return false; // Use verifyMarvellAttestation instead
    }

    /**
     * @param attestationDataBase64 base64 of {@code attest.dat}, compressed or not
     * @param certChainPem          the partition and card certificates
     * @param csrPublicKey          the CSR's public key
     */
    public MarvellAttestationResult verifyMarvellAttestation(
            String attestationDataBase64, List<String> certChainPem, PublicKey csrPublicKey) {

        MarvellAttestationResult result = new MarvellAttestationResult();
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
            MarvellAttestation.ManufacturerChain chain = MarvellAttestation.manufacturerChain(bundle, marvellRoots);
            if (chain == null) {
                result.addError("MARVELL_CHAIN_INVALID: the bundle holds no card and partition "
                        + "certificate issued under a pinned Marvell root");
                return result;
            }
            result.setChainValid(true);
            result.setPartitionSerial(chain.partition().getSerialNumber().toString(16));

            byte[] blob = MarvellAttestation.gunzipIfCompressed(Base64.getDecoder().decode(attestationDataBase64));
            MarvellAttestation.Parsed parsed = MarvellAttestation.parse(blob);
            if (!MarvellAttestation.signedBy(parsed, chain.partition())) {
                result.addError("MARVELL_SIGNATURE_INVALID: the attestation is not signed by the "
                        + "Marvell-issued partition certificate");
                return result;
            }
            result.setSignatureValid(true);

            MarvellAttestation.KeyEvidence evidence = MarvellAttestation.evaluate(List.of(parsed), csrPublicKey);
            result.setExtractable(evidence.extractable());
            result.setKeyOrigin(evidence.keyOrigin());
            result.setPublicKeyMatch(evidence.publicKeyMatch());
            result.setKeyId(evidence.keyId());
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
            log.warn("Marvell LiquidSecurity attestation verification failed: {}", e.getMessage());
        }
        return result;
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            return false;
        }
        List<X509Certificate> bundle = new ArrayList<>();
        bundle.add(attestationCert);
        Collections.addAll(bundle, chain);
        MarvellAttestation.ManufacturerChain found = MarvellAttestation.manufacturerChain(bundle, marvellRoots);
        return found != null && found.partition().equals(attestationCert);
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return attestationCert.getSerialNumber().toString(16);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        return "Marvell LiquidSecurity";
    }

    public static class MarvellAttestationResult {
        private boolean valid;
        private boolean chainValid;
        private boolean signatureValid;
        private boolean publicKeyMatch;
        private boolean extractable = true;
        private String keyOrigin = "unverified";
        private String keyId;
        private int keySize;
        private String partitionSerial;
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

        public int getKeySize() {
            return keySize;
        }

        public void setKeySize(int keySize) {
            this.keySize = keySize;
        }

        public String getPartitionSerial() {
            return partitionSerial;
        }

        public void setPartitionSerial(String partitionSerial) {
            this.partitionSerial = partitionSerial;
        }

        public List<String> getErrors() {
            return errors;
        }
    }
}
