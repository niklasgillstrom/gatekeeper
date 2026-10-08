package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Azure Managed HSM key attestation verifier.
 *
 * <p>Input is the JSON that {@code az keyvault key get-attestation} writes,
 * whole or only its {@code attributes} or {@code attributes.attestation}
 * object, as Microsoft's validator accepts it. The attestation object
 * carries {@code version} ({@code MRVL-1}, the only version Microsoft's tool
 * supports), {@code certificatePemFile} (base64url of a PEM bundle),
 * {@code privateKeyAttestation} and optionally {@code publicKeyAttestation}
 * (base64url Marvell blobs; see {@link MarvellAttestation}). Microsoft's
 * README says asymmetric keys receive only the private-key attestation;
 * Marvell's key-pair response carries both halves in one blob. Either form is
 * accepted.</p>
 *
 * <p><strong>Trust.</strong> Microsoft's validator checks two chains. The
 * Marvell chain starts from a Marvell root that the validator pins. The
 * partition chain starts from a self-signed certificate taken from the
 * submitted bundle itself
 * ({@code get_self_signed_certificate(certificate_list)}), so whoever submits
 * the bundle also chooses its root, and the chain adds no assurance. Only the
 * Marvell chain is checked here. Both attestations must be signed by the
 * partition certificate in that chain.</p>
 *
 * <p><strong>Key binding.</strong> The JSON's {@code key} JWK and the key
 * returned by Azure's API are not covered by the HSM's signature; a submitter
 * could pair a genuine attestation of one key with the JWK of another. The
 * key is taken only from the signed blobs ({@link MarvellAttestation#evaluate}).</p>
 *
 * <p>Never valid while {@link MarvellAttestation#FORMAT_CONFIRMED_BY_REAL_SAMPLE}
 * is false.</p>
 */
@Component
public class AzureHsmVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(AzureHsmVerifier.class);

    static final String SUPPORTED_VERSION = "MRVL-1";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final List<X509Certificate> marvellRoots;
    private final boolean formatConfirmed;

    public AzureHsmVerifier() {
        this(MarvellAttestation.marvellRoots(), MarvellAttestation.FORMAT_CONFIRMED_BY_REAL_SAMPLE);
    }

    /** For tests: other roots, and the format gate opened or closed. */
    AzureHsmVerifier(List<X509Certificate> marvellRoots, boolean formatConfirmed) {
        this.marvellRoots = List.copyOf(marvellRoots);
        this.formatConfirmed = formatConfirmed;
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.AZURE;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        return false; // Use verifyAzureAttestation instead
    }

    /**
     * Verifies the Marvell chain, the signature on each attestation, the key's
     * attributes, and that the attested RSA key is the CSR key.
     */
    public AzureAttestationResult verifyAzureAttestation(String attestationJson, PublicKey csrPublicKey) {
        AzureAttestationResult result = new AzureAttestationResult();
        try {
            JsonNode att = objectMapper.readTree(attestationJson);
            if (att.has("attributes")) {
                att = att.get("attributes");
            }
            if (att.has("attestation")) {
                att = att.get("attestation");
            }
            String version = text(att, "version");
            String pemFile = text(att, "certificatePemFile");
            String privateB64 = text(att, "privateKeyAttestation");
            String publicB64 = text(att, "publicKeyAttestation");
            if (pemFile == null || privateB64 == null || version == null) {
                result.addError("AZURE_ATTESTATION_INCOMPLETE: version, certificatePemFile and "
                        + "privateKeyAttestation are required");
                return result;
            }
            if (!SUPPORTED_VERSION.equals(version)) {
                result.addError("AZURE_ATTESTATION_VERSION_UNSUPPORTED: " + version);
                return result;
            }

            List<X509Certificate> bundle = MarvellAttestation.parsePemBundle(
                    new String(Base64.getUrlDecoder().decode(pemFile), StandardCharsets.US_ASCII));
            MarvellAttestation.ManufacturerChain chain = MarvellAttestation.manufacturerChain(bundle, marvellRoots);
            if (chain == null) {
                result.addError("MARVELL_CHAIN_INVALID: the bundle holds no card and partition "
                        + "certificate issued under a pinned Marvell root");
                return result;
            }
            result.setChainValid(true);

            MarvellAttestation.Parsed privateKey = MarvellAttestation.parse(Base64.getUrlDecoder().decode(privateB64));
            MarvellAttestation.Parsed publicKey = publicB64 == null
                    ? null
                    : MarvellAttestation.parse(Base64.getUrlDecoder().decode(publicB64));
            boolean signed = MarvellAttestation.signedBy(privateKey, chain.partition())
                    && (publicKey == null || MarvellAttestation.signedBy(publicKey, chain.partition()));
            if (!signed) {
                result.addError("MARVELL_SIGNATURE_INVALID: an attestation is not signed by the "
                        + "Marvell-issued partition certificate");
                return result;
            }
            result.setSignatureValid(true);

            MarvellAttestation.KeyEvidence evidence = MarvellAttestation.evaluate(
                    publicKey == null ? List.of(privateKey) : List.of(privateKey, publicKey), csrPublicKey);
            result.setExportable(evidence.extractable());
            result.setKeyOrigin(evidence.keyOrigin());
            result.setPublicKeyMatch(evidence.publicKeyMatch());
            evidence.errors().forEach(result::addError);
            String id = evidence.keyId();
            result.setHsmPool(id);
            if (id != null) {
                String[] parts = id.split("/");
                if (parts.length >= 2) {
                    result.setKeyName(parts[parts.length - 2]);
                    result.setKeyVersion(parts[parts.length - 1]);
                }
            }

            if (!formatConfirmed) {
                result.addError(MarvellAttestation.FORMAT_UNCONFIRMED_ERROR);
            }
            result.setValid(result.isChainValid() && result.isSignatureValid()
                    && result.isPublicKeyMatch() && !result.isExportable()
                    && result.getErrors().isEmpty());
        } catch (Exception e) {
            result.addError("MARVELL_ATTESTATION_MALFORMED: " + e.getMessage());
            log.warn("Azure Managed HSM attestation verification failed: {}", e.getMessage());
        }
        return result;
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() || v.asText().isBlank() ? null : v.asText();
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
        return "Azure Managed HSM";
    }

    public static class AzureAttestationResult {
        private boolean valid;
        private boolean chainValid;
        private boolean signatureValid;
        private boolean publicKeyMatch;
        private boolean exportable = true;
        private String keyOrigin = "unverified";
        private String hsmPool;
        private String keyName;
        private String keyVersion;
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

        public String getHsmPool() {
            return hsmPool;
        }

        public void setHsmPool(String hsmPool) {
            this.hsmPool = hsmPool;
        }

        public String getKeyName() {
            return keyName;
        }

        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        public String getKeyVersion() {
            return keyVersion;
        }

        public void setKeyVersion(String keyVersion) {
            this.keyVersion = keyVersion;
        }

        public List<String> getErrors() {
            return errors;
        }
    }
}
