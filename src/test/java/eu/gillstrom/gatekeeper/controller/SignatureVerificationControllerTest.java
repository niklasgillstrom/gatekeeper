package eu.gillstrom.gatekeeper.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.SignatureVerificationService;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for {@link SignatureVerificationController}. Brings up
 * the controller with {@link MockMvcBuilders#standaloneSetup} and a real
 * {@link SignatureVerificationService} backed by a hand-rolled fake
 * {@link ApprovalRegistry} so the test exercises the same crypto path that
 * production traffic does.
 */
class SignatureVerificationControllerTest {

    private MockMvc mockMvc;
    private ObjectMapper json;

    private FakeApprovalRegistry registry;
    private KeyPair signingKeyPair;
    private X509Certificate signingCert;
    private String signingCertPem;
    private String publicKeyFingerprint;

    @BeforeEach
    void setUp() throws Exception {
        registry = new FakeApprovalRegistry();
        SignatureVerificationService service = new SignatureVerificationService(registry);
        SignatureVerificationController controller = new SignatureVerificationController(service);

        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
        json = new ObjectMapper();

        signingKeyPair = TestPki.newRsaKeyPair(2048);
        signingCert = TestPki.selfSignedCa(signingKeyPair, "Test Signing Cert");
        signingCertPem = TestPki.toPem(signingCert);
        publicKeyFingerprint = computeFingerprint(signingCert.getPublicKey());
    }

    @Test
    void verifyEndpointReturns200WithCompliantTrueWhenAllChecksPass() throws Exception {
        registry.put(publicKeyFingerprint, ApprovalRegistry.RegistryEntry.builder()
                .verificationId("VID-OK")
                .compliant(true)
                .status(RegistryStatus.VERIFIED_AND_ISSUED)
                .publicKeyFingerprint(publicKeyFingerprint)
                .build());

        SignatureVerificationRequest request = signedRequest("payload-1");

        mockMvc.perform(post("/api/v1/verify")
                        .contentType("application/json")
                        .content(json.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signatureValid").value(true))
                .andExpect(jsonPath("$.compliant").value(true))
                .andExpect(jsonPath("$.auditEntryId").value("VID-OK"))
                .andExpect(jsonPath("$.reason").value("OK"));
    }

    @Test
    void verifyEndpointReturns200WithCompliantFalseWhenCertNotInRegistry() throws Exception {
        SignatureVerificationRequest request = signedRequest("payload-2");

        mockMvc.perform(post("/api/v1/verify")
                        .contentType("application/json")
                        .content(json.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signatureValid").value(true))
                .andExpect(jsonPath("$.compliant").value(false))
                .andExpect(jsonPath("$.reason").value("CERT_NOT_FOUND"));
    }

    @Test
    void verifyEndpointReturns200WithSignatureInvalidWhenSignatureDoesNotMatch() throws Exception {
        registry.put(publicKeyFingerprint, ApprovalRegistry.RegistryEntry.builder()
                .verificationId("VID-OK")
                .compliant(true)
                .status(RegistryStatus.VERIFIED_AND_ISSUED)
                .publicKeyFingerprint(publicKeyFingerprint)
                .build());

        SignatureVerificationRequest request = signedRequest("payload-3");
        // Tamper digest
        byte[] otherDigest = MessageDigest.getInstance("SHA-512")
                .digest("tampered".getBytes(StandardCharsets.UTF_8));
        request.setDigestHex(HexFormat.of().formatHex(otherDigest));

        mockMvc.perform(post("/api/v1/verify")
                        .contentType("application/json")
                        .content(json.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signatureValid").value(false))
                .andExpect(jsonPath("$.compliant").value(false))
                .andExpect(jsonPath("$.reason").value("SIGNATURE_INVALID"));
    }

    @Test
    void verifyEndpointAcceptsAndProcessesPayloadInDataMinimisedForm() throws Exception {
        // Verifies the data-minimisation contract: the request must be
        // parseable and processable without ever including transaction
        // payload content, only the digest.
        registry.put(publicKeyFingerprint, ApprovalRegistry.RegistryEntry.builder()
                .verificationId("VID-DM")
                .compliant(true)
                .status(RegistryStatus.VERIFIED_AND_ISSUED)
                .publicKeyFingerprint(publicKeyFingerprint)
                .build());

        SignatureVerificationRequest request = signedRequest(
                "any-confidential-business-payload-that-must-not-leak");

        // The serialised body must not contain the original payload string
        String body = json.writeValueAsString(request);
        org.assertj.core.api.Assertions.assertThat(body)
                .doesNotContain("any-confidential-business-payload-that-must-not-leak");

        mockMvc.perform(post("/api/v1/verify")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.compliant").value(true));
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private SignatureVerificationRequest signedRequest(String payload) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512")
                .digest(payload.getBytes(StandardCharsets.UTF_8));

        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initSign(signingKeyPair.getPrivate());
        sig.update(digest);
        byte[] signature = sig.sign();

        return SignatureVerificationRequest.builder()
                .certSerial(signingCert.getSerialNumber().toString())
                .issuerDn(signingCert.getIssuerX500Principal().getName())
                .digestHex(HexFormat.of().formatHex(digest))
                .signatureBase64(Base64.getEncoder().encodeToString(signature))
                .signingCertificatePem(signingCertPem)
                .build();
    }

    private static String computeFingerprint(PublicKey publicKey) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        StringBuilder sb = new StringBuilder(hash.length * 3);
        for (int i = 0; i < hash.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", hash[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Minimal ApprovalRegistry stand-in. Indexes entries by
     * publicKeyFingerprint only — the registry behaviours not exercised by
     * the verify endpoint are deliberately unimplemented.
     */
    private static class FakeApprovalRegistry implements ApprovalRegistry {
        private final java.util.Map<String, RegistryEntry> byFingerprint = new java.util.HashMap<>();

        void put(String fingerprint, RegistryEntry entry) {
            byFingerprint.put(fingerprint, entry);
        }

        @Override
        public Optional<RegistryEntry> findByPublicKeyFingerprint(String fingerprint) {
            return Optional.ofNullable(byFingerprint.get(fingerprint));
        }

        @Override
        public RegistryEntry register(String verificationId, String confirmationNonce, boolean compliant,
                String publicKeyFingerprint, String supplierIdentifier, String supplierName,
                String hsmVendor, String hsmModel, String countryCode) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<RegistryEntry> confirm(String verificationId, String submittedNonce,
                boolean issued, String actualPublicKeyFingerprint, boolean publicKeyMatch) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<RegistryEntry> lookup(String verificationId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public java.util.List<RegistryEntry> findByCountry(String countryCode) {
            throw new UnsupportedOperationException();
        }

        @Override
        public java.util.List<RegistryEntry> findAnomalies() {
            throw new UnsupportedOperationException();
        }

        @Override
        public java.util.List<RegistryEntry> findAwaitingConfirmation() {
            throw new UnsupportedOperationException();
        }

        @Override
        public ComplianceStats getStats(String countryCode) {
            throw new UnsupportedOperationException();
        }
    }
}
