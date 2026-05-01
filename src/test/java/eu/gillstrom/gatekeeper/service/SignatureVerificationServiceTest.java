package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SignatureVerificationService}.
 *
 * <p>The tests use throwaway RSA-2048 key pairs (faster than 4096 in CI) and
 * the same {@code Signature.getInstance("SHA512withRSA")} primitive that
 * production code uses. The signing flow mirrors what railgate sees from
 * the payment-network operator: a payload is hashed to a SHA-512 digest,
 * the digest is signed (using the standard Java signature API which
 * internally re-hashes — equivalent to the production HSM behaviour), and
 * the verifier receives only {@code (digest, signature, certPem)}.
 *
 * <p>The {@code ApprovalRegistry} is replaced with a hand-rolled fake that
 * indexes {@link RegistryEntry} by public-key fingerprint, allowing each
 * test to control compliance state independently.
 */
class SignatureVerificationServiceTest {

    private FakeApprovalRegistry registry;
    private SignatureVerificationService service;

    private KeyPair signingKeyPair;
    private X509Certificate signingCert;
    private String signingCertPem;
    private String publicKeyFingerprint;

    @BeforeEach
    void setUp() throws Exception {
        registry = new FakeApprovalRegistry();
        service = new SignatureVerificationService(registry);

        signingKeyPair = TestPki.newRsaKeyPair(2048);
        signingCert = TestPki.selfSignedCa(signingKeyPair, "Test Signing Cert");
        signingCertPem = TestPki.toPem(signingCert);
        publicKeyFingerprint = computeFingerprint(signingCert.getPublicKey());
    }

    @Test
    void allowsSettlementWhenSignatureValidAndCertCompliant() throws Exception {
        // Arrange: a compliant audit entry exists for this key.
        registry.put(publicKeyFingerprint,
                buildEntry("VID-1", true, RegistryStatus.VERIFIED_AND_ISSUED));

        SignatureVerificationRequest request = signedRequest("payload-A");

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isTrue();
        assertThat(response.isCompliant()).isTrue();
        assertThat(response.getAuditEntryId()).isEqualTo("VID-1");
        assertThat(response.getReason()).isEqualTo("OK");
    }

    @Test
    void deniesWhenCertHasNoAuditEntry() throws Exception {
        SignatureVerificationRequest request = signedRequest("payload-B");

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isTrue();
        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getAuditEntryId()).isNull();
        assertThat(response.getReason()).isEqualTo("CERT_NOT_FOUND");
    }

    @Test
    void deniesWhenCertExistsButIsNonCompliant() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-2", false, RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH));

        SignatureVerificationRequest request = signedRequest("payload-C");

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isTrue();
        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getAuditEntryId()).isEqualTo("VID-2");
        assertThat(response.getReason()).isEqualTo("CERT_NON_COMPLIANT");
    }

    @Test
    void deniesWhenSignatureDoesNotMatchDigest() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-3", true, RegistryStatus.VERIFIED_AND_ISSUED));

        SignatureVerificationRequest request = signedRequest("payload-D");
        // Tamper: replace digest with one that doesn't match the signature.
        byte[] otherDigest = MessageDigest.getInstance("SHA-512")
                .digest("different-payload".getBytes(StandardCharsets.UTF_8));
        request.setDigestHex(HexFormat.of().formatHex(otherDigest));

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isFalse();
        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getReason()).isEqualTo("SIGNATURE_INVALID");
    }

    @Test
    void deniesWhenSigningCertificatePemIsMissing() throws Exception {
        SignatureVerificationRequest request = signedRequest("payload-E");
        request.setSigningCertificatePem(null);

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isFalse();
        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getReason()).isEqualTo("MALFORMED_INPUT");
    }

    @Test
    void deniesWhenDigestHexIsMalformed() throws Exception {
        SignatureVerificationRequest request = signedRequest("payload-F");
        request.setDigestHex("not-valid-hex");

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isFalse();
        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getReason()).isEqualTo("MALFORMED_INPUT");
    }

    @Test
    void deniesWhenAlgorithmIsNotSupported() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-4", true, RegistryStatus.VERIFIED_AND_ISSUED));
        SignatureVerificationRequest request = signedRequest("payload-G");
        request.setAlgorithm("BOGUS-ALGORITHM");

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isFalse();
        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getReason()).isEqualTo("ALGORITHM_NOT_SUPPORTED");
    }

    @Test
    void looksUpByActualPublicKeyFingerprintWhenPrimaryFingerprintDiffers() throws Exception {
        // The registry may have been populated with a fingerprint different
        // from the one we'd compute from the cert (e.g. expected vs actual).
        // The service must still find it via actualPublicKeyFingerprint.
        ApprovalRegistry.RegistryEntry entry = ApprovalRegistry.RegistryEntry.builder()
                .verificationId("VID-5")
                .compliant(true)
                .publicKeyFingerprint("EXPECTED-FINGERPRINT-DIFFERENT")
                .actualPublicKeyFingerprint(publicKeyFingerprint)
                .status(RegistryStatus.VERIFIED_AND_ISSUED)
                .build();
        registry.putByActual(publicKeyFingerprint, entry);

        SignatureVerificationRequest request = signedRequest("payload-H");

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isTrue();
        assertThat(response.isCompliant()).isTrue();
        assertThat(response.getAuditEntryId()).isEqualTo("VID-5");
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /**
     * Produces a {@link SignatureVerificationRequest} containing the SHA-512
     * digest of {@code payload} and an RSA signature over that digest, using
     * the test signing key. Mirrors the production flow where the customer's
     * application hashes the payload to a digest before sending it to the
     * HSM for signing.
     */
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

    private static ApprovalRegistry.RegistryEntry buildEntry(
            String verificationId, boolean compliant, RegistryStatus status) {
        return ApprovalRegistry.RegistryEntry.builder()
                .verificationId(verificationId)
                .compliant(compliant)
                .status(status)
                .build();
    }

    /**
     * Minimal ApprovalRegistry stand-in. Indexes entries by either
     * {@code publicKeyFingerprint} or {@code actualPublicKeyFingerprint}
     * to mirror real implementations' behaviour.
     */
    private static class FakeApprovalRegistry implements ApprovalRegistry {
        private final java.util.Map<String, RegistryEntry> byPrimary = new java.util.HashMap<>();
        private final java.util.Map<String, RegistryEntry> byActual = new java.util.HashMap<>();

        void put(String fingerprint, RegistryEntry entry) {
            entry.setPublicKeyFingerprint(fingerprint);
            byPrimary.put(fingerprint, entry);
        }

        void putByActual(String fingerprint, RegistryEntry entry) {
            byActual.put(fingerprint, entry);
        }

        @Override
        public Optional<RegistryEntry> findByPublicKeyFingerprint(String fingerprint) {
            if (byPrimary.containsKey(fingerprint)) return Optional.of(byPrimary.get(fingerprint));
            if (byActual.containsKey(fingerprint)) return Optional.of(byActual.get(fingerprint));
            return Optional.empty();
        }

        // Unused in these tests; throw to make accidental dependencies obvious.
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
