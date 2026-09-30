package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.util.Fingerprints;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
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

    @TempDir
    Path tempDir;

    private FakeApprovalRegistry registry;
    private SignatureVerificationService service;
    private AppendOnlyFileAuditLog auditLog;
    private Path auditPath;

    private KeyPair signingKeyPair;
    private X509Certificate signingCert;
    private String signingCertPem;
    private String publicKeyFingerprint;

    @BeforeEach
    void setUp() throws Exception {
        registry = new FakeApprovalRegistry();
        // A real audit log on a temp path, not a stub: the settlement-time
        // audit entry is a claim about what actually lands in the chain, and
        // a stub could not falsify it.
        auditPath = tempDir.resolve("audit.jsonl");
        auditLog = new AppendOnlyFileAuditLog(auditPath.toString(), new EphemeralReceiptSigner(2048));
        auditLog.initialise();
        service = new SignatureVerificationService(registry, auditLog, new MtlsPrincipalResolver());

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

    /**
     * The registry's {@code compliant} flag records the Step-3 verdict and is
     * never rewritten; the Step-7 outcome lives in {@code status}. Reading
     * only the flag meant a certificate whose confirmation had already been
     * recorded as {@code ANOMALY_PUBLIC_KEY_MISMATCH} — the issuer produced
     * a certificate over a key that was not the attested one — kept settling
     * payments, which is the circumvention the Step-7 loop exists to detect.
     */
    @Test
    void deniesWhenConfirmationRecordedAnAnomalyDespiteACompliantVerification() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-ANOMALY", true, RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH));

        SignatureVerificationResponse response = service.verify(signedRequest("payload-M"));

        assertThat(response.isSignatureValid()).isTrue();
        assertThat(response.isCompliant())
                .as("an anomalous Step-7 outcome disqualifies the entry at settlement time "
                    + "even though the attestation itself verified")
                .isFalse();
        assertThat(response.getAuditEntryId()).isEqualTo("VID-ANOMALY");
        assertThat(response.getReason()).isEqualTo("CERT_NON_COMPLIANT");
    }

    @Test
    void deniesWhenConfirmationRecordedIssuanceDespiteRejection() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-DESPITE", true, RegistryStatus.ANOMALY_ISSUED_DESPITE_REJECTION));

        SignatureVerificationResponse response = service.verify(signedRequest("payload-N"));

        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getReason()).isEqualTo("CERT_NON_COMPLIANT");
    }

    /**
     * A verification awaiting Step 7 ({@code status == null}) is the ordinary
     * state between issuance and confirmation and must keep settling — the
     * fix above must not deny everything that has not been confirmed yet.
     */
    @Test
    void allowsSettlementWhileStillAwaitingConfirmation() throws Exception {
        registry.put(publicKeyFingerprint, buildEntry("VID-AWAITING", true, null));

        SignatureVerificationResponse response = service.verify(signedRequest("payload-O"));

        assertThat(response.isCompliant()).isTrue();
        assertThat(response.getReason()).isEqualTo("OK");
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
    void deniesWhenNeitherSigningCertificatePemNorSerialAndIssuerArePresent() throws Exception {
        SignatureVerificationRequest request = signedRequest("payload-E");
        request.setSigningCertificatePem(null);
        request.setCertSerial(null);

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isFalse();
        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getReason()).isEqualTo("MALFORMED_INPUT");
    }

    @Test
    void deniesAsCertNotFoundWhenSigningCertificatePemIsMissingAndNoCertificateIsStored() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-NO-PEM", true, RegistryStatus.VERIFIED_AND_ISSUED));
        SignatureVerificationRequest request = signedRequest("payload-E2");
        request.setSigningCertificatePem(null);

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.isSignatureValid()).isFalse();
        assertThat(response.isCompliant()).isFalse();
        assertThat(response.getReason()).isEqualTo("CERT_NOT_FOUND");
    }

    @Test
    void rsassaPssSignatureVerifiesWithSha512Mgf1AndA64ByteSalt() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-PSS", true, RegistryStatus.VERIFIED_AND_ISSUED));
        byte[] digest = MessageDigest.getInstance("SHA-512")
                .digest("payload-PSS".getBytes(StandardCharsets.UTF_8));
        Signature sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
        sig.initSign(signingKeyPair.getPrivate());
        sig.update(digest);
        SignatureVerificationRequest request = SignatureVerificationRequest.builder()
                .certSerial(signingCert.getSerialNumber().toString(16))
                .issuerDn(signingCert.getIssuerX500Principal().getName())
                .digestHex(HexFormat.of().formatHex(digest))
                .signatureBase64(Base64.getEncoder().encodeToString(sig.sign()))
                .signingCertificatePem(signingCertPem)
                .algorithm("RSASSA-PSS")
                .build();

        SignatureVerificationResponse response = service.verify(request);

        assertThat(response.getReason()).isEqualTo("OK");
        assertThat(response.isSignatureValid()).isTrue();
        assertThat(response.isCompliant()).isTrue();
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
    // Audit trail — settlement-time decisions must be in the chain
    // ---------------------------------------------------------------------

    @Test
    void writesOneAuditEntryPerSettlementVerification() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-AUDIT", true, RegistryStatus.VERIFIED_AND_ISSUED));

        service.verify(signedRequest("payload-I"));
        service.verify(signedRequest("payload-J"));

        assertThat(auditLog.size()).isEqualTo(2);
        assertThat(auditLog.verifyChainIntegrity()).isTrue();

        List<AuditEntry> entries = auditLog.findInRange(
                java.time.Instant.EPOCH, java.time.Instant.now().plusSeconds(60));
        assertThat(entries).hasSize(2);
        for (AuditEntry entry : entries) {
            assertThat(entry.operation()).isEqualTo(SignatureVerificationService.AUDIT_OPERATION);
            assertThat(entry.verificationId()).isEqualTo("VID-AUDIT");
            assertThat(entry.compliant()).isTrue();
            assertThat(entry.requestDigestBase64()).isNotBlank();
            assertThat(entry.receiptDigestBase64()).isNotBlank();
        }
        // Two distinct payloads must produce two distinct request digests,
        // otherwise the digest is not a witness to anything.
        assertThat(entries.get(0).requestDigestBase64())
                .isNotEqualTo(entries.get(1).requestDigestBase64());
    }

    @Test
    void responseCarriesTheHashOfItsOwnSettlementAuditEntry() throws Exception {
        SignatureVerificationResponse notFound = service.verify(signedRequest("payload-R"));
        assertThat(notFound.getReason()).isEqualTo("CERT_NOT_FOUND");
        assertThat(notFound.getAuditEntryId()).isNull();
        assertThat(notFound.getAuditEntryHashHex())
                .isEqualTo(auditLog.head().orElseThrow().thisEntryHashHex());

        registry.put(publicKeyFingerprint,
                buildEntry("VID-HASH", true, RegistryStatus.VERIFIED_AND_ISSUED));

        SignatureVerificationResponse first = service.verify(signedRequest("payload-P"));
        AuditEntry firstEntry = auditLog.head().orElseThrow();
        SignatureVerificationResponse second = service.verify(signedRequest("payload-Q"));
        AuditEntry secondEntry = auditLog.head().orElseThrow();

        assertThat(first.getAuditEntryId()).isEqualTo("VID-HASH");
        assertThat(second.getAuditEntryId()).isEqualTo("VID-HASH");
        assertThat(first.getAuditEntryHashHex()).isEqualTo(firstEntry.thisEntryHashHex());
        assertThat(second.getAuditEntryHashHex()).isEqualTo(secondEntry.thisEntryHashHex());
        assertThat(first.getAuditEntryHashHex()).isNotEqualTo(second.getAuditEntryHashHex());
    }

    @Test
    void auditEntryRecordsTheDenialWhenSettlementIsRefused() throws Exception {
        // No registry entry for this key: signature verifies, compliance does not.
        service.verify(signedRequest("payload-K"));

        assertThat(auditLog.size()).isEqualTo(1);
        AuditEntry entry = auditLog.head().orElseThrow();
        assertThat(entry.operation()).isEqualTo(SignatureVerificationService.AUDIT_OPERATION);
        assertThat(entry.compliant()).isFalse();
        assertThat(entry.verificationId())
                .isEqualTo(SignatureVerificationService.NO_REGISTRY_MATCH);
    }

    @Test
    void auditEntryCarriesNoRequestContentBeyondDigests() throws Exception {
        registry.put(publicKeyFingerprint,
                buildEntry("VID-DM", true, RegistryStatus.VERIFIED_AND_ISSUED));

        SignatureVerificationRequest request = signedRequest("payload-L");
        service.verify(request);

        String onDisk = Files.readString(auditPath, StandardCharsets.UTF_8);
        assertThat(onDisk).isNotBlank();
        // The transaction digest, the signature and the certificate are the
        // request's substance. None of them may be written verbatim — only
        // the SHA-256 over the canonical form. (certSerial is not asserted
        // on: TestPki issues single-digit serials, which occur incidentally
        // in any line containing a timestamp.)
        assertThat(onDisk).doesNotContain(request.getDigestHex());
        assertThat(onDisk).doesNotContain(request.getSignatureBase64());
        // A single base64 line from the middle of the certificate — a
        // whole-PEM comparison would pass trivially because of newline
        // escaping in the JSON-Lines form.
        String certBodyLine = request.getSigningCertificatePem().lines()
                .filter(l -> l.length() > 32 && !l.startsWith("-----"))
                .findFirst()
                .orElseThrow();
        assertThat(onDisk).doesNotContain(certBodyLine);
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

    /**
     * Delegates to production code on purpose. If this test computed the
     * fingerprint itself it could encode a format the production writer never
     * produces, which is exactly how the uppercase/lowercase mismatch stayed
     * hidden.
     */
    private static String computeFingerprint(PublicKey publicKey) {
        return Fingerprints.ofPublicKey(publicKey);
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
                String hsmVendor, String hsmModel, String countryCode, String verificationPrincipal) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<RegistryEntry> confirm(String verificationId, String submittedNonce,
                boolean issued, String actualPublicKeyFingerprint, boolean publicKeyMatch,
                IssuedCertificate issuedCertificate) {
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
        public java.util.List<RegistryEntry> findAnomalies(String countryCode) {
            throw new UnsupportedOperationException();
        }

        @Override
        public java.util.List<RegistryEntry> findAwaitingConfirmation(String countryCode) {
            throw new UnsupportedOperationException();
        }

        @Override
        public ComplianceStats getStats(String countryCode) {
            throw new UnsupportedOperationException();
        }
    }
}
