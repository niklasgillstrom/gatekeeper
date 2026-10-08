package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmation;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.util.Fingerprints;
import eu.gillstrom.gatekeeper.verification.AzureHsmVerifier;
import eu.gillstrom.gatekeeper.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class IssuanceConfirmationCertificateTest {

    @TempDir
    Path tempDir;

    private InMemoryApprovalRegistry registry;
    private AppendOnlyFileAuditLog auditLog;
    private VerificationService service;
    private KeyPair leafKp;
    private X509Certificate intermediate;
    private X509Certificate leaf;

    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

    @BeforeEach
    void setUp() throws Exception {
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKp, "TEST-ISSUER-ROOT");
        KeyPair intermediateKp = TestPki.newRsaKeyPair(2048);
        intermediate = TestPki.subordinateCa(
                intermediateKp, "TEST-ISSUER-INTERMEDIATE", root, rootKp.getPrivate());
        leafKp = TestPki.newRsaKeyPair(2048);
        leaf = TestPki.endEntity(leafKp, "TEST-SIGNING-CERT", intermediate, intermediateKp.getPrivate());

        Path bundle = tempDir.resolve("issuer-ca-bundle.pem");
        Files.writeString(bundle, TestPki.toPem(root), StandardCharsets.UTF_8);

        auditLog = new AppendOnlyFileAuditLog(
                tempDir.resolve("audit.jsonl").toString(), new EphemeralReceiptSigner(2048));
        auditLog.initialise();

        registry = new InMemoryApprovalRegistry();
        registry.register("VID-7", "nonce-7", true, Fingerprints.ofPublicKey(leafKp.getPublic()),
                "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE");

        service = new VerificationService(
                mock(SecurosysVerifier.class),
                mock(YubicoVerifier.class),
                mock(AzureHsmVerifier.class),
                mock(GoogleCloudHsmVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.MarvellHsmVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.ThalesLunaVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.Crypto4AVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.FortanixVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.NShieldVerifier.class),
                registry,
                signer,
                new IssuerCaValidator(bundle.toString()),
                auditLog,
                new MtlsPrincipalResolver(),
                KeyPolicy.defaults(),
                false);
    }

    private static IssuanceConfirmation issuance(String signingCertificatePem) {
        IssuanceConfirmation confirmation = new IssuanceConfirmation();
        confirmation.setVerificationId("VID-7");
        confirmation.setConfirmationNonce("nonce-7");
        confirmation.setIssued(true);
        confirmation.setSigningCertificatePem(signingCertificatePem);
        confirmation.setTimestamp(Instant.now().toString());
        return confirmation;
    }

    @Test
    void confirmationResponseIsSignedOverItsCanonicalBytes() throws Exception {
        IssuanceConfirmationResponse response = service.confirmIssuance(
                issuance(TestPki.toPem(leaf) + TestPki.toPem(intermediate)), "SE");

        assertThat(response.getSigningCertificate()).isEqualTo(signer.getSigningCertificatePem());
        java.security.PublicKey key = ((X509Certificate) java.security.cert.CertificateFactory
                .getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(
                        response.getSigningCertificate().getBytes(StandardCharsets.UTF_8))))
                .getPublicKey();
        byte[] signature = java.util.Base64.getDecoder().decode(response.getSignature());

        assertThat(verifies(key, response, signature)).isTrue();
        response.setLoopClosed(!response.isLoopClosed());
        assertThat(verifies(key, response, signature)).as("a flipped loopClosed must not verify").isFalse();
    }

    private static boolean verifies(java.security.PublicKey key, IssuanceConfirmationResponse response,
            byte[] signature) throws Exception {
        java.security.Signature s = java.security.Signature.getInstance("SHA256withRSA");
        s.initVerify(key);
        s.update(eu.gillstrom.gatekeeper.signing.ConfirmationCanonicalizer.canonicalize(response));
        return s.verify(signature);
    }

    @Test
    void issuedWithoutCertificateIsAnAnomalyAndLeavesTheLoopOpen() {
        IssuanceConfirmationResponse response = service.confirmIssuance(issuance(null), "SE");

        assertThat(response.isLoopClosed()).isFalse();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
        assertThat(response.getAnomalies()).anyMatch(a -> a.contains("without a signing certificate"));
        assertThat(response.getPublicKeyMatch()).isFalse();
        assertThat(registry.lookup("VID-7").orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
    }

    @Test
    void issuedWithBlankCertificateIsAnAnomalyAndLeavesTheLoopOpen() {
        IssuanceConfirmationResponse response = service.confirmIssuance(issuance("  "), "SE");

        assertThat(response.isLoopClosed()).isFalse();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
        assertThat(response.getAnomalies()).anyMatch(a -> a.contains("without a signing certificate"));
    }

    @Test
    void certificateIssuedUnderAnIntermediateValidatesWhenTheIntermediateIsSubmitted() throws Exception {
        IssuanceConfirmationResponse response = service.confirmIssuance(
                issuance(TestPki.toPem(leaf) + TestPki.toPem(intermediate)), "SE");

        assertThat(response.getAnomalies()).isEmpty();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(response.isLoopClosed()).isTrue();
        assertThat(response.getPublicKeyMatch()).isTrue();
    }

    @Test
    void certificateIssuedUnderAnIntermediateIsAnAnomalyWhenTheIntermediateIsMissing() throws Exception {
        IssuanceConfirmationResponse response = service.confirmIssuance(
                issuance(TestPki.toPem(leaf)), "SE");

        assertThat(response.isLoopClosed()).isFalse();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
        assertThat(response.getAnomalies()).anyMatch(a -> a.contains("not issued by a trusted issuer CA"));
    }

    private boolean auditedAsCompliant(String verificationId) {
        eu.gillstrom.gatekeeper.audit.AuditEntry entry =
                auditLog.findByVerificationId(verificationId).orElseThrow();
        assertThat(entry.operation()).isEqualTo("CONFIRM");
        return entry.compliant();
    }

    @Test
    void aCleanConfirmationClosesTheLoopAndIsAuditedAsCompliant() throws Exception {
        IssuanceConfirmationResponse response = service.confirmIssuance(
                issuance(TestPki.toPem(leaf) + TestPki.toPem(intermediate)), "SE");

        assertThat(response.isLoopClosed()).isTrue();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(auditedAsCompliant("VID-7")).isTrue();
    }

    @Test
    void anAnomalousConfirmationIsAuditedAsNonCompliant() {
        service.confirmIssuance(issuance(null), "SE");

        assertThat(auditedAsCompliant("VID-7")).isFalse();
    }

    @Test
    void aWithdrawnIssuanceClosesTheLoopWithoutAKeyComparison() {
        IssuanceConfirmation withdrawn = issuance(null);
        withdrawn.setIssued(false);

        IssuanceConfirmationResponse response = service.confirmIssuance(withdrawn, "SE");

        assertThat(response.isLoopClosed()).isTrue();
        assertThat(response.getPublicKeyMatch()).isNull();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_NOT_ISSUED);
        assertThat(response.getSignature()).isNotBlank();
        assertThat(auditedAsCompliant("VID-7")).isTrue();
    }

    @Test
    void aConfirmationForAnUnknownVerificationIsSignedAndAudited() {
        IssuanceConfirmation unknown = issuance(null);
        unknown.setVerificationId("NO-SUCH-ID");

        IssuanceConfirmationResponse response = service.confirmIssuance(unknown, "SE");

        assertThat(response.isLoopClosed()).isFalse();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION);
        assertThat(response.getSignature()).isNotBlank();
        assertThat(auditedAsCompliant("NO-SUCH-ID")).isFalse();
    }

    @Test
    void issuanceAfterARejectedVerificationIsACriticalAnomaly() throws Exception {
        registry.register("VID-REJ", "nonce-rej", false, Fingerprints.ofPublicKey(leafKp.getPublic()),
                "556000-0000", "Svensk TL", null, null, "SE");
        IssuanceConfirmation issued = issuance(TestPki.toPem(leaf) + TestPki.toPem(intermediate));
        issued.setVerificationId("VID-REJ");
        issued.setConfirmationNonce("nonce-rej");

        IssuanceConfirmationResponse response = service.confirmIssuance(issued, "SE");

        assertThat(response.isLoopClosed()).isFalse();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_ISSUED_DESPITE_REJECTION);
        assertThat(response.getAnomalies()).anyMatch(a -> a.startsWith("CRITICAL ANOMALY: Certificate issued despite"));
        assertThat(auditedAsCompliant("VID-REJ")).isFalse();
    }

    @Test
    void aRejectedVerificationThatIsNotIssuedStaysRejected() {
        registry.register("VID-REJ2", "nonce-rej2", false, "fp", "556000-0000", "Svensk TL", null, null, "SE");
        IssuanceConfirmation notIssued = issuance(null);
        notIssued.setVerificationId("VID-REJ2");
        notIssued.setConfirmationNonce("nonce-rej2");
        notIssued.setIssued(false);

        IssuanceConfirmationResponse response = service.confirmIssuance(notIssued, "SE");

        assertThat(response.isLoopClosed()).isTrue();
        assertThat(response.getAnomalies()).isEmpty();
        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.REJECTED_NOT_ISSUED);
    }
}
