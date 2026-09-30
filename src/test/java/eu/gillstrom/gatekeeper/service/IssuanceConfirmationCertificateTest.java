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
    private VerificationService service;
    private KeyPair leafKp;
    private X509Certificate intermediate;
    private X509Certificate leaf;

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

        AppendOnlyFileAuditLog auditLog = new AppendOnlyFileAuditLog(
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
                registry,
                new EphemeralReceiptSigner(2048),
                new IssuerCaValidator(bundle.toString()),
                auditLog,
                new MtlsPrincipalResolver(),
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
}
