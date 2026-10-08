package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmation;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SettlementCertificateLookupTest {

    @TempDir
    Path tempDir;

    private KeyPair issuerKp;
    private X509Certificate issuerCa;
    private KeyPair leafKp;
    private X509Certificate leaf;
    private IssuerCaValidator issuerCaValidator;
    private AppendOnlyFileAuditLog auditLog;
    private MtlsPrincipalResolver principalResolver;

    @BeforeEach
    void setUp() throws Exception {
        issuerKp = TestPki.newRsaKeyPair(2048);
        issuerCa = TestPki.selfSignedCa(issuerKp, "TEST-ISSUER-CA");
        leafKp = TestPki.newRsaKeyPair(2048);
        leaf = TestPki.endEntity(leafKp, "TEST-SIGNING-CERT", issuerCa, issuerKp.getPrivate());

        Path bundle = tempDir.resolve("issuer-ca-bundle.pem");
        Files.writeString(bundle, TestPki.toPem(issuerCa), StandardCharsets.UTF_8);
        issuerCaValidator = new IssuerCaValidator(bundle.toString());

        auditLog = new AppendOnlyFileAuditLog(
                tempDir.resolve("audit.jsonl").toString(), new EphemeralReceiptSigner(2048));
        auditLog.initialise();
        principalResolver = new MtlsPrincipalResolver();
    }

    private VerificationService verificationService(ApprovalRegistry registry) {
        return new VerificationService(
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
                new EphemeralReceiptSigner(2048),
                issuerCaValidator,
                auditLog,
                principalResolver,
                KeyPolicy.defaults(),
                false);
    }

    private void registerCompliantVerification(ApprovalRegistry registry) {
        registry.register("VID-SETTLE", "nonce-settle", true, Fingerprints.ofPublicKey(leafKp.getPublic()),
                "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE");
    }

    private IssuanceConfirmation issuanceOf(X509Certificate certificate) throws Exception {
        IssuanceConfirmation confirmation = new IssuanceConfirmation();
        confirmation.setVerificationId("VID-SETTLE");
        confirmation.setConfirmationNonce("nonce-settle");
        confirmation.setIssued(true);
        confirmation.setSigningCertificatePem(TestPki.toPem(certificate));
        confirmation.setTimestamp(Instant.now().toString());
        return confirmation;
    }

    private SignatureVerificationRequest fourFieldRequest(String certSerial, String issuerDn, String payload)
            throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(payload.getBytes(StandardCharsets.UTF_8));
        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initSign(leafKp.getPrivate());
        sig.update(digest);
        return SignatureVerificationRequest.builder()
                .certSerial(certSerial)
                .issuerDn(issuerDn)
                .digestHex(HexFormat.of().formatHex(digest))
                .signatureBase64(Base64.getEncoder().encodeToString(sig.sign()))
                .build();
    }

    private InMemoryApprovalRegistry confirmedRegistry() throws Exception {
        InMemoryApprovalRegistry registry = new InMemoryApprovalRegistry();
        registerCompliantVerification(registry);
        IssuanceConfirmationResponse confirmed =
                verificationService(registry).confirmIssuance(issuanceOf(leaf), "SE");
        assertThat(confirmed.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        return registry;
    }

    @Test
    void confirmStoresTheIssuedCertificateOnTheRegistryEntry() throws Exception {
        InMemoryApprovalRegistry registry = confirmedRegistry();

        ApprovalRegistry.RegistryEntry entry = registry.lookup("VID-SETTLE").orElseThrow();
        assertThat(entry.getIssuedCertificatePem()).isEqualTo(TestPki.toPem(leaf));
        assertThat(entry.getIssuedCertificateSerial()).isEqualTo(leaf.getSerialNumber().toString(16));
        assertThat(entry.getIssuedCertificateIssuerDn()).isEqualTo(leaf.getIssuerX500Principal().getName());
    }

    @Test
    void fourFieldSettlementRequestVerifiesAgainstTheCertificateStoredAtConfirm() throws Exception {
        InMemoryApprovalRegistry registry = confirmedRegistry();
        SignatureVerificationService settlement =
                new SignatureVerificationService(registry, auditLog, principalResolver);

        SignatureVerificationResponse response = settlement.verify(fourFieldRequest(
                leaf.getSerialNumber().toString(16), leaf.getIssuerX500Principal().getName(), "payload-1"));

        assertThat(response.getReason()).isEqualTo("OK");
        assertThat(response.isSignatureValid()).isTrue();
        assertThat(response.isCompliant()).isTrue();
        assertThat(response.getAuditEntryId()).isEqualTo("VID-SETTLE");

        AuditEntry head = auditLog.head().orElseThrow();
        assertThat(head.operation()).isEqualTo(SignatureVerificationService.AUDIT_OPERATION);
        assertThat(head.verificationId()).isEqualTo("VID-SETTLE");
        assertThat(head.compliant()).isTrue();
        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }

    @Test
    void certSerialIsHexadecimalCaseInsensitiveWithAnOptional0xPrefix() throws Exception {
        InMemoryApprovalRegistry registry = confirmedRegistry();
        SignatureVerificationService settlement =
                new SignatureVerificationService(registry, auditLog, principalResolver);
        String hex = leaf.getSerialNumber().toString(16);

        for (String certSerial : List.of(hex.toUpperCase(Locale.ROOT), "0x" + hex, "0X" + hex.toUpperCase(Locale.ROOT))) {
            SignatureVerificationResponse response = settlement.verify(fourFieldRequest(
                    certSerial, leaf.getIssuerX500Principal().getName(), "payload-" + certSerial));

            assertThat(response.getReason()).as(certSerial).isEqualTo("OK");
        }
    }

    @Test
    void unknownSerialIsCertNotFound() throws Exception {
        InMemoryApprovalRegistry registry = confirmedRegistry();
        SignatureVerificationService settlement =
                new SignatureVerificationService(registry, auditLog, principalResolver);

        SignatureVerificationResponse response = settlement.verify(fourFieldRequest(
                leaf.getSerialNumber().add(BigInteger.ONE).toString(16),
                leaf.getIssuerX500Principal().getName(), "payload-2"));

        assertThat(response.getReason()).isEqualTo("CERT_NOT_FOUND");
        assertThat(response.isSignatureValid()).isFalse();
        assertThat(response.isCompliant()).isFalse();
        assertThat(auditLog.head().orElseThrow().verificationId())
                .isEqualTo(SignatureVerificationService.NO_REGISTRY_MATCH);
    }

    @Test
    void issuerMismatchIsCertNotFound() throws Exception {
        InMemoryApprovalRegistry registry = confirmedRegistry();
        SignatureVerificationService settlement =
                new SignatureVerificationService(registry, auditLog, principalResolver);

        SignatureVerificationResponse response = settlement.verify(fourFieldRequest(
                leaf.getSerialNumber().toString(16), "CN=SOME-OTHER-CA", "payload-3"));

        assertThat(response.getReason()).isEqualTo("CERT_NOT_FOUND");
        assertThat(response.isCompliant()).isFalse();
    }

    @Test
    void unparseableIssuerDnIsMalformedInput() throws Exception {
        InMemoryApprovalRegistry registry = confirmedRegistry();
        SignatureVerificationService settlement =
                new SignatureVerificationService(registry, auditLog, principalResolver);

        SignatureVerificationResponse response = settlement.verify(fourFieldRequest(
                leaf.getSerialNumber().toString(16), "not a distinguished name", "payload-4"));

        assertThat(response.getReason()).isEqualTo("MALFORMED_INPUT");
    }

    @Test
    void nonHexadecimalSerialIsMalformedInput() throws Exception {
        InMemoryApprovalRegistry registry = confirmedRegistry();
        SignatureVerificationService settlement =
                new SignatureVerificationService(registry, auditLog, principalResolver);

        SignatureVerificationResponse response = settlement.verify(fourFieldRequest(
                "not-hex", leaf.getIssuerX500Principal().getName(), "payload-5"));

        assertThat(response.getReason()).isEqualTo("MALFORMED_INPUT");
    }

    @Test
    void confirmationThatDidNotVerifyStoresNoCertificate() throws Exception {
        InMemoryApprovalRegistry registry = new InMemoryApprovalRegistry();
        registry.register("VID-SETTLE", "nonce-settle", true, "fp-of-a-different-key",
                "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE");

        IssuanceConfirmationResponse confirmed =
                verificationService(registry).confirmIssuance(issuanceOf(leaf), "SE");

        assertThat(confirmed.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
        assertThat(registry.lookup("VID-SETTLE").orElseThrow().getIssuedCertificatePem()).isNull();
        assertThat(registry.findByIssuedCertificate(leaf.getSerialNumber(), leaf.getIssuerX500Principal()))
                .isEmpty();
    }

    @Test
    void fileRegistryReplayKeepsTheStoredCertificate() throws Exception {
        Path journal = tempDir.resolve("approval-registry.jsonl");
        AppendOnlyFileApprovalRegistry first = new AppendOnlyFileApprovalRegistry(journal.toString());
        first.initialise();
        registerCompliantVerification(first);
        IssuanceConfirmationResponse confirmed =
                verificationService(first).confirmIssuance(issuanceOf(leaf), "SE");
        assertThat(confirmed.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);

        AppendOnlyFileApprovalRegistry replayed = new AppendOnlyFileApprovalRegistry(journal.toString());
        replayed.initialise();

        ApprovalRegistry.RegistryEntry entry = replayed
                .findByIssuedCertificate(leaf.getSerialNumber(), leaf.getIssuerX500Principal())
                .orElseThrow();
        assertThat(entry.getVerificationId()).isEqualTo("VID-SETTLE");
        assertThat(entry.getIssuedCertificatePem()).isEqualTo(TestPki.toPem(leaf));
        assertThat(entry.getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(entry.getConfirmationNonce()).isNull();

        SignatureVerificationResponse response = new SignatureVerificationService(
                replayed, auditLog, principalResolver).verify(fourFieldRequest(
                        leaf.getSerialNumber().toString(16), leaf.getIssuerX500Principal().getName(), "payload-6"));
        assertThat(response.getReason()).isEqualTo("OK");
        assertThat(response.isCompliant()).isTrue();
    }

    @Test
    void confirmJournalLinesWithoutCertificateFieldsStillReplay() throws Exception {
        Path journal = tempDir.resolve("legacy-registry.jsonl");
        Files.writeString(journal,
                "{\"op\":\"REGISTER\",\"entry\":{\"verificationId\":\"VID-LEGACY\","
                        + "\"confirmationNonce\":\"nonce-legacy\",\"compliant\":true,"
                        + "\"publicKeyFingerprint\":\"fp-legacy\",\"countryCode\":\"SE\","
                        + "\"verificationTimestamp\":\"2026-01-01T00:00:00Z\",\"certificateReceived\":false}}\n"
                        + "{\"op\":\"CONFIRM\",\"verificationId\":\"VID-LEGACY\",\"issued\":true,"
                        + "\"actualPublicKeyFingerprint\":\"fp-legacy\",\"publicKeyMatch\":true}\n",
                StandardCharsets.UTF_8);

        AppendOnlyFileApprovalRegistry replayed = new AppendOnlyFileApprovalRegistry(journal.toString());
        replayed.initialise();

        ApprovalRegistry.RegistryEntry entry = replayed.lookup("VID-LEGACY").orElseThrow();
        assertThat(entry.getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(entry.getConfirmationNonce()).isNull();
        assertThat(entry.getIssuedCertificatePem()).isNull();
        assertThat(entry.getIssuedCertificateSerial()).isNull();
        assertThat(entry.getIssuedCertificateIssuerDn()).isNull();
    }
}
