package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmation;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.KeyLifecycleRequest;
import eu.gillstrom.gatekeeper.model.KeyStatusChangeResponse;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.model.VerificationRequest;
import eu.gillstrom.gatekeeper.model.VerificationResponse;
import eu.gillstrom.gatekeeper.signing.ConfirmationCanonicalizer;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.util.Fingerprints;
import eu.gillstrom.gatekeeper.verification.AzureHsmVerifier;
import eu.gillstrom.gatekeeper.verification.Crypto4AVerifier;
import eu.gillstrom.gatekeeper.verification.FortanixVerifier;
import eu.gillstrom.gatekeeper.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.gatekeeper.verification.MarvellHsmVerifier;
import eu.gillstrom.gatekeeper.verification.NShieldVerifier;
import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.ThalesLunaVerifier;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The whole service path — verification, confirmation, key-lifecycle event,
 * settlement — over the file-backed registry with the mTLS principal binding
 * on, for a certificate that is confirmed a second time.
 *
 * <p>Until 1.7.0 the second confirmation produced a second, newer registry
 * entry for the certificate, which settlement and the lifecycle events then
 * followed: a financial entity that repeated verification and confirmation
 * with the same evidence and certificate made a revoked certificate settle
 * again, and a second client that did so took the certificate's lifecycle
 * over from the client that had it issued.</p>
 *
 * <p>Only the vendor verifier is a stub, so that the test holds the private
 * key and can sign a settlement.</p>
 */
class CertificateRegisteredOnceTest {

    @TempDir
    Path tempDir;

    private EphemeralReceiptSigner signer;
    private AppendOnlyFileAuditLog auditLog;
    private AppendOnlyFileApprovalRegistry registry;
    private VerificationService verification;
    private SignatureVerificationService settlement;
    private KeyLifecycleService lifecycle;

    private KeyPair keyPair;
    private X509Certificate certificate;
    private String certificatePem;
    private VerificationRequest evidence;
    private SignatureVerificationRequest payment;

    @BeforeEach
    void setUp() throws Exception {
        signer = new EphemeralReceiptSigner(2048);
        GatekeeperKeyDirectory keyDirectory = new GatekeeperKeyDirectory(signer, "");
        keyDirectory.initialise();
        auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(), signer);
        auditLog.initialise();
        registry = new AppendOnlyFileApprovalRegistry(journal().toString());
        registry.initialise();

        KeyPair issuerKeyPair = TestPki.newRsaKeyPair(2048);
        X509Certificate issuerCa = TestPki.selfSignedCa(issuerKeyPair, "Issuer CA");
        Path issuerBundle = tempDir.resolve("issuer-bundle.pem");
        Files.writeString(issuerBundle, TestPki.toPem(issuerCa));

        YubicoVerifier yubico = mock(YubicoVerifier.class);
        YubicoVerifier.YubicoAttestationResult attested = new YubicoVerifier.YubicoAttestationResult();
        attested.setChainValid(true);
        attested.setPublicKeyMatch(true);
        attested.setGenerated(true);
        attested.setValid(true);
        when(yubico.verifyYubicoAttestation(any(), any())).thenReturn(attested);

        MtlsPrincipalResolver principals = new MtlsPrincipalResolver();
        verification = new VerificationService(
                new SecurosysVerifier(), yubico, mock(AzureHsmVerifier.class), mock(GoogleCloudHsmVerifier.class),
                mock(MarvellHsmVerifier.class), new ThalesLunaVerifier(), new Crypto4AVerifier(),
                new FortanixVerifier(), new NShieldVerifier(), registry, signer,
                new IssuerCaValidator(issuerBundle.toString()), auditLog, principals, new KeyPolicy("RSA-2048"),
                true);
        settlement = new SignatureVerificationService(registry, auditLog, principals, signer, keyDirectory);
        lifecycle = new KeyLifecycleService(settlement, registry, auditLog, principals, true);

        keyPair = TestPki.newRsaKeyPair(2048);
        certificate = TestPki.endEntity(keyPair, "Signing certificate", issuerCa, issuerKeyPair.getPrivate());
        certificatePem = TestPki.toPem(certificate);

        evidence = new VerificationRequest();
        evidence.setPublicKey("-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----");
        evidence.setHsmVendor("YUBICO");
        evidence.setAttestationCertChain(List.of("evidence"));
        evidence.setCountryCode("SE");

        byte[] digest = MessageDigest.getInstance("SHA-512").digest("pacs.008".getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(digest);
        payment = SignatureVerificationRequest.builder()
                .certSerial(certificate.getSerialNumber().toString(16))
                .issuerDn(certificate.getIssuerX500Principal().getName())
                .digestHex(HexFormat.of().formatHex(digest))
                .signatureBase64(Base64.getEncoder().encodeToString(signature.sign()))
                .build();
    }

    @AfterEach
    void clearPrincipal() {
        SecurityContextHolder.clearContext();
    }

    private Path journal() {
        return tempDir.resolve("registry.jsonl");
    }

    private static void as(String principal, String role) {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(principal, "", role));
    }

    /** Steps 3 to 7 by {@code principal}, with the one certificate. */
    private IssuanceConfirmationResponse verifyAndConfirm(String principal) {
        as(principal, "ROLE_FE");
        VerificationResponse receipt = verification.verify(evidence);
        assertThat(receipt.isCompliant()).isTrue();
        IssuanceConfirmation confirmation = new IssuanceConfirmation();
        confirmation.setVerificationId(receipt.getVerificationId());
        confirmation.setConfirmationNonce(receipt.getConfirmationNonce());
        confirmation.setIssued(true);
        confirmation.setSigningCertificatePem(certificatePem);
        confirmation.setTimestamp("2026-11-09T00:00:00Z");
        return verification.confirmIssuance(confirmation, "SE");
    }

    private KeyStatusChangeResponse event(String principal, String role, String eventType) {
        as(principal, role);
        return lifecycle.changeStatus("SE", KeyLifecycleRequest.builder()
                .eventType(eventType)
                .certSerial(certificate.getSerialNumber().toString(16))
                .issuerDn(certificate.getIssuerX500Principal().getName())
                .reason("reported")
                .build());
    }

    private SignatureVerificationResponse settle() {
        as("RAIL-1", "ROLE_SETTLEMENT_RAIL");
        return settlement.verify(payment);
    }

    @ParameterizedTest
    @CsvSource({
        "REVOKED,        REVOKED,        CERT_REVOKED",
        "DECOMMISSIONED, DECOMMISSIONED, CERT_DECOMMISSIONED",
        "ROTATED,        SUPERSEDED,     CERT_SUPERSEDED"})
    void repeatingVerificationAndConfirmationDoesNotBringACertificateBack(
            String eventType, RegistryStatus status, String denial) throws Exception {
        IssuanceConfirmationResponse issued = verifyAndConfirm("FE-1");
        assertThat(issued.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(settle().getReason()).isEqualTo("OK");
        assertThat(event("NCA-1", "ROLE_SUPERVISOR", eventType).isApplied()).isTrue();
        assertThat(settle().getReason()).isEqualTo(denial);

        IssuanceConfirmationResponse refused = verifyAndConfirm("FE-1");

        assertThat(refused.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_CERTIFICATE_ALREADY_REGISTERED);
        assertThat(refused.isLoopClosed()).isFalse();
        assertThat(refused.getAnomalies()).singleElement().asString()
                .startsWith("ANOMALY: The submitted signing certificate is already registered");
        Signature receipt = Signature.getInstance(signer.getSignatureAlgorithm());
        receipt.initVerify(signer.getPublicKey());
        receipt.update(ConfirmationCanonicalizer.canonicalize(refused));
        assertThat(receipt.verify(Base64.getDecoder().decode(refused.getSignature())))
                .as("the refusal is signed with the receipt key").isTrue();

        AuditEntry audited = auditLog.head().orElseThrow();
        assertThat(audited.operation()).isEqualTo("CONFIRM");
        assertThat(audited.verificationId()).isEqualTo(refused.getVerificationId());
        assertThat(audited.compliant()).isFalse();
        assertThat(audited.registryStatus()).isEqualTo("ANOMALY_CERTIFICATE_ALREADY_REGISTERED");
        assertThat(audited.mtlsClientPrincipal()).isEqualTo("FE-1");
        assertThat(audited.keyFingerprintHex()).isEqualTo(Fingerprints.ofPublicKey(keyPair.getPublic()));
        assertThat(audited.certSerialHex()).isEqualTo(certificate.getSerialNumber().toString(16));
        assertThat(audited.certIssuerDn()).isEqualTo(certificate.getIssuerX500Principal().getName());

        SignatureVerificationResponse after = settle();
        assertThat(after.getReason()).isEqualTo(denial);
        assertThat(after.isCompliant()).isFalse();
        assertThat(after.getAuditEntryId()).isEqualTo(issued.getVerificationId());

        // The same after a restart: the refusal was never journalled.
        AppendOnlyFileApprovalRegistry replayed = new AppendOnlyFileApprovalRegistry(journal().toString());
        replayed.initialise();
        ApprovalRegistry.RegistryEntry holder = replayed.findByIssuedCertificate(
                certificate.getSerialNumber(), certificate.getIssuerX500Principal()).orElseThrow();
        assertThat(holder.getVerificationId()).isEqualTo(issued.getVerificationId());
        assertThat(holder.getStatus()).isEqualTo(status);
        ApprovalRegistry.RegistryEntry second = replayed.lookup(refused.getVerificationId()).orElseThrow();
        assertThat(second.getStatus()).isNull();
        assertThat(second.getIssuedCertificateSerial()).isNull();
    }

    @Test
    void aSecondClientCannotTakeACertificatesLifecycleOver() {
        IssuanceConfirmationResponse issued = verifyAndConfirm("FE-1");
        assertThat(issued.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);

        IssuanceConfirmationResponse refused = verifyAndConfirm("FE-2");
        assertThat(refused.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_CERTIFICATE_ALREADY_REGISTERED);

        // The certificate is still the first client's alone to report on.
        KeyStatusChangeResponse byTheSecond = event("FE-2", "ROLE_FE", KeyLifecycleRequest.REVOKED);
        assertThat(byTheSecond.isApplied()).isFalse();
        assertThat(byTheSecond.getReason()).isEqualTo("CERT_NOT_FOUND");
        assertThat(settle().getReason()).isEqualTo("OK");

        KeyStatusChangeResponse byTheFirst = event("FE-1", "ROLE_FE", KeyLifecycleRequest.REVOKED);
        assertThat(byTheFirst.isApplied()).isTrue();
        assertThat(byTheFirst.getVerificationId()).isEqualTo(issued.getVerificationId());
        assertThat(settle().getReason()).isEqualTo("CERT_REVOKED");
    }
}
