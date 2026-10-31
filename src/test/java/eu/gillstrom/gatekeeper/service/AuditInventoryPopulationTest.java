package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmation;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.model.VerificationRequest;
import eu.gillstrom.gatekeeper.model.VerificationResponse;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Which inventory fields each audited operation records (audit entry v2),
 * and that the issuance and settlement events of one key form that key's
 * per-key chain: VERIFY → CONFIRM → SETTLEMENT_VERIFY.
 */
class AuditInventoryPopulationTest {

    @TempDir
    Path tempDir;

    private KeyPair keyKp;
    private String keyFingerprint;
    private X509Certificate issuerCa;
    private KeyPair issuerKp;
    private X509Certificate issued;
    private AppendOnlyFileAuditLog auditLog;
    private InMemoryApprovalRegistry registry;
    private VerificationService verification;
    private SignatureVerificationService settlement;
    private final YubicoVerifier yubico = mock(YubicoVerifier.class);

    @BeforeEach
    void setUp() throws Exception {
        keyKp = TestPki.newRsaKeyPair(2048);
        keyFingerprint = Fingerprints.ofPublicKey(keyKp.getPublic());
        issuerKp = TestPki.newRsaKeyPair(2048);
        issuerCa = TestPki.selfSignedCa(issuerKp, "TEST-ISSUER-CA");
        issued = TestPki.endEntity(keyKp, "TEST-SIGNING-CERT", issuerCa, issuerKp.getPrivate());
        Path bundle = tempDir.resolve("issuer-ca.pem");
        Files.writeString(bundle, TestPki.toPem(issuerCa), StandardCharsets.UTF_8);

        auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(),
                new EphemeralReceiptSigner(2048), 0);
        auditLog.initialise();
        registry = new InMemoryApprovalRegistry();
        verification = new VerificationService(mock(SecurosysVerifier.class), yubico, mock(AzureHsmVerifier.class),
                mock(GoogleCloudHsmVerifier.class), mock(MarvellHsmVerifier.class), mock(ThalesLunaVerifier.class),
                mock(Crypto4AVerifier.class), mock(FortanixVerifier.class), mock(NShieldVerifier.class), registry,
                new EphemeralReceiptSigner(2048), new IssuerCaValidator(bundle.toString()), auditLog,
                new MtlsPrincipalResolver(), new KeyPolicy("RSA-2048"), false);
        settlement = new SignatureVerificationService(registry, auditLog, new MtlsPrincipalResolver());
    }

    private void stubYubico(boolean valid) {
        var r = mock(YubicoVerifier.YubicoAttestationResult.class);
        when(r.isValid()).thenReturn(valid);
        when(r.getErrors()).thenReturn(valid ? List.of() : List.of("Certificate chain verification failed"));
        when(r.isPublicKeyMatch()).thenReturn(true);
        when(r.isChainValid()).thenReturn(valid);
        when(r.getKeyOrigin()).thenReturn("generated");
        when(r.isKeyExportable()).thenReturn(false);
        when(r.getDeviceSerial()).thenReturn("12345678");
        when(yubico.verifyYubicoAttestation(any(), any())).thenReturn(r);
    }

    private VerificationRequest request() {
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey("-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(keyKp.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----");
        request.setHsmVendor("YUBICO");
        request.setAttestationCertChain(List.of("-----BEGIN CERTIFICATE-----"));
        request.setCountryCode("SE");
        return request;
    }

    private IssuanceConfirmation confirmation(VerificationResponse receipt, X509Certificate certificate)
            throws Exception {
        IssuanceConfirmation c = new IssuanceConfirmation();
        c.setVerificationId(receipt.getVerificationId());
        c.setConfirmationNonce(receipt.getConfirmationNonce());
        c.setIssued(true);
        c.setSigningCertificatePem(TestPki.toPem(certificate));
        c.setTimestamp(Instant.now().toString());
        return c;
    }

    private SignatureVerificationRequest settlementRequest(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest("payout".getBytes(StandardCharsets.UTF_8));
        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initSign(keyKp.getPrivate());
        sig.update(digest);
        return SignatureVerificationRequest.builder()
                .certSerial(certificate.getSerialNumber().toString(16))
                .issuerDn(certificate.getIssuerX500Principal().getName())
                .digestHex(HexFormat.of().formatHex(digest))
                .signatureBase64(Base64.getEncoder().encodeToString(sig.sign()))
                .build();
    }

    private AuditEntry last() {
        return auditLog.head().orElseThrow();
    }

    @Test
    void theIssuanceAndSettlementEventsOfOneKeyCarryItsInventoryAndFormItsPerKeyChain() throws Exception {
        stubYubico(true);

        VerificationResponse receipt = verification.verify(request());
        AuditEntry verify = last();
        assertThat(verify.operation()).isEqualTo("VERIFY");
        assertThat(verify.keyFingerprintHex()).isEqualTo(keyFingerprint).isEqualTo(receipt.getPublicKeyFingerprint());
        assertThat(verify.hsmVendor()).isEqualTo("Yubico").isEqualTo(receipt.getHsmVendor());
        assertThat(verify.hsmSerial()).isEqualTo("12345678");
        assertThat(verify.certSerialHex()).isNull();
        assertThat(verify.registryStatus()).isNull();
        // Populated from the verification response (integration of feat-a and
        // feat-b). The mocked result stubs no firmware (null) and leaves the
        // Boolean FIPS flag unstubbed, which Mockito answers with false; the
        // chain is valid, so the response reports both and the entry mirrors it.
        assertThat(verify.hsmFirmwareVersion()).as("as on the response")
                .isEqualTo(receipt.getHsmFirmwareVersion()).isNull();
        assertThat(receipt.getHsmFipsApprovedMode()).isFalse();
        assertThat(verify.hsmFipsApprovedMode()).as("as on the response").isEqualTo("false");
        assertThat(verify.prevKeyEntryHashHex()).isEqualTo(AuditEntry.SENTINEL_PREV_HASH_HEX);

        IssuanceConfirmationResponse confirmed = verification.confirmIssuance(confirmation(receipt, issued), "SE");
        assertThat(confirmed.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        AuditEntry confirm = last();
        assertThat(confirm.operation()).isEqualTo("CONFIRM");
        assertThat(confirm.keyFingerprintHex()).isEqualTo(keyFingerprint);
        assertThat(confirm.certSerialHex()).isEqualTo(issued.getSerialNumber().toString(16));
        assertThat(confirm.certIssuerDn()).isEqualTo(issued.getIssuerX500Principal().getName());
        assertThat(confirm.registryStatus()).isEqualTo("VERIFIED_AND_ISSUED");
        assertThat(confirm.hsmVendor()).isNull();
        assertThat(confirm.prevKeyEntryHashHex()).isEqualTo(verify.thisEntryHashHex());

        SignatureVerificationResponse settled = settlement.verify(settlementRequest(issued));
        assertThat(settled.isCompliant()).isTrue();
        AuditEntry settle = last();
        assertThat(settle.operation()).isEqualTo("SETTLEMENT_VERIFY");
        assertThat(settle.keyFingerprintHex()).isEqualTo(keyFingerprint);
        assertThat(settle.certSerialHex()).isEqualTo(issued.getSerialNumber().toString(16));
        assertThat(settle.certIssuerDn()).isEqualTo(issued.getIssuerX500Principal().getName());
        assertThat(settle.registryStatus()).isEqualTo("VERIFIED_AND_ISSUED");
        assertThat(settle.prevKeyEntryHashHex()).isEqualTo(confirm.thisEntryHashHex());

        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }

    @Test
    void aNonCompliantVerifyRecordsTheKeyButNotTheUnverifiedHsmIdentity() {
        stubYubico(false);

        VerificationResponse receipt = verification.verify(request());

        AuditEntry entry = last();
        assertThat(receipt.isCompliant()).isFalse();
        assertThat(entry.keyFingerprintHex()).isEqualTo(keyFingerprint);
        assertThat(entry.hsmVendor()).as("as on the receipt").isNull();
        assertThat(entry.hsmSerial()).as("as on the receipt").isNull();
    }

    @Test
    void batchEntriesCarryTheSameInventoryAsSingleOnes() {
        stubYubico(true);

        verification.verifyBatch(List.of(request(), request()));

        List<AuditEntry> all = auditLog.findByPrincipal("anonymous");
        assertThat(all).hasSize(2).allSatisfy(e -> {
            assertThat(e.operation()).isEqualTo("BATCH_VERIFY");
            assertThat(e.keyFingerprintHex()).isEqualTo(keyFingerprint);
            assertThat(e.hsmVendor()).isEqualTo("Yubico");
            assertThat(e.hsmSerial()).isEqualTo("12345678");
        });
        assertThat(all.get(1).prevKeyEntryHashHex()).isEqualTo(all.get(0).thisEntryHashHex());
    }

    @Test
    void aConfirmationWhoseCertificateHasAnotherKeyRecordsTheAttestedKeyTheCertificateAndTheAnomaly()
            throws Exception {
        stubYubico(true);
        VerificationResponse receipt = verification.verify(request());
        X509Certificate otherKeyCert = TestPki.endEntity(TestPki.newRsaKeyPair(2048), "OTHER", issuerCa,
                issuerKp.getPrivate());

        verification.confirmIssuance(confirmation(receipt, otherKeyCert), "SE");

        AuditEntry confirm = last();
        assertThat(confirm.keyFingerprintHex()).as("the attested key of the registry entry").isEqualTo(keyFingerprint);
        assertThat(confirm.certSerialHex()).isEqualTo(otherKeyCert.getSerialNumber().toString(16));
        assertThat(confirm.registryStatus()).isEqualTo("ANOMALY_PUBLIC_KEY_MISMATCH");
    }

    @Test
    void aConfirmationForAnUnknownVerificationRecordsOnlyTheStatus() throws Exception {
        VerificationResponse unknown = VerificationResponse.builder().verificationId("no-such-id")
                .confirmationNonce("n").build();

        verification.confirmIssuance(confirmation(unknown, issued), "SE");

        AuditEntry confirm = last();
        assertThat(confirm.registryStatus()).isEqualTo("ANOMALY_UNKNOWN_VERIFICATION");
        assertThat(confirm.keyFingerprintHex()).isNull();
        assertThat(confirm.certSerialHex()).isNull();
        assertThat(confirm.prevKeyEntryHashHex()).isNull();
    }

    @Test
    void aSettlementWithoutARegistryMatchRecordsNoInventory() throws Exception {
        settlement.verify(settlementRequest(issued));

        AuditEntry settle = last();
        assertThat(settle.verificationId()).isEqualTo(SignatureVerificationService.NO_REGISTRY_MATCH);
        assertThat(settle.keyFingerprintHex()).isNull();
        assertThat(settle.certSerialHex()).isNull();
        assertThat(settle.registryStatus()).isNull();
        assertThat(settle.prevKeyEntryHashHex()).isNull();
        assertThat(settle.canonicalVersion()).isEqualTo("v2");
    }
}
