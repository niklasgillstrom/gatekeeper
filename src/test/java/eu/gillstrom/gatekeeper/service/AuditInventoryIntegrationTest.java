package eu.gillstrom.gatekeeper.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmation;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.KeyLifecycleRequest;
import eu.gillstrom.gatekeeper.model.KeyStatusChangeResponse;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.model.SignedEventResponse;
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

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration of the audit entry v2 inventory fields (feat-b) with the
 * firmware/FIPS fields of the verification response (feat-a) and with the
 * key-lifecycle operations (feat-c):
 * <ul>
 *   <li>{@code VERIFY} and {@code BATCH_VERIFY} carry {@code hsmFirmwareVersion}
 *       and {@code hsmFipsApprovedMode} exactly as the response reports them;</li>
 *   <li>{@code SIGNED} carries the matched row's inventory, as
 *       {@code SETTLEMENT_VERIFY} does;</li>
 *   <li>{@code ROTATED}, {@code REVOKED} and {@code DECOMMISSIONED} carry the
 *       key fingerprint, the certificate and the resulting registry status;</li>
 *   <li>{@code TRIANGULATION} carries none;</li>
 *   <li>all of one key's entries form its per-key chain, which verifies, also
 *       after a reload from disk.</li>
 * </ul>
 */
class AuditInventoryIntegrationTest {

    @TempDir
    Path tempDir;

    private KeyPair keyKp;
    private String keyFingerprint;
    private X509Certificate issuerCa;
    private KeyPair issuerKp;
    private Path auditPath;
    private Path issuerBundle;
    private EphemeralReceiptSigner signer;
    private GatekeeperKeyDirectory keyDirectory;
    private AppendOnlyFileAuditLog auditLog;
    private InMemoryApprovalRegistry registry;
    private SignatureVerificationService settlement;
    private KeyLifecycleService lifecycle;
    private final YubicoVerifier yubico = mock(YubicoVerifier.class);

    @BeforeEach
    void setUp() throws Exception {
        keyKp = TestPki.newRsaKeyPair(2048);
        keyFingerprint = Fingerprints.ofPublicKey(keyKp.getPublic());
        issuerKp = TestPki.newRsaKeyPair(2048);
        issuerCa = TestPki.selfSignedCa(issuerKp, "INVENTORY-ISSUER-CA");
        issuerBundle = tempDir.resolve("issuer-ca.pem");
        Files.writeString(issuerBundle, TestPki.toPem(issuerCa), StandardCharsets.UTF_8);

        signer = new EphemeralReceiptSigner(2048);
        keyDirectory = new GatekeeperKeyDirectory(signer, "");
        keyDirectory.initialise();
        auditPath = tempDir.resolve("audit.jsonl");
        auditLog = new AppendOnlyFileAuditLog(auditPath.toString(), signer, 0);
        auditLog.initialise();
        registry = new InMemoryApprovalRegistry();
        settlement = new SignatureVerificationService(registry, auditLog, new MtlsPrincipalResolver(), signer,
                keyDirectory);
        lifecycle = new KeyLifecycleService(settlement, registry, auditLog, new MtlsPrincipalResolver(), false);
    }

    // ------------------------------------------------------------------ helpers

    private VerificationService verification(KeyPolicy keyPolicy) {
        return new VerificationService(mock(SecurosysVerifier.class), yubico, mock(AzureHsmVerifier.class),
                mock(GoogleCloudHsmVerifier.class), mock(MarvellHsmVerifier.class), mock(ThalesLunaVerifier.class),
                mock(Crypto4AVerifier.class), mock(FortanixVerifier.class), mock(NShieldVerifier.class), registry,
                signer, new IssuerCaValidator(issuerBundle.toString()), auditLog, new MtlsPrincipalResolver(),
                keyPolicy, false);
    }

    private VerificationService verification() {
        return verification(new KeyPolicy("RSA-2048"));
    }

    private void stubYubico(boolean chainValid, String firmware, Boolean fipsApprovedMode) {
        var r = mock(YubicoVerifier.YubicoAttestationResult.class);
        when(r.isValid()).thenReturn(chainValid);
        when(r.getErrors()).thenReturn(chainValid ? List.of() : List.of("Certificate chain verification failed"));
        when(r.isPublicKeyMatch()).thenReturn(true);
        when(r.isChainValid()).thenReturn(chainValid);
        when(r.getKeyOrigin()).thenReturn("generated");
        when(r.isKeyExportable()).thenReturn(false);
        when(r.getDeviceSerial()).thenReturn("12345678");
        when(r.getFirmware()).thenReturn(firmware);
        when(r.getFipsIndicator()).thenReturn(5);
        when(r.getFipsApprovedMode()).thenReturn(fipsApprovedMode);
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

    /** Steps 2-7 for {@link #keyKp}: verify, issue a certificate under the test CA, confirm. */
    private X509Certificate issue(VerificationService verification, String cn) throws Exception {
        VerificationResponse receipt = verification.verify(request());
        assertThat(receipt.isCompliant()).isTrue();
        X509Certificate certificate = TestPki.endEntity(keyKp, cn, issuerCa, issuerKp.getPrivate());
        IssuanceConfirmation c = new IssuanceConfirmation();
        c.setVerificationId(receipt.getVerificationId());
        c.setConfirmationNonce(receipt.getConfirmationNonce());
        c.setIssued(true);
        c.setSigningCertificatePem(TestPki.toPem(certificate));
        c.setTimestamp(Instant.now().toString());
        assertThat(verification.confirmIssuance(c, "SE").getRegistryStatus())
                .isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        return certificate;
    }

    private static byte[] digest(String payload) throws Exception {
        return MessageDigest.getInstance("SHA-512").digest(payload.getBytes(StandardCharsets.UTF_8));
    }

    private String sign(byte[] digest) throws Exception {
        Signature s = Signature.getInstance("SHA512withRSA");
        s.initSign(keyKp.getPrivate());
        s.update(digest);
        return Base64.getEncoder().encodeToString(s.sign());
    }

    private SignatureVerificationResponse settle(X509Certificate certificate) throws Exception {
        byte[] d = digest("settlement");
        return settlement.verify(SignatureVerificationRequest.builder()
                .certSerial(certificate.getSerialNumber().toString(16))
                .issuerDn(certificate.getIssuerX500Principal().getName())
                .digestHex(HexFormat.of().formatHex(d))
                .signatureBase64(sign(d))
                .build());
    }

    private KeyLifecycleRequest event(String type, X509Certificate certificate) throws Exception {
        KeyLifecycleRequest r = KeyLifecycleRequest.builder()
                .eventType(type)
                .certSerial(certificate.getSerialNumber().toString(16))
                .issuerDn(certificate.getIssuerX500Principal().getName())
                .reason(KeyLifecycleRequest.SIGNED.equals(type) ? null : "reason for " + type)
                .build();
        if (KeyLifecycleRequest.SIGNED.equals(type)) {
            byte[] d = digest("signed event");
            r.setDigestHex(HexFormat.of().formatHex(d));
            r.setSignatureBase64(sign(d));
        }
        return r;
    }

    private AuditEntry last() {
        return auditLog.head().orElseThrow();
    }

    private static void assertNoInventory(AuditEntry entry) {
        assertThat(entry.canonicalVersion()).isEqualTo("v2");
        assertThat(entry.keyFingerprintHex()).isNull();
        assertThat(entry.certSerialHex()).isNull();
        assertThat(entry.certIssuerDn()).isNull();
        assertThat(entry.hsmVendor()).isNull();
        assertThat(entry.hsmSerial()).isNull();
        assertThat(entry.registryStatus()).isNull();
        assertThat(entry.hsmFirmwareVersion()).isNull();
        assertThat(entry.hsmFipsApprovedMode()).isNull();
        assertThat(entry.prevKeyEntryHashHex()).isNull();
    }

    // ------------------------------------------- task 1: firmware and FIPS state

    @Test
    void verifyEntriesCarryTheFirmwareAndTheFipsApprovedFlagAsTheResponseReportsThem() {
        VerificationService verification = verification();
        Boolean[] flags = {Boolean.TRUE, Boolean.FALSE, null};
        String[] expected = {"true", "false", null};
        for (int i = 0; i < flags.length; i++) {
            stubYubico(true, "2.2.0", flags[i]);

            VerificationResponse receipt = verification.verify(request());

            AuditEntry entry = last();
            assertThat(entry.operation()).isEqualTo("VERIFY");
            assertThat(receipt.getHsmFirmwareVersion()).isEqualTo("2.2.0");
            assertThat(receipt.getHsmFipsApprovedMode()).isEqualTo(flags[i]);
            assertThat(entry.hsmFirmwareVersion()).isEqualTo("2.2.0");
            assertThat(entry.hsmFipsApprovedMode()).as("flag " + flags[i]).isEqualTo(expected[i]);
            assertThat(entry.keyFingerprintHex()).isEqualTo(keyFingerprint);
        }
        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }

    @Test
    void batchVerifyEntriesCarryTheSameFirmwareAndFipsFields() {
        stubYubico(true, "2.4.1", Boolean.TRUE);

        verification().verifyBatch(List.of(request(), request()));

        List<AuditEntry> all = auditLog.findByPrincipal("anonymous");
        assertThat(all).hasSize(2).allSatisfy(e -> {
            assertThat(e.operation()).isEqualTo("BATCH_VERIFY");
            assertThat(e.hsmFirmwareVersion()).isEqualTo("2.4.1");
            assertThat(e.hsmFipsApprovedMode()).isEqualTo("true");
        });
        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }

    @Test
    void aChainThatDidNotValidateReportsNoFirmwareInTheResponseOrTheEntry() {
        stubYubico(false, "2.2.0", Boolean.TRUE);

        VerificationResponse receipt = verification().verify(request());

        AuditEntry entry = last();
        assertThat(receipt.isCompliant()).isFalse();
        assertThat(receipt.getHsmFirmwareVersion()).isNull();
        assertThat(entry.hsmFirmwareVersion()).isNull();
        assertThat(entry.hsmFipsApprovedMode()).isNull();
    }

    @Test
    void aNonCompliantResultFromAValidatedChainStillRecordsWhatTheAttestationStates() {
        // Requiring FIPS-approved mode makes an attestation stating "false"
        // non-compliant; the response still reports the attested values, and
        // so does the audit entry, while the HSM identity stays off both.
        stubYubico(true, "2.2.0", Boolean.FALSE);

        VerificationResponse receipt = verification(new KeyPolicy("RSA-2048", true)).verify(request());

        AuditEntry entry = last();
        assertThat(receipt.isCompliant()).isFalse();
        assertThat(receipt.getErrors()).anyMatch(e -> e.startsWith(KeyPolicy.FIPS_APPROVED_MODE_NOT_ATTESTED));
        assertThat(entry.hsmFirmwareVersion()).isEqualTo("2.2.0");
        assertThat(entry.hsmFipsApprovedMode()).isEqualTo("false");
        assertThat(entry.hsmVendor()).isNull();
        assertThat(entry.compliant()).isFalse();
    }

    @Test
    void theGenuineYubiHsm2AttestationRecordsItsFirmwareAndNoFipsFlagAndSecurosysRecordsNeither() throws Exception {
        VerificationService real = new VerificationService(new SecurosysVerifier(), new YubicoVerifier(),
                mock(AzureHsmVerifier.class), mock(GoogleCloudHsmVerifier.class), mock(MarvellHsmVerifier.class),
                new ThalesLunaVerifier(), new Crypto4AVerifier(), new FortanixVerifier(), new NShieldVerifier(),
                registry, signer, mock(IssuerCaValidator.class), auditLog, new MtlsPrincipalResolver(),
                KeyPolicy.defaults(), false);

        VerificationResponse yubicoReceipt = real.verify(fixtureRequest("yubico"));
        AuditEntry yubicoEntry = last();
        VerificationResponse securosysReceipt = real.verify(fixtureRequest("securosys"));
        AuditEntry securosysEntry = last();

        assertThat(yubicoReceipt.isCompliant()).isTrue();
        assertThat(yubicoEntry.hsmFirmwareVersion()).isEqualTo("2.2.0");
        assertThat(yubicoEntry.hsmFipsApprovedMode()).as("41482.4.12 is on neither certificate").isNull();
        assertThat(securosysReceipt.isCompliant()).isTrue();
        assertThat(securosysEntry.hsmFirmwareVersion()).isNull();
        assertThat(securosysEntry.hsmFipsApprovedMode()).isNull();
        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }

    private static VerificationRequest fixtureRequest(String vendor) throws Exception {
        JsonNode fixture;
        try (InputStream in = AuditInventoryIntegrationTest.class
                .getResourceAsStream("/fixtures/" + vendor + "/request.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        List<String> chain = new ArrayList<>();
        for (JsonNode pem : fixture.get("attestationCertChain")) {
            chain.add(pem.asText());
        }
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey(fixture.get("csr").asText());
        request.setHsmVendor(vendor.toUpperCase());
        request.setAttestationCertChain(chain);
        if (fixture.has("attestationData")) {
            request.setAttestationData(fixture.get("attestationData").asText());
            request.setAttestationSignature(fixture.get("attestationSignature").asText());
        }
        request.setSupplierIdentifier("556000-0000");
        request.setSupplierName("Svensk TL");
        request.setCountryCode("SE");
        return request;
    }

    // -------------------------------------------- task 2: lifecycle operations

    @Test
    void theWholeLifecycleOfOneKeyCarriesItsInventoryAndFormsOnePerKeyChain() throws Exception {
        stubYubico(true, "2.2.0", Boolean.TRUE);
        VerificationService verification = verification();
        X509Certificate first = issue(verification, "LIFECYCLE-1");
        AuditEntry confirm = last();
        String serial = first.getSerialNumber().toString(16);
        String issuer = first.getIssuerX500Principal().getName();

        // Settlement (rail-reported) and SIGNED (organisation-reported) carry the same inventory.
        assertThat(settle(first).getReason()).isEqualTo("OK");
        AuditEntry settled = last();
        SignedEventResponse signedResponse = lifecycle.signed("SE", event(KeyLifecycleRequest.SIGNED, first));
        assertThat(signedResponse.getVerdict().getReason()).isEqualTo("OK");
        AuditEntry signed = last();
        assertThat(signed.operation()).isEqualTo("SIGNED");
        assertThat(signed.thisEntryHashHex()).isEqualTo(signedResponse.getVerdict().getAuditEntryHashHex());
        assertThat(signed.keyFingerprintHex()).isEqualTo(keyFingerprint).isEqualTo(settled.keyFingerprintHex());
        assertThat(signed.certSerialHex()).isEqualTo(serial).isEqualTo(settled.certSerialHex());
        assertThat(signed.certIssuerDn()).isEqualTo(issuer).isEqualTo(settled.certIssuerDn());
        assertThat(signed.registryStatus()).isEqualTo("VERIFIED_AND_ISSUED").isEqualTo(settled.registryStatus());
        assertThat(signed.hsmVendor()).isNull();
        assertThat(signed.hsmFirmwareVersion()).isNull();
        assertThat(signed.prevKeyEntryHashHex()).isEqualTo(settled.thisEntryHashHex());
        assertThat(settled.prevKeyEntryHashHex()).isEqualTo(confirm.thisEntryHashHex());

        // ROTATED, then REVOKED: key, certificate and the resulting status.
        KeyStatusChangeResponse rotatedResponse = lifecycle.changeStatus("SE",
                event(KeyLifecycleRequest.ROTATED, first));
        assertThat(rotatedResponse.isApplied()).isTrue();
        AuditEntry rotated = last();
        KeyStatusChangeResponse revokedResponse = lifecycle.changeStatus("SE",
                event(KeyLifecycleRequest.REVOKED, first));
        assertThat(revokedResponse.isApplied()).isTrue();
        AuditEntry revoked = last();
        for (AuditEntry e : List.of(rotated, revoked)) {
            assertThat(e.keyFingerprintHex()).isEqualTo(keyFingerprint);
            assertThat(e.certSerialHex()).isEqualTo(serial);
            assertThat(e.certIssuerDn()).isEqualTo(issuer);
            assertThat(e.hsmVendor()).isNull();
            assertThat(e.hsmSerial()).isNull();
            assertThat(e.hsmFirmwareVersion()).isNull();
            assertThat(e.hsmFipsApprovedMode()).isNull();
            assertThat(e.compliant()).isTrue();
        }
        assertThat(rotated.operation()).isEqualTo("ROTATED");
        assertThat(rotated.registryStatus()).isEqualTo("SUPERSEDED");
        assertThat(rotated.thisEntryHashHex()).isEqualTo(rotatedResponse.getAuditEntryHashHex());
        assertThat(rotated.prevKeyEntryHashHex()).isEqualTo(signed.thisEntryHashHex());
        assertThat(revoked.operation()).isEqualTo("REVOKED");
        assertThat(revoked.registryStatus()).isEqualTo("REVOKED");
        assertThat(revoked.prevKeyEntryHashHex()).isEqualTo(rotated.thisEntryHashHex());

        // A refused change is recorded with the status the entry keeps.
        KeyStatusChangeResponse refusedResponse = lifecycle.changeStatus("SE",
                event(KeyLifecycleRequest.DECOMMISSIONED, first));
        assertThat(refusedResponse.getReason()).isEqualTo("TRANSITION_NOT_ALLOWED");
        AuditEntry refused = last();
        assertThat(refused.operation()).isEqualTo("DECOMMISSIONED");
        assertThat(refused.compliant()).isFalse();
        assertThat(refused.keyFingerprintHex()).isEqualTo(keyFingerprint);
        assertThat(refused.certSerialHex()).isEqualTo(serial);
        assertThat(refused.registryStatus()).isEqualTo("REVOKED");
        assertThat(refused.prevKeyEntryHashHex()).isEqualTo(revoked.thisEntryHashHex());

        // The revoked certificate no longer settles; the denial joins the chain.
        assertThat(settle(first).getReason()).isEqualTo("CERT_REVOKED");
        AuditEntry denied = last();
        assertThat(denied.registryStatus()).isEqualTo("REVOKED");
        assertThat(denied.prevKeyEntryHashHex()).isEqualTo(refused.thisEntryHashHex());

        // A second certificate for the same key, decommissioned: same per-key chain.
        X509Certificate second = issue(verification, "LIFECYCLE-2");
        KeyStatusChangeResponse decommissionedResponse = lifecycle.changeStatus("SE",
                event(KeyLifecycleRequest.DECOMMISSIONED, second));
        assertThat(decommissionedResponse.isApplied()).isTrue();
        AuditEntry decommissioned = last();
        assertThat(decommissioned.registryStatus()).isEqualTo("DECOMMISSIONED");
        assertThat(decommissioned.certSerialHex()).isEqualTo(second.getSerialNumber().toString(16));
        assertThat(decommissioned.keyFingerprintHex()).isEqualTo(keyFingerprint);

        // Every entry of the key, in order, links to the one before it.
        List<AuditEntry> ofKey = auditLog.findByPrincipal("anonymous").stream()
                .filter(e -> keyFingerprint.equals(e.keyFingerprintHex()))
                .toList();
        assertThat(ofKey).extracting(AuditEntry::operation).containsExactly(
                "VERIFY", "CONFIRM", "SETTLEMENT_VERIFY", "SIGNED", "ROTATED", "REVOKED", "DECOMMISSIONED",
                "SETTLEMENT_VERIFY", "VERIFY", "CONFIRM", "DECOMMISSIONED");
        assertThat(ofKey.get(0).prevKeyEntryHashHex()).isEqualTo(AuditEntry.SENTINEL_PREV_HASH_HEX);
        for (int i = 1; i < ofKey.size(); i++) {
            assertThat(ofKey.get(i).prevKeyEntryHashHex()).as("per-key link of entry " + i)
                    .isEqualTo(ofKey.get(i - 1).thisEntryHashHex());
        }
        assertThat(auditLog.verifyChainIntegrity()).isTrue();

        // The same holds after a reload from disk, and the per-key index is rebuilt.
        AppendOnlyFileAuditLog reloaded = new AppendOnlyFileAuditLog(auditPath.toString(), signer, 0);
        reloaded.initialise();
        assertThat(reloaded.verifyChainIntegrity()).isTrue();
        assertThat(reloaded.lastEntryHashForKey(keyFingerprint))
                .contains(decommissioned.thisEntryHashHex());
    }

    @Test
    void changingAnInventoryFieldOfALifecycleEntryBreaksTheChain() throws Exception {
        stubYubico(true, "2.2.0", null);
        X509Certificate certificate = issue(verification(), "TAMPER");
        lifecycle.changeStatus("SE", event(KeyLifecycleRequest.REVOKED, certificate));
        assertThat(auditLog.verifyChainIntegrity()).isTrue();

        List<String> lines = new ArrayList<>(Files.readAllLines(auditPath, StandardCharsets.UTF_8));
        String revokedLine = lines.get(lines.size() - 1);
        assertThat(revokedLine).contains("\"operation\":\"REVOKED\"").contains("\"registryStatus\":\"REVOKED\"");
        lines.set(lines.size() - 1, revokedLine.replace("\"registryStatus\":\"REVOKED\"",
                "\"registryStatus\":\"VERIFIED_AND_ISSUED\""));
        Files.write(auditPath, lines, StandardCharsets.UTF_8);

        AppendOnlyFileAuditLog reloaded = new AppendOnlyFileAuditLog(auditPath.toString(), signer, 0);
        reloaded.initialise();
        assertThat(reloaded.verifyChainIntegrity()).isFalse();
    }

    @Test
    void lifecycleEventsThatResolveToNoRegistryEntryCarryNoInventory() throws Exception {
        X509Certificate unknown = TestPki.endEntity(keyKp, "NEVER-ISSUED", issuerCa, issuerKp.getPrivate());

        SignedEventResponse signed = lifecycle.signed("SE", event(KeyLifecycleRequest.SIGNED, unknown));
        assertThat(signed.getVerdict().getReason()).isEqualTo("CERT_NOT_FOUND");
        assertThat(last().operation()).isEqualTo("SIGNED");
        assertThat(last().verificationId()).isEqualTo(SignatureVerificationService.NO_REGISTRY_MATCH);
        assertNoInventory(last());

        for (String type : List.of(KeyLifecycleRequest.ROTATED, KeyLifecycleRequest.REVOKED,
                KeyLifecycleRequest.DECOMMISSIONED)) {
            KeyStatusChangeResponse notFound = lifecycle.changeStatus("SE", event(type, unknown));
            assertThat(notFound.getReason()).isEqualTo("CERT_NOT_FOUND");
            assertThat(last().operation()).isEqualTo(type);
            assertNoInventory(last());
        }

        KeyLifecycleRequest malformed = event(KeyLifecycleRequest.REVOKED, unknown);
        malformed.setIssuerDn("this is not a distinguished name");
        assertThat(lifecycle.changeStatus("SE", malformed).getReason()).isEqualTo("MALFORMED_INPUT");
        assertNoInventory(last());

        // Another jurisdiction is not found either, even for an issued certificate.
        stubYubico(true, null, null);
        X509Certificate issued = issue(verification(), "OTHER-JURISDICTION");
        assertThat(lifecycle.changeStatus("NO", event(KeyLifecycleRequest.REVOKED, issued)).getReason())
                .isEqualTo("CERT_NOT_FOUND");
        assertNoInventory(last());
        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }

    @Test
    void aTriangulationReportCarriesNoInventory() throws Exception {
        stubYubico(true, null, null);
        issue(verification(), "TRIANGULATED");
        TriangulationService triangulation = new TriangulationService(registry, auditLog,
                new MtlsPrincipalResolver(), signer, keyDirectory, 10, 100000);
        String inquiryId = triangulation.createInquiry("SE").inquiryId();

        var report = triangulation.discrepancies("SE", inquiryId);

        AuditEntry entry = last();
        assertThat(entry.operation()).isEqualTo("TRIANGULATION");
        assertThat(entry.verificationId()).isEqualTo(inquiryId);
        assertThat(entry.thisEntryHashHex()).isEqualTo(report.auditEntryHashHex());
        assertNoInventory(entry);
        assertThat(Arrays.asList(entry.keyFingerprintHex(), entry.registryStatus())).containsOnlyNulls();
        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }
}
