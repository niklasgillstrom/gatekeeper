package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.BatchVerificationResponse;
import eu.gillstrom.gatekeeper.model.VerificationRequest;
import eu.gillstrom.gatekeeper.model.VerificationResponse;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.verification.AzureHsmVerifier;
import eu.gillstrom.gatekeeper.verification.Crypto4AVerifier;
import eu.gillstrom.gatekeeper.verification.FortanixVerifier;
import eu.gillstrom.gatekeeper.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.gatekeeper.verification.MarvellHsmVerifier;
import eu.gillstrom.gatekeeper.verification.NShieldVerifier;
import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.ThalesLunaVerifier;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * How {@link VerificationService} turns each vendor verifier's result into a
 * receipt. The verifiers are mocks: what is tested here is the dispatch, the
 * required inputs per vendor, the compliance conjunction, the warnings and
 * the batch arithmetic, not the vendor parsing.
 */
class VerificationServiceDispatchTest {

    private static String publicKeyPem;

    @TempDir
    Path tempDir;

    private final SecurosysVerifier securosys = mock(SecurosysVerifier.class);
    private final YubicoVerifier yubico = mock(YubicoVerifier.class);
    private final AzureHsmVerifier azure = mock(AzureHsmVerifier.class);
    private final GoogleCloudHsmVerifier google = mock(GoogleCloudHsmVerifier.class);
    private final MarvellHsmVerifier marvell = mock(MarvellHsmVerifier.class);
    private final ThalesLunaVerifier thales = mock(ThalesLunaVerifier.class);
    private final Crypto4AVerifier crypto4a = mock(Crypto4AVerifier.class);
    private final FortanixVerifier fortanix = mock(FortanixVerifier.class);
    private final NShieldVerifier nshield = mock(NShieldVerifier.class);
    private AppendOnlyFileAuditLog auditLog;
    private VerificationService service;

    @BeforeAll
    static void key() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        publicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----";
    }

    @BeforeEach
    void setUp() throws Exception {
        auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(),
                new EphemeralReceiptSigner(2048));
        auditLog.initialise();
        service = new VerificationService(securosys, yubico, azure, google, marvell, thales, crypto4a,
                fortanix, nshield, new InMemoryApprovalRegistry(), new EphemeralReceiptSigner(2048),
                mock(IssuerCaValidator.class), auditLog, new MtlsPrincipalResolver(), KeyPolicy.defaults(),
                false);
    }

    private static VerificationRequest request(String vendor, String attestationData, List<String> chain) {
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey(publicKeyPem);
        request.setHsmVendor(vendor);
        request.setAttestationData(attestationData);
        request.setAttestationCertChain(chain);
        request.setSupplierIdentifier("5569743098");
        request.setSupplierName("Supplier AB");
        request.setCountryCode("SE");
        return request;
    }

    private static VerificationRequest request(String vendor) {
        return request(vendor, "data", List.of("-----BEGIN CERTIFICATE-----"));
    }

    /** What a verifier reports, in the terms every result class shares. */
    private record Outcome(boolean valid, boolean match, boolean chain, boolean signature, boolean generated,
                           boolean exportable, String serial, List<String> errors) {
        static Outcome good(String serial) {
            return new Outcome(true, true, true, true, true, false, serial, List.of());
        }
    }

    private void stub(String vendor, Outcome o) {
        String origin = o.generated() ? "generated" : "imported";
        switch (vendor) {
            case "YUBICO" -> {
                var r = mock(YubicoVerifier.YubicoAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain() && o.signature());
                when(r.getKeyOrigin()).thenReturn(origin);
                when(r.isKeyExportable()).thenReturn(o.exportable());
                when(r.getDeviceSerial()).thenReturn(o.serial());
                when(yubico.verifyYubicoAttestation(any(), any())).thenReturn(r);
            }
            case "AZURE" -> {
                var r = mock(AzureHsmVerifier.AzureAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.isSignatureValid()).thenReturn(o.signature());
                when(r.getKeyOrigin()).thenReturn(origin);
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getHsmPool()).thenReturn(o.serial());
                when(azure.verifyAzureAttestation(any(), any())).thenReturn(r);
            }
            case "GOOGLE" -> {
                var r = mock(GoogleCloudHsmVerifier.GoogleAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.isSignatureValid()).thenReturn(o.signature());
                when(r.getKeyOrigin()).thenReturn(origin);
                when(r.isExtractable()).thenReturn(o.exportable());
                when(r.getKeyId()).thenReturn(o.serial());
                when(google.verifyGoogleAttestation(any(), any(), any())).thenReturn(r);
            }
            case "MARVELL" -> {
                var r = mock(MarvellHsmVerifier.MarvellAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.isSignatureValid()).thenReturn(o.signature());
                when(r.getKeyOrigin()).thenReturn(origin);
                when(r.isExtractable()).thenReturn(o.exportable());
                when(r.getPartitionSerial()).thenReturn(o.serial());
                when(marvell.verifyMarvellAttestation(any(), any(), any())).thenReturn(r);
            }
            case "THALES" -> {
                var r = mock(ThalesLunaVerifier.ThalesLunaResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain() && o.signature());
                when(r.getKeyOrigin()).thenReturn(origin);
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getHsmSerial()).thenReturn(o.serial());
                when(thales.verifyLunaAttestation(any(), any())).thenReturn(r);
            }
            case "CRYPTO4A" -> {
                var r = mock(Crypto4AVerifier.Crypto4AResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.isSignatureValid()).thenReturn(o.signature());
                when(r.getKeyOrigin()).thenReturn(origin);
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getHsmSerial()).thenReturn(o.serial());
                when(crypto4a.verifyCrypto4AAttestation(any(), any())).thenReturn(r);
            }
            case "FORTANIX" -> {
                var r = mock(FortanixVerifier.FortanixResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.isSignatureValid()).thenReturn(o.signature());
                when(r.getKeyOrigin()).thenReturn(origin);
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getKeyId()).thenReturn(o.serial());
                when(fortanix.verifyFortanixAttestation(any(), any())).thenReturn(r);
            }
            case "ENTRUST" -> {
                var r = mock(NShieldVerifier.NShieldResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain() && o.signature());
                when(r.getKeyOrigin()).thenReturn(origin);
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getEsn()).thenReturn(o.serial());
                when(nshield.verifyNShieldAttestation(any(), any())).thenReturn(r);
            }
            default -> throw new IllegalArgumentException(vendor);
        }
    }

    private void noVerifierCalled() {
        verifyNoInteractions(securosys, yubico, azure, google, marvell, thales, crypto4a, fortanix, nshield);
    }

    @ParameterizedTest
    @ValueSource(strings = {"AZURE", "GOOGLE", "MARVELL", "THALES", "CRYPTO4A", "FORTANIX", "ENTRUST"})
    void withoutAttestationDataTheVerifierIsNotCalled(String vendor) {
        for (String data : new String[] {null, " "}) {
            VerificationResponse receipt = service.verify(request(vendor, data, List.of()));
            assertThat(receipt.isCompliant()).as(vendor).isFalse();
            assertThat(receipt.getErrors()).as(vendor).singleElement().asString()
                    .startsWith("attestationData").contains("is required");
        }
        noVerifierCalled();
    }

    @Test
    void withoutACertificateChainYubicoIsNotCalled() {
        for (List<String> chain : java.util.Arrays.asList(null, List.<String>of())) {
            VerificationResponse receipt = service.verify(request("YUBICO", null, chain));
            assertThat(receipt.isCompliant()).isFalse();
            assertThat(receipt.getErrors()).containsExactly("attestationCertChain is required for Yubico verification");
        }
        noVerifierCalled();
    }

    @ParameterizedTest
    @ValueSource(strings = {"YUBICO", "AZURE", "GOOGLE", "MARVELL", "THALES", "CRYPTO4A", "FORTANIX", "ENTRUST"})
    void aCleanResultIsCompliantAndCarriesTheModelAndSerial(String vendor) {
        stub(vendor, Outcome.good("SERIAL-" + vendor));

        VerificationResponse receipt = service.verify(request(vendor));

        assertThat(receipt.getErrors()).isEmpty();
        assertThat(receipt.getWarnings()).isEmpty();
        assertThat(receipt.isCompliant()).isTrue();
        assertThat(receipt.getHsmSerialNumber()).isEqualTo("SERIAL-" + vendor);
        assertThat(receipt.getHsmModel()).isNotBlank();
        assertThat(receipt.getKeyProperties().isGeneratedOnDevice()).isTrue();
        assertThat(receipt.getKeyProperties().isExportable()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"YUBICO", "AZURE", "GOOGLE", "MARVELL", "THALES", "CRYPTO4A", "FORTANIX", "ENTRUST"})
    void aRefusingVerifierHasItsErrorsReportedAndNoDeviceNamed(String vendor) {
        stub(vendor, new Outcome(false, true, true, true, true, false, "SERIAL", List.of("refused by " + vendor)));

        VerificationResponse receipt = service.verify(request(vendor));

        assertThat(receipt.getErrors()).containsExactly("refused by " + vendor);
        assertThat(receipt.isCompliant()).isFalse();
        assertThat(receipt.getHsmVendor()).isNull();
        assertThat(receipt.getHsmModel()).isNull();
        assertThat(receipt.getHsmSerialNumber()).isNull();
    }

    @Test
    void anExportableKeyWithAValidAttestationIsWarnedAboutAndNotCompliant() {
        String exportableWarning = "CRITICAL: Key is marked as exportable";
        stub("CRYPTO4A", new Outcome(true, true, true, true, true, true, "S", List.of()));
        VerificationResponse receipt = service.verify(request("CRYPTO4A"));
        assertThat(receipt.isCompliant()).isFalse();
        assertThat(receipt.getWarnings()).singleElement().asString().startsWith(exportableWarning);

        // Without a valid chain, or without a valid signature, there is nothing to warn about.
        stub("CRYPTO4A", new Outcome(true, true, false, true, true, true, "S", List.of()));
        assertThat(service.verify(request("CRYPTO4A")).getWarnings()).isEmpty();
        stub("CRYPTO4A", new Outcome(true, true, true, false, true, true, "S", List.of()));
        assertThat(service.verify(request("CRYPTO4A")).getWarnings()).isEmpty();
    }

    @Test
    void anImportedKeyWithAValidAttestationIsWarnedAboutAndNotCompliant() {
        String importedWarning = "Key was imported into HSM, not generated on-device.";
        stub("CRYPTO4A", new Outcome(true, true, true, true, false, false, "S", List.of()));
        VerificationResponse receipt = service.verify(request("CRYPTO4A"));
        assertThat(receipt.isCompliant()).isFalse();
        assertThat(receipt.getWarnings()).singleElement().asString().startsWith(importedWarning);

        stub("CRYPTO4A", new Outcome(true, true, false, true, false, false, "S", List.of()));
        assertThat(service.verify(request("CRYPTO4A")).getWarnings()).isEmpty();
        stub("CRYPTO4A", new Outcome(true, true, true, false, false, false, "S", List.of()));
        assertThat(service.verify(request("CRYPTO4A")).getWarnings()).isEmpty();
    }

    @Test
    void aBatchCountsCompliantAndNonCompliantResults() {
        stub("CRYPTO4A", Outcome.good("S"));
        BatchVerificationResponse batch = service.verifyBatch(List.of(
                request("CRYPTO4A"), request("NO-SUCH-VENDOR"), request("CRYPTO4A", null, List.of())));

        assertThat(batch.getTotalEntities()).isEqualTo(3);
        assertThat(batch.getCompliantCount()).isEqualTo(1);
        assertThat(batch.getNonCompliantCount()).isEqualTo(2);
        assertThat(batch.getComplianceRate()).isCloseTo(100.0 / 3, org.assertj.core.data.Offset.offset(1e-9));
        assertThat(batch.getResults()).extracting(VerificationResponse::isCompliant)
                .containsExactly(true, false, false);
        for (VerificationResponse result : batch.getResults()) {
            Optional<AuditEntry> entry = auditLog.findByVerificationId(result.getVerificationId());
            assertThat(entry).get().extracting(AuditEntry::operation).isEqualTo("BATCH_VERIFY");
        }

        BatchVerificationResponse empty = service.verifyBatch(List.of());
        assertThat(empty.getTotalEntities()).isZero();
        assertThat(empty.getComplianceRate()).isZero();
    }

    @Test
    void anUnreadableKeyOrAnUnknownVendorIsASignedAuditedRefusal() {
        VerificationRequest badKey = request("CRYPTO4A");
        badKey.setPublicKey("not a key");
        VerificationRequest badVendor = request("NO-SUCH-VENDOR");

        VerificationResponse keyReceipt = service.verify(badKey);
        VerificationResponse vendorReceipt = service.verify(badVendor);

        assertThat(keyReceipt.getErrors()).singleElement().asString().startsWith("Invalid public key: ");
        assertThat(vendorReceipt.getErrors()).singleElement().asString()
                .startsWith("Unsupported or invalid HSM vendor: NO-SUCH-VENDOR");
        for (VerificationResponse receipt : List.of(keyReceipt, vendorReceipt)) {
            assertThat(receipt.isCompliant()).isFalse();
            assertThat(receipt.getSignature()).isNotBlank();
            assertThat(auditLog.findByVerificationId(receipt.getVerificationId())).get()
                    .extracting(AuditEntry::operation).isEqualTo("VERIFY");
        }
        noVerifierCalled();
    }

    @Test
    void aDisabledPrincipalBindingIsWarnedAboutAtStartUp() {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(VerificationService.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            service.warnIfPrincipalBindingDisabled();
            assertThat(appender.list).singleElement()
                    .satisfies(e -> assertThat(e.getFormattedMessage())
                            .startsWith("Step-7 confirm principal binding is DISABLED"));

            appender.list.clear();
            new VerificationService(securosys, yubico, azure, google, marvell, thales, crypto4a, fortanix,
                    nshield, new InMemoryApprovalRegistry(), new EphemeralReceiptSigner(2048),
                    mock(IssuerCaValidator.class), auditLog, new MtlsPrincipalResolver(), KeyPolicy.defaults(),
                    true).warnIfPrincipalBindingDisabled();
            assertThat(appender.list).isEmpty();
        } finally {
            logger.detachAppender(appender);
        }
    }
}
