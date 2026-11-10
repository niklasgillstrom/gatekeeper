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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
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

    /**
     * An RSA-4096 public key, which is what the default key policy accepts.
     * A constant, generated once for this test with {@code openssl genrsa
     * 4096}; its private half was not kept. The verifiers are mocks, so
     * nothing here needs it. Generating such a key takes seconds, and took
     * them again for every test method a mutation run executes on its own.
     */
    private static final String PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n"
            + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApplTQgT6ljhyXx8cBOjB\n"
            + "SNWwvnUfop+Uu34BJoKv7hedz2S9ZYohe6nZf7e3i2uyFPCo0sGkT3kjPy33ulxs\n"
            + "P29C3YLSNRMuhzqkSdjgNCfavdC9QlrZYYzYwc7RvPPBIVPG5FywmuDEMRK9vVRf\n"
            + "qJttmh1RB9H9lvSSHhYR3J8m/gtIpo4aj2k/xFwdz0zt0GPJKldCV7yZHHJRHnh0\n"
            + "sGy13YpzTX0OfzvHJLFKQUcus5OuFdn/0gfmQ8/yq0OhUL4YnmEow8wPcRQu5mc8\n"
            + "xImQ4i/bLhFia4KB7tjhSansKTbrWrADeHFI/swSJFeLWx7lLaZGVBPD1gxnv5a9\n"
            + "gQLU59FArLOi/jfTxFkEmT27UztOVLBJtPSmL4SamipsaxsHEY2OZKD9J5L0ogo2\n"
            + "f5aJawkdnVro1sdflmKREI3EiQHAAwytnVHZhlDI9qTAuyhUUxzSNbkG6h0DvB0V\n"
            + "a0+ZdwnDaRlHGvMVwaKThDibUnmOJlLsRXZDS86P1eIOVJ/i7cW2KCXfZbySpeoF\n"
            + "MMyqrmTd6QYPh4VWbzyjSxgPydpaAv47K8LLIiBhSqo1SY1NgZdkFyDRmmijgZpt\n"
            + "n7dQ+CtAX8hbJRW9x5U0FX64pP/On6St1fbbCy53o3rDneuz/KZ7NPTYwoQvZ67b\n"
            + "w2jOPlCKSk/ZjBq9gYcX9wkCAwEAAQ==\n"
            + "-----END PUBLIC KEY-----";

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
    private final InMemoryApprovalRegistry registry = new InMemoryApprovalRegistry();
    private AppendOnlyFileAuditLog auditLog;
    private VerificationService service;

    @BeforeEach
    void setUp() throws Exception {
        auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(),
                new EphemeralReceiptSigner(2048));
        auditLog.initialise();
        service = service(registry, KeyPolicy.defaults());
    }

    private VerificationService service(ApprovalRegistry approvalRegistry, KeyPolicy keyPolicy) {
        return new VerificationService(securosys, yubico, azure, google, marvell, thales, crypto4a,
                fortanix, nshield, approvalRegistry, new EphemeralReceiptSigner(2048),
                mock(IssuerCaValidator.class), auditLog, new MtlsPrincipalResolver(), keyPolicy,
                false);
    }

    private static VerificationRequest request(String vendor, String attestationData, List<String> chain) {
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey(PUBLIC_KEY_PEM);
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

    // ---- a refusal that the five flags do not show ------------------------------------------------

    private static final String NO_ATTESTATION = "The absence of valid attestation means the financial entity "
            + "cannot demonstrate compliance with DORA Articles 5(2)(b), 6(10), 9(3)(c)-(d), 9(4)(d), or 28(1)(a). "
            + "The entity must provide cryptographic attestation evidence or be considered non-compliant.";

    private static void assertNoArticleBit(VerificationResponse receipt) {
        VerificationResponse.DoraCompliance dora = receipt.getDoraCompliance();
        assertThat(List.of(dora.isArticle5_2b(), dora.isArticle6_10(), dora.isArticle9_3c(), dora.isArticle9_3d(),
                dora.isArticle9_4d(), dora.isArticle28_1a())).containsOnly(false);
    }

    /**
     * A verifier can refuse an attestation whose signature, chain, key, origin
     * and extractability all check out: Marvell while its format is
     * unconfirmed, Fortanix when the cluster states no protection profile.
     * Until 1.7.0 such a receipt was compliant=false with five article bits
     * true, and its summary read "Non-compliant: ."
     */
    @ParameterizedTest
    @ValueSource(strings = {"YUBICO", "AZURE", "GOOGLE", "MARVELL", "THALES", "CRYPTO4A", "FORTANIX", "ENTRUST"})
    void aRefusalThatNoFlagShowsSetsNoArticleBitAndIsNamedInTheSummary(String vendor) {
        stub(vendor, new Outcome(false, true, true, true, true, false, "SERIAL",
                List.of("FORMAT_UNCONFIRMED: first", "second")));

        VerificationResponse receipt = service.verify(request(vendor));

        assertThat(receipt.isCompliant()).isFalse();
        assertNoArticleBit(receipt);
        assertThat(receipt.getDoraCompliance().getSummary()).isEqualTo("Non-compliant: attestation not accepted "
                + "(FORMAT_UNCONFIRMED: first; second). " + NO_ATTESTATION);
        // The key properties are what the verifier read; the refusal is in the errors.
        assertThat(receipt.getKeyProperties().isAttestationChainValid()).isTrue();
        assertThat(receipt.getKeyProperties().isPublicKeyMatchesAttestation()).isTrue();
        assertThat(receipt.getErrors()).containsExactly("FORMAT_UNCONFIRMED: first", "second");
    }

    @Test
    void aRefusalThatAFlagShowsIsNamedByThatFlagAsBefore() {
        stub("AZURE", new Outcome(false, true, false, true, true, false, "S", List.of("AZURE_CHAIN_INVALID: x")));

        VerificationResponse receipt = service.verify(request("AZURE"));

        assertNoArticleBit(receipt);
        assertThat(receipt.getDoraCompliance().getSummary())
                .isEqualTo("Non-compliant: attestation chain invalid. " + NO_ATTESTATION);
    }

    @Test
    void aKeyOutsideThePolicyDoesNotMakeARefusedAttestationOneThatVerified() {
        VerificationService strict = service(registry, new KeyPolicy("RSA-3072"));
        String keyViolation = "key RSA-4096 is not in the allowed keys [rsa-3072]";

        // The attestation verified; only the key is outside the policy.
        stub("CRYPTO4A", Outcome.good("S"));
        VerificationResponse verified = strict.verify(request("CRYPTO4A"));
        assertThat(verified.isCompliant()).isFalse();
        assertThat(verified.getDoraCompliance().isArticle5_2b()).isTrue();
        assertThat(verified.getDoraCompliance().getSummary()).isEqualTo("Non-compliant: " + keyViolation
                + ". The attestation evidence verified, but the key is not one the scheme accepts.");

        // The verifier refused it as well: nothing verified, and both reasons are given.
        stub("CRYPTO4A", new Outcome(false, true, true, true, true, false, "S", List.of("refused")));
        VerificationResponse refused = strict.verify(request("CRYPTO4A"));
        assertNoArticleBit(refused);
        assertThat(refused.getDoraCompliance().getSummary()).isEqualTo("Non-compliant: attestation not accepted "
                + "(refused), " + keyViolation + ". " + NO_ATTESTATION);
        assertThat(refused.getErrors()).containsExactly("KEY_NOT_ALLOWED: " + keyViolation, "refused");
    }

    @Test
    void aMissingFipsStatementDoesNotMakeARefusedAttestationOneThatVerified() {
        VerificationService fips = service(registry, new KeyPolicy(KeyPolicy.DEFAULT_ALLOWED_KEYS, true));

        stub("CRYPTO4A", Outcome.good("S"));
        VerificationResponse verified = fips.verify(request("CRYPTO4A"));
        String fipsViolation = verified.getErrors().get(0);
        assertThat(fipsViolation).startsWith(KeyPolicy.FIPS_MODE_NOT_IN_ATTESTATION_FORMAT);
        assertThat(verified.getDoraCompliance().isArticle5_2b()).isTrue();
        assertThat(verified.getDoraCompliance().getSummary()).isEqualTo("Non-compliant: " + fipsViolation
                + ". The attestation evidence verified, but the scheme's policy also requires the attestation "
                + "to state FIPS-approved mode.");

        stub("CRYPTO4A", new Outcome(false, true, true, true, true, false, "S", List.of("refused")));
        VerificationResponse refused = fips.verify(request("CRYPTO4A"));
        assertNoArticleBit(refused);
        assertThat(refused.getDoraCompliance().getSummary()).isEqualTo("Non-compliant: attestation not accepted "
                + "(refused), " + fipsViolation + ". " + NO_ATTESTATION);
    }

    // ---- what is kept of a request ------------------------------------------------------------------

    /**
     * Until 1.7.0 the whole request was stored for every verification. A
     * request that passed bean validation and was not even a key left its
     * 262 144 characters in memory and in the journal.
     */
    @Test
    void theEvidenceOfAnApprovedKeyIsKeptAndThatOfARefusalIsNot() {
        stub("CRYPTO4A", Outcome.good("S"));
        VerificationRequest approved = request("CRYPTO4A");
        VerificationResponse approval = service.verify(approved);
        assertThat(approval.isCompliant()).isTrue();
        assertThat(registry.lookup(approval.getVerificationId()).orElseThrow().getSubmission()).isSameAs(approved);

        stub("CRYPTO4A", new Outcome(false, true, true, true, true, false, "S", List.of("refused")));
        VerificationRequest refusedRequest = request("CRYPTO4A");
        VerificationRequest notAKey = request("CRYPTO4A");
        notAKey.setPublicKey("not a key");
        VerificationRequest noSuchVendor = request("NO-SUCH-VENDOR");
        for (VerificationRequest refused : List.of(refusedRequest, notAKey, noSuchVendor)) {
            VerificationResponse receipt = service.verify(refused);

            assertThat(receipt.isCompliant()).isFalse();
            ApprovalRegistry.RegistryEntry entry = registry.lookup(receipt.getVerificationId()).orElseThrow();
            assertThat(entry.getSubmission()).as("no evidence is kept of a refusal").isNull();
            assertThat(entry.getSupplierIdentifier()).as("the parties still are").isEqualTo("5569743098");
            // What was refused can still be shown to be this request: the audit entry has its digest.
            assertThat(auditLog.findByVerificationId(receipt.getVerificationId()).orElseThrow()
                    .requestDigestBase64()).isEqualTo(VerificationService.requestDigestBase64(refused));
        }
    }

    @Test
    void aRefusedRequestOfTheLargestSizeLeavesAShortJournalLine() throws Exception {
        Path journal = tempDir.resolve("approval-registry.jsonl");
        AppendOnlyFileApprovalRegistry fileRegistry = new AppendOnlyFileApprovalRegistry(journal.toString());
        fileRegistry.initialise();
        VerificationRequest largest = request("CRYPTO4A",
                "A".repeat(VerificationRequest.MAX_ATTESTATION_DATA_LENGTH),
                java.util.Collections.nCopies(VerificationRequest.MAX_CERT_CHAIN_SIZE,
                        "C".repeat(VerificationRequest.MAX_CERT_LENGTH)));
        largest.setAttestationSignature("S".repeat(VerificationRequest.MAX_ATTESTATION_SIGNATURE_LENGTH));
        largest.setPublicKey("K".repeat(VerificationRequest.MAX_PUBLIC_KEY_LENGTH));

        VerificationResponse receipt = service(fileRegistry, KeyPolicy.defaults()).verify(largest);

        assertThat(receipt.isCompliant()).isFalse();
        assertThat(java.nio.file.Files.size(journal)).as("bytes in the journal for the refusal").isLessThan(1024);
        assertThat(java.nio.file.Files.readString(journal)).doesNotContain("AAAA", "CCCC", "SSSS", "KKKK");
    }

    /** "fortanix" is FORTANIX in every locale; under a Turkish one the default upper-casing gave FORTANİX. */
    @Test
    void theVendorNameIsReadTheSameInEveryLocale() {
        java.util.Locale original = java.util.Locale.getDefault();
        java.util.Locale.setDefault(java.util.Locale.forLanguageTag("tr-TR"));
        try {
            assertThat("fortanix".toUpperCase()).as("the locale this test needs").isNotEqualTo("FORTANIX");
            stub("FORTANIX", Outcome.good("S"));

            VerificationResponse receipt = service.verify(request("fortanix"));

            assertThat(receipt.getErrors()).isEmpty();
            assertThat(receipt.isCompliant()).isTrue();
        } finally {
            java.util.Locale.setDefault(original);
        }
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
