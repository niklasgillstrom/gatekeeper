package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.TriangulationBankReport;
import eu.gillstrom.gatekeeper.model.TriangulationOperatorReport;
import eu.gillstrom.gatekeeper.model.TriangulationReport;
import eu.gillstrom.gatekeeper.model.TriangulationReport.CertificateWithoutVerifiedAttestation;
import eu.gillstrom.gatekeeper.model.TriangulationReport.OrganisationNumberMismatch;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SourcedOrganisationNumber;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SwishMissingFromBanks;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SwishMissingFromOperator;
import eu.gillstrom.gatekeeper.model.TriangulationReport.VerifiedCertificateNotReported;
import eu.gillstrom.gatekeeper.model.TriangulationSubmissionResponse;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.signing.TriangulationCanonicalizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Data triangulation against the real in-memory registry and audit log: the
 * five kinds of discrepancy, determinism, the input digests, the seal, the
 * audit entry, the procedure's ordering and the caps.
 */
class TriangulationServiceTest {

    private static final String ISSUER = "CN=Swish Customer CA1 v2 for Swish,O=Getswish AB,C=SE";

    @TempDir
    Path tempDir;

    private EphemeralReceiptSigner signer;
    private GatekeeperKeyDirectory keyDirectory;
    private AppendOnlyFileAuditLog auditLog;
    private InMemoryApprovalRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        signer = new EphemeralReceiptSigner(2048);
        keyDirectory = new GatekeeperKeyDirectory(signer, "");
        keyDirectory.initialise();
        // A fresh file per set-up: one test sets up twice to compare two runs.
        auditLog = new AppendOnlyFileAuditLog(
                tempDir.resolve("audit-" + System.nanoTime() + ".jsonl").toString(), signer);
        auditLog.initialise();
        registry = new InMemoryApprovalRegistry();
    }

    private TriangulationService service(int maxInquiries, int maxEntries) {
        return new TriangulationService(registry, auditLog, new MtlsPrincipalResolver(), signer, keyDirectory,
                maxInquiries, maxEntries);
    }

    private void issued(String id, String serialHex, String country) {
        registry.register(id, "n-" + id, true, "fp-" + id, "5569743098", "TL AB", "SECUROSYS", "Primus HSM",
                country);
        registry.confirm(id, "n-" + id, true, "fp-" + id, true,
                new ApprovalRegistry.IssuedCertificate("PEM-" + id, serialHex, ISSUER));
    }

    private static TriangulationBankReport.Entry bank(String org, String swish, String serial) {
        return new TriangulationBankReport.Entry(org, swish, serial, serial == null ? null : ISSUER);
    }

    private static TriangulationOperatorReport.Entry operator(String swish, String org, String serial) {
        return new TriangulationOperatorReport.Entry(swish, org, serial, ISSUER);
    }

    private static TriangulationBankReport bankReport(String bankId, List<TriangulationBankReport.Entry> entries) {
        return new TriangulationBankReport(bankId, entries);
    }

    private static TriangulationOperatorReport operatorReport(String id, List<TriangulationOperatorReport.Entry> e) {
        return new TriangulationOperatorReport(id, e);
    }

    /** The registry and reports of the main scenario; see each expectation below. */
    private String scenario(TriangulationService service, boolean shuffled) {
        issued("VID-A", "a1", "SE");   // reported by the operator: no discrepancy
        issued("VID-B", "b2", "SE");   // not reported by the operator
        issued("VID-C", "c3", "SE");   // reported, but revoked
        registry.changeStatus("VID-C", RegistryStatus.REVOKED, "compromise", null);
        issued("VID-D", "d4", "DE");   // another jurisdiction: not this registry

        String id = service.createInquiry("SE").inquiryId();
        List<TriangulationBankReport.Entry> bank1 = new ArrayList<>(List.of(
                bank("5560000001", "1231111111", "0xA1"),
                bank("5560000002", "1232222222", null)));
        List<TriangulationBankReport.Entry> bank2 = new ArrayList<>(List.of(
                bank("5560000009", "1231111111", null),
                bank("5560000003", "1233333333", null),
                bank("5560000005", "1235555555", null)));
        List<TriangulationOperatorReport.Entry> op = new ArrayList<>(List.of(
                operator("1231111111", "5560000001", "a1"),
                operator("1233333333", null, "C3"),
                operator("1234444444", "5560000004", "e5"),
                operator("1235555555", "5560000005", "0x00d4")));
        if (shuffled) {
            Collections.reverse(bank1);
            Collections.reverse(bank2);
            Collections.reverse(op);
            service.addBankReport("SE", id, bankReport("bank-2", bank2.subList(0, 1)));
            service.addBankReport("SE", id, bankReport("bank-1", bank1));
            service.addBankReport("SE", id, bankReport("bank-2", bank2.subList(1, 3)));
            service.addOperatorReport("SE", id, operatorReport("op-1", op.subList(0, 2)));
            service.addOperatorReport("SE", id, operatorReport("op-1", op.subList(2, 4)));
        } else {
            service.addBankReport("SE", id, bankReport("bank-1", bank1));
            service.addBankReport("SE", id, bankReport("bank-2", bank2));
            service.addOperatorReport("SE", id, operatorReport("op-1", op));
        }
        return id;
    }

    @Test
    void everyKindOfDiscrepancyIsFoundAndNothingElse() {
        TriangulationService service = service(10, 1000);
        String id = scenario(service, false);

        TriangulationReport r = service.discrepancies("SE", id);

        assertThat(r.swishNumbersMissingFromOperatorReport())
                .containsExactly(new SwishMissingFromOperator("1232222222", List.of("bank-1")));
        assertThat(r.swishNumbersMissingFromBankReports())
                .containsExactly(new SwishMissingFromBanks("1234444444"));
        assertThat(r.certificatesWithoutVerifiedAttestation()).containsExactly(
                new CertificateWithoutVerifiedAttestation("c3", ISSUER, "REVOKED", "VID-C", List.of("1233333333")),
                new CertificateWithoutVerifiedAttestation("d4", ISSUER, "NOT_IN_REGISTRY", null,
                        List.of("1235555555")),
                new CertificateWithoutVerifiedAttestation("e5", ISSUER, "NOT_IN_REGISTRY", null,
                        List.of("1234444444")));
        assertThat(r.verifiedCertificatesNotReportedByOperator())
                .containsExactly(new VerifiedCertificateNotReported("b2", ISSUER, "VID-B"));
        assertThat(r.organisationNumberMismatches()).containsExactly(new OrganisationNumberMismatch("1231111111",
                List.of(new SourcedOrganisationNumber("bank:bank-1", "5560000001"),
                        new SourcedOrganisationNumber("bank:bank-2", "5560000009"),
                        new SourcedOrganisationNumber("operator:op-1", "5560000001"))));
        assertThat(r.discrepancyCount()).isEqualTo(7);
        assertThat(r.zeroDiscrepancies()).isFalse();
        assertThat(r.inputDigests().registry().entryCount()).as("VID-A, B and C; not the DE entry").isEqualTo(3);
        assertThat(r.inputDigests().bankReports()).extracting(TriangulationReport.InputDigest::reporterId)
                .containsExactly("bank-1", "bank-2");
        assertThat(r.inputDigests().operatorReport().entryCount()).isEqualTo(4);
    }

    @Test
    void theSameInputsInAnotherOrderAndOtherPartsGiveTheSameReport() throws Exception {
        TriangulationService first = service(10, 1000);
        TriangulationReport a = first.discrepancies("SE", scenario(first, false));

        setUp();
        TriangulationService second = service(10, 1000);
        TriangulationReport b = second.discrepancies("SE", scenario(second, true));

        assertThat(b.inputDigests()).isEqualTo(a.inputDigests());
        assertThat(b.swishNumbersMissingFromOperatorReport()).isEqualTo(a.swishNumbersMissingFromOperatorReport());
        assertThat(b.swishNumbersMissingFromBankReports()).isEqualTo(a.swishNumbersMissingFromBankReports());
        assertThat(b.certificatesWithoutVerifiedAttestation()).isEqualTo(a.certificatesWithoutVerifiedAttestation());
        assertThat(b.verifiedCertificatesNotReportedByOperator())
                .isEqualTo(a.verifiedCertificatesNotReportedByOperator());
        assertThat(b.organisationNumberMismatches()).isEqualTo(a.organisationNumberMismatches());
    }

    @Test
    void theInputDigestsAreTheSha256OfTheDocumentedForms() throws Exception {
        TriangulationService service = service(10, 1000);
        String id = service.createInquiry("SE").inquiryId();
        TriangulationSubmissionResponse bankAck = service.addBankReport("SE", id, bankReport("bank-1", List.of(
                new TriangulationBankReport.Entry("5569743098", "1231015932", "0x00AB",
                        "CN=Example CA, O=Example Bank, C=SE"),
                new TriangulationBankReport.Entry("5560000001", "1230000001", null, null))));
        TriangulationSubmissionResponse opAck = service.addOperatorReport("SE", id, operatorReport("op-1", List.of(
                new TriangulationOperatorReport.Entry("1231015932", null, "AB", "CN=Example CA,O=Example Bank,C=SE"))));

        assertThat(bankAck.sha256Hex()).isEqualTo(sha256Hex("tri-bank-v1|bank-1\n"
                + "5560000001|1230000001||\n"
                + "5569743098|1231015932|ab|CN%3DExample CA%2CO%3DExample Bank%2CC%3DSE\n"));
        assertThat(bankAck.entriesAccepted()).isEqualTo(2);
        assertThat(opAck.sha256Hex()).isEqualTo(sha256Hex("tri-operator-v1|op-1\n"
                + "1231015932||ab|CN%3DExample CA%2CO%3DExample Bank%2CC%3DSE\n"));

        TriangulationReport r = service.discrepancies("SE", id);
        assertThat(r.inputDigests().bankReports().get(0).sha256Hex()).isEqualTo(bankAck.sha256Hex());
        assertThat(r.inputDigests().operatorReport().sha256Hex()).isEqualTo(opAck.sha256Hex());
        assertThat(r.inputDigests().registry().sha256Hex()).isEqualTo(sha256Hex("tri-registry-v1|SE\n"));
    }

    @Test
    void theReportIsSealedAndRecordedInTheAuditLog() throws Exception {
        TriangulationService service = service(10, 1000);
        String id = scenario(service, false);

        TriangulationReport r = service.discrepancies("SE", id);

        byte[] canonical = TriangulationCanonicalizer.canonicalize(r);
        Signature check = Signature.getInstance(r.signatureAlgorithm());
        check.initVerify(signer.getPublicKey());
        check.update(canonical);
        assertThat(check.verify(Base64.getDecoder().decode(r.reportSignatureBase64()))).isTrue();
        assertThat(r.signingKeyFingerprintHex()).isEqualTo(keyDirectory.activeFingerprintHex());
        assertThat(r.canonicalVersion()).isEqualTo("tr1");

        AuditEntry entry = auditLog.head().orElseThrow();
        assertThat(r.auditEntryHashHex()).isEqualTo(entry.thisEntryHashHex());
        assertThat(entry.operation()).isEqualTo("TRIANGULATION");
        assertThat(entry.verificationId()).isEqualTo(id);
        assertThat(entry.compliant()).isFalse();
        assertThat(entry.requestDigestBase64()).isEqualTo(sha256Base64(
                TriangulationCanonicalizer.inputsCommitment(id, "SE", r.inputDigests())));
        assertThat(entry.receiptDigestBase64()).isEqualTo(sha256Base64(canonical));
        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }

    @Test
    void reportsThatAgreeWithTheRegistryHaveZeroDiscrepancies() {
        issued("VID-A", "a1", "SE");
        TriangulationService service = service(10, 1000);
        String id = service.createInquiry("se".toUpperCase()).inquiryId();
        service.addBankReport("SE", id, bankReport("bank-1", List.of(bank("5560000001", "1231111111", "a1"))));
        service.addOperatorReport("SE", id, operatorReport("op-1",
                List.of(operator("1231111111", "5560000001", "A1"))));

        TriangulationReport r = service.discrepancies("SE", id);

        assertThat(r.discrepancyCount()).isZero();
        assertThat(r.zeroDiscrepancies()).isTrue();
        assertThat(auditLog.head().orElseThrow().compliant()).isTrue();
    }

    @Test
    void banksReportBeforeTheOperatorAndThereIsOneOperator() {
        TriangulationService service = service(10, 1000);
        String id = service.createInquiry("SE").inquiryId();
        service.addBankReport("SE", id, bankReport("bank-1", List.of(bank("5560000001", "1231111111", null))));
        service.addOperatorReport("SE", id, operatorReport("op-1", List.of(operator("1231111111", null, "a1"))));

        assertThatThrownBy(() -> service.addBankReport("SE", id,
                bankReport("bank-2", List.of(bank("5560000002", "1232222222", null)))))
                .isInstanceOfSatisfying(TriangulationService.Rejection.class, e -> {
                    assertThat(e.status()).isEqualTo(409);
                    assertThat(e.reason()).isEqualTo("BANK_PHASE_CLOSED");
                });
        assertThatThrownBy(() -> service.addOperatorReport("SE", id,
                operatorReport("op-2", List.of(operator("1232222222", null, "b2")))))
                .isInstanceOfSatisfying(TriangulationService.Rejection.class,
                        e -> assertThat(e.reason()).isEqualTo("OPERATOR_MISMATCH"));
        assertThat(service.addOperatorReport("SE", id,
                operatorReport("op-1", List.of(operator("1232222222", null, "b2")))).entriesHeld())
                .as("the same operator may send a further part").isEqualTo(2);
    }

    @Test
    void theInquiryAndEntryCapsHoldAndDeletingFreesAPlace() {
        TriangulationService service = service(2, 3);
        String first = service.createInquiry("SE").inquiryId();
        service.createInquiry("SE");
        assertThatThrownBy(() -> service.createInquiry("SE"))
                .isInstanceOfSatisfying(TriangulationService.Rejection.class, e -> {
                    assertThat(e.status()).isEqualTo(409);
                    assertThat(e.reason()).isEqualTo("INQUIRY_CAP_REACHED");
                });

        service.addBankReport("SE", first, bankReport("bank-1", List.of(
                bank("5560000001", "1231111111", null), bank("5560000002", "1232222222", null))));
        assertThatThrownBy(() -> service.addBankReport("SE", first, bankReport("bank-1", List.of(
                bank("5560000003", "1233333333", null), bank("5560000004", "1234444444", null)))))
                .isInstanceOfSatisfying(TriangulationService.Rejection.class,
                        e -> assertThat(e.reason()).isEqualTo("ENTRY_CAP_REACHED"));
        assertThat(service.discrepancies("SE", first).inputDigests().bankReports().get(0).entryCount())
                .as("the refused part was not kept").isEqualTo(2);

        service.deleteInquiry("SE", first);
        assertThat(service.createInquiry("SE").inquiryId()).isNotBlank();
        assertThatThrownBy(() -> service.discrepancies("SE", first))
                .isInstanceOfSatisfying(TriangulationService.Rejection.class,
                        e -> assertThat(e.status()).isEqualTo(404));
    }

    @Test
    void theOperatorReportCountsTowardsTheEntryCapAndTheCapItselfMayBeReached() {
        TriangulationService service = service(1, 3);
        String id = service.createInquiry("SE").inquiryId();
        service.addBankReport("SE", id, bankReport("bank-1", List.of(bank("5560000001", "1231111111", null))));
        service.addOperatorReport("SE", id, operatorReport("op-1", List.of(
                operator("1231111111", "5560000001", "a1"), operator("1232222222", null, "b2"))));
        assertThatThrownBy(() -> service.addOperatorReport("SE", id, operatorReport("op-1", List.of(
                operator("1233333333", null, "c3")))))
                .isInstanceOfSatisfying(TriangulationService.Rejection.class,
                        e -> assertThat(e.reason()).isEqualTo("ENTRY_CAP_REACHED"));
    }

    @Test
    void everyListOfDiscrepanciesIsSortedByItsCanonicalLine() {
        TriangulationService service = service(1, 1000);
        for (int i = 5; i >= 1; i--) {
            issued("VID-R" + i, "9" + i, "SE");                                     // not reported
        }
        String id = service.createInquiry("SE").inquiryId();
        List<TriangulationBankReport.Entry> bankEntries = new ArrayList<>();
        List<TriangulationOperatorReport.Entry> operatorEntries = new ArrayList<>();
        for (int i = 5; i >= 1; i--) {
            bankEntries.add(bank("556000000" + i, "123900000" + i, null));           // missing from operator
            operatorEntries.add(operator("123800000" + i, null, "e" + i));            // missing from banks
            bankEntries.add(bank("5560000001", "123700000" + i, null));               // organisation numbers differ
            operatorEntries.add(operator("123700000" + i, "5560000002", "c" + i));
        }
        service.addBankReport("SE", id, bankReport("bank-1", bankEntries));
        service.addOperatorReport("SE", id, operatorReport("op-1", operatorEntries));

        TriangulationReport report = service.discrepancies("SE", id);
        assertSorted(report.swishNumbersMissingFromOperatorReport(), TriangulationCanonicalizer::line, 5);
        assertSorted(report.swishNumbersMissingFromBankReports(), TriangulationCanonicalizer::line, 5);
        assertSorted(report.certificatesWithoutVerifiedAttestation(), TriangulationCanonicalizer::line, 10);
        assertSorted(report.verifiedCertificatesNotReportedByOperator(), TriangulationCanonicalizer::line, 5);
        assertSorted(report.organisationNumberMismatches(), TriangulationCanonicalizer::line, 5);
    }

    private static <T> void assertSorted(List<T> list, java.util.function.Function<T, String> line, int size) {
        assertThat(list).hasSize(size);
        assertThat(list).isSortedAccordingTo(java.util.Comparator.comparing(line));
    }

    @Test
    void ofTwoEntriesHoldingOneCertificateTheMoreRecentIsCompared() throws Exception {
        TriangulationService service = service(1, 100);
        issued("VID-OLD", "f6", "SE");
        Thread.sleep(5);
        issued("VID-NEW", "f6", "SE");
        registry.changeStatus("VID-NEW", RegistryStatus.REVOKED, "compromise", null);
        String id = service.createInquiry("SE").inquiryId();
        service.addBankReport("SE", id, bankReport("bank-1", List.of(bank("5560000001", "1231111111", null))));
        service.addOperatorReport("SE", id, operatorReport("op-1", List.of(operator("1231111111", null, "f6"))));

        TriangulationReport report = service.discrepancies("SE", id);
        assertThat(report.certificatesWithoutVerifiedAttestation()).singleElement().satisfies(d -> {
            assertThat(d.verificationId()).isEqualTo("VID-NEW");
            assertThat(d.registryStatus()).isEqualTo("REVOKED");
        });
        assertThat(report.verifiedCertificatesNotReportedByOperator()).isEmpty();
    }

    @Test
    void anInquiryBelongsToItsJurisdiction() {
        TriangulationService service = service(10, 1000);
        String id = service.createInquiry("SE").inquiryId();
        for (Runnable call : new Runnable[] {
                () -> service.discrepancies("DE", id),
                () -> service.addBankReport("DE", id, bankReport("b", List.of())),
                () -> service.deleteInquiry("DE", id),
                () -> service.discrepancies("SE", "no-such-inquiry")}) {
            assertThatThrownBy(call::run).isInstanceOfSatisfying(TriangulationService.Rejection.class, e -> {
                assertThat(e.status()).isEqualTo(404);
                assertThat(e.reason()).isEqualTo("INQUIRY_NOT_FOUND");
            });
        }
    }

    @Test
    void anIssuerThatDoesNotParseIsMalformedInput() {
        TriangulationService service = service(10, 1000);
        String id = service.createInquiry("SE").inquiryId();
        assertThatThrownBy(() -> service.addOperatorReport("SE", id, operatorReport("op",
                List.of(new TriangulationOperatorReport.Entry("1231111111", null, "a1", "not a dn")))))
                .isInstanceOfSatisfying(TriangulationService.Rejection.class, e -> {
                    assertThat(e.status()).isEqualTo(400);
                    assertThat(e.reason()).isEqualTo("MALFORMED_INPUT");
                });
    }

    private static String sha256Hex(String s) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
    }

    private static String sha256Base64(byte[] b) throws Exception {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(b));
    }
}
