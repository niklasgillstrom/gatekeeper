package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.TriangulationBankReport;
import eu.gillstrom.gatekeeper.model.TriangulationInquiryResponse;
import eu.gillstrom.gatekeeper.model.TriangulationOperatorReport;
import eu.gillstrom.gatekeeper.model.TriangulationReport;
import eu.gillstrom.gatekeeper.model.TriangulationReport.CertificateWithoutVerifiedAttestation;
import eu.gillstrom.gatekeeper.model.TriangulationReport.InputDigest;
import eu.gillstrom.gatekeeper.model.TriangulationReport.InputDigests;
import eu.gillstrom.gatekeeper.model.TriangulationReport.OrganisationNumberMismatch;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SourcedOrganisationNumber;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SwishMissingFromBanks;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SwishMissingFromOperator;
import eu.gillstrom.gatekeeper.model.TriangulationReport.VerifiedCertificateNotReported;
import eu.gillstrom.gatekeeper.model.TriangulationSubmissionResponse;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import eu.gillstrom.gatekeeper.signing.TriangulationCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.function.BinaryOperator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Data triangulation: the banks' reports, the payment-system operator's
 * report and the gatekeeper's approval registry are compared, and the
 * differences are listed in a signed report that needs no interpretation.
 *
 * <h2>Procedure</h2>
 *
 * <ol>
 *   <li>The supervisor opens an inquiry for a jurisdiction
 *       ({@link #createInquiry}).</li>
 *   <li>Banks report their active agreements ({@link #addBankReport}). A
 *       bank may submit in several parts; its parts form one input.</li>
 *   <li>The operator reports its active Swish numbers and certificates
 *       ({@link #addOperatorReport}). Once it has reported, no further bank
 *       report is accepted ({@code BANK_PHASE_CLOSED}), so the operator
 *       cannot be answered by a bank that has seen its report — the order
 *       the procedure prescribes. One operator per inquiry; it may submit in
 *       several parts.</li>
 *   <li>The supervisor asks for the discrepancies ({@link #discrepancies}).
 *       Each call compares the inputs with the registry as it stands, signs
 *       the report with the {@link ReceiptSigner} and appends a
 *       {@code TRIANGULATION} audit entry: {@code verificationId} is the
 *       inquiryId, {@code requestDigestBase64} the Base64 SHA-256 of
 *       {@link TriangulationCanonicalizer#inputsCommitment} (which lists
 *       every input digest), {@code receiptDigestBase64} the Base64 SHA-256
 *       of the report's canonical form, and {@code compliant} is
 *       {@code true} exactly when there are no discrepancies.</li>
 * </ol>
 *
 * <h2>State</h2>
 *
 * <p>Inquiries are held in memory only: a restart discards them, and the
 * reports they hold, while the audit entries of reports already generated
 * remain. At most {@code gatekeeper.triangulation.max-inquiries} inquiries
 * (default 10) are held at a time, each with at most
 * {@code gatekeeper.triangulation.max-entries-per-inquiry} entries across
 * all its reports (default 100 000); {@link #deleteInquiry} frees one. The
 * reports may be personal data (a sole trader's organisation number is a
 * personal identity number).</p>
 *
 * <p>Failures are thrown as {@link Rejection}, carrying the HTTP status and
 * a reason code.</p>
 */
@Service
public class TriangulationService {

    private static final Logger log = LoggerFactory.getLogger(TriangulationService.class);

    public static final String AUDIT_OPERATION = "TRIANGULATION";

    /** {@code registryStatus} of an operator-reported certificate with no registry entry. */
    public static final String NOT_IN_REGISTRY = "NOT_IN_REGISTRY";

    private final ApprovalRegistry approvalRegistry;
    private final AuditLog auditLog;
    private final MtlsPrincipalResolver principalResolver;
    private final ReceiptSigner signer;
    private final GatekeeperKeyDirectory keyDirectory;
    private final int maxInquiries;
    private final int maxEntriesPerInquiry;

    private final ConcurrentHashMap<String, Inquiry> inquiries = new ConcurrentHashMap<>();

    public TriangulationService(ApprovalRegistry approvalRegistry,
                                AuditLog auditLog,
                                MtlsPrincipalResolver principalResolver,
                                ReceiptSigner signer,
                                GatekeeperKeyDirectory keyDirectory,
                                @Value("${gatekeeper.triangulation.max-inquiries:10}") int maxInquiries,
                                @Value("${gatekeeper.triangulation.max-entries-per-inquiry:100000}")
                                int maxEntriesPerInquiry) {
        this.approvalRegistry = approvalRegistry;
        this.auditLog = auditLog;
        this.principalResolver = principalResolver;
        this.signer = signer;
        this.keyDirectory = keyDirectory;
        this.maxInquiries = maxInquiries;
        this.maxEntriesPerInquiry = maxEntriesPerInquiry;
    }

    /** A refused call: HTTP status and reason code. */
    public static class Rejection extends RuntimeException {
        private final int status;
        private final String reason;

        public Rejection(int status, String reason, String message) {
            super(message);
            this.status = status;
            this.reason = reason;
        }

        public int status() {
            return status;
        }

        public String reason() {
            return reason;
        }
    }

    // ------------------------------------------------------------------ state

    private record BankRow(String organisationNumber, String swishNumber, String certSerialHex,
                           String issuerDn) {
    }

    private record OperatorRow(String swishNumber, String organisationNumber, String certSerialHex,
                               String issuerDn, String issuerKey) {
    }

    private static final class Inquiry {
        final String id;
        final String countryCode;
        final String createdAt;
        final TreeMap<String, List<BankRow>> banks = new TreeMap<>();
        String operatorId;
        final List<OperatorRow> operatorRows = new ArrayList<>();
        int entries;

        Inquiry(String id, String countryCode, String createdAt) {
            this.id = id;
            this.countryCode = countryCode;
            this.createdAt = createdAt;
        }
    }

    // ------------------------------------------------------------------ calls

    /** Open an inquiry. 409 {@code INQUIRY_CAP_REACHED} when the cap is reached. */
    public TriangulationInquiryResponse createInquiry(String countryCode) {
        synchronized (inquiries) {
            if (inquiries.size() >= maxInquiries) {
                throw new Rejection(409, "INQUIRY_CAP_REACHED", "At most " + maxInquiries
                        + " inquiries are held; delete one first (gatekeeper.triangulation.max-inquiries)");
            }
            Inquiry inquiry = new Inquiry(UUID.randomUUID().toString(), countryCode, Instant.now().toString());
            inquiries.put(inquiry.id, inquiry);
            return new TriangulationInquiryResponse(inquiry.id, inquiry.countryCode, inquiry.createdAt);
        }
    }

    /** Discard an inquiry and its reports. 404 {@code INQUIRY_NOT_FOUND} if unknown in this jurisdiction. */
    public void deleteInquiry(String countryCode, String inquiryId) {
        synchronized (inquiries) {
            inquiry(countryCode, inquiryId);
            inquiries.remove(inquiryId);
        }
    }

    /**
     * Add a bank's report, or a further part of it. 409
     * {@code BANK_PHASE_CLOSED} once the operator has reported, 409
     * {@code ENTRY_CAP_REACHED} beyond the per-inquiry cap, 400
     * {@code MALFORMED_INPUT} for an issuer DN that does not parse.
     */
    public TriangulationSubmissionResponse addBankReport(String countryCode, String inquiryId,
                                                         TriangulationBankReport report) {
        Inquiry inquiry = inquiry(countryCode, inquiryId);
        List<BankRow> rows = new ArrayList<>();
        for (TriangulationBankReport.Entry e : report.getEntries()) {
            Certificate cert = e.getCertSerial() == null ? null : certificate(e.getCertSerial(), e.getIssuerDn());
            rows.add(new BankRow(e.getOrganisationNumber(), e.getSwishNumber(),
                    cert == null ? null : cert.serialHex(), cert == null ? null : cert.issuerDn()));
        }
        synchronized (inquiry) {
            if (inquiry.operatorId != null) {
                throw new Rejection(409, "BANK_PHASE_CLOSED",
                        "The operator has reported; bank reports are no longer accepted for this inquiry");
            }
            reserve(inquiry, rows.size());
            List<BankRow> held = inquiry.banks.computeIfAbsent(report.getBankId(), k -> new ArrayList<>());
            held.addAll(rows);
            return new TriangulationSubmissionResponse(inquiry.id, report.getBankId(), rows.size(), held.size(),
                    bankDigest(report.getBankId(), held).sha256Hex());
        }
    }

    /**
     * Add the operator's report, or a further part of it. 409
     * {@code OPERATOR_MISMATCH} for a second operator, 409
     * {@code ENTRY_CAP_REACHED} beyond the cap, 400 {@code MALFORMED_INPUT}
     * for an issuer DN that does not parse.
     */
    public TriangulationSubmissionResponse addOperatorReport(String countryCode, String inquiryId,
                                                             TriangulationOperatorReport report) {
        Inquiry inquiry = inquiry(countryCode, inquiryId);
        List<OperatorRow> rows = new ArrayList<>();
        for (TriangulationOperatorReport.Entry e : report.getEntries()) {
            Certificate cert = certificate(e.getCertSerial(), e.getIssuerDn());
            rows.add(new OperatorRow(e.getSwishNumber(), e.getOrganisationNumber(), cert.serialHex(),
                    cert.issuerDn(), cert.issuerKey()));
        }
        synchronized (inquiry) {
            if (inquiry.operatorId != null && !inquiry.operatorId.equals(report.getOperatorId())) {
                throw new Rejection(409, "OPERATOR_MISMATCH",
                        "This inquiry already holds the report of another operator");
            }
            reserve(inquiry, rows.size());
            inquiry.operatorId = report.getOperatorId();
            inquiry.operatorRows.addAll(rows);
            return new TriangulationSubmissionResponse(inquiry.id, inquiry.operatorId, rows.size(),
                    inquiry.operatorRows.size(), operatorDigest(inquiry).sha256Hex());
        }
    }

    /**
     * Compare the inputs with the registry, sign the report and record it.
     * See the class javadoc and {@link TriangulationReport}.
     */
    public TriangulationReport discrepancies(String countryCode, String inquiryId) {
        Inquiry inquiry = inquiry(countryCode, inquiryId);
        Map<String, List<BankRow>> banks = new TreeMap<>();
        String operatorId;
        List<OperatorRow> operatorRows;
        synchronized (inquiry) {
            inquiry.banks.forEach((id, rows) -> banks.put(id, List.copyOf(rows)));
            operatorId = inquiry.operatorId;
            operatorRows = List.copyOf(inquiry.operatorRows);
        }
        Registry registry = registrySnapshot(countryCode);

        // Input digests.
        List<InputDigest> bankDigests = new ArrayList<>();
        banks.forEach((id, rows) -> bankDigests.add(bankDigest(id, rows)));
        InputDigest operatorDigest = operatorId == null ? null : operatorDigest(operatorId, operatorRows);
        InputDigests digests = new InputDigests(List.copyOf(bankDigests), operatorDigest, registry.digest);

        // Swish numbers per source.
        Map<String, TreeSet<String>> banksBySwish = new HashMap<>();
        Map<String, Set<SourcedOrganisationNumber>> orgBySwish = new HashMap<>();
        banks.forEach((bankId, rows) -> rows.forEach(r -> {
            banksBySwish.computeIfAbsent(r.swishNumber(), k -> new TreeSet<>()).add(bankId);
            orgBySwish.computeIfAbsent(r.swishNumber(), k -> new java.util.HashSet<>())
                    .add(new SourcedOrganisationNumber("bank:" + bankId, r.organisationNumber()));
        }));
        Set<String> operatorSwish = new java.util.HashSet<>();
        Map<String, OperatorCertificate> operatorCertificates = new LinkedHashMap<>();
        for (OperatorRow r : operatorRows) {
            operatorSwish.add(r.swishNumber());
            if (r.organisationNumber() != null) {
                orgBySwish.computeIfAbsent(r.swishNumber(), k -> new java.util.HashSet<>())
                        .add(new SourcedOrganisationNumber("operator:" + operatorId, r.organisationNumber()));
            }
            operatorCertificates.computeIfAbsent(r.certSerialHex() + '\u0000' + r.issuerKey(),
                    k -> new OperatorCertificate(r.certSerialHex(), r.issuerDn())).swishNumbers.add(r.swishNumber());
        }

        List<SwishMissingFromOperator> missingFromOperator = new ArrayList<>();
        banksBySwish.forEach((swish, bankIds) -> {
            if (!operatorSwish.contains(swish)) {
                missingFromOperator.add(new SwishMissingFromOperator(swish, List.copyOf(bankIds)));
            }
        });
        List<SwishMissingFromBanks> missingFromBanks = new ArrayList<>();
        operatorSwish.forEach(swish -> {
            if (!banksBySwish.containsKey(swish)) {
                missingFromBanks.add(new SwishMissingFromBanks(swish));
            }
        });

        List<CertificateWithoutVerifiedAttestation> unverified = new ArrayList<>();
        operatorCertificates.forEach((key, cert) -> {
            Held held = registry.byCertificate.get(key);
            ApprovalRegistry.RegistryEntry entry = held == null ? null : held.entry();
            if (entry == null || entry.getStatus() != RegistryStatus.VERIFIED_AND_ISSUED) {
                unverified.add(new CertificateWithoutVerifiedAttestation(cert.serialHex, cert.issuerDn,
                        entry == null ? NOT_IN_REGISTRY : String.valueOf(entry.getStatus()),
                        entry == null ? null : entry.getVerificationId(),
                        List.copyOf(cert.swishNumbers)));
            }
        });

        List<VerifiedCertificateNotReported> notReported = new ArrayList<>();
        registry.byCertificate.forEach((key, held) -> {
            if (held.entry().getStatus() == RegistryStatus.VERIFIED_AND_ISSUED && !operatorCertificates.containsKey(key)) {
                notReported.add(new VerifiedCertificateNotReported(held.serialHex(), held.issuerDn(),
                        held.entry().getVerificationId()));
            }
        });

        List<OrganisationNumberMismatch> mismatches = new ArrayList<>();
        orgBySwish.forEach((swish, reported) -> {
            long distinct = reported.stream().map(SourcedOrganisationNumber::organisationNumber).distinct().count();
            if (distinct > 1) {
                List<SourcedOrganisationNumber> sorted = new ArrayList<>(reported);
                sorted.sort(Comparator.comparing(SourcedOrganisationNumber::source)
                        .thenComparing(SourcedOrganisationNumber::organisationNumber));
                mismatches.add(new OrganisationNumberMismatch(swish, List.copyOf(sorted)));
            }
        });

        sortBy(missingFromOperator, TriangulationCanonicalizer::line);
        sortBy(missingFromBanks, TriangulationCanonicalizer::line);
        sortBy(unverified, TriangulationCanonicalizer::line);
        sortBy(notReported, TriangulationCanonicalizer::line);
        sortBy(mismatches, TriangulationCanonicalizer::line);

        int count = missingFromOperator.size() + missingFromBanks.size() + unverified.size()
                + notReported.size() + mismatches.size();
        TriangulationReport unsigned = new TriangulationReport(
                TriangulationCanonicalizer.REPORT_VERSION,
                inquiry.id,
                inquiry.countryCode,
                Instant.now().truncatedTo(ChronoUnit.MILLIS).toString(),
                digests,
                List.copyOf(missingFromOperator),
                List.copyOf(missingFromBanks),
                List.copyOf(unverified),
                List.copyOf(notReported),
                List.copyOf(mismatches),
                count,
                count == 0,
                keyDirectory.activeFingerprintHex(),
                null, null, null);

        byte[] canonical = TriangulationCanonicalizer.canonicalize(unsigned);
        String signature = Base64.getEncoder().encodeToString(signer.sign(canonical));
        AuditEntry entry = auditLog.append(new AuditAppendRequest(
                principalResolver.currentPrincipal(),
                AUDIT_OPERATION,
                inquiry.id,
                sha256Base64(TriangulationCanonicalizer.inputsCommitment(inquiry.id, inquiry.countryCode, digests)),
                sha256Base64(canonical),
                count == 0));
        return unsigned.sealed(signature, signer.getSignatureAlgorithm(), entry.thisEntryHashHex());
    }

    // ------------------------------------------------------------------ helpers

    private Inquiry inquiry(String countryCode, String inquiryId) {
        Inquiry inquiry = inquiryId == null ? null : inquiries.get(inquiryId);
        if (inquiry == null || !inquiry.countryCode.equals(countryCode)) {
            throw new Rejection(404, "INQUIRY_NOT_FOUND", "No such inquiry in this jurisdiction");
        }
        return inquiry;
    }

    private void reserve(Inquiry inquiry, int entries) {
        if ((long) inquiry.entries + entries > maxEntriesPerInquiry) {
            throw new Rejection(409, "ENTRY_CAP_REACHED", "An inquiry holds at most " + maxEntriesPerInquiry
                    + " entries (gatekeeper.triangulation.max-entries-per-inquiry)");
        }
        inquiry.entries += entries;
    }

    private record Certificate(String serialHex, String issuerDn, String issuerKey) {
    }

    /** Normalise a reported certificate; 400 {@code MALFORMED_INPUT} if it does not parse. */
    private static Certificate certificate(String certSerial, String issuerDn) {
        try {
            String hex = certSerial.startsWith("0x") || certSerial.startsWith("0X")
                    ? certSerial.substring(2) : certSerial;
            X500Principal issuer = new X500Principal(issuerDn);
            return new Certificate(new BigInteger(hex, 16).toString(16),
                    issuer.getName(X500Principal.RFC2253), issuer.getName(X500Principal.CANONICAL));
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new Rejection(400, "MALFORMED_INPUT", "certSerial or issuerDn cannot be parsed: " + e.getMessage());
        }
    }

    private static final class OperatorCertificate {
        final String serialHex;
        final String issuerDn;
        final TreeSet<String> swishNumbers = new TreeSet<>();

        OperatorCertificate(String serialHex, String issuerDn) {
            this.serialHex = serialHex;
            this.issuerDn = issuerDn;
        }
    }

    /** A registry entry holding a certificate, with the certificate's normalised serial and RFC 2253 issuer. */
    private record Held(ApprovalRegistry.RegistryEntry entry, String serialHex, String issuerDn) {
    }

    private static final class Registry {
        final Map<String, Held> byCertificate = new HashMap<>();
        InputDigest digest;
    }

    /**
     * The jurisdiction's entries that hold an issued certificate, keyed by
     * serial and canonical issuer name; where two hold the same certificate
     * the more recent wins, as in settlement lookup.
     */
    private Registry registrySnapshot(String countryCode) {
        Registry registry = new Registry();
        List<String> lines = new ArrayList<>();
        for (ApprovalRegistry.RegistryEntry e : approvalRegistry.findByCountry(countryCode)) {
            if (e.getIssuedCertificateSerial() == null || e.getIssuedCertificateIssuerDn() == null) {
                continue;
            }
            String serialHex;
            X500Principal issuer;
            try {
                serialHex = new BigInteger(e.getIssuedCertificateSerial(), 16).toString(16);
                issuer = new X500Principal(e.getIssuedCertificateIssuerDn());
            } catch (IllegalArgumentException ex) {
                log.warn("Triangulation: registry entry {} has an unparseable issued certificate identifier; skipped",
                        e.getVerificationId());
                continue;
            }
            String dn = issuer.getName(X500Principal.RFC2253);
            lines.add(TriangulationCanonicalizer.registryEntryLine(serialHex, dn,
                    String.valueOf(e.getStatus()), e.getVerificationId()));
            String key = serialHex + '\u0000' + issuer.getName(X500Principal.CANONICAL);
            // maxBy keeps the entry already held on a tie, as settlement lookup's Stream.max does.
            registry.byCertificate.merge(key, new Held(e, serialHex, dn),
                    BinaryOperator.maxBy(Comparator.comparing(Held::entry, ApprovalRegistry.recency())));
        }
        registry.digest = new InputDigest(null, lines.size(), TriangulationCanonicalizer.sha256Hex(
                TriangulationCanonicalizer.inputBytes(TriangulationCanonicalizer.registryHeader(countryCode), lines)));
        return registry;
    }

    private static InputDigest bankDigest(String bankId, List<BankRow> rows) {
        List<String> lines = new ArrayList<>(rows.size());
        rows.forEach(r -> lines.add(TriangulationCanonicalizer.bankEntryLine(r.organisationNumber(), r.swishNumber(),
                r.certSerialHex(), r.issuerDn())));
        return new InputDigest(bankId, lines.size(), TriangulationCanonicalizer.sha256Hex(
                TriangulationCanonicalizer.inputBytes(TriangulationCanonicalizer.bankHeader(bankId), lines)));
    }

    private static InputDigest operatorDigest(Inquiry inquiry) {
        return operatorDigest(inquiry.operatorId, inquiry.operatorRows);
    }

    private static InputDigest operatorDigest(String operatorId, List<OperatorRow> rows) {
        List<String> lines = new ArrayList<>(rows.size());
        rows.forEach(r -> lines.add(TriangulationCanonicalizer.operatorEntryLine(r.swishNumber(),
                r.organisationNumber(), r.certSerialHex(), r.issuerDn())));
        return new InputDigest(operatorId, lines.size(), TriangulationCanonicalizer.sha256Hex(
                TriangulationCanonicalizer.inputBytes(TriangulationCanonicalizer.operatorHeader(operatorId), lines)));
    }

    private static <T> void sortBy(List<T> records, Function<T, String> line) {
        records.sort(Comparator.comparing(line));
    }

    private static String sha256Base64(byte[] in) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(in));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
