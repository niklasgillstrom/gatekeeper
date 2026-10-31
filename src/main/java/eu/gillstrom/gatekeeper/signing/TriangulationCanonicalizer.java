package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.model.TriangulationReport;
import eu.gillstrom.gatekeeper.model.TriangulationReport.CertificateWithoutVerifiedAttestation;
import eu.gillstrom.gatekeeper.model.TriangulationReport.InputDigest;
import eu.gillstrom.gatekeeper.model.TriangulationReport.OrganisationNumberMismatch;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SwishMissingFromBanks;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SwishMissingFromOperator;
import eu.gillstrom.gatekeeper.model.TriangulationReport.VerifiedCertificateNotReported;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.StringJoiner;
import java.util.function.Function;

/**
 * Canonical forms of a triangulation inquiry: of each input (for the input
 * digests) and of the discrepancy report (for its signature).
 *
 * <h2>Common rules</h2>
 *
 * <ul>
 *   <li>A canonical form is a sequence of lines, each terminated by one LF
 *       ({@code \n}); fields within a line are separated by {@code |}. The
 *       bytes are the UTF-8 encoding.</li>
 *   <li>Every field is escaped: {@code %} → {@code %25} first, then
 *       {@code |} → {@code %7C}, {@code ,} → {@code %2C}, {@code =} →
 *       {@code %3D}, LF → {@code %0A}, CR → {@code %0D}. {@code null} is the
 *       empty string.</li>
 *   <li>Certificate serials are lower-case hexadecimal without leading
 *       zeros ({@code BigInteger.toString(16)}); issuer DNs are
 *       {@code X500Principal.getName(RFC2253)} of the value given.</li>
 *   <li>"Sorted" means ascending by {@link String#compareTo} (UTF-16 code
 *       units; for ASCII the same as byte order).</li>
 *   <li>Digests are SHA-256, lower-case hex.</li>
 * </ul>
 *
 * <h2>Inputs</h2>
 *
 * <p>A header line, then one line per entry, the entry lines sorted
 * (duplicates kept):</p>
 * <pre>
 * tri-bank-v1|bankId
 * organisationNumber|swishNumber|certSerialHex|issuerDn      (certificate fields empty when not given)
 *
 * tri-operator-v1|operatorId
 * swishNumber|organisationNumber|certSerialHex|issuerDn      (organisationNumber empty when not given)
 *
 * tri-registry-v1|countryCode
 * certSerialHex|issuerDn|status|verificationId               (every entry of the jurisdiction with an issued certificate)
 * </pre>
 *
 * <p>Several submissions from one {@code bankId} (or the {@code operatorId})
 * form one input. The audit entry's {@code requestDigestBase64} is the
 * Base64 SHA-256 of {@link #inputsCommitment}: the line
 * {@code tri-inputs-v1|inquiryId|countryCode} followed by the report's
 * {@code in|...} lines (below).</p>
 *
 * <h2>Report, version {@code tr1}</h2>
 *
 * <pre>
 * tr1|inquiryId|countryCode|generatedAt|signingKeyFingerprintHex
 * in|bank|bankId|entryCount|sha256Hex                         (one per bank, sorted)
 * in|operator|operatorId|entryCount|sha256Hex                 (in|operator||0| when none received)
 * in|registry|entryCount|sha256Hex
 * d|SWISH_MISSING_FROM_OPERATOR|swishNumber|bankId,bankId...  (sorted)
 * d|SWISH_MISSING_FROM_BANKS|swishNumber                      (sorted)
 * d|CERT_WITHOUT_VERIFIED_ATTESTATION|certSerialHex|issuerDn|registryStatus|verificationId|swishNumber,...  (sorted)
 * d|VERIFIED_CERT_NOT_REPORTED|certSerialHex|issuerDn|verificationId  (sorted)
 * d|ORG_NUMBER_MISMATCH|swishNumber|source=organisationNumber,...    (sorted)
 * total|discrepancyCount
 * </pre>
 *
 * <p>Within a line, list elements are escaped and joined with {@code ,} in
 * the order the report gives them: bank IDs and Swish numbers ascending by
 * raw (unescaped) value, {@code source=organisationNumber} pairs ascending
 * by raw source, then raw organisation number. The JSON lists of the report
 * are in the order of their lines here. The
 * signature, its algorithm and {@code auditEntryHashHex} are not part of the
 * form; {@code canonicalVersion}, {@code discrepancyCount} and
 * {@code zeroDiscrepancies} are fixed by it.</p>
 */
public final class TriangulationCanonicalizer {

    public static final String REPORT_VERSION = "tr1";
    public static final String BANK_INPUT_VERSION = "tri-bank-v1";
    public static final String OPERATOR_INPUT_VERSION = "tri-operator-v1";
    public static final String REGISTRY_INPUT_VERSION = "tri-registry-v1";
    public static final String INPUTS_COMMITMENT_VERSION = "tri-inputs-v1";

    private TriangulationCanonicalizer() {
    }

    // ------------------------------------------------------------------ inputs

    public static String bankHeader(String bankId) {
        return BANK_INPUT_VERSION + '|' + escape(bankId);
    }

    public static String bankEntryLine(String organisationNumber, String swishNumber, String certSerialHex,
                                       String issuerDn) {
        return fields(organisationNumber, swishNumber, certSerialHex, issuerDn);
    }

    public static String operatorHeader(String operatorId) {
        return OPERATOR_INPUT_VERSION + '|' + escape(operatorId);
    }

    public static String operatorEntryLine(String swishNumber, String organisationNumber, String certSerialHex,
                                           String issuerDn) {
        return fields(swishNumber, organisationNumber, certSerialHex, issuerDn);
    }

    public static String registryHeader(String countryCode) {
        return REGISTRY_INPUT_VERSION + '|' + escape(countryCode);
    }

    public static String registryEntryLine(String certSerialHex, String issuerDn, String status,
                                           String verificationId) {
        return fields(certSerialHex, issuerDn, status, verificationId);
    }

    /** The header, then the entry lines sorted; every line LF-terminated. */
    public static byte[] inputBytes(String header, List<String> entryLines) {
        StringBuilder sb = new StringBuilder(header).append('\n');
        entryLines.stream().sorted().forEach(l -> sb.append(l).append('\n'));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** {@code tri-inputs-v1|inquiryId|countryCode}, then the report's {@code in|...} lines. */
    public static byte[] inputsCommitment(String inquiryId, String countryCode,
                                          TriangulationReport.InputDigests digests) {
        StringBuilder sb = new StringBuilder(INPUTS_COMMITMENT_VERSION)
                .append('|').append(escape(inquiryId))
                .append('|').append(escape(countryCode)).append('\n');
        appendInputLines(sb, digests);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ report

    /** The {@code tr1} form of {@code report}; see the class javadoc. */
    public static byte[] canonicalize(TriangulationReport report) {
        StringBuilder sb = new StringBuilder(1024);
        sb.append(REPORT_VERSION)
          .append('|').append(escape(report.inquiryId()))
          .append('|').append(escape(report.countryCode()))
          .append('|').append(escape(report.generatedAt()))
          .append('|').append(escape(report.signingKeyFingerprintHex()))
          .append('\n');
        appendInputLines(sb, report.inputDigests());
        appendSorted(sb, report.swishNumbersMissingFromOperatorReport(), TriangulationCanonicalizer::line);
        appendSorted(sb, report.swishNumbersMissingFromBankReports(), TriangulationCanonicalizer::line);
        appendSorted(sb, report.certificatesWithoutVerifiedAttestation(), TriangulationCanonicalizer::line);
        appendSorted(sb, report.verifiedCertificatesNotReportedByOperator(), TriangulationCanonicalizer::line);
        appendSorted(sb, report.organisationNumberMismatches(), TriangulationCanonicalizer::line);
        sb.append("total|").append(report.discrepancyCount()).append('\n');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static String line(SwishMissingFromOperator d) {
        return "d|SWISH_MISSING_FROM_OPERATOR|" + escape(d.swishNumber()) + '|' + list(d.bankIds());
    }

    public static String line(SwishMissingFromBanks d) {
        return "d|SWISH_MISSING_FROM_BANKS|" + escape(d.swishNumber());
    }

    public static String line(CertificateWithoutVerifiedAttestation d) {
        return "d|CERT_WITHOUT_VERIFIED_ATTESTATION|" + fields(d.certSerialHex(), d.issuerDn(), d.registryStatus(),
                d.verificationId()) + '|' + list(d.swishNumbers());
    }

    public static String line(VerifiedCertificateNotReported d) {
        return "d|VERIFIED_CERT_NOT_REPORTED|" + fields(d.certSerialHex(), d.issuerDn(), d.verificationId());
    }

    public static String line(OrganisationNumberMismatch d) {
        List<String> pairs = new ArrayList<>();
        d.reported().forEach(r -> pairs.add(escape(r.source()) + '=' + escape(r.organisationNumber())));
        return "d|ORG_NUMBER_MISMATCH|" + escape(d.swishNumber()) + '|' + String.join(",", pairs);
    }

    // ------------------------------------------------------------------ helpers

    public static String sha256Hex(byte[] in) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(in));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Escape one field; see the class javadoc. */
    public static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("%", "%25")
                .replace("|", "%7C")
                .replace(",", "%2C")
                .replace("=", "%3D")
                .replace("\n", "%0A")
                .replace("\r", "%0D");
    }

    private static void appendInputLines(StringBuilder sb, TriangulationReport.InputDigests digests) {
        List<String> bankLines = new ArrayList<>();
        for (InputDigest d : digests.bankReports()) {
            bankLines.add("in|bank|" + escape(d.reporterId()) + '|' + d.entryCount() + '|' + escape(d.sha256Hex()));
        }
        bankLines.stream().sorted().forEach(l -> sb.append(l).append('\n'));
        InputDigest op = digests.operatorReport();
        if (op == null) {
            sb.append("in|operator||0|\n");
        } else {
            sb.append("in|operator|").append(escape(op.reporterId())).append('|').append(op.entryCount())
              .append('|').append(escape(op.sha256Hex())).append('\n');
        }
        InputDigest reg = digests.registry();
        sb.append("in|registry|").append(reg.entryCount()).append('|').append(escape(reg.sha256Hex())).append('\n');
    }

    private static <T> void appendSorted(StringBuilder sb, List<T> records, Function<T, String> line) {
        records.stream().map(line).sorted().forEach(l -> sb.append(l).append('\n'));
    }

    private static String fields(String... values) {
        StringJoiner j = new StringJoiner("|");
        for (String v : values) {
            j.add(escape(v));
        }
        return j.toString();
    }

    private static String list(List<String> values) {
        StringJoiner j = new StringJoiner(",");
        values.forEach(v -> j.add(escape(v)));
        return j.toString();
    }
}
