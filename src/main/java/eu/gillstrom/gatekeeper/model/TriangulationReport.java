package eu.gillstrom.gatekeeper.model;

import java.util.List;

/**
 * The discrepancy report of a triangulation inquiry:
 * {@code GET /v1/triangulation/{countryCode}/inquiries/{inquiryId}/discrepancies}.
 *
 * <p>Compares the bank reports, the operator report and the gatekeeper's
 * approval registry for the jurisdiction. Five kinds of discrepancy, each
 * a list sorted by its canonical line
 * ({@code eu.gillstrom.gatekeeper.signing.TriangulationCanonicalizer}):</p>
 * <ul>
 *   <li>{@code swishNumbersMissingFromOperatorReport} — in some bank report,
 *       not in the operator report.</li>
 *   <li>{@code swishNumbersMissingFromBankReports} — in the operator report,
 *       in no bank report.</li>
 *   <li>{@code certificatesWithoutVerifiedAttestation} — reported by the
 *       operator, with no registry entry of this jurisdiction in
 *       {@code VERIFIED_AND_ISSUED} for that serial and issuer.</li>
 *   <li>{@code verifiedCertificatesNotReportedByOperator} — in
 *       {@code VERIFIED_AND_ISSUED} in the registry, not in the operator
 *       report.</li>
 *   <li>{@code organisationNumberMismatches} — one Swish number reported
 *       with more than one organisation number.</li>
 * </ul>
 *
 * <p>{@code zeroDiscrepancies} is {@code true} when {@code discrepancyCount}
 * is 0 and the inquiry holds an operator report and at least one bank report
 * ({@code inputDigests}): with a side missing nothing has been compared, and
 * the field is {@code false} whatever the count.</p>
 *
 * <p>{@code reportSignatureBase64} is the gatekeeper's signature over the
 * canonical form of every field except itself, {@code signatureAlgorithm}
 * and {@code auditEntryHashHex}. {@code auditEntryHashHex} names the
 * {@code TRIANGULATION} audit entry, whose {@code receiptDigestBase64} is the
 * SHA-256 of that canonical form.</p>
 */
public record TriangulationReport(
        String canonicalVersion,
        String inquiryId,
        String countryCode,
        String generatedAt,
        InputDigests inputDigests,
        List<SwishMissingFromOperator> swishNumbersMissingFromOperatorReport,
        List<SwishMissingFromBanks> swishNumbersMissingFromBankReports,
        List<CertificateWithoutVerifiedAttestation> certificatesWithoutVerifiedAttestation,
        List<VerifiedCertificateNotReported> verifiedCertificatesNotReportedByOperator,
        List<OrganisationNumberMismatch> organisationNumberMismatches,
        int discrepancyCount,
        boolean zeroDiscrepancies,
        String signingKeyFingerprintHex,
        String reportSignatureBase64,
        String signatureAlgorithm,
        String auditEntryHashHex) {

    /** This report with its seal and audit link set. */
    public TriangulationReport sealed(String signatureBase64, String algorithm, String auditHashHex) {
        return new TriangulationReport(canonicalVersion, inquiryId, countryCode, generatedAt, inputDigests,
                swishNumbersMissingFromOperatorReport, swishNumbersMissingFromBankReports,
                certificatesWithoutVerifiedAttestation, verifiedCertificatesNotReportedByOperator,
                organisationNumberMismatches, discrepancyCount, zeroDiscrepancies, signingKeyFingerprintHex,
                signatureBase64, algorithm, auditHashHex);
    }

    /**
     * SHA-256 digests of the canonical inputs.
     *
     * @param bankReports one per {@code bankId}, sorted by {@code bankId}
     * @param operatorReport {@code null} when no operator report was received
     * @param registry the registry rows of the jurisdiction that hold an issued certificate
     */
    public record InputDigests(List<InputDigest> bankReports, InputDigest operatorReport, InputDigest registry) {
    }

    /**
     * @param reporterId {@code bankId}, {@code operatorId}, or {@code null} for the registry
     * @param entryCount lines in the canonical input after its header
     * @param sha256Hex lower-case hex SHA-256 of the canonical input
     */
    public record InputDigest(String reporterId, int entryCount, String sha256Hex) {
    }

    /** @param bankIds the banks that reported the number, sorted */
    public record SwishMissingFromOperator(String swishNumber, List<String> bankIds) {
    }

    public record SwishMissingFromBanks(String swishNumber) {
    }

    /**
     * @param certSerialHex serial, lower-case hex without leading zeros
     * @param issuerDn issuer in RFC 2253 form, as first reported
     * @param registryStatus the entry's status ({@code SUPERSEDED},
     *     {@code REVOKED} or {@code DECOMMISSIONED} — only
     *     {@code VERIFIED_AND_ISSUED} confirmations store a certificate), or
     *     {@code NOT_IN_REGISTRY}
     * @param verificationId the registry entry, {@code null} for {@code NOT_IN_REGISTRY}
     * @param swishNumbers the Swish numbers the operator reported with the certificate, sorted
     */
    public record CertificateWithoutVerifiedAttestation(String certSerialHex, String issuerDn,
                                                        String registryStatus, String verificationId,
                                                        List<String> swishNumbers) {
    }

    public record VerifiedCertificateNotReported(String certSerialHex, String issuerDn, String verificationId) {
    }

    /** @param reported every distinct (source, organisation number) pair, sorted */
    public record OrganisationNumberMismatch(String swishNumber, List<SourcedOrganisationNumber> reported) {
    }

    /** @param source {@code bank:<bankId>} or {@code operator:<operatorId>} */
    public record SourcedOrganisationNumber(String source, String organisationNumber) {
    }
}
