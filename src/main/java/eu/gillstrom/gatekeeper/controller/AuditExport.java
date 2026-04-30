package eu.gillstrom.gatekeeper.controller;

import eu.gillstrom.gatekeeper.audit.AuditEntry;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Tamper-evident export bundle returned by
 * {@code GET /v1/audit/export?from=...&to=...}.
 *
 * <p>This is the artefact a supervisory inspection team requests when
 * opening an enquiry: a single self-contained, signed JSON document
 * containing every audit entry in the requested time window plus the
 * head hash of the chain at the moment of export, all sealed under the
 * gatekeeper's active signing key.</p>
 *
 * <p>The signature covers the canonical byte representation produced by
 * {@link #canonicalBytesForSignature}, which is a fixed-format pipe-
 * delimited string of every field except the signature itself. Verifying
 * the export is therefore a strictly mechanical operation that can be
 * carried out by any party in possession of the public key from
 * {@code GET /v1/gatekeeper/keys}.</p>
 *
 * <p>Legal basis: DORA Article 28(6) (5-year retention; supervisory
 * exports must be tamper-evident); EBA Regulation 1093/2010 Article
 * 35(1) (supervisory access).</p>
 */
public record AuditExport(
        String inspectionId,
        Instant generatedAt,
        Instant rangeFrom,
        Instant rangeTo,
        long entryCount,
        List<AuditEntry> entries,
        String chainHeadHashAtExport,
        String exportSignatureBase64,
        String signingKeyFingerprintHex) {

    public AuditExport {
        Objects.requireNonNull(inspectionId, "inspectionId must not be null");
        Objects.requireNonNull(generatedAt, "generatedAt must not be null");
        Objects.requireNonNull(rangeFrom, "rangeFrom must not be null");
        Objects.requireNonNull(rangeTo, "rangeTo must not be null");
        Objects.requireNonNull(entries, "entries must not be null");
        Objects.requireNonNull(chainHeadHashAtExport, "chainHeadHashAtExport must not be null");
        Objects.requireNonNull(exportSignatureBase64, "exportSignatureBase64 must not be null");
        Objects.requireNonNull(signingKeyFingerprintHex, "signingKeyFingerprintHex must not be null");
    }

    /**
     * Canonical byte representation signed by the gatekeeper. The
     * signature MUST cover every field that affects a supervisor's
     * conclusions about the export — anything missing here is, by
     * construction, not authenticated.
     *
     * <p>Order: {@code v1|inspectionId|generatedAt|rangeFrom|rangeTo|
     * entryCount|chainHeadHashAtExport|signingKeyFingerprintHex|
     * thisHash_1|thisHash_2|...|thisHash_n}. Including each entry's
     * {@code thisEntryHashHex} (rather than the full entry) is sufficient
     * because each thisHash uniquely identifies the entry's content under
     * SHA-256 — a forged export with substituted entries cannot match
     * the listed hashes.</p>
     */
    public static byte[] canonicalBytesForSignature(
            String inspectionId,
            Instant generatedAt,
            Instant rangeFrom,
            Instant rangeTo,
            long entryCount,
            List<AuditEntry> entries,
            String chainHeadHashAtExport,
            String signingKeyFingerprintHex) {
        StringBuilder sb = new StringBuilder(256 + entries.size() * 70);
        sb.append("v1").append('|')
          .append(safe(inspectionId)).append('|')
          .append(generatedAt.toString()).append('|')
          .append(rangeFrom.toString()).append('|')
          .append(rangeTo.toString()).append('|')
          .append(entryCount).append('|')
          .append(safe(chainHeadHashAtExport)).append('|')
          .append(safe(signingKeyFingerprintHex));
        for (AuditEntry e : entries) {
            sb.append('|').append(safe(e.thisEntryHashHex()));
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String safe(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("%", "%25").replace("|", "%7C");
    }
}
