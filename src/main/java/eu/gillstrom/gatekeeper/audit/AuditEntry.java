package eu.gillstrom.gatekeeper.audit;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;

/**
 * A single tamper-evident entry in the gatekeeper's hash-chained audit log.
 *
 * <p>Each entry is a node in a Merkle-style hash chain: every entry's
 * {@code prevEntryHashHex} references the {@code thisEntryHashHex} of its
 * predecessor, and {@code thisEntryHashHex} is computed deterministically
 * over the entry's decision-relevant fields plus the predecessor hash.
 * Modifying any historical entry breaks the chain at that point and at
 * every entry that follows; {@link AuditLog#verifyChainIntegrity()}
 * detects any such modification.</p>
 *
 * <p>The first entry in a fresh log uses 64 ASCII zeros
 * ({@link #SENTINEL_PREV_HASH_HEX}) as its predecessor hash so that
 * "empty log" is a deterministic, well-known starting point rather than
 * an implicit nullable value.</p>
 *
 * <p>Each entry is additionally signed by the gatekeeper's
 * {@link eu.gillstrom.gatekeeper.signing.ReceiptSigner} (in production,
 * the NCA's organisation-certificate-backed signing key — the certificate
 * the NCA uses for ordinary administrative signing of supervisory acts)
 * over the hex bytes of {@code thisEntryHashHex}. The signature binds
 * the entry to the gatekeeper's signing key at the moment of write, so
 * that retroactive fabrication of an entire alternate chain by an
 * attacker who controls the storage layer is also infeasible without
 * compromising the signing private key.</p>
 *
 * <p>Legal basis:</p>
 * <ul>
 *   <li>DORA (EU 2022/2554) Article 28(6) — 5-year retention of records
 *       relating to ICT third-party service providers (gatekeeper
 *       receipts and the audit trail that links them are precisely such
 *       records).</li>
 *   <li>DORA Article 5(2)(b), 9(3)(c) — authenticity and integrity of
 *       financial records.</li>
 *   <li>EBA Regulation (EU) 1093/2010 Article 35(1) — supervisory
 *       access to records.</li>
 * </ul>
 */
public record AuditEntry(
        long sequenceNumber,
        Instant timestamp,
        String mtlsClientPrincipal,
        String operation,
        String verificationId,
        String requestDigestBase64,
        String receiptDigestBase64,
        boolean compliant,
        String prevEntryHashHex,
        String thisEntryHashHex,
        String entrySignatureBase64) {

    /**
     * Sentinel predecessor hash for the first entry in the chain. Sixty-four
     * ASCII zeros — the hex form of the 32-byte all-zero "empty" digest.
     */
    public static final String SENTINEL_PREV_HASH_HEX =
            "0000000000000000000000000000000000000000000000000000000000000000";

    /**
     * Marker value for a missing receipt digest in the canonical form. The
     * value is chosen so it cannot collide with a real Base64-encoded
     * SHA-256 digest (which always has length 44 and ends in {@code =}).
     */
    private static final String NO_RECEIPT_MARKER = "<no-receipt>";

    public AuditEntry {
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Objects.requireNonNull(mtlsClientPrincipal, "mtlsClientPrincipal must not be null");
        Objects.requireNonNull(operation, "operation must not be null");
        Objects.requireNonNull(verificationId, "verificationId must not be null");
        Objects.requireNonNull(requestDigestBase64, "requestDigestBase64 must not be null");
        Objects.requireNonNull(prevEntryHashHex, "prevEntryHashHex must not be null");
        Objects.requireNonNull(thisEntryHashHex, "thisEntryHashHex must not be null");
        Objects.requireNonNull(entrySignatureBase64, "entrySignatureBase64 must not be null");
        if (sequenceNumber < 1) {
            throw new IllegalArgumentException("sequenceNumber must be >= 1, got " + sequenceNumber);
        }
        if (prevEntryHashHex.length() != 64) {
            throw new IllegalArgumentException("prevEntryHashHex must be 64 hex chars, got " + prevEntryHashHex.length());
        }
        if (thisEntryHashHex.length() != 64) {
            throw new IllegalArgumentException("thisEntryHashHex must be 64 hex chars, got " + thisEntryHashHex.length());
        }
    }

    /**
     * Build the canonical byte representation that {@code thisEntryHashHex}
     * is computed over. The format is fixed and pipe-delimited; pipe
     * characters in field values are percent-encoded so a malicious value
     * cannot desynchronise the canonical form. {@code receiptDigestBase64}
     * is rendered as {@link #NO_RECEIPT_MARKER} when {@code null}.
     *
     * <p>Order: {@code v1|sequenceNumber|timestamp|principal|operation|
     * verificationId|requestDigest|receiptDigestOrMarker|compliant|
     * prevEntryHashHex}.</p>
     */
    public static byte[] canonicalBytesForHash(
            long sequenceNumber,
            Instant timestamp,
            String mtlsClientPrincipal,
            String operation,
            String verificationId,
            String requestDigestBase64,
            String receiptDigestBase64,
            boolean compliant,
            String prevEntryHashHex) {

        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Objects.requireNonNull(mtlsClientPrincipal, "mtlsClientPrincipal must not be null");
        Objects.requireNonNull(operation, "operation must not be null");
        Objects.requireNonNull(verificationId, "verificationId must not be null");
        Objects.requireNonNull(requestDigestBase64, "requestDigestBase64 must not be null");
        Objects.requireNonNull(prevEntryHashHex, "prevEntryHashHex must not be null");

        StringBuilder sb = new StringBuilder(256);
        sb.append("v1").append('|')
          .append(sequenceNumber).append('|')
          .append(timestamp.toString()).append('|')
          .append(safe(mtlsClientPrincipal)).append('|')
          .append(safe(operation)).append('|')
          .append(safe(verificationId)).append('|')
          .append(safe(requestDigestBase64)).append('|')
          .append(receiptDigestBase64 == null ? NO_RECEIPT_MARKER : safe(receiptDigestBase64)).append('|')
          .append(Boolean.toString(compliant)).append('|')
          .append(prevEntryHashHex);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Convenience overload that derives the canonical hash bytes from an
     * already-constructed entry. Used during chain validation.
     */
    public static byte[] canonicalBytesForHash(AuditEntry e) {
        Objects.requireNonNull(e, "entry must not be null");
        return canonicalBytesForHash(
                e.sequenceNumber(),
                e.timestamp(),
                e.mtlsClientPrincipal(),
                e.operation(),
                e.verificationId(),
                e.requestDigestBase64(),
                e.receiptDigestBase64(),
                e.compliant(),
                e.prevEntryHashHex());
    }

    /**
     * Bytes the gatekeeper's seal signs over for this entry. Signing the
     * hex form of the chain hash (rather than the raw 32-byte digest)
     * keeps the signature input identical to what is published in the
     * JSON-Lines storage form, simplifying retroactive verification by
     * a supervisor.
     */
    public static byte[] canonicalBytesForSignature(String thisEntryHashHex) {
        Objects.requireNonNull(thisEntryHashHex, "thisEntryHashHex must not be null");
        return thisEntryHashHex.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Convenience overload for an already-constructed entry.
     */
    public static byte[] canonicalBytesForSignature(AuditEntry e) {
        Objects.requireNonNull(e, "entry must not be null");
        return canonicalBytesForSignature(e.thisEntryHashHex());
    }

    private static String safe(String s) {
        return s.replace("%", "%25").replace("|", "%7C");
    }
}
