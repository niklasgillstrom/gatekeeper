package eu.gillstrom.gatekeeper.audit;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;

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
 * <h2>Canonical versions</h2>
 *
 * <p>Two canonical forms exist. {@code canonicalVersion == null} (every
 * entry written before the inventory fields existed, and every JSON line
 * that has no such field) is {@code v1}: {@link #canonicalBytesForHash(long,
 * Instant, String, String, String, String, String, boolean, String)}.
 * {@code canonicalVersion == "v2"} is {@link #canonicalBytesForHashV2}: every
 * v1 field plus the inventory fields and {@code prevKeyEntryHashHex}, in a
 * fixed order. Every entry the gatekeeper writes now is v2. The version is
 * itself bound by the hash: the canonical bytes start with {@code v1|} or
 * {@code v2|}, so changing the stored version changes the recomputed hash.</p>
 *
 * <h2>Per-key chain</h2>
 *
 * <p>Besides the global link ({@code prevEntryHashHex}), a v2 entry that
 * carries a {@code keyFingerprintHex} also carries
 * {@code prevKeyEntryHashHex}: the {@code thisEntryHashHex} of the previous
 * entry with the same {@code keyFingerprintHex}, or
 * {@link #SENTINEL_PREV_HASH_HEX} for the first such entry. It is
 * {@code null} when the entry has no key fingerprint. Both links are inside
 * the hashed bytes.</p>
 *
 * <h2>Outside the hash</h2>
 *
 * <p>{@code entrySignatureBase64} and {@code timestampTokenBase64} are not
 * covered by {@code thisEntryHashHex}: both are computed over it. The
 * signature input is unchanged by v2 — the UTF-8 bytes of
 * {@code thisEntryHashHex} — and the RFC 3161 token, when present, is over
 * the SHA-256 of the same bytes.</p>
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
        String entrySignatureBase64,
        // ---- v2 (all nullable; null on v1 entries) ----
        String canonicalVersion,
        String keyFingerprintHex,
        String certSerialHex,
        String certIssuerDn,
        String hsmVendor,
        String hsmSerial,
        String registryStatus,
        String hsmFirmwareVersion,
        String hsmFipsApprovedMode,
        String prevKeyEntryHashHex,
        // ---- outside the hash, like the signature ----
        String timestampTokenBase64) {

    /** Value of {@link #canonicalVersion()} for entries written in the v2 canonical form. */
    public static final String CANONICAL_V2 = "v2";

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

    /**
     * Marker for a {@code null} field in the v2 canonical form. Every field
     * value passes through {@link #safe(String)}, which rewrites each
     * {@code %} to {@code %25} and each {@code |} to {@code %7C}; an escaped
     * value therefore never contains {@code %} followed by {@code N}, so no
     * value — including the empty string — can encode to this marker.
     */
    static final String V2_NULL_MARKER = "%N";

    @JsonCreator
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
     * A v1 entry: the eleven fields of the original record, every v2 field
     * {@code null}. Kept so code that built entries before v2 still compiles.
     */
    public AuditEntry(long sequenceNumber, Instant timestamp, String mtlsClientPrincipal, String operation,
                      String verificationId, String requestDigestBase64, String receiptDigestBase64,
                      boolean compliant, String prevEntryHashHex, String thisEntryHashHex,
                      String entrySignatureBase64) {
        this(sequenceNumber, timestamp, mtlsClientPrincipal, operation, verificationId, requestDigestBase64,
                receiptDigestBase64, compliant, prevEntryHashHex, thisEntryHashHex, entrySignatureBase64,
                null, null, null, null, null, null, null, null, null, null, null);
    }

    /** {@code true} when this entry's hash is computed over the v2 canonical form. Not serialised. */
    @JsonIgnore
    public boolean isV2() {
        return CANONICAL_V2.equals(canonicalVersion);
    }

    /**
     * Whether any field that exists only in v2 — or the timestamp token,
     * which only a v2 writer produces — is set. A v1 entry with such a field
     * carries data its hash does not cover.
     */
    @JsonIgnore
    public boolean hasV2OnlyFields() {
        return keyFingerprintHex != null || certSerialHex != null || certIssuerDn != null
                || hsmVendor != null || hsmSerial != null || registryStatus != null
                || hsmFirmwareVersion != null || hsmFipsApprovedMode != null
                || prevKeyEntryHashHex != null || timestampTokenBase64 != null;
    }

    /** A copy of this entry carrying the given RFC 3161 token (outside the hash). */
    public AuditEntry withTimestampToken(String tokenBase64) {
        return new AuditEntry(sequenceNumber, timestamp, mtlsClientPrincipal, operation, verificationId,
                requestDigestBase64, receiptDigestBase64, compliant, prevEntryHashHex, thisEntryHashHex,
                entrySignatureBase64, canonicalVersion, keyFingerprintHex, certSerialHex, certIssuerDn,
                hsmVendor, hsmSerial, registryStatus, hsmFirmwareVersion, hsmFipsApprovedMode,
                prevKeyEntryHashHex, tokenBase64);
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
     * The v2 canonical form. Every v1 field, in the v1 order, followed by the
     * inventory fields and the per-key link:
     *
     * <p>{@code v2|sequenceNumber|timestamp|principal|operation|
     * verificationId|requestDigest|receiptDigest|compliant|prevEntryHashHex|
     * keyFingerprintHex|certSerialHex|certIssuerDn|hsmVendor|hsmSerial|
     * registryStatus|hsmFirmwareVersion|hsmFipsApprovedMode|
     * prevKeyEntryHashHex}</p>
     *
     * <p>Every value is escaped as in v1 ({@code %} → {@code %25},
     * {@code |} → {@code %7C}). A {@code null} — including a {@code null}
     * receipt digest, which v1 rendered as {@code <no-receipt>} — is written
     * as {@link #V2_NULL_MARKER} ({@code %N}), which no escaped value can
     * equal. {@code compliant} is {@code true} or {@code false};
     * {@code timestamp} is {@link Instant#toString()}.</p>
     */
    public static byte[] canonicalBytesForHashV2(
            long sequenceNumber,
            Instant timestamp,
            String mtlsClientPrincipal,
            String operation,
            String verificationId,
            String requestDigestBase64,
            String receiptDigestBase64,
            boolean compliant,
            String prevEntryHashHex,
            String keyFingerprintHex,
            String certSerialHex,
            String certIssuerDn,
            String hsmVendor,
            String hsmSerial,
            String registryStatus,
            String hsmFirmwareVersion,
            String hsmFipsApprovedMode,
            String prevKeyEntryHashHex) {

        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Objects.requireNonNull(mtlsClientPrincipal, "mtlsClientPrincipal must not be null");
        Objects.requireNonNull(operation, "operation must not be null");
        Objects.requireNonNull(verificationId, "verificationId must not be null");
        Objects.requireNonNull(requestDigestBase64, "requestDigestBase64 must not be null");
        Objects.requireNonNull(prevEntryHashHex, "prevEntryHashHex must not be null");

        StringBuilder sb = new StringBuilder(512);
        sb.append(CANONICAL_V2).append('|')
          .append(sequenceNumber).append('|')
          .append(timestamp.toString()).append('|')
          .append(v2(mtlsClientPrincipal)).append('|')
          .append(v2(operation)).append('|')
          .append(v2(verificationId)).append('|')
          .append(v2(requestDigestBase64)).append('|')
          .append(v2(receiptDigestBase64)).append('|')
          .append(Boolean.toString(compliant)).append('|')
          .append(v2(prevEntryHashHex)).append('|')
          .append(v2(keyFingerprintHex)).append('|')
          .append(v2(certSerialHex)).append('|')
          .append(v2(certIssuerDn)).append('|')
          .append(v2(hsmVendor)).append('|')
          .append(v2(hsmSerial)).append('|')
          .append(v2(registryStatus)).append('|')
          .append(v2(hsmFirmwareVersion)).append('|')
          .append(v2(hsmFipsApprovedMode)).append('|')
          .append(v2(prevKeyEntryHashHex));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Canonical hash bytes of an already-constructed entry, in the form its
     * {@code canonicalVersion} names: v1 when {@code null}, v2 when
     * {@code "v2"}. Used during chain validation.
     *
     * @throws IllegalArgumentException for any other version string — an
     *     entry claiming a form this code does not know cannot be verified
     */
    public static byte[] canonicalBytesForHash(AuditEntry e) {
        Objects.requireNonNull(e, "entry must not be null");
        if (e.canonicalVersion() == null) {
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
        if (e.isV2()) {
            return canonicalBytesForHashV2(
                    e.sequenceNumber(),
                    e.timestamp(),
                    e.mtlsClientPrincipal(),
                    e.operation(),
                    e.verificationId(),
                    e.requestDigestBase64(),
                    e.receiptDigestBase64(),
                    e.compliant(),
                    e.prevEntryHashHex(),
                    e.keyFingerprintHex(),
                    e.certSerialHex(),
                    e.certIssuerDn(),
                    e.hsmVendor(),
                    e.hsmSerial(),
                    e.registryStatus(),
                    e.hsmFirmwareVersion(),
                    e.hsmFipsApprovedMode(),
                    e.prevKeyEntryHashHex());
        }
        throw new IllegalArgumentException("Unknown audit entry canonicalVersion '" + e.canonicalVersion()
                + "' at sequenceNumber " + e.sequenceNumber());
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

    private static String v2(String s) {
        return s == null ? V2_NULL_MARKER : safe(s);
    }
}
