package eu.gillstrom.gatekeeper.timestamp;

import java.time.Instant;
import java.util.Objects;

/**
 * One RFC 3161 anchor of the audit-chain head, as persisted (one JSON line
 * each) in the anchor file beside the audit log and as served by
 * {@code GET /v1/gatekeeper/anchor} and
 * {@code GET /v1/gatekeeper/anchor/timestamps}.
 *
 * @param headSequenceNumber sequence number of the head entry that was
 *     time-stamped
 * @param headHashHex that entry's {@code thisEntryHashHex}; the token's
 *     message imprint is SHA-256 over the UTF-8 bytes of this string — the
 *     same bytes the entry signature and the signed anchor cover
 * @param tokenBase64 the DER {@code TimeStampToken}, Base64
 * @param genTime the token's {@code genTime}, copied for convenience; the
 *     value inside the token is authoritative, and the audit log's chain
 *     check fails when the copy differs from it
 */
public record TimestampAnchorRecord(long headSequenceNumber, String headHashHex, String tokenBase64,
                                    Instant genTime) {

    public TimestampAnchorRecord {
        Objects.requireNonNull(headHashHex, "headHashHex");
        Objects.requireNonNull(tokenBase64, "tokenBase64");
        if (headSequenceNumber < 1) {
            throw new IllegalArgumentException("headSequenceNumber must be >= 1");
        }
    }
}
