package eu.gillstrom.gatekeeper.controller;

import com.fasterxml.jackson.annotation.JsonInclude;
import eu.gillstrom.gatekeeper.timestamp.TimestampAnchorRecord;

import java.time.Instant;

/**
 * Snapshot of the audit-chain head, signed by the gatekeeper's active key.
 *
 * <p>An anchor is the supervisor's commitment artefact: published
 * periodically (typically daily) by Finansinspektionen / EBA to a public
 * commitment log, it pins the audit trail to a point in time. Any
 * subsequent retroactive modification of an audit entry produced before
 * the anchor was published is detectable by recomputing the chain hash
 * up to {@code headSequenceNumber} and comparing against
 * {@code headHashHex}.</p>
 *
 * <p>Fields:</p>
 * <ul>
 *   <li>{@code headSequenceNumber} — sequence of the latest entry at
 *       the time the anchor was generated.</li>
 *   <li>{@code headHashHex} — hex SHA-256 of that entry's canonical
 *       bytes (its {@code thisEntryHashHex}).</li>
 *   <li>{@code headTimestamp} — timestamp recorded on the head entry.</li>
 *   <li>{@code headSignatureBase64} — gatekeeper's signature over the
 *       UTF-8 bytes of {@code headHashHex}, and over nothing else in this
 *       record. {@code headSequenceNumber} and {@code headTimestamp} are
 *       covered by that hash, so whoever holds the head entry can check
 *       them; {@code totalEntries} is not signed, and the anchor carries no
 *       time of its own.</li>
 *   <li>{@code signingKeyFingerprintHex} — fingerprint of the gatekeeper
 *       key that produced {@code headSignatureBase64}; allows a relying
 *       party to look up the certificate via
 *       {@code GET /v1/gatekeeper/keys}.</li>
 *   <li>{@code totalEntries} — convenience: equal to
 *       {@code headSequenceNumber} for a strictly monotonic chain, but
 *       returned independently so a supervisor cannot be misled by a
 *       buggy implementation that double-counts.</li>
 *   <li>{@code latestTimestamp} — the most recent RFC 3161 anchor record
 *       ({@code headSequenceNumber}, {@code headHashHex},
 *       {@code tokenBase64}, {@code genTime}) when the anchor file holds one
 *       (i.e. {@code gatekeeper.timestamping.mode=anchor}, or trusted TSA
 *       certificates configured and anchors on disk). It may name an older
 *       head than {@code headSequenceNumber}. Absent from the JSON otherwise,
 *       so the default output is unchanged.</li>
 * </ul>
 *
 * <p>Legal basis: DORA Regulation (EU) 2022/2554 Article 28(6) (5-year
 * retention); EBA Regulation (EU) 1093/2010 Article 35(1) (supervisory
 * access). The anchor is signed with the NCA's organisation-certificate-
 * backed signing key per its ordinary administrative signing practice.</p>
 */
public record AuditAnchor(
        long headSequenceNumber,
        String headHashHex,
        Instant headTimestamp,
        String headSignatureBase64,
        String signingKeyFingerprintHex,
        long totalEntries,
        @JsonInclude(JsonInclude.Include.NON_NULL) TimestampAnchorRecord latestTimestamp) {

    /** An anchor without an RFC 3161 record. */
    public AuditAnchor(long headSequenceNumber, String headHashHex, Instant headTimestamp,
                       String headSignatureBase64, String signingKeyFingerprintHex, long totalEntries) {
        this(headSequenceNumber, headHashHex, headTimestamp, headSignatureBase64, signingKeyFingerprintHex,
                totalEntries, null);
    }
}
