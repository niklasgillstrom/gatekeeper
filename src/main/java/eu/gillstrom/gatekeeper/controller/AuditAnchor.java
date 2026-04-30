package eu.gillstrom.gatekeeper.controller;

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
 *       UTF-8 bytes of {@code headHashHex}.</li>
 *   <li>{@code signingKeyFingerprintHex} — fingerprint of the gatekeeper
 *       key that produced {@code headSignatureBase64}; allows a relying
 *       party to look up the certificate via
 *       {@code GET /v1/gatekeeper/keys}.</li>
 *   <li>{@code totalEntries} — convenience: equal to
 *       {@code headSequenceNumber} for a strictly monotonic chain, but
 *       returned independently so a supervisor cannot be misled by a
 *       buggy implementation that double-counts.</li>
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
        long totalEntries) {
}
