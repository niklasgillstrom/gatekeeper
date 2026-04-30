package eu.gillstrom.gatekeeper.controller;

import java.time.Instant;

/**
 * Operational health snapshot returned by {@code GET /v1/gatekeeper/health}.
 *
 * <p>Distinct from the lightweight {@code /v1/attestation/health} liveness
 * endpoint: the gatekeeper health view also reports tamper-evidence
 * status of the audit log so an operator (or a supervisor's monitoring
 * harness) can fail closed if the chain has been broken.</p>
 *
 * @param auditLogReadable {@code true} iff the audit log file can be
 *     read and parsed
 * @param chainIntact result of {@link
 *     eu.gillstrom.gatekeeper.audit.AuditLog#verifyChainIntegrity()}
 * @param headSequenceNumber sequence of the head entry (0 for empty)
 * @param headTimestamp timestamp of the head entry, or {@code null} for
 *     an empty log
 * @param totalEntries equal to {@code size()} of the audit log
 * @param activeKeyFingerprint fingerprint of the active signing key
 *     (so a supervisor can verify which key the gatekeeper is using)
 * @param mode signing mode — {@code "configured"} or {@code "ephemeral"};
 *     a value of {@code "ephemeral"} is a loud signal that the
 *     gatekeeper is running with a throwaway reference key
 */
public record HealthStatus(
        boolean auditLogReadable,
        boolean chainIntact,
        long headSequenceNumber,
        Instant headTimestamp,
        long totalEntries,
        String activeKeyFingerprint,
        String mode) {
}
