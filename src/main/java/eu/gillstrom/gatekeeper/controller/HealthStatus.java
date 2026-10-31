package eu.gillstrom.gatekeeper.controller;

import com.fasterxml.jackson.annotation.JsonInclude;

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
 * @param chainIntact most recent result of {@link
 *     eu.gillstrom.gatekeeper.audit.AuditLog#verifyChainIntegrity()},
 *     served from the cache described on {@link
 *     eu.gillstrom.gatekeeper.audit.AuditLog#cachedIntegrityStatus()}
 * @param chainCheckedAt when {@code chainIntact} was computed. The value
 *     is deliberately exposed: a monitoring system needs to know how stale
 *     the integrity answer is, and an operator who wants a fresher one
 *     lowers {@code gatekeeper.audit.integrity-check-interval-seconds}.
 *     {@code null} means no check has completed yet
 * @param headSequenceNumber sequence of the head entry (0 for empty)
 * @param headTimestamp timestamp of the head entry, or {@code null} for
 *     an empty log
 * @param totalEntries equal to {@code size()} of the audit log
 * @param activeKeyFingerprint fingerprint of the active signing key
 *     (so a supervisor can verify which key the gatekeeper is using)
 * @param mode signing mode — {@code "configured"} or {@code "ephemeral"};
 *     a value of {@code "ephemeral"} is a loud signal that the
 *     gatekeeper is running with a throwaway reference key
 * @param activeKeyAttested whether the HSM attestation of the active signing
 *     key was verified at start-up ({@code gatekeeper.signing.attestation.*}).
 *     Present only when attestation is configured — and then {@code true},
 *     because an attestation that does not verify stops start-up. Absent
 *     means not configured, i.e. not attested; a monitor that requires an
 *     attested key checks for {@code activeKeyAttested == true}
 * @param timestampingMode {@code "entry"} or {@code "anchor"}; absent when
 *     {@code gatekeeper.timestamping.mode=off}
 * @param untimestampedEntries {@code entry} mode only: entries in the chain
 *     without an RFC 3161 token — written while the TSA failed, or before the
 *     mode was enabled
 * @param latestTimestampAnchorSequenceNumber {@code anchor} mode only: head
 *     sequence number of the latest anchor record, absent before the first
 * @param latestTimestampAnchorGenTime {@code anchor} mode only: its
 *     {@code genTime}
 */
public record HealthStatus(
        boolean auditLogReadable,
        boolean chainIntact,
        Instant chainCheckedAt,
        long headSequenceNumber,
        Instant headTimestamp,
        long totalEntries,
        String activeKeyFingerprint,
        String mode,
        @JsonInclude(JsonInclude.Include.NON_NULL) Boolean activeKeyAttested,
        @JsonInclude(JsonInclude.Include.NON_NULL) String timestampingMode,
        @JsonInclude(JsonInclude.Include.NON_NULL) Long untimestampedEntries,
        @JsonInclude(JsonInclude.Include.NON_NULL) Long latestTimestampAnchorSequenceNumber,
        @JsonInclude(JsonInclude.Include.NON_NULL) Instant latestTimestampAnchorGenTime) {

    /** The eight fields of the original health record; every optional field absent. */
    public HealthStatus(boolean auditLogReadable, boolean chainIntact, Instant chainCheckedAt,
                        long headSequenceNumber, Instant headTimestamp, long totalEntries,
                        String activeKeyFingerprint, String mode) {
        this(auditLogReadable, chainIntact, chainCheckedAt, headSequenceNumber, headTimestamp, totalEntries,
                activeKeyFingerprint, mode, null, null, null, null, null);
    }
}
