package eu.gillstrom.gatekeeper.model;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Answer to a {@code ROTATED}, {@code REVOKED} or {@code DECOMMISSIONED}
 * event on {@code POST /v1/attestation/{countryCode}/lifecycle}.
 *
 * <p>{@code reason} is a code, as on the settlement answer:</p>
 * <ul>
 *   <li>{@code OK} (HTTP 200) — the status change was applied.</li>
 *   <li>{@code CERT_NOT_FOUND} (404) — no certificate stored at Step 7 for
 *       {@code (certSerial, issuerDn)} in this jurisdiction that the caller
 *       may act on.</li>
 *   <li>{@code TRANSITION_NOT_ALLOWED} (409) — the change is not allowed
 *       from the entry's current status ({@code previousStatus}).</li>
 *   <li>{@code SUCCESSOR_NOT_FOUND} (409) — a {@code ROTATED} event named a
 *       {@code successorVerificationId} that is not a registry entry in this
 *       jurisdiction, or is the rotated entry itself.</li>
 *   <li>{@code MALFORMED_INPUT} (400) — {@code certSerial} or
 *       {@code issuerDn} cannot be parsed.</li>
 * </ul>
 *
 * <p>Not signed. {@code auditEntryHashHex} identifies the audit entry that
 * records the event, which is signed.</p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyStatusChangeResponse {

    /** {@code ROTATED}, {@code REVOKED} or {@code DECOMMISSIONED}. */
    private String eventType;

    /** The registry entry the certificate belongs to; {@code null} when none was found. */
    private String verificationId;

    /** Whether the status change was applied. */
    private boolean applied;

    /** Status before the event; {@code null} when no entry was found. */
    private RegistryStatus previousStatus;

    /** Status after the event (unchanged unless applied); {@code null} when no entry was found. */
    private RegistryStatus registryStatus;

    /** For an applied {@code ROTATED}: the successor's verificationId, when given. */
    private String successorVerificationId;

    /** Result code, see class javadoc. */
    private String reason;

    /** ISO-8601 instant the gatekeeper processed the event. */
    private String processedAt;

    /** {@code thisEntryHashHex} of the audit entry written for this event. */
    private String auditEntryHashHex;
}
