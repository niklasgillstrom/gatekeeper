package eu.gillstrom.gatekeeper.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response to an issuance confirmation (Step 7).
 *
 * EBA returns this after receiving the confirmation from GetSwish AB,
 * indicating whether the issued certificate matches the approved
 * attestation evidence, and updating the approval registry accordingly.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IssuanceConfirmationResponse {

    /**
     * The EBA verification ID linking to the original verification.
     */
    private String verificationId;

    /**
     * Whether the loop was closed successfully.
     */
    private boolean loopClosed;

    /**
     * If a certificate was submitted: whether the public key in the
     * certificate matches the public key from the approved attestation.
     * Null if the confirmation was a non-issuance notice.
     */
    private Boolean publicKeyMatch;

    /**
     * The public key fingerprint from the original attestation verification.
     */
    private String expectedPublicKeyFingerprint;

    /**
     * The public key fingerprint extracted from the submitted certificate.
     * Null if the confirmation was a non-issuance notice.
     */
    private String actualPublicKeyFingerprint;

    /**
     * Final status in the approval registry after this confirmation.
     */
    private RegistryStatus registryStatus;

    /**
     * ISO 8601 timestamp of when EBA processed this confirmation.
     */
    private String processedTimestamp;

    /**
     * Any anomalies detected during the confirmation.
     * E.g. public key mismatch, confirmation for unknown verification ID,
     * certificate issued despite NON-COMPLIANT status.
     */
    private java.util.List<String> anomalies;

    public enum RegistryStatus {
        /** Attestation approved, certificate issued, public key matches. */
        VERIFIED_AND_ISSUED,
        /** Attestation approved, certificate not issued (TL withdrew etc). */
        VERIFIED_NOT_ISSUED,
        /** Attestation rejected, certificate correctly not issued. */
        REJECTED_NOT_ISSUED,
        /** ANOMALY: Certificate issued despite rejection. */
        ANOMALY_ISSUED_DESPITE_REJECTION,
        /** ANOMALY: Public key in certificate does not match attestation. */
        ANOMALY_PUBLIC_KEY_MISMATCH,
        /** ANOMALY: Confirmation received for unknown verification ID. */
        ANOMALY_UNKNOWN_VERIFICATION
    }
}
