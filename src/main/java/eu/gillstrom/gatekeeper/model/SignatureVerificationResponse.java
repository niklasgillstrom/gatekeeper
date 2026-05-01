package eu.gillstrom.gatekeeper.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Result of a settlement-time signature verification.
 *
 * <p>{@code signatureValid} reports whether the cryptographic verification
 * succeeded against the certificate's public key. {@code compliant} reports
 * whether the certificate corresponds to a gatekeeper audit entry that
 * passed structural-independence and HSM-attestation checks at issuance.
 *
 * <p>The settlement-rail enforcement layer (railgate) allows settlement
 * if and only if both flags are true. Any false value triggers default-deny.
 *
 * <p>{@code reason} is one of:
 * <ul>
 *   <li>{@code OK} — verification passed</li>
 *   <li>{@code CERT_NOT_FOUND} — no audit entry for this certSerial</li>
 *   <li>{@code SIGNATURE_INVALID} — cryptographic verification failed</li>
 *   <li>{@code CERT_NON_COMPLIANT} — cert exists but did not pass
 *       structural compliance at issuance</li>
 *   <li>{@code MALFORMED_INPUT} — request fields could not be parsed</li>
 *   <li>{@code ALGORITHM_NOT_SUPPORTED} — algorithm parameter unrecognised</li>
 * </ul>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignatureVerificationResponse {

    private boolean signatureValid;

    private boolean compliant;

    private String auditEntryId;

    private String reason;
}
