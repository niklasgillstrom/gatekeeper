package eu.gillstrom.gatekeeper.model;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Issuance Confirmation — Step 7 of the verification flow.
 * 
 * Sent by GetSwish AB (or the issuing bank) back to EBA after
 * the certificate issuance decision. Closes the verification loop
 * by allowing EBA to independently verify that the issued certificate
 * matches the attestation evidence approved in Step 3.
 * 
 * This confirmation is cryptographic, not contractual: EBA extracts
 * the public key from the submitted certificate and verifies that
 * it matches the attestation evidence — it does not rely on
 * GetSwish AB's assertion.
 */
@Data
public class IssuanceConfirmation {

    /**
     * The EBA verification ID from the signed receipt (Step 5).
     * Links this confirmation to the original verification request.
     */
    @NotBlank(message = "Verification ID is required")
    private String verificationId;

    /**
     * Server-issued single-use nonce returned by the gatekeeper in the
     * verify response (`VerificationResponse.confirmationNonce`).
     * The financial entity must echo this exact value back when calling
     * confirm; the gatekeeper rejects the confirm with HTTP 400 if the
     * submitted nonce does not match the one bound to the
     * verificationId at verify time. This binds the confirm call to the
     * original verify call and prevents replay by an attacker who has
     * obtained a valid issuer-CA-chained certificate and learned a
     * verificationId out of band.
     */
    @NotBlank(message = "Confirmation nonce is required")
    private String confirmationNonce;

    /**
     * Whether the certificate was issued or refused.
     */
    private boolean issued;

    /**
     * If issued: the full signing certificate in PEM format.
     * EBA extracts the public key and verifies it matches the
     * attestation evidence approved in Step 3.
     * Null if not issued.
     */
    private String signingCertificatePem;

    /**
     * ISO 8601 timestamp of the issuance or refusal.
     */
    @NotBlank(message = "Timestamp is required")
    private String timestamp;

    /**
     * If not issued: reason for non-issuance.
     * E.g. "NON-COMPLIANT attestation", "Technical supplier withdrew request"
     */
    private String nonIssuanceReason;

    /**
     * The Swish number associated with this certificate.
     */
    private String swishNumber;

    /**
     * Organisation number of the corporate customer.
     */
    private String organisationNumber;
}
