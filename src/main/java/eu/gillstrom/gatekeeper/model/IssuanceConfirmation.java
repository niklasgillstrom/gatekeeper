package eu.gillstrom.gatekeeper.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
     * Size limits, added after an independent review found none on any
     * request model. A verificationId is a UUID (36 characters), the nonce
     * is 32 random bytes in unpadded base64url (43 characters), and a PEM
     * certificate is 1–3 KB — every ceiling here is an order of magnitude
     * above the artefact it bounds, so it can only be tripped by a request
     * that is malformed or hostile.
     */
    public static final int MAX_CERT_PEM_LENGTH = 16 * 1024;

    /**
     * The EBA verification ID from the signed receipt (Step 5).
     * Links this confirmation to the original verification request.
     */
    @NotBlank(message = "Verification ID is required")
    @Size(max = 64, message = "verificationId exceeds the maximum accepted length")
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
    @Size(max = 128, message = "confirmationNonce exceeds the maximum accepted length")
    private String confirmationNonce;

    /**
     * Whether the certificate was issued or refused.
     */
    private boolean issued;

    /**
     * If issued: the full signing certificate in PEM format, optionally
     * followed by the intermediate CA certificates that issued it.
     * EBA extracts the public key and verifies it matches the
     * attestation evidence approved in Step 3.
     * Null if not issued; null or blank with {@code issued=true} is an
     * anomaly.
     */
    @Size(max = MAX_CERT_PEM_LENGTH, message = "signingCertificatePem exceeds the maximum accepted length")
    private String signingCertificatePem;

    /**
     * ISO 8601 timestamp of the issuance or refusal.
     */
    @NotBlank(message = "Timestamp is required")
    @Size(max = 64, message = "timestamp exceeds the maximum accepted length")
    private String timestamp;

    /**
     * If not issued: reason for non-issuance.
     * E.g. "NON-COMPLIANT attestation", "Technical supplier withdrew request"
     */
    @Size(max = 1024, message = "nonIssuanceReason exceeds the maximum accepted length")
    private String nonIssuanceReason;

    /**
     * The Swish number associated with this certificate.
     */
    @Size(max = 32, message = "swishNumber exceeds the maximum accepted length")
    private String swishNumber;

    /**
     * Organisation number of the corporate customer.
     */
    @Size(max = 32, message = "organisationNumber exceeds the maximum accepted length")
    private String organisationNumber;
}
