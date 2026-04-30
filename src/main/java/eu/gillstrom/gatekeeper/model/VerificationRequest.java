package eu.gillstrom.gatekeeper.model;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import java.util.List;

/**
 * EBA Independent Verification Request.
 * 
 * Simplified request model for EBA's independent verification of HSM attestation.
 * Does not require BankID signature or organisational context — verifies purely
 * whether the cryptographic proof demonstrates DORA-compliant key protection.
 * 
 * Legal basis: DORA Articles 6(10), 9(3)(d), 9(4)(d)
 * EBA mandate: Regulation 1093/2010, Articles 17(6) and 29
 */
@Data
public class VerificationRequest {

    /**
     * The public key to verify, in PEM format.
     * This is the key that the entity claims is HSM-protected.
     */
    @NotBlank(message = "Public key is required")
    private String publicKey;

    /**
     * HSM vendor identifier.
     * Required to select the correct attestation verification logic.
     * Supported: YUBICO, SECUROSYS, AZURE, GOOGLE
     */
    @NotBlank(message = "HSM vendor is required for verification")
    private String hsmVendor;

    /**
     * Vendor-specific attestation data.
     * - Securosys: XML attestation file (base64)
     * - Azure: JSON from `az keyvault key get-attestation`
     * - Google Cloud: base64 of decompressed attestation.dat
     * - Yubico: not required (attestation is in cert chain)
     */
    private String attestationData;

    /**
     * Securosys only: attestation signature file (.sig) base64.
     */
    private String attestationSignature;

    /**
     * Attestation certificate chain (excluding root which is verified on server).
     * Required for all vendors.
     */
    private List<String> attestationCertChain;

    // === Optional metadata for batch/audit purposes ===

    /**
     * Optional: Technical supplier identifier (e.g. organisation number) for audit trail.
     * Not used in cryptographic verification — purely for EBA's records.
     */
    private String supplierIdentifier;

    /**
     * Optional: Technical supplier name for audit trail.
     */
    private String supplierName;

    /**
     * Optional: Description of the key's purpose (e.g. "Swish payment signing").
     */
    private String keyPurpose;

    /**
     * ISO 3166-1 alpha-2 country code for registry partitioning.
     * Determines which jurisdiction this verification belongs to.
     * E.g. "SE" for Sweden. Used in the API path as well
     * (dora-api.eba.europa.eu/v1/attestation/{countryCode}/verify).
     */
    private String countryCode;
}
