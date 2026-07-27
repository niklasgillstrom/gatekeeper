package eu.gillstrom.gatekeeper.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
 *
 * <h2>Field size limits</h2>
 *
 * <p>No field carried a length constraint until an independent review
 * pointed it out, so a single request could carry an arbitrary number of
 * megabytes into Jackson, into the PEM/XML parsers, and — via the audit
 * log's canonical request bytes — onto disk. The limits below are sized
 * from the real artefacts, with headroom:</p>
 *
 * <ul>
 *   <li>An RSA-4096 SubjectPublicKeyInfo PEM is ~800 bytes and a
 *       PKCS#10 CSR with a few extensions ~2 KB, so 8 KiB is generous for
 *       anything the flow actually accepts.</li>
 *   <li>A Securosys XML attestation and a Google attestation blob are tens
 *       of kilobytes; 256 KiB leaves an order of magnitude of headroom for
 *       vendor formats we have not seen.</li>
 *   <li>A DER certificate in PEM is 1–3 KB. 16 KiB per chain element and
 *       10 elements covers any realistic chain — a PKIX path of more than
 *       10 is not a chain we would validate anyway.</li>
 * </ul>
 *
 * <p>These are DoS guards, not business rules: every one of them is far
 * above what a legitimate attestation needs, and a request that trips one
 * is malformed or hostile rather than merely unusual.</p>
 */
@Data
public class VerificationRequest {

    /** Generous ceiling for a PEM public key or PKCS#10 CSR (see class javadoc). */
    public static final int MAX_PUBLIC_KEY_LENGTH = 8 * 1024;

    /** Vendor-specific attestation blob: XML, JSON or base64. */
    public static final int MAX_ATTESTATION_DATA_LENGTH = 256 * 1024;

    /** Detached signature over the attestation blob, base64. */
    public static final int MAX_ATTESTATION_SIGNATURE_LENGTH = 32 * 1024;

    /** One PEM certificate in the attestation chain. */
    public static final int MAX_CERT_LENGTH = 16 * 1024;

    /** Elements in the attestation certificate chain. */
    public static final int MAX_CERT_CHAIN_SIZE = 10;

    /**
     * The public key to verify, in PEM format.
     * This is the key that the entity claims is HSM-protected.
     */
    @NotBlank(message = "Public key is required")
    @Size(max = MAX_PUBLIC_KEY_LENGTH, message = "Public key exceeds the maximum accepted length")
    private String publicKey;

    /**
     * HSM vendor identifier.
     * Required to select the correct attestation verification logic.
     * Supported: YUBICO, SECUROSYS, AZURE, GOOGLE
     */
    @NotBlank(message = "HSM vendor is required for verification")
    @Size(max = 32, message = "HSM vendor identifier exceeds the maximum accepted length")
    private String hsmVendor;

    /**
     * Vendor-specific attestation data.
     * - Securosys: XML attestation file (base64)
     * - Azure: JSON from `az keyvault key get-attestation`
     * - Google Cloud: base64 of decompressed attestation.dat
     * - Yubico: not required (attestation is in cert chain)
     */
    @Size(max = MAX_ATTESTATION_DATA_LENGTH, message = "attestationData exceeds the maximum accepted length")
    private String attestationData;

    /**
     * Securosys only: attestation signature file (.sig) base64.
     */
    @Size(max = MAX_ATTESTATION_SIGNATURE_LENGTH,
          message = "attestationSignature exceeds the maximum accepted length")
    private String attestationSignature;

    /**
     * Attestation certificate chain (excluding root which is verified on server).
     * Required for all vendors.
     *
     * <p>Both the chain length and each element are bounded. The element
     * constraint is a Bean Validation container-element constraint, so it
     * applies to every entry rather than to the list reference.</p>
     */
    @Size(max = MAX_CERT_CHAIN_SIZE, message = "attestationCertChain has more elements than a PKIX path can need")
    private List<@Size(max = MAX_CERT_LENGTH,
                       message = "attestation certificate exceeds the maximum accepted length") String>
            attestationCertChain;

    // === Optional metadata for batch/audit purposes ===

    /**
     * Optional: Technical supplier identifier (e.g. organisation number) for audit trail.
     * Not used in cryptographic verification — purely for EBA's records.
     */
    @Size(max = 64, message = "supplierIdentifier exceeds the maximum accepted length")
    private String supplierIdentifier;

    /**
     * Optional: Technical supplier name for audit trail.
     */
    @Size(max = 256, message = "supplierName exceeds the maximum accepted length")
    private String supplierName;

    /**
     * Optional: Description of the key's purpose (e.g. "Swish payment signing").
     */
    @Size(max = 512, message = "keyPurpose exceeds the maximum accepted length")
    private String keyPurpose;

    /**
     * ISO 3166-1 alpha-2 country code for registry partitioning.
     * Determines which jurisdiction this verification belongs to.
     * E.g. "SE" for Sweden. Used in the API path as well
     * (dora-api.eba.europa.eu/v1/attestation/{countryCode}/verify).
     *
     * <p>Not validated as alpha-2 here because the controller overwrites it
     * from the path variable before the service sees it; the length bound
     * exists so a body that reaches a code path where it is not overwritten
     * still cannot carry an arbitrary string.</p>
     */
    @Size(max = 8, message = "countryCode exceeds the maximum accepted length")
    private String countryCode;
}
