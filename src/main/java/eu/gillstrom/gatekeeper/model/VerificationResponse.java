package eu.gillstrom.gatekeeper.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

/**
 * EBA Signed Verification Receipt — Step 5 of the verification flow.
 * 
 * This is not a simple boolean response but a traceable, cryptographically
 * signed document that serves as the authoritative record of EBA's
 * verification determination. The receipt contains:
 * 
 * - A unique verification ID linking to EBA's approval registry
 * - The binary compliance determination with DORA article mapping
 * - HSM and key details for audit trail
 * - EBA's digital signature over the receipt
 * 
 * The signature allows GetSwish AB — and any subsequent auditor — to
 * independently verify that the approval originated from EBA.
 * The receipt ID is the key that links the certificate to EBA's
 * approval registry and the Step 7 confirmation loop.
 */
@Data
@Builder
public class VerificationResponse {

    // === Receipt Identity ===

    /**
     * Unique verification ID. Primary key linking the original verification
     * (Step 3), registry entry (Step 4), this receipt (Step 5), and the
     * issuance confirmation (Step 7).
     */
    private String verificationId;

    /**
     * Server-issued single-use nonce that the financial entity MUST echo
     * back when calling the Step 7 confirm endpoint. The gatekeeper binds
     * this nonce to the verificationId at verify time and rejects any
     * confirm call whose submitted nonce does not match. This prevents
     * Step-7 replay by an attacker who has obtained a valid issuer-CA-
     * chained certificate and learned a verificationId out of band.
     *
     * <p>Security properties:</p>
     * <ul>
     *   <li>Generated from {@link java.security.SecureRandom}.</li>
     *   <li>Base64url-encoded; 32 random bytes (256 bits) before encoding.</li>
     *   <li>Single-use: the gatekeeper retains the nonce only until the
     *       matching confirm call (or until a deployment-configurable
     *       TTL elapses). After consumption, replay of the same nonce is
     *       rejected.</li>
     *   <li>Not included in the canonical receipt-signing bytes — the
     *       nonce is operational anti-replay, not a decision-relevant
     *       field. The receipt remains independently verifiable without
     *       the nonce.</li>
     * </ul>
     */
    private String confirmationNonce;

    /**
     * Binary compliance determination.
     * true = signing key is cryptographically proven to be HSM-protected.
     * false = cannot verify HSM protection.
     */
    private boolean compliant;

    /**
     * ISO 8601 timestamp of when verification was performed.
     */
    private Instant verificationTimestamp;

    // === EBA Digital Signature ===

    /**
     * EBA's digital signature over this receipt, in Base64 encoding.
     * Computed over the canonical JSON representation of all fields
     * except this signature field itself. Allows any party to verify
     * that this receipt was issued by EBA and has not been tampered with.
     * 
     * In the reference implementation, this uses a self-signed key pair.
     * In production, the operating NCA signs with its organisation
     * certificate — the certificate the NCA uses for ordinary
     * administrative signing of supervisory acts.
     */
    private String signature;

    /**
     * The certificate (PEM) of the key used to sign this receipt,
     * so that the signature can be verified independently.
     */
    private String signingCertificate;

    // === Public Key Details ===

    private String publicKeyFingerprint;
    private String publicKeyAlgorithm;

    // === HSM Details (null if non-compliant) ===

    private String hsmVendor;
    private String hsmModel;
    private String hsmSerialNumber;

    // === Key Properties ===

    private KeyProperties keyProperties;

    // === DORA Compliance Mapping ===

    private DoraCompliance doraCompliance;

    // === Technical supplier metadata (from request, if provided) ===

    private String supplierIdentifier;
    private String supplierName;
    private String keyPurpose;

    // === Country code for registry partitioning ===

    private String countryCode;

    // === Errors and Warnings ===

    private List<String> errors;
    private List<String> warnings;

    @Data
    @Builder
    public static class KeyProperties {
        /** true = key was generated inside the HSM (not imported). */
        private boolean generatedOnDevice;

        /** false = key cannot be exported. If true, CRITICAL compliance failure. */
        private boolean exportable;

        /** true = attestation certificate chain validates against manufacturer root CA. */
        private boolean attestationChainValid;

        /** true = public key in attestation matches the public key submitted. */
        private boolean publicKeyMatchesAttestation;
    }

    @Data
    @Builder
    public static class DoraCompliance {
        /** Article 5(2)(b): Management body maintains high standards for authenticity and integrity. */
        private boolean article5_2b;

        /** Article 6(10): Financial entity remains fully responsible for verification of compliance. */
        private boolean article6_10;

        /** Article 9(3)(c): Prevent the impairment of authenticity and integrity. */
        private boolean article9_3c;

        /** Article 9(3)(d): Protection against poor administration, processing risks, human factor. */
        private boolean article9_3d;

        /** Article 9(4)(d): Strong authentication mechanisms based on dedicated control systems. */
        private boolean article9_4d;

        /** Article 28(1)(a): Financial entity at all times remains fully responsible. */
        private boolean article28_1a;

        /** Human-readable summary for formal EBA communications. */
        private String summary;
    }
}
