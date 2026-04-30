package eu.gillstrom.gatekeeper.service;

import lombok.Builder;
import lombok.Data;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;

import java.util.List;
import java.util.Optional;

/**
 * Approval Registry — Step 4 of the verification flow.
 *
 * <p>Maintains an authoritative record of all attestation verifications
 * performed by the gatekeeper. Every verification — compliant and
 * non-compliant — is registered. This registry serves three functions:</p>
 *
 * <ol>
 *   <li>Links each verification to its outcome (issued/not issued)
 *       after the Step 7 confirmation loop.</li>
 *   <li>Enables secondary reconciliation: certificates that exist in
 *       a technical provider's system but lack a registry entry were
 *       issued outside the approved process.</li>
 *   <li>Provides the data basis for EBA Regulation (EU) No 1093/2010
 *       Article 17 investigations and Article 29 supervisory convergence
 *       assessments.</li>
 * </ol>
 *
 * <h2>Implementations</h2>
 *
 * <p>Two implementations ship with this reference build, selectable via
 * the {@code gatekeeper.registry.mode} property:</p>
 *
 * <ul>
 *   <li><strong>{@code in-memory}</strong> ({@link InMemoryApprovalRegistry})
 *       — default for the reference build and for tests. Backed by a
 *       {@link java.util.concurrent.ConcurrentHashMap}. State is lost on
 *       restart. Sufficient for development and CI; not suitable for
 *       production deployment because pending {@code verificationId}s
 *       (registered by {@code verify} but not yet confirmed by
 *       {@code confirm}) disappear on every restart.</li>
 *   <li><strong>{@code file}</strong> ({@link AppendOnlyFileApprovalRegistry})
 *       — production-shaped. Append-only JSONL journal at a configured
 *       path; each {@code register}/{@code confirm} operation is fsynced
 *       before returning. On startup the journal is replayed to rebuild
 *       the in-memory query index. Restart-safe.</li>
 * </ul>
 *
 * <p>The {@code application-nca.yaml} profile sets
 * {@code gatekeeper.registry.mode=file} and a production journal path;
 * the default {@code application.yaml} leaves it at {@code in-memory}
 * for the reference flow.</p>
 *
 * <p>Implementations MUST be safe for concurrent {@code register} and
 * {@code confirm} calls. Read methods may be eventually consistent with
 * respect to concurrent writes but MUST NOT return a partially-built
 * entry.</p>
 */
public interface ApprovalRegistry {

    /**
     * Register a verification result (Step 4).
     * Called immediately after attestation verification completes.
     *
     * <p>{@code confirmationNonce} is a server-issued single-use string
     * that the financial entity must echo back at Step 7. The registry
     * binds it to the {@code verificationId} so
     * {@link #confirm(String, String, boolean, String, boolean)} can
     * reject any confirm call with a non-matching nonce.</p>
     */
    RegistryEntry register(String verificationId,
                           String confirmationNonce,
                           boolean compliant,
                           String publicKeyFingerprint,
                           String supplierIdentifier,
                           String supplierName,
                           String hsmVendor,
                           String hsmModel,
                           String countryCode);

    /**
     * Update a registry entry with the Step 7 confirmation result.
     *
     * <p>The implementation MUST verify that {@code submittedNonce}
     * matches the {@code confirmationNonce} bound at register time;
     * implementations return {@link Optional#empty()} on mismatch so
     * callers can distinguish "no such verificationId" from "nonce
     * mismatch" via the {@link NonceMismatchException} signalling
     * channel below.</p>
     */
    Optional<RegistryEntry> confirm(String verificationId,
                                    String submittedNonce,
                                    boolean issued,
                                    String actualPublicKeyFingerprint,
                                    boolean publicKeyMatch) throws NonceMismatchException;

    /**
     * Thrown by {@link #confirm} when the submitted nonce does not match
     * the one bound to the verificationId at verify time. Distinct from
     * an empty Optional (which means "no such verificationId") so the
     * controller can return 400 (mismatch — replay attempt) versus 404
     * (unknown verificationId).
     */
    class NonceMismatchException extends RuntimeException {
        public NonceMismatchException(String verificationId) {
            super("Submitted confirmation nonce does not match the nonce bound at verify time for verificationId="
                    + verificationId);
        }
    }

    /** Look up a registry entry by verification ID. */
    Optional<RegistryEntry> lookup(String verificationId);

    /** Find all entries for a given country code (for Article 17 investigations). */
    List<RegistryEntry> findByCountry(String countryCode);

    /** Find all anomalies (for supervisory review). */
    List<RegistryEntry> findAnomalies();

    /** Find all entries awaiting Step 7 confirmation. */
    List<RegistryEntry> findAwaitingConfirmation();

    /** Compliance statistics for a given country code. */
    ComplianceStats getStats(String countryCode);

    /** Aggregate compliance statistics. */
    record ComplianceStats(long total, long compliant, long anomalies, double complianceRate) {}

    /**
     * A single entry in the approval registry.
     *
     * <p>The unique key is {@code verificationId}, NOT
     * {@code publicKeyFingerprint}. The same HSM-protected signing key
     * (same fingerprint) may appear in multiple registry entries — this
     * is expected and correct:</p>
     *
     * <ul>
     *   <li>Pre-existing keys verified for the first time when the
     *       gatekeeper flow is introduced (the key existed before the
     *       registry did).</li>
     *   <li>Certificate renewal: same key, new certificate, new
     *       verification.</li>
     *   <li>Re-verification after registry transition from EBA to NCA.</li>
     * </ul>
     *
     * <p>Blocking duplicate fingerprints would prevent legitimate
     * operations and force unnecessary key regeneration with no security
     * benefit — the key never left the HSM, which is exactly what the
     * attestation proves.</p>
     */
    @Data
    @Builder
    class RegistryEntry {
        private String verificationId;
        /**
         * Server-issued single-use nonce bound to the verificationId at
         * register time. Echoed back by the FE at confirm time and
         * compared by {@link ApprovalRegistry#confirm}. Not exposed in
         * external query responses (controllers strip this field before
         * returning a registry entry).
         */
        private String confirmationNonce;
        private boolean compliant;
        private String publicKeyFingerprint;
        private String actualPublicKeyFingerprint;
        private String supplierIdentifier;
        private String supplierName;
        private String hsmVendor;
        private String hsmModel;
        private String countryCode;
        private String verificationTimestamp;
        private String confirmationTimestamp;
        private RegistryStatus status;
        private boolean certificateReceived;
    }
}
