package eu.gillstrom.gatekeeper.service;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
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
                           String countryCode,
                           String verificationPrincipal);

    /**
     * The customer and, when there is one, the technical supplier of a
     * verification. Supplier fields are {@code null} when the customer
     * holds the key itself.
     */
    record Parties(String customerOrganisationNumber, String customerSwishNumber,
                   String supplierIdentifier, String supplierNumber, String supplierName) {

        /** Only the supplier identifier and name, as before 1.6.0. */
        public static Parties supplierOnly(String supplierIdentifier, String supplierName) {
            return new Parties(null, null, supplierIdentifier, null, supplierName);
        }
    }

    /**
     * As {@link #register(String, String, boolean, String, String, String, String, String, String, String)},
     * recording the customer and the supplier. The two shipped registries
     * store every field; this default, for other implementations, keeps
     * only the supplier identifier and name.
     */
    default RegistryEntry register(String verificationId,
                                   String confirmationNonce,
                                   boolean compliant,
                                   String publicKeyFingerprint,
                                   Parties parties,
                                   String hsmVendor,
                                   String hsmModel,
                                   String countryCode,
                                   String verificationPrincipal) {
        return register(verificationId, confirmationNonce, compliant, publicKeyFingerprint,
                parties.supplierIdentifier(), parties.supplierName(), hsmVendor, hsmModel,
                countryCode, verificationPrincipal);
    }

    /**
     * As above, also keeping the submitted request: the attestation evidence
     * itself, so the supervisor can run the verification again later, and
     * every field of the audited request digest, so it can show that what it
     * keeps is what was checked ({@code VerificationService.requestDigestBase64}).
     * The two shipped registries store it; this default drops it.
     * {@code VerificationService} passes it for an approved key only.
     *
     * @param submission the request to keep, or {@code null} to keep none
     */
    default RegistryEntry register(String verificationId,
                                   String confirmationNonce,
                                   boolean compliant,
                                   String publicKeyFingerprint,
                                   Parties parties,
                                   eu.gillstrom.gatekeeper.model.VerificationRequest submission,
                                   String hsmVendor,
                                   String hsmModel,
                                   String countryCode,
                                   String verificationPrincipal) {
        return register(verificationId, confirmationNonce, compliant, publicKeyFingerprint, parties,
                hsmVendor, hsmModel, countryCode, verificationPrincipal);
    }

    /**
     * Convenience overload for callers with no authenticated principal to
     * record (tests, and deployments running the permissive reference
     * filter chain). Equivalent to passing {@code null} as
     * {@code verificationPrincipal}, which disables the principal binding
     * on {@code confirm} for that entry.
     */
    default RegistryEntry register(String verificationId,
                                   String confirmationNonce,
                                   boolean compliant,
                                   String publicKeyFingerprint,
                                   String supplierIdentifier,
                                   String supplierName,
                                   String hsmVendor,
                                   String hsmModel,
                                   String countryCode) {
        return register(verificationId, confirmationNonce, compliant, publicKeyFingerprint,
                supplierIdentifier, supplierName, hsmVendor, hsmModel, countryCode, null);
    }

    /**
     * Update a registry entry with the Step 7 confirmation result.
     *
     * <p>The implementation MUST verify that {@code submittedNonce}
     * matches the {@code confirmationNonce} bound at register time, and
     * MUST check and consume the nonce atomically, so that two concurrent
     * confirmations carrying the same nonce cannot both succeed.
     * {@link Optional#empty()} means "no such verificationId";
     * {@link NonceMismatchException} means "the nonce did not match" —
     * two distinct outcomes so the controller can answer 404 and 400
     * respectively.</p>
     *
     * <p>{@code issuedCertificate} is stored on the entry when the
     * confirmation ends in {@code VERIFIED_AND_ISSUED}, so that
     * {@link #findByIssuedCertificate(BigInteger, X500Principal)} can
     * resolve a settlement-time request that carries only the certificate
     * serial and issuer DN. {@code null} stores nothing.</p>
     *
     * <p>An issued certificate is stored on one entry only. A confirmation
     * that would store a certificate another entry already holds is refused
     * with {@link CertificateAlreadyRegisteredException}: the entry and its
     * nonce are left as they were and nothing is journalled. The check and
     * the store are one atomic step. Until 1.7.0 such a confirmation created
     * a second, newer entry, which settlement and key-lifecycle events then
     * followed instead of the original one — so repeating verification and
     * confirmation brought a revoked certificate back.</p>
     */
    Optional<RegistryEntry> confirm(String verificationId,
                                    String submittedNonce,
                                    boolean issued,
                                    String actualPublicKeyFingerprint,
                                    boolean publicKeyMatch,
                                    IssuedCertificate issuedCertificate)
            throws NonceMismatchException, CertificateAlreadyRegisteredException;

    default Optional<RegistryEntry> confirm(String verificationId,
                                            String submittedNonce,
                                            boolean issued,
                                            String actualPublicKeyFingerprint,
                                            boolean publicKeyMatch) throws NonceMismatchException {
        return confirm(verificationId, submittedNonce, issued, actualPublicKeyFingerprint,
                publicKeyMatch, null);
    }

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

    /**
     * Thrown by {@link #confirm} when the certificate it would store is
     * already stored on another entry. No state transition has occurred:
     * the entry is still awaiting confirmation and its nonce is unspent.
     */
    class CertificateAlreadyRegisteredException extends RuntimeException {
        public CertificateAlreadyRegisteredException(String verificationId, String holderVerificationId) {
            super("The certificate confirmed for verificationId=" + verificationId
                    + " is already registered under verificationId=" + holderVerificationId);
        }
    }

    /**
     * Change the status of a confirmed entry for a key-lifecycle event
     * ({@code ROTATED}, {@code REVOKED}, {@code DECOMMISSIONED}; see
     * {@code KeyLifecycleService}).
     *
     * <p>{@code target} must be {@link RegistryStatus#SUPERSEDED},
     * {@link RegistryStatus#REVOKED} or {@link RegistryStatus#DECOMMISSIONED};
     * anything else is an {@link IllegalArgumentException}. The change is
     * applied only when {@link #isAllowedStatusChange} allows it from the
     * entry's current status; the check and the change are one atomic step,
     * so two concurrent events cannot both apply from the same status.</p>
     *
     * <p>The file-backed registry journals an applied change as a
     * {@code STATUS_CHANGE} operation before applying it in memory, and
     * replays it at start-up. A refused change is not journalled: nothing
     * changed. Both outcomes are recorded in the audit log by the caller.</p>
     *
     * <p>The default throws {@link UnsupportedOperationException}, so that an
     * implementation that does not support status changes cannot silently
     * report one as applied.</p>
     *
     * @param reason free-text reason supplied with the event, stored on the entry
     * @param successorVerificationId for {@code SUPERSEDED}, the verification
     *     of the key that replaces this one; {@code null} otherwise or when
     *     not supplied
     */
    default StatusChange changeStatus(String verificationId, RegistryStatus target, String reason,
                                      String successorVerificationId) {
        throw new UnsupportedOperationException(
                getClass().getName() + " does not support registry status changes");
    }

    /**
     * Whether a key-lifecycle event may move an entry from {@code from} to
     * {@code to}. Only a confirmed issuance ({@code VERIFIED_AND_ISSUED}) has
     * a key lifecycle; a superseded key may still be revoked or
     * decommissioned; {@code REVOKED} and {@code DECOMMISSIONED} are final.
     */
    static boolean isAllowedStatusChange(RegistryStatus from, RegistryStatus to) {
        if (to == RegistryStatus.SUPERSEDED) {
            return from == RegistryStatus.VERIFIED_AND_ISSUED;
        }
        if (to == RegistryStatus.REVOKED || to == RegistryStatus.DECOMMISSIONED) {
            return from == RegistryStatus.VERIFIED_AND_ISSUED || from == RegistryStatus.SUPERSEDED;
        }
        return false;
    }

    /**
     * Apply an allowed status change to an entry. Shared by both registries
     * and by journal replay so that they cannot drift apart. The successor
     * is set only by {@code SUPERSEDED}; a later {@code REVOKED} or
     * {@code DECOMMISSIONED} keeps the successor recorded at rotation.
     */
    static void applyStatusChange(RegistryEntry entry, RegistryStatus target, String changedAt,
                                  String reason, String successorVerificationId) {
        entry.setStatus(target);
        entry.setStatusChangedAt(changedAt);
        entry.setStatusChangeReason(reason);
        if (target == RegistryStatus.SUPERSEDED) {
            entry.setSuccessorVerificationId(successorVerificationId);
        }
    }

    /** The three statuses {@link #changeStatus} can set. */
    static boolean isLifecycleStatus(RegistryStatus status) {
        return status == RegistryStatus.SUPERSEDED
                || status == RegistryStatus.REVOKED
                || status == RegistryStatus.DECOMMISSIONED;
    }

    /**
     * Whether an entry's confirmation ended in {@code VERIFIED_AND_ISSUED},
     * whether or not a later lifecycle event moved it on. {@link #getStats}
     * counts these as compliant, so that rotating, revoking or
     * decommissioning a key does not lower a jurisdiction's compliance rate:
     * the issuance it describes passed the gate.
     */
    static boolean wasVerifiedAndIssued(RegistryStatus status) {
        return status == RegistryStatus.VERIFIED_AND_ISSUED || isLifecycleStatus(status);
    }

    /**
     * Outcome of {@link #changeStatus}.
     *
     * @param outcome {@code APPLIED}, {@code REFUSED} (transition not allowed
     *     from the current status) or {@code NOT_FOUND} (no such verificationId)
     * @param previousStatus the status before the call
     * @param currentStatus the status after the call (equal to
     *     {@code previousStatus} unless applied)
     * @param changedAt ISO-8601 instant of an applied change, else {@code null}
     */
    record StatusChange(Outcome outcome, RegistryStatus previousStatus, RegistryStatus currentStatus,
                        String changedAt) {

        public enum Outcome { APPLIED, REFUSED, NOT_FOUND }

        public static StatusChange notFound() {
            return new StatusChange(Outcome.NOT_FOUND, null, null, null);
        }

        public static StatusChange refused(RegistryStatus current) {
            return new StatusChange(Outcome.REFUSED, current, current, null);
        }

        public static StatusChange applied(RegistryStatus previous, RegistryStatus current, String changedAt) {
            return new StatusChange(Outcome.APPLIED, previous, current, changedAt);
        }

        public boolean isApplied() {
            return outcome == Outcome.APPLIED;
        }
    }

    /** Look up a registry entry by verification ID. */
    Optional<RegistryEntry> lookup(String verificationId);

    /**
     * Look up a registry entry by verification ID <em>within one
     * jurisdiction</em>.
     *
     * <p>{@code POST /v1/attestation/&#x7b;cc&#x7d;/confirm} carries a
     * country code in the path and used to discard it, so a confirmation
     * posted to {@code /DE/confirm} could close the loop on a Swedish
     * entry. Registry contents are supervisory material under DORA Article
     * 55; the jurisdiction in the URL has to be part of the lookup key, not
     * decoration.</p>
     *
     * <p>Matching is exact and case-sensitive on {@code countryCode};
     * callers normalise to upper case. An entry whose {@code countryCode}
     * is {@code null}, or a {@code null} argument, matches nothing — the
     * result is indistinguishable from an unknown {@code verificationId},
     * which is the point: a caller must not be able to use the country
     * code as an oracle for whether an entry exists elsewhere.</p>
     */
    default Optional<RegistryEntry> lookup(String verificationId, String countryCode) {
        if (countryCode == null) {
            return Optional.empty();
        }
        return lookup(verificationId)
                .filter(e -> countryCode.equals(e.getCountryCode()));
    }

    /** Find all entries for a given country code (for Article 17 investigations). */
    List<RegistryEntry> findByCountry(String countryCode);

    /**
     * Find anomalies within one jurisdiction (for supervisory review).
     *
     * <p>These two methods used to take no argument. {@code
     * VerificationController} accepted a {@code countryCode} path variable
     * on {@code /v1/attestation/&#x7b;cc&#x7d;/registry/anomalies} and
     * {@code .../awaiting}, and then discarded it: every NCA's query
     * returned every other Member State's rows. Taking the jurisdiction as
     * a parameter — rather than offering an unfiltered overload alongside a
     * filtered one — is what makes the mistake unrepeatable.</p>
     *
     * <p>Matching is exact on {@code countryCode}; callers normalise to
     * upper case. Entries whose {@code countryCode} is {@code null} (the
     * request carried none) belong to no jurisdiction and are returned by
     * no jurisdiction's query.</p>
     */
    List<RegistryEntry> findAnomalies(String countryCode);

    /** Find entries within one jurisdiction awaiting Step 7 confirmation. */
    List<RegistryEntry> findAwaitingConfirmation(String countryCode);

    /**
     * Find a registry entry by the public-key fingerprint of the certificate.
     *
     * <p>Not used by the settlement-time signature verification endpoint
     * ({@code POST /api/v1/verify}), which looks the entry up by the issued
     * certificate ({@link #findByIssuedCertificate}). The fingerprint is the
     * canonical SHA-256 of the X.509 SubjectPublicKeyInfo encoding (DER),
     * lower-case hex, colon-separated, as produced by
     * {@code eu.gillstrom.gatekeeper.util.Fingerprints}.
     *
     * <p>If multiple entries share the same fingerprint (e.g. after
     * certificate renewal — same key, new cert, new verification), the
     * most recent compliant entry wins. If no compliant entry exists,
     * the most recent non-compliant entry is returned so the caller can
     * see the non-compliant verdict.
     *
     * @param fingerprint canonical SHA-256 fingerprint of the public key
     * @return registry entry if found, empty if no audit entry exists for
     *     this public key
     */
    default Optional<RegistryEntry> findByPublicKeyFingerprint(String fingerprint) {
        return Optional.empty();
    }

    default Optional<RegistryEntry> findByIssuedCertificate(BigInteger serial, X500Principal issuer) {
        return Optional.empty();
    }

    static boolean issuedCertificateMatches(RegistryEntry entry, BigInteger serial, X500Principal issuer) {
        if (serial == null || issuer == null
                || entry.getIssuedCertificateSerial() == null
                || entry.getIssuedCertificateIssuerDn() == null) {
            return false;
        }
        try {
            return serial.equals(new BigInteger(entry.getIssuedCertificateSerial(), 16))
                    && issuer.equals(new X500Principal(entry.getIssuedCertificateIssuerDn()));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Refuse a confirmation that would store {@code certificate} when an
     * entry already stores it. Both registries call it from {@link #confirm},
     * under the lock that also covers the store, before anything is changed
     * or journalled.
     *
     * <p>A certificate whose serial or issuer is absent or does not parse is
     * let through: stored like that it matches no lookup, so no entry can
     * hold it.</p>
     */
    static void requireCertificateNotRegistered(Collection<RegistryEntry> entries, String verificationId,
                                                IssuedCertificate certificate) {
        if (certificate.serialHex() == null || certificate.issuerDn() == null) {
            return;
        }
        BigInteger serial;
        X500Principal issuer;
        try {
            serial = new BigInteger(certificate.serialHex(), 16);
            issuer = new X500Principal(certificate.issuerDn());
        } catch (IllegalArgumentException e) {
            return;
        }
        Optional<RegistryEntry> holder = entries.stream()
                .filter(e -> issuedCertificateMatches(e, serial, issuer))
                .findFirst();
        if (holder.isPresent()) {
            throw new CertificateAlreadyRegisteredException(verificationId, holder.get().getVerificationId());
        }
    }

    /**
     * Which entry {@link #findByIssuedCertificate} returns when more than
     * one stores the certificate: an entry that a key-lifecycle event has
     * moved to {@code SUPERSEDED}, {@code REVOKED} or {@code DECOMMISSIONED}
     * before any other, then the most recent ({@link #recency()}).
     *
     * <p>{@link #confirm} no longer stores a certificate twice, so several
     * holders exist only in a journal written by 1.7.0 or earlier. There a
     * later re-confirmation must not outrank the revocation of the same
     * certificate, which is what ordering by recency alone did.</p>
     */
    static Comparator<RegistryEntry> certificatePrecedence() {
        return Comparator.comparing((RegistryEntry e) -> isLifecycleStatus(e.getStatus()))
                .thenComparing(recency());
    }

    static Comparator<RegistryEntry> recency() {
        return Comparator
                .comparing((RegistryEntry e) -> parseInstant(e.getVerificationTimestamp()),
                        Comparator.nullsFirst(Comparator.<Instant>naturalOrder()))
                .thenComparing((RegistryEntry e) -> parseInstant(e.getConfirmationTimestamp()),
                        Comparator.nullsFirst(Comparator.<Instant>naturalOrder()));
    }

    private static Instant parseInstant(String timestamp) {
        if (timestamp == null || timestamp.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(timestamp);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /**
     * Compliance statistics for a given country code. {@code compliant}
     * counts entries for which {@link #wasVerifiedAndIssued} holds.
     */
    ComplianceStats getStats(String countryCode);

    /** Aggregate compliance statistics. */
    record ComplianceStats(long total, long compliant, long anomalies, double complianceRate) {}

    record IssuedCertificate(String pem, String serialHex, String issuerDn) {

        public static IssuedCertificate of(X509Certificate certificate) throws CertificateEncodingException {
            String pem = "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
            return new IssuedCertificate(
                    pem,
                    certificate.getSerialNumber().toString(16),
                    certificate.getIssuerX500Principal().getName());
        }
    }

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
    @Builder(toBuilder = true)
    @NoArgsConstructor
    @AllArgsConstructor
    class RegistryEntry {
        private String verificationId;
        /**
         * Server-issued single-use nonce bound to the verificationId at
         * register time. Echoed back by the FE at confirm time and
         * compared by {@link ApprovalRegistry#confirm}.
         *
         * <p>Single-use: cleared by {@code confirm} once a submitted nonce has
         * matched, so a replayed confirm cannot succeed.</p>
         *
         * <p>Never returned to callers. The field stays serialisable because
         * {@code AppendOnlyFileApprovalRegistry} persists entries to its
         * journal and must be able to replay a pending nonce after restart;
         * {@code VerificationController} therefore strips it per response
         * instead of the field carrying {@code @JsonIgnore}.</p>
         */
        private String confirmationNonce;
        private boolean compliant;
        private String publicKeyFingerprint;
        private String actualPublicKeyFingerprint;
        private String customerOrganisationNumber;
        private String customerSwishNumber;
        private String supplierIdentifier;
        private String supplierNumber;
        private String supplierName;
        /**
         * The verification request as submitted: public key, attestation data,
         * signature and chain, parties. Not secret and kept for the retention
         * period, so the verification can be repeated, for instance with a
         * corrected verifier. {@code null} for entries written before 1.6.0
         * and, since 1.8.0, for a verification that did not approve the key:
         * of a refused request the audit log keeps the digest, and nothing
         * else of it is stored.
         */
        private eu.gillstrom.gatekeeper.model.VerificationRequest submission;
        private String hsmVendor;
        private String hsmModel;
        private String countryCode;
        /**
         * The mTLS client principal that performed the Step 3 verification,
         * as resolved by {@code MtlsPrincipalResolver} at register time.
         *
         * <p>Bound so that {@code confirm} can require the same principal:
         * knowing a {@code verificationId} and its nonce is not by itself a
         * reason to let a <em>different</em> financial entity close the
         * loop. {@code null} when the gatekeeper runs the permissive
         * reference filter chain ({@code gatekeeper.security.mtls.enabled=false}),
         * where there is no authenticated caller to bind to; the binding is
         * then skipped and the startup WARN says so.</p>
         */
        private String verificationPrincipal;
        private String verificationTimestamp;
        private String confirmationTimestamp;
        private RegistryStatus status;
        private boolean certificateReceived;
        private String issuedCertificatePem;
        private String issuedCertificateSerial;
        private String issuedCertificateIssuerDn;
        /**
         * ISO-8601 instant of the latest key-lifecycle status change
         * ({@code SUPERSEDED}, {@code REVOKED}, {@code DECOMMISSIONED});
         * {@code null} while the entry has had none. Earlier changes are in
         * the journal and the audit log, not on the entry.
         */
        private String statusChangedAt;
        /** Free-text reason given with the latest status change. */
        private String statusChangeReason;
        /** For {@code SUPERSEDED}: the verificationId of the successor key, when given. */
        private String successorVerificationId;
    }
}
