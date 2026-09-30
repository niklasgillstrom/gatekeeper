package eu.gillstrom.gatekeeper.audit;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Append-only, hash-chained, signed audit log of every decision-relevant
 * operation performed by the gatekeeper.
 *
 * <p>The log is the gatekeeper's primary tamper-evident record. Every
 * verification, batch-verification, and issuance confirmation produces
 * exactly one entry. Entries are linked into a hash chain so any
 * retroactive modification is detectable; entries are individually
 * signed so an attacker who controls the storage layer also has to
 * compromise the signing private key to forge or replace any entry.</p>
 *
 * <p>Legal basis:</p>
 * <ul>
 *   <li>DORA (EU 2022/2554) Article 28(6) — 5-year retention of records
 *       relating to ICT third-party service providers.</li>
 *   <li>DORA Article 6(10) — full responsibility for verification of
 *       compliance: a record-of-evidence is the presupposition of any
 *       supervisory inquiry into that responsibility.</li>
 *   <li>EBA Regulation (EU) 1093/2010 Article 35(1) — supervisory
 *       cooperation; this audit log is the artefact a supervisor
 *       requests under that article.</li>
 * </ul>
 *
 * <p>Implementations MUST be safe for concurrent {@code append()} calls
 * — append is the hot path under load. Read methods may be eventually
 * consistent with respect to concurrent appends but MUST NOT return
 * a partially-constructed entry.</p>
 */
public interface AuditLog {

    /**
     * Append a new entry to the chain. The implementation is responsible
     * for assigning the next monotonic {@code sequenceNumber}, computing
     * {@code thisEntryHashHex} against the current head, signing the
     * entry, persisting it durably (fsync where backed by a file) and
     * advancing the head pointer atomically.
     *
     * @return the newly persisted, signed entry
     * @throws AuditLogException if persistence fails — callers MUST
     *     treat this as a supervisory-grade incident.
     */
    AuditEntry append(AuditAppendRequest req);

    /**
     * Look up the earliest entry with the given {@code verificationId}.
     * Each {@code VERIFY} and {@code BATCH_VERIFY} entry has its own
     * {@code verificationId}, generated at verification, so for an
     * issuance this returns that entry.
     *
     * <p>The {@code verificationId} is not unique across the log. Every
     * {@code CONFIRM} attempt for it — including one rejected for a nonce
     * mismatch — and every {@code SETTLEMENT_VERIFY} query against the
     * certificate appends a further entry carrying the same identifier, and
     * this method returns none of them. Use
     * {@link #findInRange(Instant, Instant)} to enumerate them.</p>
     */
    Optional<AuditEntry> findByVerificationId(String verificationId);

    /**
     * Range query by entry timestamp. {@code from} is inclusive, {@code to}
     * is exclusive — this matches half-open interval conventions used
     * elsewhere in the codebase. Returns entries in ascending sequence
     * number order.
     */
    List<AuditEntry> findInRange(Instant from, Instant to);

    /**
     * Return every entry written by the given mTLS client principal.
     * Comparison is exact-string; a caller looking for "all CN=swish" should
     * normalise upstream.
     */
    List<AuditEntry> findByPrincipal(String principal);

    /**
     * The latest entry, or {@link Optional#empty()} for an empty log.
     * Implementations may also return a sentinel synthetic entry; the
     * documented contract is that {@code head()} on an empty log is
     * empty, and on a non-empty log returns the entry whose
     * {@code thisEntryHashHex} would be the predecessor hash for the
     * next append.
     */
    Optional<AuditEntry> head();

    /**
     * Total number of entries currently in the chain.
     */
    long size();

    /**
     * Walk the chain from the first entry to the head and verify
     * three properties of every entry:
     * <ol>
     *   <li>{@code prevEntryHashHex} matches the predecessor's
     *       {@code thisEntryHashHex} (or the sentinel for the first
     *       entry).</li>
     *   <li>{@code thisEntryHashHex} equals the SHA-256 of the entry's
     *       canonical bytes.</li>
     *   <li>{@code entrySignatureBase64} verifies, with the signing
     *       algorithm the gatekeeper is configured with, under the active
     *       signing certificate or a retired one listed in
     *       {@code gatekeeper.signing.retired-keys}.</li>
     * </ol>
     * Any failure returns {@code false}; passing all three for every
     * entry returns {@code true}. An empty log is considered intact
     * (vacuously true).
     *
     * <p>The walk is O(n) in the length of the chain and performs one
     * signature verification per entry. Callers on a request thread should
     * use {@link #cachedIntegrityStatus()} instead.</p>
     */
    boolean verifyChainIntegrity();

    /**
     * The most recent {@link #verifyChainIntegrity()} outcome together with
     * the instant it was computed.
     *
     * <p>{@code GET /v1/gatekeeper/health} used to call
     * {@link #verifyChainIntegrity()} synchronously on every request, which
     * made an unauthenticated endpoint a lever for O(chain length) RSA work
     * per call — and, in the file-backed implementation, made that work hold
     * the append lock, so a health poll stalled every concurrent
     * verification. Implementations recompute at most once per configured
     * interval and serve the previous answer in between; the returned
     * instant tells the caller how stale the answer is.</p>
     *
     * <p>The default implementation computes on every call and is intended
     * only for test doubles and in-memory implementations whose chain is
     * short enough for that to be free.</p>
     */
    default IntegrityStatus cachedIntegrityStatus() {
        return new IntegrityStatus(verifyChainIntegrity(), Instant.now());
    }

    /**
     * Outcome of a chain-integrity check and the instant it was performed.
     *
     * @param intact result of the walk described in
     *     {@link #verifyChainIntegrity()}
     * @param checkedAt when that walk ran; {@code null} if no check has run
     *     yet (the implementation could not produce even a stale answer)
     */
    record IntegrityStatus(boolean intact, Instant checkedAt) {}
}
