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
     * Look up an entry by its associated {@code verificationId}. The
     * relation is one-to-one for {@code VERIFY} and {@code CONFIRM}
     * operations, so this returns at most one entry. (For
     * {@code BATCH_VERIFY}, each request inside the batch is appended
     * with its own per-request {@code verificationId} and is therefore
     * also recoverable here.)
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
     *   <li>{@code entrySignatureBase64} verifies under the gatekeeper's
     *       active signing certificate.</li>
     * </ol>
     * Any failure returns {@code false}; passing all three for every
     * entry returns {@code true}. An empty log is considered intact
     * (vacuously true).
     */
    boolean verifyChainIntegrity();
}
