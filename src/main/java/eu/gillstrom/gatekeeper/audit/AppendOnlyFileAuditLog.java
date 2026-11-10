package eu.gillstrom.gatekeeper.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import eu.gillstrom.gatekeeper.timestamp.AuditTimestamping;
import eu.gillstrom.gatekeeper.timestamp.TimestampAnchorRecord;
import eu.gillstrom.gatekeeper.timestamp.TimestampAnchorStore;
import eu.gillstrom.gatekeeper.timestamp.TimestampTokenVerifier;
import eu.gillstrom.gatekeeper.util.JournalAppender;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Default {@link AuditLog} implementation backed by a JSON-Lines file.
 *
 * <p>Storage layout: one entry per line, UTF-8 JSON, terminated with
 * {@code \n}. Each append is forced to the device
 * ({@code FileChannel.force(true)}) before {@code append()} returns so
 * that crash persistence is guaranteed and the chain cannot acquire
 * gaps between entries that returned successfully and entries actually
 * on disk. An append that fails leaves no part of its line in the file,
 * and what a stopped process left after the last newline is removed by
 * the next append ({@link JournalAppender}).</p>
 *
 * <p>Permissions: when the file is created the implementation attempts
 * to set the POSIX permissions to {@code 0640} so that arbitrary
 * processes on the host cannot read or modify the trail. On non-POSIX
 * filesystems this step is logged at WARN and execution continues.</p>
 *
 * <p>Recovery: at startup the file is read line-by-line and chain
 * integrity is validated. A trailing line that fails to parse is treated
 * as an aborted append (e.g. process killed mid-write) and is best-effort
 * truncated. An earlier line that does not parse stops start-up with an
 * {@code AuditLogException}. A file that parses but whose chain does not
 * verify is reported at WARN and does not prevent boot — the operator must
 * investigate, and {@code GET /v1/gatekeeper/health} reports it. Mid-file corruption MUST
 * fail {@link #verifyChainIntegrity()} so it is detectable by supervisory
 * tooling.</p>
 *
 * <p>Concurrency: {@link #append(AuditAppendRequest)} is serialised under
 * a {@link ReentrantLock}. The lock is acquired interruptibly so a
 * shutdown hook cannot wedge a worker thread; on interrupt the operation
 * fails with {@link AuditLogException}. Read methods take a snapshot of
 * the in-memory entry list, so they never observe a half-built entry.
 * {@link #verifyChainIntegrity()} copies the list under the lock, releases
 * it, reads the file back from disk with the parser used at load, requires
 * the entries on disk to end at the in-memory head, and only then
 * recomputes hashes and verifies signatures over what is on disk — the
 * walk is O(n) with one signature verification per entry and must not sit
 * in the append path. {@link #cachedIntegrityStatus()} additionally bounds
 * how often that walk runs.</p>
 *
 * <p>Entry format: every entry this class writes is in the v2 canonical form
 * ({@link AuditEntry#canonicalBytesForHashV2}), with the inventory fields of
 * the {@link AuditAppendRequest} and the per-key link
 * {@code prevKeyEntryHashHex}. Entries already on disk in the v1 form are
 * read and verified in the v1 form; a file may switch from v1 to v2 once, at
 * the upgrade. The per-key index (last {@code thisEntryHashHex} per
 * {@code keyFingerprintHex}) is rebuilt from the file at start-up.</p>
 *
 * <p>Time-stamping: with {@code gatekeeper.timestamping.mode=entry}, each
 * entry gets an RFC 3161 token over its signature input before it is
 * persisted; a TSA failure writes the entry without one (see
 * {@link AuditTimestamping}). When trusted TSA certificates are configured,
 * {@link #verifyChainIntegrity()} validates every entry token and every
 * record in the anchor file, and requires an entry token to have been issued
 * at the entry's own time (see {@link AuditTimestamping}).</p>
 *
 * <p>Legal basis: see {@link AuditLog} javadoc.</p>
 */
@Component
public class AppendOnlyFileAuditLog implements AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AppendOnlyFileAuditLog.class);

    /** Default recompute interval for {@link #cachedIntegrityStatus()}. */
    public static final long DEFAULT_INTEGRITY_CHECK_INTERVAL_SECONDS = 300L;

    private final Path filePath;
    private final JournalAppender journal;
    private final ReceiptSigner signer;
    private final GatekeeperKeyDirectory keyDirectory;
    private final ObjectMapper json;
    private final ReentrantLock appendLock = new ReentrantLock();

    /**
     * How long a chain-integrity result is served before it is recomputed.
     * Configured via {@code gatekeeper.audit.integrity-check-interval-seconds}.
     * Zero or negative means "recompute on every call" and is intended for
     * tests only.
     */
    private final long integrityCheckIntervalSeconds;

    /**
     * Last computed integrity result, or {@code null} before the first check.
     * Written by {@link #verifyChainIntegrity()} and
     * {@link #cachedIntegrityStatus()}; read without locking.
     */
    private final AtomicReference<IntegrityStatus> cachedIntegrity = new AtomicReference<>();

    /**
     * Held while a recompute is in flight. Separate from {@link #appendLock}
     * on purpose: the whole point of the change is that the O(n) RSA walk
     * runs outside the append path, so a concurrent verify is never blocked
     * by a health poll, and a second health poll serves the previous answer
     * rather than queueing behind the first.
     */
    private final ReentrantLock integrityComputeLock = new ReentrantLock();

    /**
     * In-memory mirror of the on-disk chain. Reads (range, principal,
     * verificationId) operate over this list. The list is mutated only
     * under {@link #appendLock}; read methods snapshot it under the lock
     * to avoid a torn read against a concurrent append.
     */
    private final List<AuditEntry> entries = new ArrayList<>();

    /**
     * Per-key index: {@code keyFingerprintHex} → {@code thisEntryHashHex} of
     * the latest entry carrying that fingerprint. Mutated only under
     * {@link #appendLock}; rebuilt from the file at start-up.
     */
    private final Map<String, String> lastEntryHashByKey = new HashMap<>();

    /** Entries in {@link #entries} without a timestamp token. Guarded by {@link #appendLock}. */
    private long untimestamped;

    /** RFC 3161 configuration; {@link AuditTimestamping#off()} when none is wired. */
    private final AuditTimestamping timestamping;

    /**
     * Convenience constructor using
     * {@link #DEFAULT_INTEGRITY_CHECK_INTERVAL_SECONDS}. Not the
     * Spring-injected one — see the {@link Autowired} constructor below.
     */
    public AppendOnlyFileAuditLog(String configuredPath, ReceiptSigner signer) {
        this(configuredPath, signer, DEFAULT_INTEGRITY_CHECK_INTERVAL_SECONDS);
    }

    public AppendOnlyFileAuditLog(String configuredPath, ReceiptSigner signer,
                                  long integrityCheckIntervalSeconds) {
        this(configuredPath, signer, integrityCheckIntervalSeconds, null);
    }

    public AppendOnlyFileAuditLog(String configuredPath, ReceiptSigner signer,
                                  long integrityCheckIntervalSeconds, GatekeeperKeyDirectory keyDirectory) {
        this(configuredPath, signer, integrityCheckIntervalSeconds, keyDirectory, null);
    }

    @Autowired
    public AppendOnlyFileAuditLog(
            @Value("${gatekeeper.audit.path:./audit-log.jsonl}") String configuredPath,
            ReceiptSigner signer,
            @Value("${gatekeeper.audit.integrity-check-interval-seconds:300}")
            long integrityCheckIntervalSeconds,
            GatekeeperKeyDirectory keyDirectory,
            AuditTimestamping timestamping) {
        this.filePath = Paths.get(configuredPath);
        this.journal = new JournalAppender(filePath);
        this.signer = signer;
        this.keyDirectory = keyDirectory;
        this.timestamping = timestamping == null ? AuditTimestamping.off() : timestamping;
        this.integrityCheckIntervalSeconds = integrityCheckIntervalSeconds;
        @SuppressWarnings("deprecation")
        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .setSerializationInclusion(JsonInclude.Include.ALWAYS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        this.json = mapper;
    }

    /**
     * Read the existing audit file (if any), validate the chain, populate
     * the in-memory mirror. Best-effort recovers a corrupt trailing line.
     */
    @PostConstruct
    public void initialise() {
        try {
            if (Files.exists(filePath)) {
                loadExisting();
            } else {
                Path parent = filePath.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                // Eager creation so that 0640 permissions are applied even when
                // the first append has not yet happened.
                Files.createFile(filePath);
                applyRestrictivePermissions(filePath);
                log.info("AppendOnlyFileAuditLog initialised: created new empty audit log at {}", filePath.toAbsolutePath());
            }
        } catch (IOException e) {
            throw new AuditLogException("Failed to initialise audit log at " + filePath.toAbsolutePath(), e);
        }
    }

    private void loadExisting() throws IOException {
        applyRestrictivePermissions(filePath);
        List<String> lines = Files.readAllLines(filePath, StandardCharsets.UTF_8);
        long expectedSeq = 1;
        String expectedPrev = AuditEntry.SENTINEL_PREV_HASH_HEX;
        boolean truncatedTrailer = false;

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            AuditEntry entry;
            try {
                entry = parseLine(line);
            } catch (Exception parseEx) {
                if (i == lines.size() - 1) {
                    log.warn("AppendOnlyFileAuditLog: trailing line {} is not parseable as JSON. "
                            + "Treating as aborted append (best-effort truncate). cause={}",
                            i + 1, parseEx.toString());
                    truncatedTrailer = true;
                    break;
                }
                throw new AuditLogException(
                        "Audit log corruption at line " + (i + 1) + " of " + filePath.toAbsolutePath(),
                        parseEx);
            }

            if (entry.sequenceNumber() != expectedSeq) {
                log.warn("AppendOnlyFileAuditLog: chain anomaly at line {} — expected sequenceNumber {}, got {}. "
                        + "Continuing load; verifyChainIntegrity() will report false.",
                        i + 1, expectedSeq, entry.sequenceNumber());
            }
            if (!entry.prevEntryHashHex().equals(expectedPrev)) {
                log.warn("AppendOnlyFileAuditLog: chain link broken at line {} (sequenceNumber={}) — "
                        + "expected prevEntryHashHex {}, got {}. Continuing load; verifyChainIntegrity() will report false.",
                        i + 1, entry.sequenceNumber(), expectedPrev, entry.prevEntryHashHex());
            }

            entries.add(entry);
            indexForAppend(entry);
            expectedSeq = entry.sequenceNumber() + 1;
            expectedPrev = entry.thisEntryHashHex();
        }

        if (truncatedTrailer) {
            rewriteTruncated();
        } else if (journal.terminateLastLine()) {
            // The last line is an entry, read and loaded above, without a
            // newline after it. The next append removes whatever follows the
            // last newline (JournalAppender), so it gets its newline now.
            log.warn("AppendOnlyFileAuditLog: the last entry of {} was not followed by a newline; one was added",
                    filePath.toAbsolutePath());
        }

        // Run a full chain-integrity check after loading so any tampering
        // since the previous shutdown is surfaced at startup, not only the
        // first time a supervisor calls /v1/gatekeeper/health.
        boolean intactAtBoot;
        try {
            intactAtBoot = verifyChain(List.copyOf(entries), readAnchorsForCheck());
        } catch (AnchorReadFailure e) {
            log.warn("AuditLog chain check failed: the timestamp anchor file could not be read: {}",
                    e.getCause().toString());
            intactAtBoot = false;
        }
        cachedIntegrity.set(new IntegrityStatus(intactAtBoot, Instant.now()));
        if (!intactAtBoot && !entries.isEmpty()) {
            log.warn("AppendOnlyFileAuditLog: chain integrity check FAILED at startup. The audit "
                    + "log at {} appears to have been tampered with. Continuing to boot — "
                    + "operator must investigate via /v1/audit/export and /v1/gatekeeper/anchor.",
                    filePath.toAbsolutePath());
        }

        log.info("AppendOnlyFileAuditLog loaded {} existing entries from {} (head sequenceNumber={}, chainIntact={})",
                entries.size(), filePath.toAbsolutePath(),
                entries.isEmpty() ? 0 : entries.get(entries.size() - 1).sequenceNumber(),
                intactAtBoot);
    }

    /**
     * After we detected and skipped a corrupt trailing line, rewrite the
     * file with only the entries we successfully parsed. Done atomically
     * via a temp file + replace so a crash mid-rewrite cannot lose data.
     */
    private void rewriteTruncated() throws IOException {
        Path tmp = filePath.resolveSibling(filePath.getFileName() + ".recover");
        StringBuilder sb = new StringBuilder();
        for (AuditEntry e : entries) {
            sb.append(json.writeValueAsString(e)).append('\n');
        }
        Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        // Atomic move where the FS supports it; fall back to plain replace.
        try {
            Files.move(tmp, filePath, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception atomicFail) {
            Files.move(tmp, filePath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        applyRestrictivePermissions(filePath);
    }

    @Override
    public AuditEntry append(AuditAppendRequest req) {
        if (req == null) {
            throw new AuditLogException("AuditAppendRequest must not be null");
        }
        try {
            // Acquire the append lock interruptibly so a shutdown hook
            // cannot wedge a worker thread waiting on a hung filesystem.
            appendLock.lockInterruptibly();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AuditLogException("Interrupted while waiting for audit-log lock", ie);
        }
        try {
            long nextSeq = entries.isEmpty() ? 1L : entries.get(entries.size() - 1).sequenceNumber() + 1;
            String prevHash = entries.isEmpty()
                    ? AuditEntry.SENTINEL_PREV_HASH_HEX
                    : entries.get(entries.size() - 1).thisEntryHashHex();
            Instant now = Instant.now();

            // Per-key link: the previous entry for the same attested key, the
            // sentinel for the key's first entry, null without a key.
            String keyFingerprint = req.keyFingerprintHex();
            String prevKeyHash = keyFingerprint == null
                    ? null
                    : lastEntryHashByKey.getOrDefault(keyFingerprint, AuditEntry.SENTINEL_PREV_HASH_HEX);

            byte[] canonical = AuditEntry.canonicalBytesForHashV2(
                    nextSeq, now,
                    req.mtlsClientPrincipal(), req.operation(), req.verificationId(),
                    req.requestDigestBase64(), req.receiptDigestBase64(), req.compliant(),
                    prevHash,
                    keyFingerprint, req.certSerialHex(), req.certIssuerDn(),
                    req.hsmVendor(), req.hsmSerial(), req.registryStatus(),
                    req.hsmFirmwareVersion(), req.hsmFipsApprovedMode(),
                    prevKeyHash);
            String thisHash = sha256Hex(canonical);
            byte[] sigBytes = signer.sign(AuditEntry.canonicalBytesForSignature(thisHash));
            String signatureB64 = Base64.getEncoder().encodeToString(sigBytes);

            // Entry mode: a token over the signature input, outside the hash.
            // A TSA failure returns empty and the entry is written without one
            // — supervision is never blocked on the TSA. A token that is not
            // of this entry's time is not stored either.
            String tokenB64 = timestamping.mode() == AuditTimestamping.Mode.ENTRY
                    ? timestamping.timestampEntry(thisHash, now).map(AuditTimestamping.Token::tokenBase64).orElse(null)
                    : null;

            AuditEntry entry = new AuditEntry(
                    nextSeq, now,
                    req.mtlsClientPrincipal(), req.operation(), req.verificationId(),
                    req.requestDigestBase64(), req.receiptDigestBase64(), req.compliant(),
                    prevHash, thisHash, signatureB64,
                    AuditEntry.CANONICAL_V2,
                    keyFingerprint, req.certSerialHex(), req.certIssuerDn(),
                    req.hsmVendor(), req.hsmSerial(), req.registryStatus(),
                    req.hsmFirmwareVersion(), req.hsmFipsApprovedMode(),
                    prevKeyHash,
                    tokenB64);

            persist(entry);
            entries.add(entry);
            indexForAppend(entry);

            log.info("AuditLog append: seq={}, principal={}, op={}, verificationId={}, compliant={}",
                    entry.sequenceNumber(), entry.mtlsClientPrincipal(), entry.operation(),
                    entry.verificationId(), entry.compliant());

            return entry;
        } finally {
            // Reached only after lockInterruptibly() succeeded.
            appendLock.unlock();
        }
    }

    /**
     * Advance the per-key index and the untimestamped counter for an entry
     * that is now part of the chain. Caller holds {@link #appendLock} (or is
     * the single-threaded loader).
     */
    private void indexForAppend(AuditEntry entry) {
        if (entry.isV2() && entry.keyFingerprintHex() != null) {
            lastEntryHashByKey.put(entry.keyFingerprintHex(), entry.thisEntryHashHex());
        }
        if (entry.timestampTokenBase64() == null) {
            untimestamped++;
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Counted over the whole chain, including entries written before
     * {@code entry} mode was enabled and v1 entries.</p>
     */
    @Override
    public OptionalLong untimestampedEntryCount() {
        appendLock.lock();
        try {
            return OptionalLong.of(untimestamped);
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * The {@code thisEntryHashHex} of the latest entry for a key fingerprint,
     * i.e. the value the next entry for that key will carry as
     * {@code prevKeyEntryHashHex}; empty when the key has no entry yet.
     */
    public Optional<String> lastEntryHashForKey(String keyFingerprintHex) {
        appendLock.lock();
        try {
            return Optional.ofNullable(lastEntryHashByKey.get(keyFingerprintHex));
        } finally {
            appendLock.unlock();
        }
    }

    private void persist(AuditEntry entry) {
        String line;
        try {
            line = json.writeValueAsString(entry);
        } catch (Exception jsonEx) {
            throw new AuditLogException("Failed to serialise audit entry to JSON", jsonEx);
        }
        // The entry and its newline are forced to the device before this
        // returns; an append that fails leaves no part of the line behind
        // (JournalAppender).
        try {
            journal.appendLine(line);
        } catch (IOException ioe) {
            throw new AuditLogException("Failed to persist audit entry seq=" + entry.sequenceNumber()
                    + " to " + filePath.toAbsolutePath(), ioe);
        }
    }

    @Override
    public Optional<AuditEntry> findByVerificationId(String id) {
        if (id == null) {
            return Optional.empty();
        }
        appendLock.lock();
        try {
            for (AuditEntry e : entries) {
                if (id.equals(e.verificationId())) {
                    return Optional.of(e);
                }
            }
            return Optional.empty();
        } finally {
            appendLock.unlock();
        }
    }

    @Override
    public List<AuditEntry> findInRange(Instant from, Instant to) {
        if (from == null || to == null) {
            throw new IllegalArgumentException("from/to must not be null");
        }
        if (from.isAfter(to)) {
            throw new IllegalArgumentException("from must be <= to");
        }
        appendLock.lock();
        try {
            List<AuditEntry> out = new ArrayList<>();
            for (AuditEntry e : entries) {
                Instant t = e.timestamp();
                if (!t.isBefore(from) && t.isBefore(to)) {
                    out.add(e);
                }
            }
            return out;
        } finally {
            appendLock.unlock();
        }
    }

    @Override
    public List<AuditEntry> findByPrincipal(String principal) {
        if (principal == null) {
            return Collections.emptyList();
        }
        appendLock.lock();
        try {
            List<AuditEntry> out = new ArrayList<>();
            for (AuditEntry e : entries) {
                if (principal.equals(e.mtlsClientPrincipal())) {
                    out.add(e);
                }
            }
            return out;
        } finally {
            appendLock.unlock();
        }
    }

    @Override
    public Optional<AuditEntry> head() {
        appendLock.lock();
        try {
            if (entries.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(entries.get(entries.size() - 1));
        } finally {
            appendLock.unlock();
        }
    }

    @Override
    public long size() {
        appendLock.lock();
        try {
            return entries.size();
        } finally {
            appendLock.unlock();
        }
    }

    @Override
    public boolean verifyChainIntegrity() {
        boolean intact = verifyChainOnDisk();
        cachedIntegrity.set(new IntegrityStatus(intact, Instant.now()));
        return intact;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Recomputes at most once per
     * {@code gatekeeper.audit.integrity-check-interval-seconds} (default
     * {@value #DEFAULT_INTEGRITY_CHECK_INTERVAL_SECONDS}). The recompute
     * itself takes a snapshot of the entry list under {@link #appendLock}
     * and then releases the lock before reading the file back and walking
     * the chain, so the signature verifications never block a concurrent
     * {@code append}.</p>
     */
    @Override
    public IntegrityStatus cachedIntegrityStatus() {
        IntegrityStatus current = cachedIntegrity.get();
        if (isFresh(current)) {
            return current;
        }
        if (current == null) {
            // No answer at all yet — the caller has to wait for the first one.
            integrityComputeLock.lock();
        } else if (!integrityComputeLock.tryLock()) {
            // A recompute is already running. Serving the previous result is
            // the point of the cache: health must not queue behind the walk.
            return current;
        }
        try {
            IntegrityStatus latest = cachedIntegrity.get();
            if (isFresh(latest)) {
                return latest;
            }
            IntegrityStatus fresh = new IntegrityStatus(verifyChainOnDisk(), Instant.now());
            cachedIntegrity.set(fresh);
            return fresh;
        } finally {
            integrityComputeLock.unlock();
        }
    }

    private boolean isFresh(IntegrityStatus status) {
        if (status == null || status.checkedAt() == null) {
            return false;
        }
        if (integrityCheckIntervalSeconds < 1) {
            return false;
        }
        return Instant.now().isBefore(status.checkedAt().plusSeconds(integrityCheckIntervalSeconds));
    }

    /**
     * Copy the entry list under {@link #appendLock} so the chain walk can
     * run without holding it. {@link AuditEntry} is a record of immutable
     * fields, so the copy is a consistent view and not a defensive-copy
     * illusion.
     */
    private List<AuditEntry> snapshot() {
        appendLock.lock();
        try {
            return List.copyOf(entries);
        } finally {
            appendLock.unlock();
        }
    }

    private AuditEntry parseLine(String line) throws IOException {
        return json.readValue(line, AuditEntry.class);
    }

    /**
     * Anchor records for the chain check; none when anchors are not checked
     * (no trusted TSA certificates, so nothing to validate them against, or
     * no anchor file configured). Read before the memory
     * snapshot is taken: every anchor is written for a head that was already
     * in memory, so an anchor read first can never legitimately point past
     * the snapshot.
     *
     * @throws AnchorReadFailure wrapped I/O or parse failure of the file
     */
    private List<TimestampAnchorRecord> readAnchorsForCheck() {
        Optional<TimestampAnchorStore> store = timestamping.verifier().isPresent()
                ? timestamping.anchorStore() : Optional.empty();
        try {
            return store.isPresent() ? store.get().readFromDisk() : List.of();
        } catch (IOException e) {
            throw new AnchorReadFailure(e);
        }
    }

    /** Unchecked carrier for a failed anchor-file read inside the chain check. */
    private static final class AnchorReadFailure extends RuntimeException {
        AnchorReadFailure(IOException cause) {
            super(cause);
        }
    }

    private boolean verifyChainOnDisk() {
        List<TimestampAnchorRecord> anchors;
        try {
            anchors = readAnchorsForCheck();
        } catch (AnchorReadFailure e) {
            log.warn("AuditLog chain check failed: the timestamp anchor file could not be read back: {}",
                    e.getCause().toString());
            return false;
        }
        List<AuditEntry> memory = snapshot();
        List<AuditEntry> onDisk = new ArrayList<>();
        try {
            String content = new String(Files.readAllBytes(filePath), StandardCharsets.UTF_8);
            for (String line : content.lines().toList()) {
                if (onDisk.size() == memory.size()) {
                    break;
                }
                if (line.isBlank()) {
                    continue;
                }
                onDisk.add(parseLine(line));
            }
        } catch (Exception e) {
            log.warn("AuditLog chain check failed: {} could not be read back and parsed: {}",
                    filePath.toAbsolutePath(), e.toString());
            return false;
        }
        if (onDisk.size() != memory.size()) {
            log.warn("AuditLog chain check failed: {} holds {} entries, the in-memory chain {}",
                    filePath.toAbsolutePath(), onDisk.size(), memory.size());
            return false;
        }
        if (!memory.isEmpty()) {
            AuditEntry memoryHead = memory.get(memory.size() - 1);
            AuditEntry diskHead = onDisk.get(onDisk.size() - 1);
            if (memoryHead.sequenceNumber() != diskHead.sequenceNumber()
                    || !MessageDigest.isEqual(
                            memoryHead.thisEntryHashHex().getBytes(StandardCharsets.UTF_8),
                            diskHead.thisEntryHashHex().getBytes(StandardCharsets.UTF_8))) {
                log.warn("AuditLog chain check failed: head on disk (sequenceNumber {}) does not match "
                        + "the in-memory head (sequenceNumber {})",
                        diskHead.sequenceNumber(), memoryHead.sequenceNumber());
                return false;
            }
        }
        return verifyChain(onDisk, anchors);
    }

    /**
     * The chain walk itself. Takes no lock; operates on a snapshot.
     *
     * <p>Per entry: sequence number, global link, recomputed hash (v1 or v2
     * form, as the entry states), signature. For v2 entries additionally the
     * per-key link. Across entries: once a v2 entry has been seen, no v1
     * entry may follow, and a v1 entry may not carry any field that only v2
     * hashes (it would be unauthenticated). When a token validator is
     * configured, every entry token and every anchor record is validated, an
     * entry token must be of the entry's time, and every anchor must name an
     * entry of this chain by sequence number and hash.</p>
     *
     * @param anchors anchor records to check; empty when anchors are not checked, which is
     *     always so without a token validator
     */
    private boolean verifyChain(List<AuditEntry> chain, List<TimestampAnchorRecord> anchors) {
        String algorithm = signer.getSignatureAlgorithm();
        List<PublicKey> verificationKeys = verificationKeys();
        TimestampTokenVerifier tokenVerifier = timestamping.verifier().orElse(null);
        Map<String, String> lastByKey = new HashMap<>();
        boolean seenV2 = false;
        long unvalidatedTokens = 0;
        String expectedPrev = AuditEntry.SENTINEL_PREV_HASH_HEX;
        long expectedSeq = 1;
        for (AuditEntry e : chain) {
            if (e.sequenceNumber() != expectedSeq) {
                log.warn("AuditLog chain check failed: sequenceNumber gap at {} (expected {}, got {})",
                        e.sequenceNumber(), expectedSeq, e.sequenceNumber());
                return false;
            }
            if (!e.prevEntryHashHex().equals(expectedPrev)) {
                log.warn("AuditLog chain check failed: prevEntryHash mismatch at sequenceNumber {}", e.sequenceNumber());
                return false;
            }
            if (e.isV2()) {
                seenV2 = true;
                String fp = e.keyFingerprintHex();
                if (fp == null) {
                    if (e.prevKeyEntryHashHex() != null) {
                        log.warn("AuditLog chain check failed: entry without keyFingerprintHex carries a "
                                + "prevKeyEntryHashHex at sequenceNumber {}", e.sequenceNumber());
                        return false;
                    }
                } else {
                    String expectedPrevKey = lastByKey.getOrDefault(fp, AuditEntry.SENTINEL_PREV_HASH_HEX);
                    if (e.prevKeyEntryHashHex() == null || !e.prevKeyEntryHashHex().equals(expectedPrevKey)) {
                        log.warn("AuditLog chain check failed: prevKeyEntryHash mismatch at sequenceNumber {} "
                                + "(key {})", e.sequenceNumber(), fp);
                        return false;
                    }
                    lastByKey.put(fp, e.thisEntryHashHex());
                }
            } else if (e.canonicalVersion() == null) {
                if (seenV2) {
                    log.warn("AuditLog chain check failed: v1 entry after a v2 entry at sequenceNumber {}",
                            e.sequenceNumber());
                    return false;
                }
                if (e.hasV2OnlyFields()) {
                    log.warn("AuditLog chain check failed: v1 entry at sequenceNumber {} carries v2 fields "
                            + "its hash does not cover", e.sequenceNumber());
                    return false;
                }
            } else {
                log.warn("AuditLog chain check failed: unknown canonicalVersion '{}' at sequenceNumber {}",
                        e.canonicalVersion(), e.sequenceNumber());
                return false;
            }
            String recomputed = sha256Hex(AuditEntry.canonicalBytesForHash(e));
            if (!MessageDigest.isEqual(
                    recomputed.getBytes(StandardCharsets.UTF_8),
                    e.thisEntryHashHex().getBytes(StandardCharsets.UTF_8))) {
                log.warn("AuditLog chain check failed: thisEntryHash mismatch at sequenceNumber {} "
                        + "(recomputed {}, stored {})",
                        e.sequenceNumber(), recomputed, e.thisEntryHashHex());
                return false;
            }
            if (!verifySignature(e, algorithm, verificationKeys)) {
                log.warn("AuditLog chain check failed: signature did not verify at sequenceNumber {}", e.sequenceNumber());
                return false;
            }
            if (e.timestampTokenBase64() != null) {
                if (tokenVerifier == null) {
                    unvalidatedTokens++;
                } else if (!verifyEntryToken(tokenVerifier, e)) {
                    return false;
                }
            }
            expectedSeq = e.sequenceNumber() + 1;
            expectedPrev = e.thisEntryHashHex();
        }
        if (unvalidatedTokens > 0) {
            log.warn("AuditLog chain check: {} entry timestamp token(s) present but not validated — "
                    + "gatekeeper.timestamping.trusted-certs-path is not configured", unvalidatedTokens);
        }
        for (TimestampAnchorRecord a : anchors) {
            long seq = a.headSequenceNumber();
            if (seq < 1 || seq > chain.size()) {
                log.warn("AuditLog chain check failed: timestamp anchor names sequenceNumber {} but the "
                        + "chain holds {} entries", seq, chain.size());
                return false;
            }
            AuditEntry anchored = chain.get((int) (seq - 1));
            if (!MessageDigest.isEqual(anchored.thisEntryHashHex().getBytes(StandardCharsets.UTF_8),
                    a.headHashHex().getBytes(StandardCharsets.UTF_8))) {
                log.warn("AuditLog chain check failed: timestamp anchor for sequenceNumber {} does not "
                        + "match that entry's hash", seq);
                return false;
            }
            TimestampTokenVerifier.Verification token = verifiedToken(tokenVerifier, a.tokenBase64(),
                    a.headHashHex(), "anchor of sequenceNumber " + seq);
            if (token == null) {
                return false;
            }
            // The record's genTime is a copy of the token's, and it is the
            // copy that /anchor, /anchor/timestamps and /health report. Until
            // 1.7.0 the two were never compared, so the copy could be edited
            // in the anchor file without the chain check noticing.
            if (!Objects.equals(a.genTime(), token.genTime())) {
                log.warn("AuditLog chain check failed: timestamp anchor for sequenceNumber {} states genTime {} "
                        + "but its token was issued at {}", seq, a.genTime(), token.genTime());
                return false;
            }
        }
        return true;
    }

    /**
     * An entry's token: valid for the entry's hash, and issued at the entry's
     * own time. Without the second condition the holder of the signing key
     * could write the chain again and have every entry time-stamped anew —
     * the new tokens are valid for the new hashes, and only their
     * {@code genTime} shows that they were not obtained when the entries say
     * they were written.
     */
    private boolean verifyEntryToken(TimestampTokenVerifier verifier, AuditEntry e) {
        TimestampTokenVerifier.Verification v = verifiedToken(verifier, e.timestampTokenBase64(),
                e.thisEntryHashHex(), "entry sequenceNumber " + e.sequenceNumber());
        if (v == null) {
            return false;
        }
        if (!timestamping.isEntryTime(e.timestamp(), v.genTime())) {
            log.warn("AuditLog chain check failed: timestamp token of entry sequenceNumber {} was issued at {}, "
                            + "more than {}s from the entry's timestamp {} — the entry was time-stamped again, "
                            + "or its timestamp is not the time it was written",
                    e.sequenceNumber(), v.genTime(), timestamping.entryTokenTolerance().toSeconds(), e.timestamp());
            return false;
        }
        return true;
    }

    /** The verification of a token that is valid for {@code hashHex}; {@code null}, after a WARN, otherwise. */
    private static TimestampTokenVerifier.Verification verifiedToken(TimestampTokenVerifier verifier,
                                                                     String tokenBase64, String hashHex,
                                                                     String what) {
        byte[] token;
        try {
            token = Base64.getDecoder().decode(tokenBase64);
        } catch (IllegalArgumentException ex) {
            log.warn("AuditLog chain check failed: timestamp token of {} is not valid Base64", what);
            return null;
        }
        TimestampTokenVerifier.Verification v = verifier.verify(token, hashHex.getBytes(StandardCharsets.UTF_8));
        if (!v.valid()) {
            log.warn("AuditLog chain check failed: timestamp token of {} did not validate: {}", what, v.error());
            return null;
        }
        return v;
    }

    /**
     * Verify an entry's signature with the signer's algorithm against the
     * active key and every retired key in turn. An entry passes if any of
     * them verifies it: entries written before a rotation are signed under
     * a key that is now retired.
     */
    private boolean verifySignature(AuditEntry e, String algorithm, List<PublicKey> verificationKeys) {
        byte[] sig;
        try {
            sig = Base64.getDecoder().decode(e.entrySignatureBase64());
        } catch (Exception ex) {
            log.warn("AuditLog signature at sequenceNumber {} is not valid Base64: {}",
                    e.sequenceNumber(), ex.toString());
            return false;
        }
        byte[] signedBytes = AuditEntry.canonicalBytesForSignature(e);
        Exception lastFailure = null;
        for (PublicKey key : verificationKeys) {
            try {
                Signature verifier = Signature.getInstance(algorithm);
                verifier.initVerify(key);
                verifier.update(signedBytes);
                if (verifier.verify(sig)) {
                    return true;
                }
            } catch (Exception ex) {
                lastFailure = ex;
            }
        }
        if (lastFailure != null) {
            log.warn("AuditLog signature verification threw an exception at sequenceNumber {}: {}",
                    e.sequenceNumber(), lastFailure.toString());
        }
        return false;
    }

    private List<PublicKey> verificationKeys() {
        List<PublicKey> keys = new ArrayList<>();
        addCertificateKey(keys, signer.getSigningCertificatePem());
        if (keyDirectory != null) {
            for (GatekeeperKeyDirectory.KeyEntry key : keyDirectory.allKeys()) {
                if ("RETIRED".equals(key.status())) {
                    addCertificateKey(keys, key.certificatePem());
                }
            }
        }
        return keys;
    }

    private static void addCertificateKey(List<PublicKey> keys, String certificatePem) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certificatePem.getBytes(StandardCharsets.UTF_8)));
            keys.add(cert.getPublicKey());
        } catch (Exception ex) {
            log.warn("AuditLog: signing certificate could not be parsed and is not used for "
                    + "chain verification: {}", ex.toString());
        }
    }

    private static String sha256Hex(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(md.digest(in));
        } catch (NoSuchAlgorithmException nsae) {
            // SHA-256 is mandated by every JRE; reaching this branch is a
            // platform misconfiguration we cannot recover from.
            throw new AuditLogException("SHA-256 not available on JRE", nsae);
        }
    }

    private static void applyRestrictivePermissions(Path p) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ);
            Files.setPosixFilePermissions(p, PosixFilePermissions.asFileAttribute(perms).value());
        } catch (UnsupportedOperationException nonPosix) {
            log.warn("AppendOnlyFileAuditLog: non-POSIX filesystem at {}; cannot enforce 0640 permissions.",
                    p.toAbsolutePath());
        } catch (IOException ioe) {
            log.warn("AppendOnlyFileAuditLog: failed to set 0640 permissions on {}: {}",
                    p.toAbsolutePath(), ioe.toString());
        }
    }
}
