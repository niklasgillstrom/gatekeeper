package eu.gillstrom.gatekeeper.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Default {@link AuditLog} implementation backed by a JSON-Lines file.
 *
 * <p>Storage layout: one entry per line, UTF-8 JSON, terminated with
 * {@code \n}. Each append is fsynced via {@link RandomAccessFile#getFD()}
 * + {@code FileDescriptor.sync()} before {@code append()} returns so
 * that crash persistence is guaranteed and the chain cannot acquire
 * gaps between entries that returned successfully and entries actually
 * on disk.</p>
 *
 * <p>Permissions: when the file is created the implementation attempts
 * to set the POSIX permissions to {@code 0640} so that arbitrary
 * processes on the host cannot read or modify the trail. On non-POSIX
 * filesystems this step is logged at WARN and execution continues.</p>
 *
 * <p>Recovery: at startup the file is read line-by-line and chain
 * integrity is validated. A trailing line that fails to parse is treated
 * as an aborted append (e.g. process killed mid-write) and is best-effort
 * truncated; any earlier corruption is reported at WARN but does not
 * prevent boot — the operator must investigate. Mid-file corruption MUST
 * fail {@link #verifyChainIntegrity()} so it is detectable by supervisory
 * tooling.</p>
 *
 * <p>Concurrency: {@link #append(AuditAppendRequest)} is serialised under
 * a {@link ReentrantLock}. The lock is acquired interruptibly so a
 * shutdown hook cannot wedge a worker thread; on interrupt the operation
 * fails with {@link AuditLogException}. Read methods take a snapshot of
 * the in-memory entry list, so they never observe a half-built entry.</p>
 *
 * <p>Legal basis: see {@link AuditLog} javadoc.</p>
 */
@Component
public class AppendOnlyFileAuditLog implements AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AppendOnlyFileAuditLog.class);

    private final Path filePath;
    private final ReceiptSigner signer;
    private final ObjectMapper json;
    private final ReentrantLock appendLock = new ReentrantLock();

    /**
     * In-memory mirror of the on-disk chain. Reads (range, principal,
     * verificationId) operate over this list. The list is mutated only
     * under {@link #appendLock}; read methods snapshot it under the lock
     * to avoid a torn read against a concurrent append.
     */
    private final List<AuditEntry> entries = new ArrayList<>();

    public AppendOnlyFileAuditLog(
            @Value("${gatekeeper.audit.path:./audit-log.jsonl}") String configuredPath,
            ReceiptSigner signer) {
        this.filePath = Paths.get(configuredPath);
        this.signer = signer;
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
                if (parent != null && !Files.exists(parent)) {
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
                entry = json.readValue(line, AuditEntry.class);
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
            expectedSeq = entry.sequenceNumber() + 1;
            expectedPrev = entry.thisEntryHashHex();
        }

        if (truncatedTrailer) {
            rewriteTruncated();
        }

        // Run a full chain-integrity check after loading so any tampering
        // since the previous shutdown is surfaced at startup, not only the
        // first time a supervisor calls /v1/audit/health.
        boolean intactAtBoot = verifyChainIntegrityNoLock();
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
     * Internal chain-integrity check executed during {@link #initialise()}
     * before the lock-acquiring read methods are exposed to callers.
     * Identical logic to {@link #verifyChainIntegrity()} but does not
     * acquire {@link #appendLock} (we are still inside @PostConstruct).
     */
    private boolean verifyChainIntegrityNoLock() {
        String expectedPrev = AuditEntry.SENTINEL_PREV_HASH_HEX;
        long expectedSeq = 1;
        for (AuditEntry e : entries) {
            if (e.sequenceNumber() != expectedSeq) {
                return false;
            }
            if (!e.prevEntryHashHex().equals(expectedPrev)) {
                return false;
            }
            String recomputed = sha256Hex(AuditEntry.canonicalBytesForHash(e));
            if (!MessageDigest.isEqual(
                    recomputed.getBytes(StandardCharsets.UTF_8),
                    e.thisEntryHashHex().getBytes(StandardCharsets.UTF_8))) {
                return false;
            }
            if (!verifySignature(e)) {
                return false;
            }
            expectedSeq = e.sequenceNumber() + 1;
            expectedPrev = e.thisEntryHashHex();
        }
        return true;
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

            byte[] canonical = AuditEntry.canonicalBytesForHash(
                    nextSeq, now,
                    req.mtlsClientPrincipal(), req.operation(), req.verificationId(),
                    req.requestDigestBase64(), req.receiptDigestBase64(), req.compliant(),
                    prevHash);
            String thisHash = sha256Hex(canonical);
            byte[] sigBytes = signer.sign(AuditEntry.canonicalBytesForSignature(thisHash));
            String signatureB64 = Base64.getEncoder().encodeToString(sigBytes);

            AuditEntry entry = new AuditEntry(
                    nextSeq, now,
                    req.mtlsClientPrincipal(), req.operation(), req.verificationId(),
                    req.requestDigestBase64(), req.receiptDigestBase64(), req.compliant(),
                    prevHash, thisHash, signatureB64);

            persist(entry);
            entries.add(entry);

            log.info("AuditLog append: seq={}, principal={}, op={}, verificationId={}, compliant={}",
                    entry.sequenceNumber(), entry.mtlsClientPrincipal(), entry.operation(),
                    entry.verificationId(), entry.compliant());

            return entry;
        } finally {
            if (appendLock.isHeldByCurrentThread()) {
                appendLock.unlock();
            }
        }
    }

    private void persist(AuditEntry entry) {
        String line;
        try {
            line = json.writeValueAsString(entry) + "\n";
        } catch (Exception jsonEx) {
            throw new AuditLogException("Failed to serialise audit entry to JSON", jsonEx);
        }
        // We open the file via RandomAccessFile so we can fsync via the
        // FileDescriptor — Files.write() does not expose an fsync hook on
        // every JDK and on every filesystem.
        try (RandomAccessFile raf = new RandomAccessFile(filePath.toFile(), "rwd")) {
            raf.seek(raf.length());
            raf.write(line.getBytes(StandardCharsets.UTF_8));
            // "rwd" mode already syncs writes to the underlying device;
            // explicitly call getFD().sync() as a belt-and-braces measure
            // for filesystems that interpret "rwd" loosely.
            raf.getFD().sync();
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
        appendLock.lock();
        try {
            String expectedPrev = AuditEntry.SENTINEL_PREV_HASH_HEX;
            long expectedSeq = 1;
            for (AuditEntry e : entries) {
                if (e.sequenceNumber() != expectedSeq) {
                    log.warn("AuditLog chain check failed: sequenceNumber gap at {} (expected {}, got {})",
                            e.sequenceNumber(), expectedSeq, e.sequenceNumber());
                    return false;
                }
                if (!e.prevEntryHashHex().equals(expectedPrev)) {
                    log.warn("AuditLog chain check failed: prevEntryHash mismatch at sequenceNumber {}", e.sequenceNumber());
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
                if (!verifySignature(e)) {
                    log.warn("AuditLog chain check failed: signature did not verify at sequenceNumber {}", e.sequenceNumber());
                    return false;
                }
                expectedSeq = e.sequenceNumber() + 1;
                expectedPrev = e.thisEntryHashHex();
            }
            return true;
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Verify an entry's signature against the gatekeeper's active key.
     *
     * <p>Limitation: when the gatekeeper rotates its signing key, entries
     * older than the rotation will fail this check because they were
     * signed under a now-retired key. A future iteration should consult
     * {@code GatekeeperKeyDirectory} and try each retired key in turn.
     * The current implementation suffices for a deployment that has not
     * yet rotated; rotation triggers a clean re-anchor of the chain so
     * the issue is also catchable by {@code /v1/gatekeeper/anchor}.</p>
     */
    private boolean verifySignature(AuditEntry e) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(signer.getSigningCertificatePem().getBytes(StandardCharsets.UTF_8)));
            String algorithm = pickAlgorithmFor(cert.getPublicKey().getAlgorithm());
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(cert.getPublicKey());
            verifier.update(AuditEntry.canonicalBytesForSignature(e));
            byte[] sig = Base64.getDecoder().decode(e.entrySignatureBase64());
            return verifier.verify(sig);
        } catch (Exception ex) {
            log.warn("AuditLog signature verification threw an exception at sequenceNumber {}: {}",
                    e.sequenceNumber(), ex.toString());
            return false;
        }
    }

    /**
     * Pick a verification algorithm consistent with the signer's signing
     * algorithm. The {@link AuditLog} contract specifies SHA256withRSA
     * (or SHA256withECDSA when the signer is bound to an EC key); deployments
     * that wire {@link ReceiptSigner} with PSS or SHA384 must update this
     * mapping in lock-step. The lock-step is acceptable here because the
     * configuration is deployment-time and verifyChainIntegrity() is
     * exercised by the gatekeeper's own startup hook.
     */
    private static String pickAlgorithmFor(String keyAlg) {
        if ("EC".equalsIgnoreCase(keyAlg)) {
            return "SHA256withECDSA";
        }
        return "SHA256withRSA";
    }

    private static String sha256Hex(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(in);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
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
