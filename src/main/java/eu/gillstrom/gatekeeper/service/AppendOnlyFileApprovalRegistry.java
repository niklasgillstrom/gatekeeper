package eu.gillstrom.gatekeeper.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.util.JournalAppender;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * File-backed implementation of {@link ApprovalRegistry}.
 *
 * <p>Activated when {@code gatekeeper.registry.mode=file}. Maintains an
 * in-memory index for fast queries (same shape as
 * {@link InMemoryApprovalRegistry}) plus an append-only JSONL journal at
 * {@code gatekeeper.registry.path} that records every {@code register}
 * and {@code confirm} operation. The journal is fsynced before each
 * write returns, so a crash after a successful return cannot lose the
 * record. A write that fails leaves no part of its line in the file, and
 * what a stopped process left after the last newline is removed by the
 * next write ({@link JournalAppender}); until 1.7.0 the next write
 * continued on that line, and the record it acknowledged was skipped as
 * malformed at the next start.</p>
 *
 * <h2>Journal format</h2>
 *
 * <p>One operation per line, UTF-8 JSON. Two operation types:</p>
 *
 * <ul>
 *   <li><strong>{@code REGISTER}</strong> — emitted by
 *       {@code register(...)}. Carries the full initial entry payload.</li>
 *   <li><strong>{@code CONFIRM}</strong> — emitted by
 *       {@code confirm(...)}. Carries the confirmation outcome plus the
 *       {@code verificationId} key needed to apply it, the
 *       {@code confirmationTimestamp}, and — when the
 *       outcome is {@code VERIFIED_AND_ISSUED} — the issued certificate as
 *       {@code issuedCertificatePem}, {@code issuedCertificateSerial} and
 *       {@code issuedCertificateIssuerDn}. Lines written before 1.5.0 lack
 *       those four fields and replay without a stored certificate and with
 *       a {@code null} {@code confirmationTimestamp}.</li>
 *   <li><strong>{@code STATUS_CHANGE}</strong> — emitted by
 *       {@code changeStatus(...)} for an applied key-lifecycle event. Carries
 *       {@code verificationId}, {@code status} (the new status:
 *       {@code SUPERSEDED}, {@code REVOKED} or {@code DECOMMISSIONED}),
 *       {@code previousStatus}, {@code statusChangedAt}, and, when given,
 *       {@code reason} and {@code successorVerificationId}. Journals written
 *       before this operation existed contain none and replay unchanged. A
 *       build that predates it skips such lines as an unknown op type, so
 *       downgrading loses the status changes.</li>
 * </ul>
 *
 * <p>On startup the journal is replayed in order: each {@code REGISTER}
 * creates an entry; each {@code CONFIRM} applies the confirmation
 * outcome to the existing entry. A {@code CONFIRM} for an unknown
 * {@code verificationId} is logged at WARN and skipped — this should
 * not happen with disciplined writes but is recoverable. A
 * {@code STATUS_CHANGE} is applied when its entry exists and the change is
 * allowed from the entry's replayed status
 * ({@link ApprovalRegistry#isAllowedStatusChange}); otherwise it is logged at
 * WARN and skipped.</p>
 *
 * <p>Permissions: at every start, for a new journal and for an existing
 * one, the implementation attempts to set POSIX permissions to
 * {@code 0640}. On non-POSIX filesystems this step is logged at WARN and
 * execution continues.</p>
 *
 * <p>Concurrency: writes are serialised under a {@link ReentrantLock};
 * reads return snapshots from the in-memory index.</p>
 *
 * <p>Legal basis: see {@link ApprovalRegistry} javadoc.</p>
 */
@Component
@ConditionalOnProperty(name = "gatekeeper.registry.mode", havingValue = "file")
public class AppendOnlyFileApprovalRegistry implements ApprovalRegistry {

    private static final Logger log = LoggerFactory.getLogger(AppendOnlyFileApprovalRegistry.class);

    private static final String OP_REGISTER = "REGISTER";
    private static final String OP_CONFIRM = "CONFIRM";
    private static final String OP_STATUS_CHANGE = "STATUS_CHANGE";

    private final Path journalPath;
    private final JournalAppender journal;
    private final ObjectMapper json;
    private final ConcurrentHashMap<String, RegistryEntry> entries = new ConcurrentHashMap<>();
    private final ReentrantLock writeLock = new ReentrantLock();

    public AppendOnlyFileApprovalRegistry(
            @Value("${gatekeeper.registry.path:/var/lib/gatekeeper/approval-registry.jsonl}") String path) {
        this.journalPath = Paths.get(path);
        this.journal = new JournalAppender(journalPath);
        @SuppressWarnings("deprecation")
        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        this.json = mapper;
    }

    @PostConstruct
    void initialise() throws IOException {
        if (Files.notExists(journalPath)) {
            if (journalPath.getParent() != null) {
                Files.createDirectories(journalPath.getParent());
            }
            Files.createFile(journalPath);
            applyPosixPermissions(journalPath);
            log.info("AppendOnlyFileApprovalRegistry initialised: created new empty journal at {}", journalPath);
            return;
        }

        // As for a new journal, and as the audit log does at every start:
        // until 1.7.0 the permissions were set only when the file was created.
        applyPosixPermissions(journalPath);

        // Replay the journal to rebuild the in-memory index.
        int registerCount = 0;
        int confirmCount = 0;
        int statusChangeCount = 0;
        int skipped = 0;
        boolean lastLineIsARecord = false;
        try (var lines = Files.lines(journalPath, StandardCharsets.UTF_8)) {
            for (String line : (Iterable<String>) lines::iterator) {
                if (line.isBlank()) {
                    continue;
                }
                lastLineIsARecord = false;
                try {
                    JsonNode op = json.readTree(line);
                    lastLineIsARecord = true;
                    String opType = op.path("op").asText();
                    if (OP_REGISTER.equals(opType)) {
                        RegistryEntry entry = json.treeToValue(op.path("entry"), RegistryEntry.class);
                        entries.put(entry.getVerificationId(), entry);
                        registerCount++;
                    } else if (OP_CONFIRM.equals(opType)) {
                        String verificationId = op.path("verificationId").asText();
                        RegistryEntry existing = entries.get(verificationId);
                        if (existing == null) {
                            log.warn("Replay: CONFIRM for unknown verificationId={} — skipping", verificationId);
                            skipped++;
                            continue;
                        }
                        applyConfirmation(existing,
                                op.path("confirmationTimestamp").asText(null),
                                op.path("issued").asBoolean(),
                                op.path("actualPublicKeyFingerprint").asText(null),
                                op.path("publicKeyMatch").asBoolean(),
                                issuedCertificateFrom(op));
                        // A journalled CONFIRM is proof the nonce was spent,
                        // so replay must consume it too — otherwise a restart
                        // would make an already-used nonce valid again.
                        existing.setConfirmationNonce(null);
                        confirmCount++;
                    } else if (OP_STATUS_CHANGE.equals(opType)) {
                        if (replayStatusChange(op)) {
                            statusChangeCount++;
                        } else {
                            skipped++;
                        }
                    } else {
                        log.warn("Replay: unknown op type {} — skipping line", opType);
                        skipped++;
                    }
                } catch (JsonProcessingException e) {
                    log.warn("Replay: malformed line skipped: {}", e.getMessage());
                    skipped++;
                }
            }
        }
        // A last line that is a whole record but has no newline after it was
        // read and applied above. It gets its newline now: the next append
        // removes whatever follows the last newline (JournalAppender). A last
        // line that is not a record is left for that append to remove.
        if (lastLineIsARecord && journal.terminateLastLine()) {
            log.warn("Replay: the last record of {} was not followed by a newline; one was added", journalPath);
        }
        log.info("AppendOnlyFileApprovalRegistry initialised: replayed {} REGISTER + {} CONFIRM ops "
                + "+ {} STATUS_CHANGE ops from {} ({} entries in index, {} skipped)",
                registerCount, confirmCount, statusChangeCount, journalPath, entries.size(), skipped);
    }

    /**
     * Apply one journalled {@code STATUS_CHANGE}. Returns {@code false}, after
     * a WARN, when the entry is unknown, the status is not a lifecycle status,
     * or the change is not allowed from the entry's replayed status: the
     * journal only ever records allowed changes, so any of these means the
     * line is not one this registry wrote in that order.
     */
    private boolean replayStatusChange(JsonNode op) {
        String verificationId = op.path("verificationId").asText();
        RegistryEntry existing = entries.get(verificationId);
        if (existing == null) {
            log.warn("Replay: STATUS_CHANGE for unknown verificationId={} — skipping", verificationId);
            return false;
        }
        RegistryStatus target;
        try {
            target = RegistryStatus.valueOf(op.path("status").asText());
        } catch (IllegalArgumentException e) {
            log.warn("Replay: STATUS_CHANGE with unknown status '{}' for verificationId={} — skipping",
                    op.path("status").asText(), verificationId);
            return false;
        }
        if (!ApprovalRegistry.isLifecycleStatus(target)
                || !ApprovalRegistry.isAllowedStatusChange(existing.getStatus(), target)) {
            log.warn("Replay: STATUS_CHANGE {} -> {} for verificationId={} is not an allowed transition — skipping",
                    existing.getStatus(), target, verificationId);
            return false;
        }
        ApprovalRegistry.applyStatusChange(existing, target,
                op.path("statusChangedAt").asText(null),
                op.path("reason").asText(null),
                op.path("successorVerificationId").asText(null));
        return true;
    }

    private void applyPosixPermissions(Path path) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ);
            Files.setPosixFilePermissions(path, PosixFilePermissions.asFileAttribute(perms).value());
        } catch (UnsupportedOperationException | IOException e) {
            log.warn("Could not set POSIX permissions on {}: {}", path, e.getMessage());
        }
    }

    @Override
    public RegistryEntry register(String verificationId,
                                  String confirmationNonce,
                                  boolean compliant,
                                  String publicKeyFingerprint,
                                  String supplierIdentifier,
                                  String supplierName,
                                  String hsmVendor,
                                  String hsmModel,
                                  String countryCode,
                                  String verificationPrincipal) {
        return register(verificationId, confirmationNonce, compliant, publicKeyFingerprint,
                Parties.supplierOnly(supplierIdentifier, supplierName), hsmVendor, hsmModel,
                countryCode, verificationPrincipal);
    }

    @Override
    public RegistryEntry register(String verificationId,
                                  String confirmationNonce,
                                  boolean compliant,
                                  String publicKeyFingerprint,
                                  Parties parties,
                                  String hsmVendor,
                                  String hsmModel,
                                  String countryCode,
                                  String verificationPrincipal) {
        return register(verificationId, confirmationNonce, compliant, publicKeyFingerprint, parties, null,
                hsmVendor, hsmModel, countryCode, verificationPrincipal);
    }

    @Override
    public RegistryEntry register(String verificationId,
                                  String confirmationNonce,
                                  boolean compliant,
                                  String publicKeyFingerprint,
                                  Parties parties,
                                  eu.gillstrom.gatekeeper.model.VerificationRequest submission,
                                  String hsmVendor,
                                  String hsmModel,
                                  String countryCode,
                                  String verificationPrincipal) {
        RegistryEntry entry = RegistryEntry.builder()
                .submission(submission)
                .verificationId(verificationId)
                .confirmationNonce(confirmationNonce)
                .compliant(compliant)
                .publicKeyFingerprint(publicKeyFingerprint)
                .customerOrganisationNumber(parties.customerOrganisationNumber())
                .customerSwishNumber(parties.customerSwishNumber())
                .supplierIdentifier(parties.supplierIdentifier())
                .supplierNumber(parties.supplierNumber())
                .supplierName(parties.supplierName())
                .hsmVendor(hsmVendor)
                .hsmModel(hsmModel)
                .countryCode(countryCode)
                .verificationPrincipal(verificationPrincipal)
                .verificationTimestamp(Instant.now().toString())
                .status(compliant ? RegistryStatus.VERIFIED_AND_ISSUED : RegistryStatus.REJECTED_NOT_ISSUED)
                .certificateReceived(false)
                .build();

        if (compliant) {
            entry.setStatus(null); // Awaiting confirmation
        }

        appendOp(OP_REGISTER, verificationId, mapper -> mapper
                .createObjectNode()
                .put("op", OP_REGISTER)
                .set("entry", json.valueToTree(entry)));

        entries.put(verificationId, entry);
        return entry;
    }

    /**
     * {@inheritDoc}
     *
     * <p>The whole operation runs under {@link #writeLock}, not just the
     * journal append. The nonce check and the nonce consumption are one
     * atomic step: with them apart, two concurrent confirmations carrying
     * the same nonce both read a non-null value and both succeed, which
     * defeats the single-use property. {@code appendOp} re-enters the same
     * lock.</p>
     *
     * <p>The in-memory transition is applied and the nonce cleared only
     * <em>after</em> the journal append has returned. Clearing the nonce
     * first meant that an I/O failure on the journal burned the nonce: the
     * transition was never recorded, the caller got a 5xx and was told to
     * retry, and the retry then failed the nonce check against a null
     * expected value — the FE could never close the loop for that
     * verificationId again.</p>
     */
    @Override
    public Optional<RegistryEntry> confirm(String verificationId,
                                           String submittedNonce,
                                           boolean issued,
                                           String actualPublicKeyFingerprint,
                                           boolean publicKeyMatch,
                                           IssuedCertificate issuedCertificate) {
        writeLock.lock();
        try {
            RegistryEntry entry = entries.get(verificationId);
            if (entry == null) {
                return Optional.empty();
            }

            // Constant-time nonce comparison. Mismatch is a Step-7 replay
            // attempt and must NOT be journalled (no state transition occurs).
            String expectedNonce = entry.getConfirmationNonce();
            if (expectedNonce == null
                    || submittedNonce == null
                    || !java.security.MessageDigest.isEqual(
                            expectedNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                            submittedNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                log.warn("Nonce mismatch on confirm for verificationId={} — possible Step-7 replay attempt",
                        verificationId);
                throw new NonceMismatchException(verificationId);
            }

            // Journal the state transition first; then apply it to the
            // in-memory entry. If journalling fails we let the exception
            // propagate and the caller surfaces it as a 5xx so the FE
            // retries — with the entry untouched and the nonce still intact.
            String confirmationTimestamp = Instant.now().toString();
            boolean storesCertificate = issuedCertificate != null
                    && entry.isCompliant() && issued && publicKeyMatch;
            if (storesCertificate) {
                // Before the journal append: a refused confirmation is no
                // state transition, exactly like a nonce mismatch.
                ApprovalRegistry.requireCertificateNotRegistered(entries.values(), verificationId, issuedCertificate);
            }
            appendOp(OP_CONFIRM, verificationId, mapper -> {
                ObjectNode op = mapper
                        .createObjectNode()
                        .put("op", OP_CONFIRM)
                        .put("verificationId", verificationId)
                        .put("issued", issued)
                        .put("actualPublicKeyFingerprint", actualPublicKeyFingerprint)
                        .put("publicKeyMatch", publicKeyMatch)
                        .put("confirmationTimestamp", confirmationTimestamp);
                if (storesCertificate) {
                    op.put("issuedCertificatePem", issuedCertificate.pem());
                    op.put("issuedCertificateSerial", issuedCertificate.serialHex());
                    op.put("issuedCertificateIssuerDn", issuedCertificate.issuerDn());
                }
                return op;
            });

            // Durable now. The nonce is spent: a replay finds null and is
            // rejected by the check above.
            applyConfirmation(entry, confirmationTimestamp, issued, actualPublicKeyFingerprint,
                    publicKeyMatch, issuedCertificate);
            entry.setConfirmationNonce(null);

            return Optional.of(entry);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Apply a confirmation outcome to an entry. Does not touch the nonce —
     * see {@link #confirm} for why consumption is ordered after the journal
     * append, and {@link #initialise()} for the replay path, which clears
     * the nonce because the journal proves the confirmation happened.
     */
    private void applyConfirmation(RegistryEntry entry,
                                   String confirmationTimestamp,
                                   boolean issued,
                                   String actualPublicKeyFingerprint,
                                   boolean publicKeyMatch,
                                   IssuedCertificate issuedCertificate) {
        entry.setConfirmationTimestamp(confirmationTimestamp);
        entry.setCertificateReceived(issued);

        if (entry.isCompliant() && issued && publicKeyMatch) {
            entry.setStatus(RegistryStatus.VERIFIED_AND_ISSUED);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
            if (issuedCertificate != null) {
                entry.setIssuedCertificatePem(issuedCertificate.pem());
                entry.setIssuedCertificateSerial(issuedCertificate.serialHex());
                entry.setIssuedCertificateIssuerDn(issuedCertificate.issuerDn());
            }
        } else if (entry.isCompliant() && issued && !publicKeyMatch) {
            entry.setStatus(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
        } else if (entry.isCompliant() && !issued) {
            entry.setStatus(RegistryStatus.VERIFIED_NOT_ISSUED);
        } else if (!entry.isCompliant() && issued) {
            entry.setStatus(RegistryStatus.ANOMALY_ISSUED_DESPITE_REJECTION);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
        }
        // Neither compliant nor issued: the entry keeps the REJECTED_NOT_ISSUED
        // it was registered with, and confirm is single-use, so nothing changed it.
    }

    /**
     * {@inheritDoc}
     *
     * <p>Runs under {@link #writeLock}, like {@link #confirm}: the check
     * against the current status, the journal append and the in-memory change
     * are one step. The {@code STATUS_CHANGE} line is fsynced before the
     * in-memory entry changes, so a journal failure leaves the entry as it
     * was and propagates as {@link IllegalStateException}.</p>
     */
    @Override
    public StatusChange changeStatus(String verificationId, RegistryStatus target, String reason,
                                     String successorVerificationId) {
        if (!ApprovalRegistry.isLifecycleStatus(target)) {
            throw new IllegalArgumentException("Not a lifecycle status: " + target);
        }
        writeLock.lock();
        try {
            RegistryEntry entry = entries.get(verificationId);
            if (entry == null) {
                return StatusChange.notFound();
            }
            RegistryStatus current = entry.getStatus();
            if (!ApprovalRegistry.isAllowedStatusChange(current, target)) {
                return StatusChange.refused(current);
            }
            String changedAt = Instant.now().toString();
            String successor = target == RegistryStatus.SUPERSEDED ? successorVerificationId : null;
            appendOp(OP_STATUS_CHANGE, verificationId, mapper -> {
                ObjectNode op = mapper
                        .createObjectNode()
                        .put("op", OP_STATUS_CHANGE)
                        .put("verificationId", verificationId)
                        .put("status", target.name())
                        .put("previousStatus", current.name())
                        .put("statusChangedAt", changedAt);
                if (reason != null) {
                    op.put("reason", reason);
                }
                if (successor != null) {
                    op.put("successorVerificationId", successor);
                }
                return op;
            });
            ApprovalRegistry.applyStatusChange(entry, target, changedAt, reason, successor);
            return StatusChange.applied(current, target, changedAt);
        } finally {
            writeLock.unlock();
        }
    }

    private static IssuedCertificate issuedCertificateFrom(JsonNode op) {
        String pem = op.path("issuedCertificatePem").asText(null);
        String serialHex = op.path("issuedCertificateSerial").asText(null);
        String issuerDn = op.path("issuedCertificateIssuerDn").asText(null);
        if (pem == null || serialHex == null || issuerDn == null) {
            return null;
        }
        return new IssuedCertificate(pem, serialHex, issuerDn);
    }

    @FunctionalInterface
    private interface OpBuilder {
        JsonNode build(ObjectMapper mapper);
    }

    private void appendOp(String opType, String verificationId, OpBuilder builder) {
        writeLock.lock();
        try {
            JsonNode op = builder.build(json);
            journal.appendLine(json.writeValueAsString(op));
            log.debug("Registry append: op={} verificationId={}", opType, verificationId);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to append " + opType + " to approval-registry journal", e);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public Optional<RegistryEntry> lookup(String verificationId) {
        return Optional.ofNullable(entries.get(verificationId));
    }

    @Override
    public List<RegistryEntry> findByCountry(String countryCode) {
        return entries.values().stream()
                .filter(e -> inCountry(e, countryCode))
                .collect(Collectors.toList());
    }

    @Override
    public List<RegistryEntry> findAnomalies(String countryCode) {
        return entries.values().stream()
                .filter(e -> inCountry(e, countryCode))
                .filter(e -> e.getStatus() != null && e.getStatus().name().startsWith("ANOMALY"))
                .collect(Collectors.toList());
    }

    @Override
    public List<RegistryEntry> findAwaitingConfirmation(String countryCode) {
        return entries.values().stream()
                .filter(e -> inCountry(e, countryCode))
                .filter(e -> e.getStatus() == null)
                .collect(Collectors.toList());
    }

    /**
     * Jurisdiction predicate shared by every country-scoped query. Mirrors
     * {@link InMemoryApprovalRegistry} exactly — the two implementations
     * answering the same supervisory question differently would be a defect
     * in itself. A {@code null} argument matches nothing.
     */
    private static boolean inCountry(RegistryEntry entry, String countryCode) {
        return countryCode != null && countryCode.equals(entry.getCountryCode());
    }

    @Override
    public Optional<RegistryEntry> findByPublicKeyFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.isBlank()) {
            return Optional.empty();
        }
        Optional<RegistryEntry> compliantMatch = entries.values().stream()
                .filter(e -> fingerprint.equals(e.getPublicKeyFingerprint())
                        || fingerprint.equals(e.getActualPublicKeyFingerprint()))
                .filter(RegistryEntry::isCompliant)
                .max(ApprovalRegistry.recency());
        if (compliantMatch.isPresent()) {
            return compliantMatch;
        }
        return entries.values().stream()
                .filter(e -> fingerprint.equals(e.getPublicKeyFingerprint())
                        || fingerprint.equals(e.getActualPublicKeyFingerprint()))
                .max(ApprovalRegistry.recency());
    }

    @Override
    public Optional<RegistryEntry> findByIssuedCertificate(BigInteger serial, X500Principal issuer) {
        return entries.values().stream()
                .filter(e -> ApprovalRegistry.issuedCertificateMatches(e, serial, issuer))
                .max(ApprovalRegistry.certificatePrecedence());
    }

    @Override
    public ComplianceStats getStats(String countryCode) {
        List<RegistryEntry> countryEntries = findByCountry(countryCode);
        long total = countryEntries.size();
        long compliant = countryEntries.stream()
                .filter(e -> ApprovalRegistry.wasVerifiedAndIssued(e.getStatus()))
                .count();
        long anomalies = countryEntries.stream()
                .filter(e -> e.getStatus() != null && e.getStatus().name().startsWith("ANOMALY"))
                .count();
        return new ComplianceStats(total, compliant, anomalies,
                total > 0 ? (double) compliant / total * 100.0 : 0.0);
    }
}
