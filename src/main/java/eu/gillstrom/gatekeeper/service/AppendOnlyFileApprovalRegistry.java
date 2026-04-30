package eu.gillstrom.gatekeeper.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;

import java.io.IOException;
import java.io.RandomAccessFile;
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
 * record.</p>
 *
 * <h2>Journal format</h2>
 *
 * <p>One operation per line, UTF-8 JSON. Two operation types:</p>
 *
 * <ul>
 *   <li><strong>{@code REGISTER}</strong> — emitted by
 *       {@link #register(String, boolean, String, String, String, String, String, String)}.
 *       Carries the full initial entry payload.</li>
 *   <li><strong>{@code CONFIRM}</strong> — emitted by
 *       {@link #confirm(String, boolean, String, boolean)}. Carries the
 *       confirmation outcome plus the {@code verificationId} key needed
 *       to apply it.</li>
 * </ul>
 *
 * <p>On startup the journal is replayed in order: each {@code REGISTER}
 * creates an entry; each {@code CONFIRM} applies the confirmation
 * outcome to the existing entry. A {@code CONFIRM} for an unknown
 * {@code verificationId} is logged at WARN and skipped — this should
 * not happen with disciplined writes but is recoverable.</p>
 *
 * <p>Permissions: when the file is created the implementation attempts
 * to set POSIX permissions to {@code 0640}. On non-POSIX filesystems
 * this step is logged at WARN and execution continues.</p>
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

    private final Path journalPath;
    private final ObjectMapper json;
    private final ConcurrentHashMap<String, RegistryEntry> entries = new ConcurrentHashMap<>();
    private final ReentrantLock writeLock = new ReentrantLock();

    public AppendOnlyFileApprovalRegistry(
            @Value("${gatekeeper.registry.path:/var/lib/gatekeeper/approval-registry.jsonl}") String path) {
        this.journalPath = Paths.get(path);
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

        // Replay the journal to rebuild the in-memory index.
        int registerCount = 0;
        int confirmCount = 0;
        int skipped = 0;
        try (var lines = Files.lines(journalPath, StandardCharsets.UTF_8)) {
            for (String line : (Iterable<String>) lines::iterator) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    JsonNode op = json.readTree(line);
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
                                op.path("issued").asBoolean(),
                                op.path("actualPublicKeyFingerprint").asText(null),
                                op.path("publicKeyMatch").asBoolean());
                        confirmCount++;
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
        log.info("AppendOnlyFileApprovalRegistry initialised: replayed {} REGISTER + {} CONFIRM ops "
                + "from {} ({} entries in index, {} skipped)",
                registerCount, confirmCount, journalPath, entries.size(), skipped);
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
                                  String countryCode) {
        RegistryEntry entry = RegistryEntry.builder()
                .verificationId(verificationId)
                .confirmationNonce(confirmationNonce)
                .compliant(compliant)
                .publicKeyFingerprint(publicKeyFingerprint)
                .supplierIdentifier(supplierIdentifier)
                .supplierName(supplierName)
                .hsmVendor(hsmVendor)
                .hsmModel(hsmModel)
                .countryCode(countryCode)
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

    @Override
    public Optional<RegistryEntry> confirm(String verificationId,
                                           String submittedNonce,
                                           boolean issued,
                                           String actualPublicKeyFingerprint,
                                           boolean publicKeyMatch) {
        RegistryEntry entry = entries.get(verificationId);
        if (entry == null) {
            return Optional.empty();
        }

        // Constant-time nonce comparison. Mismatch is a Step-7 replay attempt
        // and must NOT be journalled (no state transition occurs).
        String expectedNonce = entry.getConfirmationNonce();
        if (expectedNonce == null
                || submittedNonce == null
                || !java.security.MessageDigest.isEqual(
                        expectedNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        submittedNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            log.warn("Nonce mismatch on confirm for verificationId={} — possible Step-7 replay attempt", verificationId);
            throw new NonceMismatchException(verificationId);
        }

        // Apply the state transition to the in-memory entry first; then
        // journal it. If journalling fails we let the exception propagate
        // and the caller surfaces it as a 5xx so the FE retries.
        applyConfirmation(entry, issued, actualPublicKeyFingerprint, publicKeyMatch);
        appendOp(OP_CONFIRM, verificationId, mapper -> mapper
                .createObjectNode()
                .put("op", OP_CONFIRM)
                .put("verificationId", verificationId)
                .put("issued", issued)
                .put("actualPublicKeyFingerprint", actualPublicKeyFingerprint)
                .put("publicKeyMatch", publicKeyMatch));

        return Optional.of(entry);
    }

    private void applyConfirmation(RegistryEntry entry,
                                   boolean issued,
                                   String actualPublicKeyFingerprint,
                                   boolean publicKeyMatch) {
        entry.setConfirmationTimestamp(Instant.now().toString());
        entry.setCertificateReceived(issued);

        if (entry.isCompliant() && issued && publicKeyMatch) {
            entry.setStatus(RegistryStatus.VERIFIED_AND_ISSUED);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
        } else if (entry.isCompliant() && issued && !publicKeyMatch) {
            entry.setStatus(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
        } else if (entry.isCompliant() && !issued) {
            entry.setStatus(RegistryStatus.VERIFIED_NOT_ISSUED);
        } else if (!entry.isCompliant() && issued) {
            entry.setStatus(RegistryStatus.ANOMALY_ISSUED_DESPITE_REJECTION);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
        } else {
            entry.setStatus(RegistryStatus.REJECTED_NOT_ISSUED);
        }
    }

    @FunctionalInterface
    private interface OpBuilder {
        JsonNode build(ObjectMapper mapper);
    }

    private void appendOp(String opType, String verificationId, OpBuilder builder) {
        writeLock.lock();
        try {
            JsonNode op = builder.build(json);
            byte[] payload = (json.writeValueAsString(op) + "\n").getBytes(StandardCharsets.UTF_8);

            try (RandomAccessFile raf = new RandomAccessFile(journalPath.toFile(), "rwd")) {
                raf.seek(raf.length());
                raf.write(payload);
                raf.getFD().sync();
            }
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
                .filter(e -> countryCode.equals(e.getCountryCode()))
                .collect(Collectors.toList());
    }

    @Override
    public List<RegistryEntry> findAnomalies() {
        return entries.values().stream()
                .filter(e -> e.getStatus() != null && e.getStatus().name().startsWith("ANOMALY"))
                .collect(Collectors.toList());
    }

    @Override
    public List<RegistryEntry> findAwaitingConfirmation() {
        return entries.values().stream()
                .filter(e -> e.getStatus() == null)
                .collect(Collectors.toList());
    }

    @Override
    public ComplianceStats getStats(String countryCode) {
        List<RegistryEntry> countryEntries = findByCountry(countryCode);
        long total = countryEntries.size();
        long compliant = countryEntries.stream()
                .filter(e -> e.getStatus() == RegistryStatus.VERIFIED_AND_ISSUED)
                .count();
        long anomalies = countryEntries.stream()
                .filter(e -> e.getStatus() != null && e.getStatus().name().startsWith("ANOMALY"))
                .count();
        return new ComplianceStats(total, compliant, anomalies,
                total > 0 ? (double) compliant / total * 100.0 : 0.0);
    }
}
