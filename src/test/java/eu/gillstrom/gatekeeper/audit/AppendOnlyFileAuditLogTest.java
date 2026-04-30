package eu.gillstrom.gatekeeper.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AppendOnlyFileAuditLog}. Each test exercises a property
 * the supervisory inspection regime depends on:
 * <ul>
 *   <li>monotonic, hash-linked chain growth</li>
 *   <li>tamper detection via {@link AuditLog#verifyChainIntegrity()}</li>
 *   <li>lookup by verification ID, time range, and principal</li>
 *   <li>persistence across process restart (DORA Art 28(6))</li>
 * </ul>
 * Each test runs against a fresh {@link TempDir}-backed log file.
 */
class AppendOnlyFileAuditLogTest {

    @TempDir
    Path tempDir;

    private EphemeralReceiptSigner signer;

    @BeforeEach
    void setUp() {
        // 2048-bit ephemeral RSA — fast enough for tests, real enough to
        // exercise SHA256withRSA verification end-to-end.
        signer = new EphemeralReceiptSigner(2048);
    }

    private AppendOnlyFileAuditLog newLog(Path file) {
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(file.toString(), signer);
        log.initialise();
        return log;
    }

    private static AuditAppendRequest sampleRequest(String suffix, boolean compliant, String op) {
        return new AuditAppendRequest(
                "CN=client-" + suffix,
                op,
                "verif-" + suffix,
                base64Sha256("req-" + suffix),
                base64Sha256("rcpt-" + suffix),
                compliant);
    }

    private static String base64Sha256(String s) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void appendsCreateMonotonicChain() {
        AppendOnlyFileAuditLog log = newLog(tempDir.resolve("chain-1.jsonl"));

        AuditEntry e1 = log.append(sampleRequest("1", true, "VERIFY"));
        AuditEntry e2 = log.append(sampleRequest("2", false, "VERIFY"));
        AuditEntry e3 = log.append(sampleRequest("3", true, "CONFIRM"));
        AuditEntry e4 = log.append(sampleRequest("4", true, "VERIFY"));
        AuditEntry e5 = log.append(sampleRequest("5", true, "BATCH_VERIFY"));

        assertThat(log.size()).isEqualTo(5);
        assertThat(e1.sequenceNumber()).isEqualTo(1);
        assertThat(e2.sequenceNumber()).isEqualTo(2);
        assertThat(e3.sequenceNumber()).isEqualTo(3);
        assertThat(e4.sequenceNumber()).isEqualTo(4);
        assertThat(e5.sequenceNumber()).isEqualTo(5);

        // Entry 1's predecessor must be the sentinel.
        assertThat(e1.prevEntryHashHex()).isEqualTo(AuditEntry.SENTINEL_PREV_HASH_HEX);
        // Each subsequent entry's prev must equal the predecessor's this.
        assertThat(e2.prevEntryHashHex()).isEqualTo(e1.thisEntryHashHex());
        assertThat(e3.prevEntryHashHex()).isEqualTo(e2.thisEntryHashHex());
        assertThat(e4.prevEntryHashHex()).isEqualTo(e3.thisEntryHashHex());
        assertThat(e5.prevEntryHashHex()).isEqualTo(e4.thisEntryHashHex());

        assertThat(log.verifyChainIntegrity()).isTrue();
    }

    @Test
    void tamperedFileBreaksChainValidation() throws IOException {
        Path file = tempDir.resolve("chain-tamper.jsonl");
        AppendOnlyFileAuditLog log = newLog(file);

        log.append(sampleRequest("a", true, "VERIFY"));
        log.append(sampleRequest("b", true, "VERIFY"));
        log.append(sampleRequest("c", true, "VERIFY"));

        // Sanity: untampered chain validates.
        assertThat(log.verifyChainIntegrity()).isTrue();

        // Modify line 2 (the middle entry) and reload.
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        ObjectNode node = (ObjectNode) mapper.readTree(lines.get(1));
        // Flip the compliance flag — surgical, single-bit modification.
        node.put("compliant", !node.get("compliant").asBoolean());
        lines.set(1, mapper.writeValueAsString(node));
        Files.write(file, lines, StandardCharsets.UTF_8);

        // A fresh instance must report the chain as broken.
        AppendOnlyFileAuditLog reloaded = newLog(file);
        assertThat(reloaded.verifyChainIntegrity()).isFalse();
    }

    @Test
    void findByVerificationIdReturnsCorrectEntry() {
        AppendOnlyFileAuditLog log = newLog(tempDir.resolve("by-id.jsonl"));
        log.append(sampleRequest("1", true, "VERIFY"));
        AuditEntry target = log.append(sampleRequest("2", false, "VERIFY"));
        log.append(sampleRequest("3", true, "VERIFY"));

        Optional<AuditEntry> found = log.findByVerificationId("verif-2");
        assertThat(found).isPresent();
        assertThat(found.get().sequenceNumber()).isEqualTo(target.sequenceNumber());
        assertThat(found.get().compliant()).isFalse();

        assertThat(log.findByVerificationId("verif-not-there")).isEmpty();
    }

    @Test
    void findInRangeFiltersByTimestamp() {
        AppendOnlyFileAuditLog log = newLog(tempDir.resolve("range.jsonl"));

        AuditEntry e1 = log.append(sampleRequest("a", true, "VERIFY"));
        log.append(sampleRequest("b", true, "VERIFY"));
        AuditEntry e3 = log.append(sampleRequest("c", true, "VERIFY"));

        Instant before = e1.timestamp().minusSeconds(1);
        Instant after = e3.timestamp().plusSeconds(1);

        // Wide window includes everything.
        List<AuditEntry> all = log.findInRange(before, after);
        assertThat(all).hasSize(3);

        // Window that ends strictly before any entry timestamp returns nothing.
        List<AuditEntry> empty = log.findInRange(before, before.plusMillis(1));
        assertThat(empty).isEmpty();

        // Window starting after all entries returns nothing.
        List<AuditEntry> none = log.findInRange(after, after.plusSeconds(60));
        assertThat(none).isEmpty();

        // Window that starts at e1.timestamp() (inclusive) and ends at
        // e3.timestamp().plusNanos(1) (exclusive) must include e1.
        // Note: high-resolution clocks may give e2 and e3 the same nanosecond
        // value as e1 — so we only assert "e1 is present" rather than the
        // exact set.
        List<AuditEntry> fromE1 = log.findInRange(e1.timestamp(), after);
        assertThat(fromE1)
                .extracting(AuditEntry::verificationId)
                .contains("verif-a");
    }

    @Test
    void findByPrincipalReturnsAllForThatClient() {
        AppendOnlyFileAuditLog log = newLog(tempDir.resolve("principal.jsonl"));
        log.append(new AuditAppendRequest("CN=swish", "VERIFY", "v-1",
                base64Sha256("r1"), base64Sha256("re1"), true));
        log.append(new AuditAppendRequest("CN=other", "VERIFY", "v-2",
                base64Sha256("r2"), base64Sha256("re2"), true));
        log.append(new AuditAppendRequest("CN=swish", "VERIFY", "v-3",
                base64Sha256("r3"), base64Sha256("re3"), false));
        log.append(new AuditAppendRequest("CN=swish", "CONFIRM", "v-1",
                base64Sha256("r4"), null, true));

        List<AuditEntry> swishEntries = log.findByPrincipal("CN=swish");
        assertThat(swishEntries).hasSize(3);
        assertThat(swishEntries)
                .allSatisfy(e -> assertThat(e.mtlsClientPrincipal()).isEqualTo("CN=swish"));

        assertThat(log.findByPrincipal("CN=other")).hasSize(1);
        assertThat(log.findByPrincipal("CN=nobody")).isEmpty();
    }

    @Test
    void persistenceAcrossRestart() {
        Path file = tempDir.resolve("restart.jsonl");
        AppendOnlyFileAuditLog first = newLog(file);
        first.append(sampleRequest("1", true, "VERIFY"));
        first.append(sampleRequest("2", true, "VERIFY"));
        first.append(sampleRequest("3", false, "CONFIRM"));

        AppendOnlyFileAuditLog second = newLog(file);
        assertThat(second.size()).isEqualTo(3);
        assertThat(second.verifyChainIntegrity()).isTrue();
        assertThat(second.findByVerificationId("verif-3")).isPresent();
        assertThat(second.head()).isPresent();
        assertThat(second.head().get().sequenceNumber()).isEqualTo(3);

        // Subsequent appends continue the chain monotonically.
        AuditEntry e4 = second.append(sampleRequest("4", true, "VERIFY"));
        assertThat(e4.sequenceNumber()).isEqualTo(4);
        assertThat(second.verifyChainIntegrity()).isTrue();
    }

    @Test
    void corruptTrailingLineIsRecovered() throws IOException {
        Path file = tempDir.resolve("corrupt-trailer.jsonl");
        AppendOnlyFileAuditLog first = newLog(file);
        first.append(sampleRequest("1", true, "VERIFY"));
        first.append(sampleRequest("2", true, "VERIFY"));

        // Simulate an aborted append: write a partial JSON fragment.
        Files.writeString(file,
                Files.readString(file, StandardCharsets.UTF_8) + "{\"sequenceNumber\":3,\"timesta",
                StandardCharsets.UTF_8);

        // Reload and verify the corrupt trailer was truncated.
        AppendOnlyFileAuditLog second = newLog(file);
        assertThat(second.size()).isEqualTo(2);
        assertThat(second.verifyChainIntegrity()).isTrue();
    }

    @Test
    void appendIsConsistentAcrossInstancesViaPersistence() {
        // Documenting the contract: a second instance opening the same file
        // sees the entries the first wrote, and its size() matches.
        Path file = tempDir.resolve("consistent.jsonl");
        AppendOnlyFileAuditLog first = newLog(file);
        first.append(sampleRequest("x", true, "VERIFY"));

        AppendOnlyFileAuditLog second = newLog(file);
        assertThat(second.size()).isEqualTo(first.size());
        assertThat(second.head().get().thisEntryHashHex())
                .isEqualTo(first.head().get().thisEntryHashHex());
    }
}
