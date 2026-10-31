package eu.gillstrom.gatekeeper.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Audit entry v2 in {@link AppendOnlyFileAuditLog}: inventory fields on disk
 * and in memory, the per-key chain and its index, a file that switches from
 * v1 to v2, and the checks {@code verifyChainIntegrity} adds for v2.
 */
class AuditLogV2ChainTest {

    @TempDir
    Path tempDir;

    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    private static final String KEY_A = "aa:" + "00:".repeat(30) + "01";
    private static final String KEY_B = "bb:" + "00:".repeat(30) + "02";

    private AppendOnlyFileAuditLog open(Path file) {
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(file.toString(), signer, 0);
        log.initialise();
        return log;
    }

    private static AuditAppendRequest plain(String id) {
        return new AuditAppendRequest("CN=fe", "VERIFY", id, "cmVx", "cmNwdA==", true);
    }

    private static AuditAppendRequest forKey(String id, String key) {
        return plain(id).withKeyFingerprintHex(key).withHsm("Yubico", "12345678");
    }

    private void editLine(Path file, int index, Consumer<ObjectNode> edit) throws Exception {
        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        ObjectNode node = (ObjectNode) mapper.readTree(lines.get(index));
        edit.accept(node);
        lines.set(index, mapper.writeValueAsString(node));
        Files.write(file, lines, StandardCharsets.UTF_8);
    }

    private static String sha256Hex(byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    /** Rewrite line {@code index} with the edit applied and its hash and signature recomputed — a forger with the key. */
    private void resealLine(Path file, int index, Consumer<ObjectNode> edit) throws Exception {
        editLine(file, index, node -> {
            edit.accept(node);
            try {
                AuditEntry e = mapper.treeToValue(node, AuditEntry.class);
                String hash = sha256Hex(AuditEntry.canonicalBytesForHash(e));
                node.put("thisEntryHashHex", hash);
                node.put("entrySignatureBase64", Base64.getEncoder().encodeToString(
                        signer.sign(hash.getBytes(StandardCharsets.UTF_8))));
            } catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
        });
    }

    @Test
    void newEntriesAreV2AndCarryTheInventoryFieldsOnDiskAndAfterReload() throws Exception {
        Path file = tempDir.resolve("inv.jsonl");
        AppendOnlyFileAuditLog log = open(file);
        AuditEntry e = log.append(plain("v-1").withKeyFingerprintHex(KEY_A).withCertificate("1f", "CN=Issuer")
                .withHsm("Yubico", "12345678").withRegistryStatus("VERIFIED_AND_ISSUED")
                .withHsmFirmware("2.4.0", "true"));

        assertThat(e.canonicalVersion()).isEqualTo("v2");
        assertThat(e.thisEntryHashHex()).isEqualTo(sha256Hex(AuditEntry.canonicalBytesForHashV2(
                1, e.timestamp(), "CN=fe", "VERIFY", "v-1", "cmVx", "cmNwdA==", true,
                AuditEntry.SENTINEL_PREV_HASH_HEX, KEY_A, "1f", "CN=Issuer", "Yubico", "12345678",
                "VERIFIED_AND_ISSUED", "2.4.0", "true", AuditEntry.SENTINEL_PREV_HASH_HEX)));

        JsonNode line = mapper.readTree(Files.readAllLines(file, StandardCharsets.UTF_8).get(0));
        assertThat(line.get("canonicalVersion").asText()).isEqualTo("v2");
        assertThat(line.get("keyFingerprintHex").asText()).isEqualTo(KEY_A);
        assertThat(line.get("certSerialHex").asText()).isEqualTo("1f");
        assertThat(line.get("certIssuerDn").asText()).isEqualTo("CN=Issuer");
        assertThat(line.get("hsmVendor").asText()).isEqualTo("Yubico");
        assertThat(line.get("hsmSerial").asText()).isEqualTo("12345678");
        assertThat(line.get("registryStatus").asText()).isEqualTo("VERIFIED_AND_ISSUED");
        assertThat(line.get("hsmFirmwareVersion").asText()).isEqualTo("2.4.0");
        assertThat(line.get("hsmFipsApprovedMode").asText()).isEqualTo("true");
        assertThat(line.get("prevKeyEntryHashHex").asText()).isEqualTo(AuditEntry.SENTINEL_PREV_HASH_HEX);
        assertThat(line.get("timestampTokenBase64").isNull()).isTrue();

        AppendOnlyFileAuditLog reloaded = open(file);
        assertThat(reloaded.head().orElseThrow()).isEqualTo(e);
        assertThat(reloaded.verifyChainIntegrity()).isTrue();
    }

    @Test
    void entriesOfTheSameKeyAreChainedAndOthersAreNot() {
        AppendOnlyFileAuditLog log = open(tempDir.resolve("perkey.jsonl"));
        AuditEntry a1 = log.append(forKey("v-1", KEY_A));
        AuditEntry b1 = log.append(forKey("v-2", KEY_B));
        AuditEntry none = log.append(plain("v-3"));
        AuditEntry a2 = log.append(forKey("v-4", KEY_A));
        AuditEntry b2 = log.append(forKey("v-5", KEY_B));

        assertThat(a1.prevKeyEntryHashHex()).isEqualTo(AuditEntry.SENTINEL_PREV_HASH_HEX);
        assertThat(b1.prevKeyEntryHashHex()).isEqualTo(AuditEntry.SENTINEL_PREV_HASH_HEX);
        assertThat(none.prevKeyEntryHashHex()).isNull();
        assertThat(none.keyFingerprintHex()).isNull();
        assertThat(a2.prevKeyEntryHashHex()).isEqualTo(a1.thisEntryHashHex());
        assertThat(b2.prevKeyEntryHashHex()).isEqualTo(b1.thisEntryHashHex());
        assertThat(a2.prevEntryHashHex()).as("the global link is unchanged").isEqualTo(none.thisEntryHashHex());
        assertThat(log.lastEntryHashForKey(KEY_A)).contains(a2.thisEntryHashHex());
        assertThat(log.verifyChainIntegrity()).isTrue();
    }

    @Test
    void thePerKeyIndexIsRebuiltAtStartUp() {
        Path file = tempDir.resolve("index.jsonl");
        AppendOnlyFileAuditLog first = open(file);
        AuditEntry a1 = first.append(forKey("v-1", KEY_A));
        first.append(forKey("v-2", KEY_B));

        AppendOnlyFileAuditLog second = open(file);
        assertThat(second.lastEntryHashForKey(KEY_A)).contains(a1.thisEntryHashHex());
        AuditEntry a2 = second.append(forKey("v-3", KEY_A));

        assertThat(a2.prevKeyEntryHashHex()).isEqualTo(a1.thisEntryHashHex());
        assertThat(open(file).verifyChainIntegrity()).isTrue();
    }

    /** A v1 line exactly as 1.6.0 wrote it: eleven fields, no v2 field at all. */
    private String v1Line(long seq, String prev, String id) throws Exception {
        Instant t = Instant.parse("2026-01-0" + seq + "T10:00:00Z");
        String hash = sha256Hex(AuditEntry.canonicalBytesForHash(seq, t, "CN=old", "VERIFY", id,
                "cmVx", null, true, prev));
        String sig = Base64.getEncoder().encodeToString(signer.sign(hash.getBytes(StandardCharsets.UTF_8)));
        return "{\"sequenceNumber\":" + seq + ",\"timestamp\":\"" + t + "\",\"mtlsClientPrincipal\":\"CN=old\","
                + "\"operation\":\"VERIFY\",\"verificationId\":\"" + id + "\",\"requestDigestBase64\":\"cmVx\","
                + "\"receiptDigestBase64\":null,\"compliant\":true,\"prevEntryHashHex\":\"" + prev + "\","
                + "\"thisEntryHashHex\":\"" + hash + "\",\"entrySignatureBase64\":\"" + sig + "\"}";
    }

    private Path v1File(String name) throws Exception {
        Path file = tempDir.resolve(name);
        String l1 = v1Line(1, AuditEntry.SENTINEL_PREV_HASH_HEX, "old-1");
        String h1 = mapper.readTree(l1).get("thisEntryHashHex").asText();
        String l2 = v1Line(2, h1, "old-2");
        Files.writeString(file, l1 + "\n" + l2 + "\n", StandardCharsets.UTF_8);
        return file;
    }

    @Test
    void aV1FileStillParsesAndVerifiesAndThenContinuesInV2() throws Exception {
        Path file = v1File("upgrade.jsonl");

        AppendOnlyFileAuditLog log = open(file);
        assertThat(log.size()).isEqualTo(2);
        assertThat(log.head().orElseThrow().canonicalVersion()).isNull();
        assertThat(log.verifyChainIntegrity()).as("v1 entries already on disk verify").isTrue();

        AuditEntry v2 = log.append(forKey("new-1", KEY_A));
        assertThat(v2.canonicalVersion()).isEqualTo("v2");
        assertThat(v2.prevEntryHashHex()).isEqualTo(log.findByVerificationId("old-2").orElseThrow().thisEntryHashHex());
        assertThat(v2.prevKeyEntryHashHex()).isEqualTo(AuditEntry.SENTINEL_PREV_HASH_HEX);
        assertThat(log.verifyChainIntegrity()).isTrue();
        assertThat(open(file).verifyChainIntegrity()).as("a file switching from v1 to v2 verifies").isTrue();
    }

    @Test
    void aV1EntryAfterAV2EntryBreaksTheChain() throws Exception {
        Path file = tempDir.resolve("regress.jsonl");
        AppendOnlyFileAuditLog log = open(file);
        log.append(plain("v-1"));
        log.append(plain("v-2"));
        // A correctly hashed and signed v1 entry after a v2 one.
        resealLine(file, 1, n -> {
            n.putNull("canonicalVersion");
            n.remove("prevKeyEntryHashHex");
        });
        // Reopened, so memory and disk agree and only the version rule can fail.
        assertThat(open(file).verifyChainIntegrity()).isFalse();
    }

    @Test
    void aV1EntryCarryingAFieldItsHashDoesNotCoverBreaksTheChain() throws Exception {
        Path file = v1File("v1-extra.jsonl");
        AppendOnlyFileAuditLog log = open(file);
        assertThat(log.verifyChainIntegrity()).isTrue();

        editLine(file, 0, n -> n.put("hsmSerial", "99999999"));
        assertThat(log.verifyChainIntegrity()).isFalse();
    }

    @Test
    void changingAnInventoryFieldOrTheVersionBreaksTheChain() throws Exception {
        String[][] edits = {
                {"keyFingerprintHex", KEY_B}, {"certSerialHex", "20"}, {"certIssuerDn", "CN=Other"},
                {"hsmVendor", "Securosys"}, {"hsmSerial", "2"}, {"registryStatus", "REJECTED_NOT_ISSUED"},
                {"hsmFirmwareVersion", "9"}, {"hsmFipsApprovedMode", "false"},
                {"prevKeyEntryHashHex", "11".repeat(32)}, {"canonicalVersion", null}, {"canonicalVersion", "v3"}};
        for (String[] edit : edits) {
            Path file = tempDir.resolve("edit-" + edit[0] + "-" + edit[1] + ".jsonl");
            AppendOnlyFileAuditLog log = open(file);
            log.append(plain("v-1").withKeyFingerprintHex(KEY_A).withCertificate("1f", "CN=I")
                    .withHsm("Yubico", "1").withRegistryStatus("VERIFIED_AND_ISSUED").withHsmFirmware("2", "true"));
            assertThat(log.verifyChainIntegrity()).isTrue();
            editLine(file, 0, n -> {
                if (edit[1] == null) {
                    n.putNull(edit[0]);
                } else {
                    n.put(edit[0], edit[1]);
                }
            });
            assertThat(log.verifyChainIntegrity()).as(edit[0] + "=" + edit[1]).isFalse();
        }
    }

    @Test
    void aWrongPerKeyLinkBreaksTheChainEvenWhenTheEntryIsCorrectlyHashedAndSigned() throws Exception {
        Path file = tempDir.resolve("forged-link.jsonl");
        AppendOnlyFileAuditLog log = open(file);
        log.append(forKey("v-1", KEY_A));
        log.append(forKey("v-2", KEY_A));
        assertThat(log.verifyChainIntegrity()).isTrue();

        // Point the second entry's per-key link at the sentinel and re-hash
        // and re-sign it; it is the head, so no later global link changes.
        resealLine(file, 1, n -> n.put("prevKeyEntryHashHex", AuditEntry.SENTINEL_PREV_HASH_HEX));
        AppendOnlyFileAuditLog reloaded = open(file);
        assertThat(reloaded.verifyChainIntegrity()).isFalse();
    }

    @Test
    void aPerKeyLinkWithoutAKeyBreaksTheChainEvenWhenSigned() throws Exception {
        Path file = tempDir.resolve("link-no-key.jsonl");
        open(file).append(plain("v-1"));
        resealLine(file, 0, n -> n.put("prevKeyEntryHashHex", AuditEntry.SENTINEL_PREV_HASH_HEX));

        assertThat(open(file).verifyChainIntegrity()).isFalse();
    }
}
