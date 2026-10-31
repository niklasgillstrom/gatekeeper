package eu.gillstrom.gatekeeper.timestamp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.controller.GatekeeperController;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * {@code gatekeeper.timestamping.mode=anchor}: periodic RFC 3161 tokens over
 * the chain head, persisted beside the audit log, served on
 * {@code /v1/gatekeeper/anchor} and {@code /v1/gatekeeper/anchor/timestamps},
 * and cross-checked by the chain-integrity walk.
 */
class AnchorTimestampingTest {

    @TempDir
    Path tempDir;

    private static TestTsa tsa;
    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @BeforeAll
    static void startTsa() throws Exception {
        tsa = new TestTsa();
    }

    private record Setup(AppendOnlyFileAuditLog log, AuditTimestamping ts, TimestampAnchorService anchors,
                         Path audit, Path anchorFile) {
    }

    private Setup setup(String name, long interval) {
        Path audit = tempDir.resolve(name + ".jsonl");
        Path anchorFile = tempDir.resolve(name + ".jsonl.tsa-anchors.jsonl");
        AuditTimestamping ts = new AuditTimestamping(AuditTimestamping.Mode.ANCHOR, tsa, tsa.verifier(), anchorFile,
                interval);
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(audit.toString(), signer, 0, null, ts);
        log.initialise();
        return new Setup(log, ts, new TimestampAnchorService(log, ts), audit, anchorFile);
    }

    private static AuditAppendRequest request(String id) {
        return new AuditAppendRequest("CN=fe", "VERIFY", id, "cmVx", null, true);
    }

    @Test
    void theHeadIsAnchoredOncePerNewHeadAndPersistedFsyncedBesideTheLog() throws Exception {
        Setup s = setup("anchors", 3600);
        assertThat(s.anchors().anchorNow()).as("empty log: nothing to anchor").isEmpty();

        s.log().append(request("v-1"));
        AuditEntry head = s.log().append(request("v-2"));
        TimestampAnchorRecord first = s.anchors().anchorNow().orElseThrow();
        assertThat(first.headSequenceNumber()).isEqualTo(2);
        assertThat(first.headHashHex()).isEqualTo(head.thisEntryHashHex());
        assertThat(first.genTime()).isNotNull();
        assertThat(tsa.verifier().verify(Base64.getDecoder().decode(first.tokenBase64()),
                head.thisEntryHashHex().getBytes(StandardCharsets.UTF_8)).valid()).isTrue();

        assertThat(s.anchors().anchorNow()).as("same head: skipped").isEmpty();
        s.log().append(request("v-3"));
        TimestampAnchorRecord second = s.anchors().anchorNow().orElseThrow();
        assertThat(second.headSequenceNumber()).isEqualTo(3);

        List<String> lines = Files.readAllLines(s.anchorFile(), StandardCharsets.UTF_8);
        assertThat(lines).hasSize(2);
        JsonNode line = mapper.readTree(lines.get(0));
        assertThat(line.get("headSequenceNumber").asLong()).isEqualTo(2);
        assertThat(line.get("headHashHex").asText()).isEqualTo(head.thisEntryHashHex());
        assertThat(line.get("tokenBase64").asText()).isEqualTo(first.tokenBase64());
        assertThat(line.has("genTime")).isTrue();
        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(s.anchorFile()))).isEqualTo("rw-r-----");

        assertThat(s.log().verifyChainIntegrity()).isTrue();
        Setup reloaded = setup("anchors", 3600);
        assertThat(reloaded.anchors().all()).containsExactly(first, second);
        assertThat(reloaded.log().verifyChainIntegrity()).isTrue();
    }

    @Test
    void aTsaOutageLeavesNoRecordAndTheNextAttemptAnchors() throws Exception {
        Setup s = setup("outage", 3600);
        s.log().append(request("v-1"));
        tsa.down.set(true);
        try {
            assertThat(s.anchors().anchorNow()).isEmpty();
        } finally {
            tsa.down.set(false);
        }
        assertThat(s.anchors().all()).isEmpty();
        assertThat(s.anchors().anchorNow()).isPresent();
    }

    @Test
    void anAnchorThatNoLongerMatchesTheChainBreaksIt() throws Exception {
        Setup s = setup("mismatch", 3600);
        s.log().append(request("v-1"));
        s.anchors().anchorNow().orElseThrow();
        assertThat(s.log().verifyChainIntegrity()).isTrue();

        List<String> lines = new ArrayList<>(Files.readAllLines(s.anchorFile(), StandardCharsets.UTF_8));
        ObjectNode node = (ObjectNode) mapper.readTree(lines.get(0));
        node.put("headHashHex", "11".repeat(32));
        lines.set(0, mapper.writeValueAsString(node));
        Files.write(s.anchorFile(), lines, StandardCharsets.UTF_8);

        assertThat(s.log().verifyChainIntegrity()).isFalse();
    }

    @Test
    void aChainTruncatedBelowAnAnchoredHeadIsReportedAfterRestart() throws Exception {
        Setup s = setup("truncated", 3600);
        s.log().append(request("v-1"));
        s.log().append(request("v-2"));
        s.anchors().anchorNow().orElseThrow();

        // At rest, drop the last entry: the remaining chain is internally
        // consistent, but the anchored head (sequence 2) is gone.
        List<String> lines = Files.readAllLines(s.audit(), StandardCharsets.UTF_8);
        Files.write(s.audit(), lines.subList(0, 1), StandardCharsets.UTF_8);

        Setup restarted = setup("truncated", 3600);
        assertThat(restarted.log().size()).isEqualTo(1);
        assertThat(restarted.log().verifyChainIntegrity()).isFalse();
    }

    @Test
    void aCorruptAnchorFileBreaksTheCheck() throws Exception {
        Setup s = setup("corrupt", 3600);
        s.log().append(request("v-1"));
        s.anchors().anchorNow().orElseThrow();
        s.log().append(request("v-2"));
        s.anchors().anchorNow().orElseThrow();
        List<String> lines = new ArrayList<>(Files.readAllLines(s.anchorFile(), StandardCharsets.UTF_8));
        lines.set(0, "not json");
        Files.write(s.anchorFile(), lines, StandardCharsets.UTF_8);

        assertThat(s.log().verifyChainIntegrity()).isFalse();
    }

    @Test
    void theSchedulerAnchorsAtStartUp() throws Exception {
        Setup s = setup("scheduled", 3600);
        s.log().append(request("v-1"));
        s.anchors().start();
        try {
            long deadline = System.nanoTime() + 10_000_000_000L;
            while (s.anchors().latest().isEmpty() && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertThat(s.anchors().latest()).isPresent();
        } finally {
            s.anchors().stop();
        }
    }

    @Test
    void theEndpointsServeTheLatestAndTheListAndHealthReportsIt() throws Exception {
        Setup s = setup("endpoints", 3600);
        s.log().append(request("v-1"));
        TimestampAnchorRecord a1 = s.anchors().anchorNow().orElseThrow();
        s.log().append(request("v-2"));
        TimestampAnchorRecord a2 = s.anchors().anchorNow().orElseThrow();
        s.log().append(request("v-3"));
        GatekeeperKeyDirectory directory = new GatekeeperKeyDirectory(signer, "");
        directory.initialise();
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new GatekeeperController(directory, s.log(), signer,
                "ephemeral", null, s.ts(), s.anchors())).build();

        JsonNode anchor = mapper.readTree(mvc.perform(get("/v1/gatekeeper/anchor")).andReturn().getResponse()
                .getContentAsString());
        assertThat(anchor.get("headSequenceNumber").asLong()).isEqualTo(3);
        assertThat(anchor.get("latestTimestamp").get("headSequenceNumber").asLong()).isEqualTo(2);
        assertThat(anchor.get("latestTimestamp").get("tokenBase64").asText()).isEqualTo(a2.tokenBase64());

        JsonNode list = mapper.readTree(mvc.perform(get("/v1/gatekeeper/anchor/timestamps")).andReturn()
                .getResponse().getContentAsString());
        assertThat(list.get("timestampingMode").asText()).isEqualTo("anchor");
        assertThat(list.get("total").asLong()).isEqualTo(2);
        assertThat(list.get("records").get(0).get("headHashHex").asText()).isEqualTo(a1.headHashHex());

        JsonNode page = mapper.readTree(mvc.perform(get("/v1/gatekeeper/anchor/timestamps")
                .param("offset", "1").param("limit", "5")).andReturn().getResponse().getContentAsString());
        assertThat(page.get("offset").asInt()).isEqualTo(1);
        assertThat(page.get("records")).hasSize(1);
        assertThat(page.get("records").get(0).get("headSequenceNumber").asLong()).isEqualTo(2);

        assertThat(mvc.perform(get("/v1/gatekeeper/anchor/timestamps").param("limit", "0")).andReturn()
                .getResponse().getStatus()).isEqualTo(400);
        assertThat(mvc.perform(get("/v1/gatekeeper/anchor/timestamps").param("limit", "1001")).andReturn()
                .getResponse().getStatus()).isEqualTo(400);
        assertThat(mvc.perform(get("/v1/gatekeeper/anchor/timestamps").param("offset", "-1")).andReturn()
                .getResponse().getStatus()).isEqualTo(400);

        JsonNode health = mapper.readTree(mvc.perform(get("/v1/gatekeeper/health")).andReturn().getResponse()
                .getContentAsString());
        assertThat(health.get("timestampingMode").asText()).isEqualTo("anchor");
        assertThat(health.get("latestTimestampAnchorSequenceNumber").asLong()).isEqualTo(2);
        assertThat(health.has("latestTimestampAnchorGenTime")).isTrue();
        assertThat(health.has("untimestampedEntries")).as("entry mode only").isFalse();
    }

    @Test
    void aTornLastAnchorLineIsRemovedAtStartUp() throws Exception {
        Setup s = setup("torn", 3600);
        s.log().append(request("v-1"));
        TimestampAnchorRecord kept = s.anchors().anchorNow().orElseThrow();
        Files.writeString(s.anchorFile(), "{\"headSequenceNumber\":2,\"head", StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);

        Setup restarted = setup("torn", 3600);
        assertThat(restarted.anchors().all()).containsExactly(kept);
        assertThat(Files.readAllLines(s.anchorFile(), StandardCharsets.UTF_8)).hasSize(1);
        assertThat(restarted.log().verifyChainIntegrity()).isTrue();
        assertThat(Optional.of(restarted.anchors().latest().orElseThrow())).contains(kept);
    }
}
