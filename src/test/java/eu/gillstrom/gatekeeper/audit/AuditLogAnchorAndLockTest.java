package eu.gillstrom.gatekeeper.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.timestamp.AuditTimestamping;
import eu.gillstrom.gatekeeper.timestamp.TestTsa;
import eu.gillstrom.gatekeeper.timestamp.TimestampAnchorService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;

/**
 * The audit log's read methods release the append lock, an anchor whose
 * token does not validate breaks the chain, and an implementation that does
 * not count untimestamped entries says so.
 */
class AuditLogAnchorAndLockTest {

    @TempDir
    Path tempDir;

    private static TestTsa trustedTsa;
    private static TestTsa otherTsa;
    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

    @BeforeAll
    static void startTsas() throws Exception {
        trustedTsa = new TestTsa();
        otherTsa = new TestTsa();
    }

    private static AuditAppendRequest request(String id) {
        return new AuditAppendRequest("CN=fe", "VERIFY", id, "cmVx", null, true);
    }

    @Test
    void theReadMethodsReleaseTheAppendLockForOtherThreads() throws Exception {
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(tempDir.resolve("lock.jsonl").toString(), signer);
        log.initialise();
        log.append(request("v-1"));

        ExecutorService other = Executors.newSingleThreadExecutor();
        try {
            assertThat(other.submit(log::untimestampedEntryCount).get()).isPresent();
            assertThat(other.submit(() -> log.lastEntryHashForKey("no-such-key")).get()).isEmpty();
            assertTimeoutPreemptively(Duration.ofSeconds(10), () -> log.append(request("v-2")));
        } finally {
            other.shutdownNow();
        }
    }

    @Test
    void anAnchorWithATokenFromAnUntrustedTsaBreaksTheChain() throws Exception {
        Path audit = tempDir.resolve("anchored.jsonl");
        Path anchorFile = tempDir.resolve("anchored.jsonl.tsa-anchors.jsonl");
        AuditTimestamping ts = new AuditTimestamping(AuditTimestamping.Mode.ANCHOR, trustedTsa, trustedTsa.verifier(),
                anchorFile, 3600);
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(audit.toString(), signer, 0, null, ts);
        log.initialise();
        AuditEntry head = log.append(request("v-1"));
        new TimestampAnchorService(log, ts).anchorNow().orElseThrow();
        assertThat(log.verifyChainIntegrity()).isTrue();

        // The same head, time-stamped by a TSA the verifier does not trust.
        byte[] imprint = MessageDigest.getInstance("SHA-256")
                .digest(head.thisEntryHashHex().getBytes(StandardCharsets.UTF_8));
        String foreign = Base64.getEncoder().encodeToString(otherTsa.timestamp(imprint));
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        List<String> lines = new ArrayList<>(Files.readAllLines(anchorFile, StandardCharsets.UTF_8));
        ObjectNode node = (ObjectNode) mapper.readTree(lines.get(0));
        node.put("tokenBase64", foreign);
        lines.set(0, mapper.writeValueAsString(node));
        Files.write(anchorFile, lines, StandardCharsets.UTF_8);

        assertThat(log.verifyChainIntegrity()).isFalse();
        AuditTimestamping reloaded = new AuditTimestamping(AuditTimestamping.Mode.ANCHOR, trustedTsa,
                trustedTsa.verifier(), anchorFile, 3600);
        AppendOnlyFileAuditLog restarted = new AppendOnlyFileAuditLog(audit.toString(), signer, 0, null, reloaded);
        restarted.initialise();
        assertThat(restarted.verifyChainIntegrity()).isFalse();
    }

    /**
     * The record's genTime is a copy of the token's, and the copy is what
     * /anchor, /anchor/timestamps and /health report. Until 1.7.0 the two
     * were never compared, so the copy could be edited in the anchor file and
     * the chain check still passed.
     */
    @Test
    void anAnchorWhoseStatedTimeIsNotItsTokensBreaksTheChain() throws Exception {
        Path audit = tempDir.resolve("retimed.jsonl");
        Path anchorFile = tempDir.resolve("retimed.jsonl.tsa-anchors.jsonl");
        AuditTimestamping ts = new AuditTimestamping(AuditTimestamping.Mode.ANCHOR, trustedTsa, trustedTsa.verifier(),
                anchorFile, 3600);
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(audit.toString(), signer, 0, null, ts);
        log.initialise();
        log.append(request("v-1"));
        new TimestampAnchorService(log, ts).anchorNow().orElseThrow();
        assertThat(log.verifyChainIntegrity()).isTrue();
        String original = Files.readString(anchorFile, StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

        for (String stated : new String[] {"2020-01-01T00:00:00Z", null}) {
            ObjectNode node = (ObjectNode) mapper.readTree(original.lines().findFirst().orElseThrow());
            assertThat(node.path("genTime").asText()).as("the token's time, as an ISO instant").endsWith("Z");
            node.put("genTime", stated);
            Files.writeString(anchorFile, mapper.writeValueAsString(node) + "\n", StandardCharsets.UTF_8);

            ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger)
                    org.slf4j.LoggerFactory.getLogger(AppendOnlyFileAuditLog.class);
            ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> logs =
                    new ch.qos.logback.core.read.ListAppender<>();
            logs.start();
            logger.addAppender(logs);
            try {
                assertThat(log.verifyChainIntegrity()).as("stated genTime %s", stated).isFalse();
            } finally {
                logger.detachAppender(logs);
            }
            assertThat(logs.list).map(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage)
                    .anySatisfy(m -> assertThat(m).startsWith("AuditLog chain check failed: timestamp anchor for "
                            + "sequenceNumber 1 states genTime " + (stated == null ? "null" : stated)
                            + " but its token was issued at "));
        }

        // Put back, the chain is intact again: nothing else was wrong with it.
        Files.writeString(anchorFile, original, StandardCharsets.UTF_8);
        assertThat(log.verifyChainIntegrity()).isTrue();
    }

    @Test
    void anImplementationThatDoesNotCountUntimestampedEntriesReportsNoCount() {
        assertThat(mock(AuditLog.class, CALLS_REAL_METHODS).untimestampedEntryCount()).isEmpty();
    }
}
