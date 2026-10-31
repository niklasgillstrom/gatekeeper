package eu.gillstrom.gatekeeper.timestamp;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import org.slf4j.LoggerFactory;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * {@code gatekeeper.timestamping.mode=entry}: a validated RFC 3161 token on
 * each entry, outside the hash; a TSA outage never blocks an append; the
 * chain check validates the tokens when trusted TSA certificates are set.
 */
class EntryTimestampingTest {

    @TempDir
    Path tempDir;

    private static TestTsa tsa;
    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

    @BeforeAll
    static void startTsa() throws Exception {
        tsa = new TestTsa();
    }

    private AppendOnlyFileAuditLog open(Path file, AuditTimestamping ts) {
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(file.toString(), signer, 0, null, ts);
        log.initialise();
        return log;
    }

    private static AuditTimestamping entryMode(TsaClient client) {
        return new AuditTimestamping(AuditTimestamping.Mode.ENTRY, client, tsa.verifier(), null, 0);
    }

    private static AuditAppendRequest request(String id) {
        return new AuditAppendRequest("CN=fe", "VERIFY", id, "cmVx", null, true);
    }

    @Test
    void eachEntryCarriesAValidTokenOverItsSignatureInputOutsideTheHash() throws Exception {
        Path file = tempDir.resolve("entry.jsonl");
        AppendOnlyFileAuditLog log = open(file, entryMode(tsa));

        AuditEntry e1 = log.append(request("v-1"));
        AuditEntry e2 = log.append(request("v-2"));

        for (AuditEntry e : List.of(e1, e2)) {
            assertThat(e.timestampTokenBase64()).isNotNull();
            TimestampTokenVerifier.Verification v = tsa.verifier().verify(
                    Base64.getDecoder().decode(e.timestampTokenBase64()),
                    e.thisEntryHashHex().getBytes(StandardCharsets.UTF_8));
            assertThat(v.valid()).isTrue();
            // The hash is the same as without the token: the token is not hashed.
            assertThat(AuditEntry.canonicalBytesForHash(e))
                    .isEqualTo(AuditEntry.canonicalBytesForHash(e.withTimestampToken(null)));
        }
        assertThat(log.untimestampedEntryCount()).hasValue(0);
        assertThat(log.verifyChainIntegrity()).isTrue();
        assertThat(open(file, entryMode(tsa)).verifyChainIntegrity()).isTrue();
    }

    @Test
    void aTsaOutageWritesTheEntryWithoutATokenAndCountsIt() {
        TestTsa flaky = tsa;
        AppendOnlyFileAuditLog log = open(tempDir.resolve("outage.jsonl"), entryMode(flaky));
        log.append(request("v-1"));
        flaky.down.set(true);
        AuditEntry missing;
        try {
            missing = log.append(request("v-2"));
        } finally {
            flaky.down.set(false);
        }
        log.append(request("v-3"));

        assertThat(missing.timestampTokenBase64()).isNull();
        assertThat(log.size()).isEqualTo(3);
        assertThat(log.untimestampedEntryCount()).hasValue(1);
        assertThat(log.verifyChainIntegrity()).isTrue();
    }

    @Test
    void aTokenThatDoesNotValidateIsNotStored() throws Exception {
        TestTsa untrusted = new TestTsa();
        AppendOnlyFileAuditLog log = open(tempDir.resolve("untrusted.jsonl"), entryMode(untrusted));

        AuditEntry e = log.append(request("v-1"));

        assertThat(untrusted.requests.get()).isEqualTo(1);
        assertThat(e.timestampTokenBase64()).as("a token from a TSA outside the trust set is dropped").isNull();
        assertThat(log.untimestampedEntryCount()).hasValue(1);
    }

    @Test
    void aTokenMovedToAnotherEntryOrDamagedBreaksTheChain() throws Exception {
        Path file = tempDir.resolve("swap.jsonl");
        AppendOnlyFileAuditLog log = open(file, entryMode(tsa));
        log.append(request("v-1"));
        log.append(request("v-2"));
        assertThat(log.verifyChainIntegrity()).isTrue();

        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        String firstToken = mapper.readTree(lines.get(0)).get("timestampTokenBase64").asText();
        ObjectNode second = (ObjectNode) mapper.readTree(lines.get(1));
        second.put("timestampTokenBase64", firstToken);
        lines.set(1, mapper.writeValueAsString(second));
        Files.write(file, lines, StandardCharsets.UTF_8);

        assertThat(open(file, entryMode(tsa)).verifyChainIntegrity()).as("token over another entry's hash").isFalse();

        second.put("timestampTokenBase64", "!!");
        lines.set(1, mapper.writeValueAsString(second));
        Files.write(file, lines, StandardCharsets.UTF_8);
        assertThat(open(file, entryMode(tsa)).verifyChainIntegrity()).as("not Base64").isFalse();
    }

    @Test
    void withoutTrustedCertificatesTokensAreNotValidatedAndTheCheckSaysSo() {
        Path file = tempDir.resolve("no-trust.jsonl");
        open(file, entryMode(tsa)).append(request("v-1"));

        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        Logger logger = (Logger) LoggerFactory.getLogger(AppendOnlyFileAuditLog.class);
        logger.addAppender(appender);
        try {
            AppendOnlyFileAuditLog plain = open(file, AuditTimestamping.off());
            assertThat(plain.verifyChainIntegrity()).isTrue();
            assertThat(appender.list).anyMatch(e -> e.getFormattedMessage()
                    .contains("timestamp token(s) present but not validated"));
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void healthReportsTheModeAndTheUntimestampedCount() throws Exception {
        AuditTimestamping ts = entryMode(tsa);
        AppendOnlyFileAuditLog log = open(tempDir.resolve("health.jsonl"), ts);
        log.append(request("v-1"));
        tsa.down.set(true);
        try {
            log.append(request("v-2"));
        } finally {
            tsa.down.set(false);
        }
        GatekeeperKeyDirectory directory = new GatekeeperKeyDirectory(signer, "");
        directory.initialise();
        var mvc = MockMvcBuilders.standaloneSetup(new GatekeeperController(directory, log, signer, "ephemeral",
                null, ts, new TimestampAnchorService(log, ts))).build();

        var health = new ObjectMapper().readTree(mvc.perform(get("/v1/gatekeeper/health")).andReturn()
                .getResponse().getContentAsString());

        assertThat(health.get("timestampingMode").asText()).isEqualTo("entry");
        assertThat(health.get("untimestampedEntries").asLong()).isEqualTo(1);
        assertThat(health.has("latestTimestampAnchorGenTime")).isFalse();
        assertThat(health.has("activeKeyAttested")).isFalse();
    }
}
