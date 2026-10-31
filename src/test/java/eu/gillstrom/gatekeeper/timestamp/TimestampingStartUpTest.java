package eu.gillstrom.gatekeeper.timestamp;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * What {@link AuditTimestamping} reports when it starts, and the thread
 * {@link TimestampAnchorService} runs anchors on.
 */
class TimestampingStartUpTest {

    private static final String TSA_URL = "http://127.0.0.1:9/tsr";
    private static TestTsa tsa;

    @TempDir
    Path tempDir;

    private ListAppender<ILoggingEvent> logs;

    @BeforeAll
    static void startTsa() throws Exception {
        tsa = new TestTsa();
    }

    @BeforeEach
    void captureLogs() {
        logs = new ListAppender<>();
        logs.start();
        ((Logger) LoggerFactory.getLogger(AuditTimestamping.class)).addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        ((Logger) LoggerFactory.getLogger(AuditTimestamping.class)).detachAppender(logs);
    }

    private String startUpLine(String mode, String policyOid) throws Exception {
        logs.list.clear();
        Path trust = tsa.writeTrustPem(tempDir.resolve("trust-" + mode + ".pem"));
        Path anchors = tempDir.resolve("anchors-" + mode + ".jsonl");
        new AuditTimestamping(mode, TSA_URL, "SHA-256", policyOid, 1000, 2000, trust.toString(), 60,
                anchors.toString());
        List<String> info = logs.list.stream().filter(e -> e.getLevel() == Level.INFO)
                .map(ILoggingEvent::getFormattedMessage).filter(m -> m.startsWith("AuditTimestamping: mode=")).toList();
        assertThat(info).hasSize(1);
        return info.get(0);
    }

    @Test
    void theStartUpLineNamesThePolicyOrTheTsaDefaultAndTheAnchorSettingsInAnchorModeOnly() throws Exception {
        assertThat(startUpLine("entry", null)).contains("policy-oid=(TSA default),").endsWith("timeout=1000ms/2000ms");
        assertThat(startUpLine("entry", " ")).contains("policy-oid=(TSA default),");
        assertThat(startUpLine("entry", "1.2.3.4")).contains("policy-oid=1.2.3.4,");
        assertThat(startUpLine("anchor", "")).contains(", anchor interval=60s, anchor file=")
                .endsWith(tempDir.resolve("anchors-anchor.jsonl").toAbsolutePath().toString());
    }

    private static Optional<Thread> anchorThread() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals("gatekeeper-tsa-anchor") && t.isAlive()).findFirst();
    }

    @Test
    void anchorsRunOnADaemonThreadThatStopEnds() throws Exception {
        AuditTimestamping ts = new AuditTimestamping(AuditTimestamping.Mode.ANCHOR, tsa, tsa.verifier(),
                tempDir.resolve("a.jsonl.tsa-anchors.jsonl"), 3600);
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(tempDir.resolve("a.jsonl").toString(),
                new EphemeralReceiptSigner(2048), 0, null, ts);
        log.initialise();
        TimestampAnchorService service = new TimestampAnchorService(log, ts);
        assertThat(service.mode()).isEqualTo(AuditTimestamping.Mode.ANCHOR);

        service.start();
        Thread thread = anchorThread().orElseThrow();
        assertThat(thread.isDaemon()).isTrue();

        service.stop();
        thread.join(5_000);
        assertThat(thread.isAlive()).as("stop() shuts the scheduler down").isFalse();
    }

    @Test
    void stoppingAServiceThatNeverStartedIsANoOp() {
        TimestampAnchorService off = new TimestampAnchorService(null, AuditTimestamping.off());
        off.start();
        assertThat(off.mode()).isEqualTo(AuditTimestamping.Mode.OFF);
        assertThatCode(off::stop).doesNotThrowAnyException();
    }
}
