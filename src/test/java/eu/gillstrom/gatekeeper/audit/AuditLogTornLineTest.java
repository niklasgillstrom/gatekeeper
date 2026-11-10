package eu.gillstrom.gatekeeper.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The audit log after an append that did not complete.
 *
 * <p>Until 1.7.0 the next append continued on the line the failed one had
 * left. If that was the log's last line at the next start, it was taken for
 * an aborted append and dropped, and with it an entry whose append had been
 * acknowledged; if another entry followed it, the log refused to load. Here
 * the fragment is written to the file directly, as a stopped process or a
 * failed write would have left it.</p>
 */
class AuditLogTornLineTest {

    private static final String FRAGMENT = "{\"sequenceNumber\":3,\"timesta";

    @TempDir
    Path dir;

    private Path file;
    private EphemeralReceiptSigner signer;
    private ListAppender<ILoggingEvent> logged;

    @BeforeEach
    void setUp() {
        file = dir.resolve("audit-log.jsonl");
        signer = new EphemeralReceiptSigner(2048);
        logged = new ListAppender<>();
        logged.start();
        ((Logger) LoggerFactory.getLogger(AppendOnlyFileAuditLog.class)).addAppender(logged);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(AppendOnlyFileAuditLog.class)).detachAppender(logged);
    }

    private AppendOnlyFileAuditLog start() {
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(file.toString(), signer);
        log.initialise();
        return log;
    }

    private static AuditAppendRequest request(String id) {
        return new AuditAppendRequest("CN=client", "VERIFY", "verif-" + id, "cmVx", "cmNwdA==", true);
    }

    private List<String> warnings() {
        return logged.list.stream().filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage).toList();
    }

    private void leaveAFragment() throws IOException {
        Files.writeString(file, FRAGMENT, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
    }

    @Test
    void anEntryAcknowledgedAfterAFragmentIsReadAtTheNextStart() throws Exception {
        AppendOnlyFileAuditLog log = start();
        log.append(request("1"));
        log.append(request("2"));
        leaveAFragment();

        AuditEntry third = log.append(request("3"));

        assertThat(third.sequenceNumber()).isEqualTo(3);
        assertThat(Files.readAllLines(file, StandardCharsets.UTF_8)).hasSize(3)
                .allSatisfy(line -> assertThat(line).startsWith("{\"sequenceNumber\":").endsWith("}"));
        AppendOnlyFileAuditLog restarted = start();
        assertThat(restarted.size()).as("the entry whose append was acknowledged").isEqualTo(3);
        assertThat(restarted.findByVerificationId("verif-3")).isPresent();
        assertThat(restarted.verifyChainIntegrity()).isTrue();
    }

    @Test
    void theLogStartsWhenEntriesWereAppendedAfterAFragment() throws Exception {
        AppendOnlyFileAuditLog log = start();
        log.append(request("1"));
        log.append(request("2"));
        leaveAFragment();
        log.append(request("3"));
        log.append(request("4"));

        AppendOnlyFileAuditLog restarted = start();

        assertThat(restarted.size()).isEqualTo(4);
        assertThat(restarted.verifyChainIntegrity()).isTrue();
        assertThat(restarted.append(request("5")).sequenceNumber()).isEqualTo(5);
    }

    /**
     * What start-up removes and an append would not: a last line that is not
     * an entry but is complete, newline and all. Left in place it would be a
     * corrupt line in the middle of the log after the next append.
     */
    @Test
    void aLastLineThatIsNotAnEntryIsRemovedAtStartUpWithOrWithoutItsNewline() throws Exception {
        for (String trailer : new String[] {FRAGMENT, "not an entry\n"}) {
            Files.deleteIfExists(file);
            AppendOnlyFileAuditLog log = start();
            log.append(request("1"));
            log.append(request("2"));
            String whole = Files.readString(file, StandardCharsets.UTF_8);
            Files.writeString(file, trailer, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
            logged.list.clear();

            AppendOnlyFileAuditLog restarted = start();

            assertThat(Files.readString(file, StandardCharsets.UTF_8)).as("after start-up").isEqualTo(whole);
            assertThat(warnings()).anyMatch(w -> w.contains("trailing line 3 is not parseable"));
            assertThat(restarted.size()).isEqualTo(2);
            restarted.append(request("3"));
            AppendOnlyFileAuditLog again = start();
            assertThat(again.size()).isEqualTo(3);
            assertThat(again.verifyChainIntegrity()).isTrue();
        }
    }

    @Test
    void aWholeLastEntryWithoutItsNewlineIsKeptAndGivenOne() throws Exception {
        AppendOnlyFileAuditLog log = start();
        log.append(request("1"));
        log.append(request("2"));
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Files.writeString(file, content.substring(0, content.length() - 1), StandardCharsets.UTF_8);
        logged.list.clear();

        AppendOnlyFileAuditLog restarted = start();

        assertThat(restarted.size()).isEqualTo(2);
        assertThat(warnings()).containsExactly("AppendOnlyFileAuditLog: the last entry of " + file.toAbsolutePath()
                + " was not followed by a newline; one was added");
        assertThat(Files.readString(file, StandardCharsets.UTF_8)).isEqualTo(content);

        // The next append therefore leaves the entry in place.
        restarted.append(request("3"));
        AppendOnlyFileAuditLog again = start();
        assertThat(again.size()).isEqualTo(3);
        assertThat(again.verifyChainIntegrity()).isTrue();
    }

    @Test
    void aLogThatEndsInANewlineIsNotTouchedAtStart() throws Exception {
        AppendOnlyFileAuditLog log = start();
        log.append(request("1"));
        byte[] before = Files.readAllBytes(file);
        logged.list.clear();

        start();

        assertThat(Files.readAllBytes(file)).isEqualTo(before);
        assertThat(warnings()).isEmpty();
    }
}
