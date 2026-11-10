package eu.gillstrom.gatekeeper.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
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
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The registry journal after an append that did not complete.
 *
 * <p>A process that stops in the middle of an append leaves a line without
 * its newline. Until 1.7.0 the next append continued on that line: the two
 * became one line that replay skipped as malformed, so the record the second
 * append had acknowledged was gone after the next start. Here the fragment is
 * written to the file directly, as the stopped process would have left it.</p>
 */
class ApprovalRegistryTornLineTest {

    private static final String FRAGMENT = "{\"op\":\"CONFIRM\",\"verificationId\":\"TORN-FRAGMENT\",\"iss";

    @TempDir
    Path dir;

    private Path journal;
    private ListAppender<ILoggingEvent> log;

    @BeforeEach
    void setUp() {
        journal = dir.resolve("approval-registry.jsonl");
        log = new ListAppender<>();
        log.start();
        ((Logger) LoggerFactory.getLogger(AppendOnlyFileApprovalRegistry.class)).addAppender(log);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(AppendOnlyFileApprovalRegistry.class)).detachAppender(log);
    }

    private AppendOnlyFileApprovalRegistry start() throws IOException {
        AppendOnlyFileApprovalRegistry registry = new AppendOnlyFileApprovalRegistry(journal.toString());
        registry.initialise();
        return registry;
    }

    /** A registry holding one issued certificate, as VID {@code KEY}. */
    private AppendOnlyFileApprovalRegistry withAnIssuedCertificate() throws IOException {
        AppendOnlyFileApprovalRegistry registry = start();
        registry.register("KEY", "nonce", true, "fp", "5569743098", "Supplier AB", "SECUROSYS", "Primus HSM", "SE");
        registry.confirm("KEY", "nonce", true, "fp", true);
        assertThat(registry.lookup("KEY").orElseThrow().getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        return registry;
    }

    private void leaveAFragment() throws IOException {
        Files.writeString(journal, FRAGMENT, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
    }

    private List<String> lines() throws IOException {
        return Files.readAllLines(journal, StandardCharsets.UTF_8);
    }

    private List<String> warnings() {
        return log.list.stream().filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Test
    void aRevocationAcknowledgedAfterAFragmentIsStillThereAfterARestart() throws Exception {
        AppendOnlyFileApprovalRegistry registry = withAnIssuedCertificate();
        leaveAFragment();

        assertThat(registry.changeStatus("KEY", RegistryStatus.REVOKED, "key compromise", null).isApplied()).isTrue();

        assertThat(lines()).hasSize(3).allSatisfy(line -> assertThat(line).startsWith("{\"op\":\"").endsWith("}"));
        assertThat(lines().get(2)).startsWith("{\"op\":\"STATUS_CHANGE\"").doesNotContain("TORN-FRAGMENT");
        assertThat(Files.readString(journal)).endsWith("}\n");
        assertThat(start().lookup("KEY").orElseThrow().getStatus())
                .as("the revocation the caller was told had been recorded")
                .isEqualTo(RegistryStatus.REVOKED);
    }

    @Test
    void aFragmentIsSkippedAtStartAndRemovedByTheNextWrite() throws Exception {
        withAnIssuedCertificate();
        leaveAFragment();

        AppendOnlyFileApprovalRegistry restarted = start();

        assertThat(restarted.lookup("KEY").orElseThrow().getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(warnings()).anyMatch(w -> w.startsWith("Replay: malformed line skipped"))
                .noneMatch(w -> w.contains("was not followed by a newline"));
        assertThat(Files.readString(journal)).as("left as it was until something is written").endsWith(FRAGMENT);

        restarted.register("NEXT", "n2", true, "fp2", "5569743098", "Supplier AB", "SECUROSYS", "Primus HSM", "SE");

        assertThat(lines()).hasSize(3).noneMatch(line -> line.contains("TORN-FRAGMENT"));
        AppendOnlyFileApprovalRegistry again = start();
        assertThat(again.lookup("KEY")).isPresent();
        assertThat(again.lookup("NEXT")).isPresent();
    }

    @Test
    void aWholeLastRecordWithoutItsNewlineIsKeptAndGivenOne() throws Exception {
        withAnIssuedCertificate();
        // The record is complete; only its newline did not reach the file.
        Files.writeString(journal, "{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"KEY\",\"status\":\"REVOKED\","
                + "\"previousStatus\":\"VERIFIED_AND_ISSUED\",\"statusChangedAt\":\"2026-11-10T00:00:00Z\"}",
                StandardCharsets.UTF_8, StandardOpenOption.APPEND);

        AppendOnlyFileApprovalRegistry restarted = start();

        assertThat(restarted.lookup("KEY").orElseThrow().getStatus()).isEqualTo(RegistryStatus.REVOKED);
        assertThat(warnings()).containsExactly("Replay: the last record of " + journal
                + " was not followed by a newline; one was added");
        assertThat(Files.readString(journal)).endsWith("\"}\n");

        // The next write therefore leaves it in place.
        restarted.register("NEXT", "n2", true, "fp2", "5569743098", "Supplier AB", "SECUROSYS", "Primus HSM", "SE");
        assertThat(lines()).hasSize(4);
        AppendOnlyFileApprovalRegistry again = start();
        assertThat(again.lookup("KEY").orElseThrow().getStatus()).isEqualTo(RegistryStatus.REVOKED);
        assertThat(again.lookup("NEXT")).isPresent();
    }

    @Test
    void aJournalThatEndsInANewlineIsNotTouchedAtStart() throws Exception {
        withAnIssuedCertificate();
        byte[] before = Files.readAllBytes(journal);
        log.list.clear();

        start();

        assertThat(Files.readAllBytes(journal)).isEqualTo(before);
        assertThat(warnings()).isEmpty();
    }

    /** DEPLOYMENT.md says the journal's permissions are enforced at startup; until 1.7.0 only for a new file. */
    @Test
    void anExistingJournalIsSetTo0640AtEveryStart() throws Exception {
        withAnIssuedCertificate();
        Files.setPosixFilePermissions(journal, PosixFilePermissions.fromString("rw-rw-rw-"));

        start();

        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(journal))).isEqualTo("rw-r-----");
    }
}
