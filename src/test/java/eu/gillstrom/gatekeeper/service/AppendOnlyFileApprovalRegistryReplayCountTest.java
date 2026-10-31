package eu.gillstrom.gatekeeper.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry.StatusChange;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * Replaying {@code STATUS_CHANGE} lines: which are applied and which are
 * skipped, as the start-up summary counts them; and a status change releases
 * the registry's write lock.
 */
class AppendOnlyFileApprovalRegistryReplayCountTest {

    private static final String ISSUER = "CN=Swish Customer CA1 v2 for Swish,O=Getswish AB,C=SE";

    @TempDir
    Path tempDir;

    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void captureLogs() {
        logs = new ListAppender<>();
        logs.start();
        ((Logger) LoggerFactory.getLogger(AppendOnlyFileApprovalRegistry.class)).addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        ((Logger) LoggerFactory.getLogger(AppendOnlyFileApprovalRegistry.class)).detachAppender(logs);
    }

    private static void issued(ApprovalRegistry registry, String id, String serial) {
        registry.register(id, "n-" + id, true, "fp-" + id, "5569743098", "Supplier AB", "SECUROSYS",
                "Primus HSM", "SE");
        registry.confirm(id, "n-" + id, true, "fp-" + id, true,
                new ApprovalRegistry.IssuedCertificate("PEM-" + id, serial, ISSUER));
    }

    private static String statusChange(String id, String status) {
        return "{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"" + id + "\",\"status\":\"" + status
                + "\",\"statusChangedAt\":\"2026-10-30T12:00:00Z\"}\n";
    }

    @Test
    void theStartUpSummaryCountsAppliedAndSkippedStatusChanges() throws Exception {
        Path journal = tempDir.resolve("registry.jsonl");
        AppendOnlyFileApprovalRegistry first = new AppendOnlyFileApprovalRegistry(journal.toString());
        first.initialise();
        issued(first, "A", "a1");
        issued(first, "B", "b2");
        assertThat(first.changeStatus("A", RegistryStatus.REVOKED, "compromise", null).isApplied()).isTrue();
        Files.writeString(journal, Files.readString(journal)
                + statusChange("UNKNOWN", "REVOKED")                // no such entry
                + statusChange("B", "NOT_A_STATUS")                 // no such status
                + statusChange("B", "VERIFIED_AND_ISSUED")          // not a lifecycle status
                + statusChange("A", "SUPERSEDED"),                  // not allowed from REVOKED
                StandardCharsets.UTF_8);

        logs.list.clear();
        AppendOnlyFileApprovalRegistry second = new AppendOnlyFileApprovalRegistry(journal.toString());
        second.initialise();

        assertThat(second.lookup("A").orElseThrow().getStatus()).isEqualTo(RegistryStatus.REVOKED);
        assertThat(second.lookup("B").orElseThrow().getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(logs.list).filteredOn(e -> e.getLevel() == Level.INFO)
                .map(ILoggingEvent::getFormattedMessage)
                .anySatisfy(m -> assertThat(m)
                        .contains("replayed 2 REGISTER + 2 CONFIRM ops + 1 STATUS_CHANGE ops from ")
                        .endsWith("(2 entries in index, 4 skipped)"));
    }

    @Test
    void aStatusChangeReleasesTheWriteLockForOtherThreads() throws Exception {
        AppendOnlyFileApprovalRegistry registry =
                new AppendOnlyFileApprovalRegistry(tempDir.resolve("lock.jsonl").toString());
        registry.initialise();
        issued(registry, "L", "c3");

        ExecutorService other = Executors.newSingleThreadExecutor();
        try {
            assertThat(other.submit(() -> registry.changeStatus("L", RegistryStatus.DECOMMISSIONED, "retired", null))
                    .get().isApplied()).isTrue();
            assertTimeoutPreemptively(Duration.ofSeconds(10), () -> issued(registry, "M", "d4"));
        } finally {
            other.shutdownNow();
        }
    }

    @Test
    void onlyAnAppliedChangeIsApplied() {
        assertThat(StatusChange.applied(RegistryStatus.VERIFIED_AND_ISSUED, RegistryStatus.REVOKED,
                "2026-10-30T12:00:00Z").isApplied()).isTrue();
        assertThat(StatusChange.refused(RegistryStatus.REVOKED).isApplied()).isFalse();
        assertThat(StatusChange.notFound().isApplied()).isFalse();
    }
}
