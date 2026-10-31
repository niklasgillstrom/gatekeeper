package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry.StatusChange;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

/**
 * {@link ApprovalRegistry#changeStatus}: the allowed lifecycle transitions,
 * on both registries, and the {@code STATUS_CHANGE} journal operation of the
 * file-backed one.
 */
class ApprovalRegistryStatusChangeTest {

    private static final String ISSUER = "CN=Swish Customer CA1 v2 for Swish,O=Getswish AB,C=SE";

    @TempDir
    Path tempDir;

    private ApprovalRegistry open(String implementation) throws Exception {
        if (implementation.equals("memory")) {
            return new InMemoryApprovalRegistry();
        }
        AppendOnlyFileApprovalRegistry registry =
                new AppendOnlyFileApprovalRegistry(tempDir.resolve("registry.jsonl").toString());
        registry.initialise();
        return registry;
    }

    private ApprovalRegistry reopen(String implementation, ApprovalRegistry current) throws Exception {
        return implementation.equals("memory") ? current : open(implementation);
    }

    private static void issued(ApprovalRegistry registry, String id) {
        registry.register(id, "n-" + id, true, "fp-" + id, "5569743098", "Supplier AB", "SECUROSYS",
                "Primus HSM", "SE");
        registry.confirm(id, "n-" + id, true, "fp-" + id, true,
                new ApprovalRegistry.IssuedCertificate("PEM-" + id, Integer.toHexString(id.hashCode() & 0xffff),
                        ISSUER));
    }

    @Test
    void theTransitionMatrixIsExactlyTheDocumentedOne() {
        Set<RegistryStatus> lifecycle =
                EnumSet.of(RegistryStatus.SUPERSEDED, RegistryStatus.REVOKED, RegistryStatus.DECOMMISSIONED);
        for (RegistryStatus from : RegistryStatus.values()) {
            for (RegistryStatus to : RegistryStatus.values()) {
                boolean expected = (from == RegistryStatus.VERIFIED_AND_ISSUED && lifecycle.contains(to))
                        || (from == RegistryStatus.SUPERSEDED
                                && (to == RegistryStatus.REVOKED || to == RegistryStatus.DECOMMISSIONED));
                assertThat(ApprovalRegistry.isAllowedStatusChange(from, to)).as(from + " -> " + to)
                        .isEqualTo(expected);
            }
            assertThat(ApprovalRegistry.isAllowedStatusChange(null, RegistryStatus.REVOKED))
                    .as("awaiting confirmation").isFalse();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void aConfirmedIssuanceMovesThroughTheLifecycleAndTheChangeSurvivesARestart(String implementation)
            throws Exception {
        ApprovalRegistry registry = open(implementation);
        issued(registry, "ROT");
        issued(registry, "NEXT");

        StatusChange rotated = registry.changeStatus("ROT", RegistryStatus.SUPERSEDED, "planned rotation", "NEXT");
        assertThat(rotated.outcome()).isEqualTo(StatusChange.Outcome.APPLIED);
        assertThat(rotated.previousStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(rotated.currentStatus()).isEqualTo(RegistryStatus.SUPERSEDED);
        assertThat(rotated.changedAt()).isNotNull();

        StatusChange revoked = registry.changeStatus("ROT", RegistryStatus.REVOKED, "key compromise", null);
        assertThat(revoked.isApplied()).isTrue();
        assertThat(revoked.previousStatus()).isEqualTo(RegistryStatus.SUPERSEDED);

        for (ApprovalRegistry r : new ApprovalRegistry[] {registry, reopen(implementation, registry)}) {
            ApprovalRegistry.RegistryEntry entry = r.lookup("ROT").orElseThrow();
            assertThat(entry.getStatus()).isEqualTo(RegistryStatus.REVOKED);
            assertThat(entry.getStatusChangeReason()).isEqualTo("key compromise");
            assertThat(entry.getStatusChangedAt()).isEqualTo(revoked.changedAt());
            assertThat(entry.getSuccessorVerificationId())
                    .as("the successor recorded at rotation is kept by the later revocation")
                    .isEqualTo("NEXT");
            assertThat(entry.getIssuedCertificateSerial()).as("the certificate stays findable").isNotNull();
            assertThat(r.lookup("NEXT").orElseThrow().getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void aRefusedChangeChangesNothing(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        issued(registry, "DEC");
        registry.register("PENDING", "n", true, "fp", "5569743098", "Supplier AB", "SECUROSYS", "P", "SE");
        registry.register("REJ", "n", false, "fp", "5569743098", "Supplier AB", "SECUROSYS", "P", "SE");
        assertThat(registry.changeStatus("DEC", RegistryStatus.DECOMMISSIONED, "end of life", null).isApplied())
                .isTrue();

        for (RegistryStatus target : new RegistryStatus[] {
                RegistryStatus.SUPERSEDED, RegistryStatus.REVOKED, RegistryStatus.DECOMMISSIONED}) {
            StatusChange refused = registry.changeStatus("DEC", target, "again", null);
            assertThat(refused.outcome()).isEqualTo(StatusChange.Outcome.REFUSED);
            assertThat(refused.previousStatus()).isEqualTo(RegistryStatus.DECOMMISSIONED);
            assertThat(refused.currentStatus()).isEqualTo(RegistryStatus.DECOMMISSIONED);
            assertThat(registry.changeStatus("PENDING", target, "x", null).outcome())
                    .isEqualTo(StatusChange.Outcome.REFUSED);
            assertThat(registry.changeStatus("REJ", target, "x", null).outcome())
                    .isEqualTo(StatusChange.Outcome.REFUSED);
        }
        assertThat(registry.changeStatus("NOPE", RegistryStatus.REVOKED, "x", null).outcome())
                .isEqualTo(StatusChange.Outcome.NOT_FOUND);

        for (ApprovalRegistry r : new ApprovalRegistry[] {registry, reopen(implementation, registry)}) {
            assertThat(r.lookup("DEC").orElseThrow().getStatusChangeReason()).isEqualTo("end of life");
            assertThat(r.lookup("PENDING").orElseThrow().getStatus()).isNull();
            assertThat(r.lookup("REJ").orElseThrow().getStatus()).isEqualTo(RegistryStatus.REJECTED_NOT_ISSUED);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void onlyLifecycleStatusesCanBeSet(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        issued(registry, "A");
        assertThatThrownBy(() -> registry.changeStatus("A", RegistryStatus.VERIFIED_NOT_ISSUED, "x", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> registry.changeStatus("A", null, "x", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void lifecycleEntriesStillCountAsCompliantInTheStatistics(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        issued(registry, "A");
        issued(registry, "B");
        issued(registry, "C");
        registry.register("REJ", "n", false, "fp", "5569743098", "Supplier AB", "SECUROSYS", "P", "SE");
        registry.changeStatus("A", RegistryStatus.SUPERSEDED, "rotation", null);
        registry.changeStatus("B", RegistryStatus.REVOKED, "compromise", null);

        assertThat(reopen(implementation, registry).getStats("SE"))
                .isEqualTo(new ApprovalRegistry.ComplianceStats(4, 3, 0, 75.0));
    }

    @Test
    void theStatusChangeIsJournalledAsItsOwnOperation() throws Exception {
        Path journal = tempDir.resolve("registry.jsonl");
        ApprovalRegistry registry = open("file");
        issued(registry, "J");
        registry.changeStatus("J", RegistryStatus.SUPERSEDED, "rotation|50%", "J2");

        String last = Files.readAllLines(journal, StandardCharsets.UTF_8).getLast();
        assertThat(last)
                .startsWith("{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"J\",\"status\":\"SUPERSEDED\","
                        + "\"previousStatus\":\"VERIFIED_AND_ISSUED\",\"statusChangedAt\":\"")
                .endsWith("\"reason\":\"rotation|50%\",\"successorVerificationId\":\"J2\"}");
    }

    @Test
    void aJournalWrittenBeforeStatusChangesReplaysAndCanBeExtended() throws Exception {
        Path journal = tempDir.resolve("legacy.jsonl");
        Files.writeString(journal,
                "{\"op\":\"REGISTER\",\"entry\":{\"verificationId\":\"OLD\",\"confirmationNonce\":\"n\","
                        + "\"compliant\":true,\"publicKeyFingerprint\":\"fp\",\"countryCode\":\"SE\","
                        + "\"verificationTimestamp\":\"2026-01-01T00:00:00Z\",\"certificateReceived\":false}}\n"
                        + "{\"op\":\"CONFIRM\",\"verificationId\":\"OLD\",\"issued\":true,"
                        + "\"actualPublicKeyFingerprint\":\"fp\",\"publicKeyMatch\":true,"
                        + "\"confirmationTimestamp\":\"2026-01-01T00:01:00Z\",\"issuedCertificatePem\":\"PEM\","
                        + "\"issuedCertificateSerial\":\"c0ffee\",\"issuedCertificateIssuerDn\":\"" + ISSUER + "\"}\n",
                StandardCharsets.UTF_8);

        AppendOnlyFileApprovalRegistry first = new AppendOnlyFileApprovalRegistry(journal.toString());
        first.initialise();
        ApprovalRegistry.RegistryEntry entry = first.lookup("OLD").orElseThrow();
        assertThat(entry.getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(entry.getStatusChangedAt()).isNull();
        assertThat(first.changeStatus("OLD", RegistryStatus.DECOMMISSIONED, "retired", null).isApplied()).isTrue();

        AppendOnlyFileApprovalRegistry second = new AppendOnlyFileApprovalRegistry(journal.toString());
        second.initialise();
        assertThat(second.lookup("OLD").orElseThrow().getStatus()).isEqualTo(RegistryStatus.DECOMMISSIONED);
    }

    @Test
    void aStatusChangeLineThatDoesNotFitIsSkippedOnReplay() throws Exception {
        Path journal = tempDir.resolve("registry.jsonl");
        ApprovalRegistry registry = open("file");
        issued(registry, "K");
        registry.register("PENDING", "n", true, "fp", "5569743098", "Supplier AB", "SECUROSYS", "P", "SE");
        Files.writeString(journal, String.join("\n",
                "{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"UNKNOWN\",\"status\":\"REVOKED\"}",
                "{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"PENDING\",\"status\":\"REVOKED\"}",
                "{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"K\",\"status\":\"NO_SUCH_STATUS\"}",
                "{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"K\",\"status\":\"VERIFIED_NOT_ISSUED\"}",
                "{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"K\",\"status\":\"REVOKED\",\"reason\":\"ok\"}",
                "{\"op\":\"STATUS_CHANGE\",\"verificationId\":\"K\",\"status\":\"SUPERSEDED\"}",
                ""), StandardCharsets.UTF_8, StandardOpenOption.APPEND);

        ApprovalRegistry replayed = open("file");

        assertThat(replayed.lookup("PENDING").orElseThrow().getStatus()).isNull();
        ApprovalRegistry.RegistryEntry k = replayed.lookup("K").orElseThrow();
        assertThat(k.getStatus()).as("only the one allowed line applies").isEqualTo(RegistryStatus.REVOKED);
        assertThat(k.getStatusChangeReason()).isEqualTo("ok");
    }

    @Test
    void aFailedJournalWriteLeavesTheStatusUnchanged() throws Exception {
        Path journal = tempDir.resolve("registry.jsonl");
        ApprovalRegistry registry = open("file");
        issued(registry, "F");
        Files.delete(journal);
        Files.createDirectory(journal);

        assertThatThrownBy(() -> registry.changeStatus("F", RegistryStatus.REVOKED, "x", null))
                .isInstanceOf(IllegalStateException.class);
        ApprovalRegistry.RegistryEntry entry = registry.lookup("F").orElseThrow();
        assertThat(entry.getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(entry.getStatusChangedAt()).isNull();
    }

    @Test
    void anImplementationWithoutStatusChangesRefusesLoudly() {
        ApprovalRegistry other = mock(ApprovalRegistry.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        assertThatThrownBy(() -> other.changeStatus("X", RegistryStatus.REVOKED, "x", null))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
