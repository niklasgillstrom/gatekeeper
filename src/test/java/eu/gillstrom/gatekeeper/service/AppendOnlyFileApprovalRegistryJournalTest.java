package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AppendOnlyFileApprovalRegistryJournalTest {

    @TempDir
    Path tempDir;

    private AppendOnlyFileApprovalRegistry registryAt(Path journal) throws IOException {
        AppendOnlyFileApprovalRegistry registry = new AppendOnlyFileApprovalRegistry(journal.toString());
        registry.initialise();
        return registry;
    }

    private static void registerPending(ApprovalRegistry registry) {
        registry.register("VID-J", "nonce-j", true, "fp-j",
                "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE");
    }

    @Test
    void failedJournalWriteLeavesTheEntryAwaitingConfirmation() throws Exception {
        Path journal = tempDir.resolve("approval-registry.jsonl");
        AppendOnlyFileApprovalRegistry registry = registryAt(journal);
        registerPending(registry);

        Files.delete(journal);
        Files.createDirectory(journal);

        assertThatThrownBy(() -> registry.confirm("VID-J", "nonce-j", true, "fp-j", true))
                .isInstanceOf(IllegalStateException.class);

        ApprovalRegistry.RegistryEntry entry = registry.lookup("VID-J").orElseThrow();
        assertThat(entry.getStatus()).isNull();
        assertThat(entry.getConfirmationTimestamp()).isNull();
        assertThat(entry.isCertificateReceived()).isFalse();
        assertThat(entry.getActualPublicKeyFingerprint()).isNull();
        assertThat(entry.getConfirmationNonce()).isEqualTo("nonce-j");
        assertThat(registry.findAwaitingConfirmation("SE"))
                .extracting(ApprovalRegistry.RegistryEntry::getVerificationId)
                .containsExactly("VID-J");
    }

    @Test
    void confirmationTimestampIsJournalledAndReplayed() throws Exception {
        Path journal = tempDir.resolve("approval-registry.jsonl");
        AppendOnlyFileApprovalRegistry first = registryAt(journal);
        registerPending(first);
        String confirmedAt = first.confirm("VID-J", "nonce-j", false, null, false)
                .orElseThrow()
                .getConfirmationTimestamp();

        assertThat(confirmedAt).isNotNull();
        assertThat(Files.readString(journal, StandardCharsets.UTF_8))
                .contains("\"confirmationTimestamp\":\"" + confirmedAt + "\"");

        ApprovalRegistry.RegistryEntry replayed = registryAt(journal).lookup("VID-J").orElseThrow();
        assertThat(replayed.getStatus()).isEqualTo(RegistryStatus.VERIFIED_NOT_ISSUED);
        assertThat(replayed.getConfirmationTimestamp()).isEqualTo(confirmedAt);
    }

    @Test
    void confirmLinesWithoutATimestampReplayWithoutOne() throws Exception {
        Path journal = tempDir.resolve("legacy-registry.jsonl");
        Files.writeString(journal,
                "{\"op\":\"REGISTER\",\"entry\":{\"verificationId\":\"VID-LEGACY\","
                        + "\"confirmationNonce\":\"nonce-legacy\",\"compliant\":true,"
                        + "\"publicKeyFingerprint\":\"fp-legacy\",\"countryCode\":\"SE\","
                        + "\"verificationTimestamp\":\"2026-01-01T00:00:00Z\",\"certificateReceived\":false}}\n"
                        + "{\"op\":\"CONFIRM\",\"verificationId\":\"VID-LEGACY\",\"issued\":true,"
                        + "\"actualPublicKeyFingerprint\":\"fp-legacy\",\"publicKeyMatch\":true}\n",
                StandardCharsets.UTF_8);

        ApprovalRegistry.RegistryEntry entry = registryAt(journal).lookup("VID-LEGACY").orElseThrow();

        assertThat(entry.getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(entry.getConfirmationTimestamp()).isNull();
    }
}
