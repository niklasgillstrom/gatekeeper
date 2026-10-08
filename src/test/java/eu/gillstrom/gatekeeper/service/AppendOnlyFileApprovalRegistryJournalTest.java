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

    @Test
    void thePartiesAreJournalledAndReplayed(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        Path journal = dir.resolve("parties.jsonl");
        registryAt(journal).register("SE-P", "nonce", true, "fp",
                new ApprovalRegistry.Parties("5569743098", "1231015932", "5566778899", "9871234567", "TL AB"),
                "SECUROSYS", "Primus HSM", "SE", "CN=FE");

        ApprovalRegistry.RegistryEntry replayed = registryAt(journal).lookup("SE-P").orElseThrow();

        org.assertj.core.api.Assertions.assertThat(replayed.getCustomerOrganisationNumber()).isEqualTo("5569743098");
        org.assertj.core.api.Assertions.assertThat(replayed.getCustomerSwishNumber()).isEqualTo("1231015932");
        org.assertj.core.api.Assertions.assertThat(replayed.getSupplierIdentifier()).isEqualTo("5566778899");
        org.assertj.core.api.Assertions.assertThat(replayed.getSupplierNumber()).isEqualTo("9871234567");
        org.assertj.core.api.Assertions.assertThat(replayed.getSupplierName()).isEqualTo("TL AB");
    }

    @Test
    void theSubmissionIsJournalledAndReplayedWithTheSameDigest(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        Path journal = dir.resolve("submission.jsonl");
        eu.gillstrom.gatekeeper.model.VerificationRequest sent = new eu.gillstrom.gatekeeper.model.VerificationRequest();
        sent.setPublicKey("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----");
        sent.setHsmVendor("YUBICO");
        sent.setAttestationData("YXR0ZXN0YXRpb24=");
        sent.setAttestationCertChain(java.util.List.of("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"));
        sent.setCustomerOrganisationNumber("5569743098");
        sent.setCustomerSwishNumber("1231015932");
        sent.setKeyPurpose("Swish SIGNING");
        sent.setCountryCode("SE");
        registryAt(journal).register("SE-S", "nonce", true, "fp",
                new ApprovalRegistry.Parties("5569743098", "1231015932", null, null, null), sent,
                "Yubico", "YubiHSM 2", "SE", "CN=FE");

        eu.gillstrom.gatekeeper.model.VerificationRequest replayed =
                registryAt(journal).lookup("SE-S").orElseThrow().getSubmission();

        org.assertj.core.api.Assertions.assertThat(replayed).isEqualTo(sent);
        org.assertj.core.api.Assertions.assertThat(VerificationService.requestDigestBase64(replayed))
                .isEqualTo(VerificationService.requestDigestBase64(sent));
    }
}
