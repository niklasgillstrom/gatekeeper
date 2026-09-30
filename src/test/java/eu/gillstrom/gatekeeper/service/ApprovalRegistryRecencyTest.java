package eu.gillstrom.gatekeeper.service;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class ApprovalRegistryRecencyTest {

    @TempDir
    Path tempDir;

    static Stream<Function<Path, ApprovalRegistry>> implementations() {
        return Stream.of(
                dir -> new InMemoryApprovalRegistry(),
                dir -> {
                    AppendOnlyFileApprovalRegistry registry =
                            new AppendOnlyFileApprovalRegistry(
                                    dir.resolve("registry-" + System.nanoTime() + ".jsonl").toString());
                    try {
                        registry.initialise();
                    } catch (Exception e) {
                        throw new IllegalStateException("Could not initialise file registry", e);
                    }
                    return registry;
                });
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void findByPublicKeyFingerprintReturnsTheMostRecentCompliantEntry(Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        ApprovalRegistry.RegistryEntry original = registry.register("VID-ORIGINAL", "nonce-original", true,
                "fp-shared", "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE");
        original.setVerificationTimestamp("2026-01-01T00:00:00Z");
        ApprovalRegistry.RegistryEntry renewal = registry.register("VID-RENEWAL", "nonce-renewal", true,
                "fp-shared", "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE");
        renewal.setVerificationTimestamp("2026-06-01T00:00:00Z");

        assertThat(registry.findByPublicKeyFingerprint("fp-shared").orElseThrow().getVerificationId())
                .isEqualTo("VID-RENEWAL");
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void findByPublicKeyFingerprintReturnsTheMostRecentNonCompliantEntryWhenNoneIsCompliant(
            Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        ApprovalRegistry.RegistryEntry original = registry.register("VID-ORIGINAL", "nonce-original", false,
                "fp-shared", "556000-0000", "Svensk TL", null, null, "SE");
        original.setVerificationTimestamp("2026-01-01T00:00:00Z");
        ApprovalRegistry.RegistryEntry renewal = registry.register("VID-RENEWAL", "nonce-renewal", false,
                "fp-shared", "556000-0000", "Svensk TL", null, null, "SE");
        renewal.setVerificationTimestamp("2026-06-01T00:00:00Z");

        assertThat(registry.findByPublicKeyFingerprint("fp-shared").orElseThrow().getVerificationId())
                .isEqualTo("VID-RENEWAL");
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void confirmationTimestampBreaksATieOnVerificationTimestamp(Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        ApprovalRegistry.RegistryEntry original = registry.register("VID-ORIGINAL", "nonce-original", true,
                "fp-shared", "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE");
        original.setVerificationTimestamp("2026-01-01T00:00:00Z");
        original.setConfirmationTimestamp("2026-01-02T00:00:00Z");
        ApprovalRegistry.RegistryEntry renewal = registry.register("VID-RENEWAL", "nonce-renewal", true,
                "fp-shared", "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE");
        renewal.setVerificationTimestamp("2026-01-01T00:00:00Z");
        renewal.setConfirmationTimestamp("2026-01-03T00:00:00Z");

        assertThat(registry.findByPublicKeyFingerprint("fp-shared").orElseThrow().getVerificationId())
                .isEqualTo("VID-RENEWAL");
    }
}
