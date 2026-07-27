package eu.gillstrom.gatekeeper.service;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Jurisdiction scoping of the registry queries, run against
 * <em>both</em> {@link ApprovalRegistry} implementations.
 *
 * <p>The defect these tests pin down: {@code VerificationController}
 * accepted a {@code countryCode} path variable on
 * {@code /v1/attestation/&#x7b;cc&#x7d;/registry/anomalies} and
 * {@code .../awaiting} and then called registry methods that took no
 * argument, so a Swedish supervisor's query returned German and French rows
 * as well. Registry contents are supervisory material subject to DORA
 * Article 55 professional secrecy; leaking them across NCA boundaries is
 * not a cosmetic bug.</p>
 *
 * <p>Both implementations are exercised from one parameterised source
 * because the two answering the same question differently would itself be
 * a defect — and because the file-backed one was the implementation the
 * production profile selects.</p>
 */
class ApprovalRegistryCountryScopeTest {

    @TempDir
    Path tempDir;

    /**
     * Supplies a fresh registry of each implementation. The file-backed one
     * needs a journal path, hence the {@link Path} argument.
     */
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
    void findByCountryReturnsOnlyThatJurisdiction(Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        registry.register("SE-1", "nonce-se", true, "fp-se", "556000-0000", "Svensk TL",
                "SECUROSYS", "Primus HSM", "SE");
        registry.register("DE-1", "nonce-de", true, "fp-de", "DE-123", "Deutscher TL",
                "SECUROSYS", "Primus HSM", "DE");

        assertThat(registry.findByCountry("SE"))
                .extracting(ApprovalRegistry.RegistryEntry::getVerificationId)
                .containsExactly("SE-1");
        assertThat(registry.findByCountry("DE"))
                .extracting(ApprovalRegistry.RegistryEntry::getVerificationId)
                .containsExactly("DE-1");
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void awaitingConfirmationIsScopedToTheRequestedCountry(
            Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        // A compliant register() leaves status null == awaiting Step 7.
        registry.register("SE-1", "nonce-se", true, "fp-se", "556000-0000", "Svensk TL",
                "SECUROSYS", "Primus HSM", "SE");
        registry.register("DE-1", "nonce-de", true, "fp-de", "DE-123", "Deutscher TL",
                "SECUROSYS", "Primus HSM", "DE");

        List<ApprovalRegistry.RegistryEntry> swedish = registry.findAwaitingConfirmation("SE");

        assertThat(swedish)
                .extracting(ApprovalRegistry.RegistryEntry::getVerificationId)
                .containsExactly("SE-1");
        assertThat(swedish)
                .extracting(ApprovalRegistry.RegistryEntry::getCountryCode)
                .containsOnly("SE");
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void anomaliesAreScopedToTheRequestedCountry(Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);

        // Non-compliant verification, then a confirmation saying the
        // certificate was issued anyway → ANOMALY_ISSUED_DESPITE_REJECTION.
        registry.register("SE-BAD", "nonce-se", false, "fp-se", "556000-0000", "Svensk TL",
                null, null, "SE");
        registry.confirm("SE-BAD", "nonce-se", true, "fp-se-actual", false);

        registry.register("DE-BAD", "nonce-de", false, "fp-de", "DE-123", "Deutscher TL",
                null, null, "DE");
        registry.confirm("DE-BAD", "nonce-de", true, "fp-de-actual", false);

        assertThat(registry.findAnomalies("SE"))
                .extracting(ApprovalRegistry.RegistryEntry::getVerificationId)
                .containsExactly("SE-BAD");
        assertThat(registry.findAnomalies("DE"))
                .extracting(ApprovalRegistry.RegistryEntry::getVerificationId)
                .containsExactly("DE-BAD");
        // The German anomaly must not appear in the Swedish supervisor's view.
        assertThat(registry.findAnomalies("SE"))
                .extracting(ApprovalRegistry.RegistryEntry::getCountryCode)
                .doesNotContain("DE");
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void unknownCountryReturnsNothingRatherThanEverything(
            Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        registry.register("SE-1", "nonce-se", true, "fp-se", "556000-0000", "Svensk TL",
                "SECUROSYS", "Primus HSM", "SE");
        registry.register("SE-BAD", "nonce-bad", false, "fp-bad", "556000-0001", "Svensk TL 2",
                null, null, "SE");
        registry.confirm("SE-BAD", "nonce-bad", true, "fp-bad-actual", false);

        assertThat(registry.findByCountry("XX")).isEmpty();
        assertThat(registry.findAwaitingConfirmation("XX")).isEmpty();
        assertThat(registry.findAnomalies("XX")).isEmpty();
        assertThat(registry.getStats("XX").total()).isZero();
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void entriesWithNoCountryBelongToNoJurisdiction(Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        registry.register("NULL-CC", "nonce", true, "fp", "556000-0000", "Namnlös TL",
                "SECUROSYS", "Primus HSM", null);

        assertThat(registry.findByCountry("SE")).isEmpty();
        assertThat(registry.findAwaitingConfirmation("SE")).isEmpty();
        assertThat(registry.findAnomalies("SE")).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void statsCountOnlyTheRequestedJurisdiction(Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        registry.register("SE-1", "nonce-se", true, "fp-se", "556000-0000", "Svensk TL",
                "SECUROSYS", "Primus HSM", "SE");
        registry.confirm("SE-1", "nonce-se", true, "fp-se", true);
        registry.register("DE-1", "nonce-de", true, "fp-de", "DE-123", "Deutscher TL",
                "SECUROSYS", "Primus HSM", "DE");
        registry.confirm("DE-1", "nonce-de", true, "fp-de", true);

        ApprovalRegistry.ComplianceStats se = registry.getStats("SE");
        assertThat(se.total()).isEqualTo(1);
        assertThat(se.compliant()).isEqualTo(1);
        assertThat(se.complianceRate()).isEqualTo(100.0);
    }
}
