package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry.IssuedCertificate;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry.RegistryEntry;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What every {@link ApprovalRegistry} must do, run against both
 * implementations. For the file-backed one each assertion is repeated on a
 * registry reopened from the journal, so that what is answered in memory is
 * also what was written.
 */
class ApprovalRegistryContractTest {

    private static final String ISSUER = "CN=SEB Customer CA1 v2 for Swish,O=Skandinaviska Enskilda Banken AB,C=SE";

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

    /** The registry as a restart would see it; the same object for the in-memory one. */
    private ApprovalRegistry reopen(String implementation, ApprovalRegistry current) throws Exception {
        return implementation.equals("memory") ? current : open(implementation);
    }

    private static void register(ApprovalRegistry registry, String id, boolean compliant, String fingerprint,
                                 String country) throws InterruptedException {
        registry.register(id, "nonce-" + id, compliant, fingerprint, "5569743098", "Supplier AB",
                "SECUROSYS", "Primus HSM", country);
        Thread.sleep(2); // distinct verification timestamps for the recency order
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void aRejectedVerificationIsFinalAndACompliantOneAwaitsConfirmation(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        register(registry, "REJ", false, "fp-rej", "SE");
        register(registry, "OK", true, "fp-ok", "SE");

        for (ApprovalRegistry r : new ApprovalRegistry[] {registry, reopen(implementation, registry)}) {
            assertThat(r.lookup("REJ").orElseThrow().getStatus()).isEqualTo(RegistryStatus.REJECTED_NOT_ISSUED);
            assertThat(r.lookup("OK").orElseThrow().getStatus()).isNull();
            assertThat(r.findAwaitingConfirmation("SE")).extracting(RegistryEntry::getVerificationId)
                    .containsExactly("OK");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void eachConfirmationOutcomeIsRecorded(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        register(registry, "ISSUED", true, "fp-1", "SE");
        register(registry, "MISMATCH", true, "fp-2", "SE");
        register(registry, "WITHDRAWN", true, "fp-3", "SE");
        register(registry, "DESPITE", false, "fp-4", "SE");
        register(registry, "REFUSED", false, "fp-5", "SE");

        IssuedCertificate certificate = new IssuedCertificate("PEM", "0a1b", ISSUER);
        registry.confirm("ISSUED", "nonce-ISSUED", true, "fp-1", true, certificate);
        registry.confirm("MISMATCH", "nonce-MISMATCH", true, "fp-other", false, certificate);
        registry.confirm("WITHDRAWN", "nonce-WITHDRAWN", false, "fp-ignored", true, certificate);
        registry.confirm("DESPITE", "nonce-DESPITE", true, "fp-4b", true, certificate);
        registry.confirm("REFUSED", "nonce-REFUSED", false, "fp-ignored", false, certificate);

        for (ApprovalRegistry r : new ApprovalRegistry[] {registry, reopen(implementation, registry)}) {
            RegistryEntry issued = r.lookup("ISSUED").orElseThrow();
            assertThat(issued.getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
            assertThat(issued.isCertificateReceived()).isTrue();
            assertThat(issued.getConfirmationTimestamp()).isNotBlank();
            assertThat(issued.getActualPublicKeyFingerprint()).isEqualTo("fp-1");
            assertThat(issued.getIssuedCertificatePem()).isEqualTo("PEM");
            assertThat(issued.getIssuedCertificateSerial()).isEqualTo("0a1b");
            assertThat(issued.getIssuedCertificateIssuerDn()).isEqualTo(ISSUER);

            RegistryEntry mismatch = r.lookup("MISMATCH").orElseThrow();
            assertThat(mismatch.getStatus()).isEqualTo(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
            assertThat(mismatch.getActualPublicKeyFingerprint()).isEqualTo("fp-other");
            assertThat(mismatch.getIssuedCertificateSerial()).as("no certificate is bound to an anomaly").isNull();

            RegistryEntry withdrawn = r.lookup("WITHDRAWN").orElseThrow();
            assertThat(withdrawn.getStatus()).isEqualTo(RegistryStatus.VERIFIED_NOT_ISSUED);
            assertThat(withdrawn.isCertificateReceived()).isFalse();
            assertThat(withdrawn.getActualPublicKeyFingerprint()).isNull();

            RegistryEntry despite = r.lookup("DESPITE").orElseThrow();
            assertThat(despite.getStatus()).isEqualTo(RegistryStatus.ANOMALY_ISSUED_DESPITE_REJECTION);
            assertThat(despite.getActualPublicKeyFingerprint()).isEqualTo("fp-4b");
            assertThat(despite.getIssuedCertificateSerial()).isNull();

            RegistryEntry refused = r.lookup("REFUSED").orElseThrow();
            assertThat(refused.getStatus()).isEqualTo(RegistryStatus.REJECTED_NOT_ISSUED);
            assertThat(refused.isCertificateReceived()).isFalse();

            assertThat(r.findAnomalies("SE")).extracting(RegistryEntry::getVerificationId)
                    .containsExactlyInAnyOrder("MISMATCH", "DESPITE");
            assertThat(r.findAwaitingConfirmation("SE")).isEmpty();
            assertThat(r.getStats("SE")).isEqualTo(new ApprovalRegistry.ComplianceStats(5, 1, 2, 20.0));
            assertThat(r.getStats("DE")).isEqualTo(new ApprovalRegistry.ComplianceStats(0, 0, 0, 0.0));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void aConfirmationIsSingleUseAndBoundToItsNonce(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        register(registry, "ID", true, "fp", "SE");

        assertThat(registry.confirm("UNKNOWN", "nonce-ID", true, "fp", true)).isEmpty();
        assertThatThrownBy(() -> registry.confirm("ID", "wrong", true, "fp", true))
                .isInstanceOf(ApprovalRegistry.NonceMismatchException.class);
        assertThatThrownBy(() -> registry.confirm("ID", null, true, "fp", true))
                .isInstanceOf(ApprovalRegistry.NonceMismatchException.class);
        assertThat(registry.lookup("ID").orElseThrow().getStatus()).as("a refused confirm changes nothing").isNull();

        assertThat(registry.confirm("ID", "nonce-ID", true, "fp", true)).isPresent();
        assertThatThrownBy(() -> registry.confirm("ID", "nonce-ID", true, "fp", true))
                .isInstanceOf(ApprovalRegistry.NonceMismatchException.class);
        ApprovalRegistry reopened = reopen(implementation, registry);
        assertThatThrownBy(() -> reopened.confirm("ID", "nonce-ID", true, "fp", true))
                .as("the spent nonce stays spent after a restart")
                .isInstanceOf(ApprovalRegistry.NonceMismatchException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void aFingerprintIsFoundByTheAttestedOrTheIssuedKeyAndPrefersACompliantEntry(String implementation)
            throws Exception {
        ApprovalRegistry registry = open(implementation);
        register(registry, "COMPLIANT", true, "fp-a", "SE");
        registry.confirm("COMPLIANT", "nonce-COMPLIANT", true, "fp-a", true);
        register(registry, "LATER-REJECTED", false, "fp-a", "SE");
        register(registry, "MISMATCH", true, "fp-b", "SE");
        registry.confirm("MISMATCH", "nonce-MISMATCH", true, "fp-c", false);

        for (ApprovalRegistry r : new ApprovalRegistry[] {registry, reopen(implementation, registry)}) {
            assertThat(r.findByPublicKeyFingerprint("fp-a")).get()
                    .extracting(RegistryEntry::getVerificationId).isEqualTo("COMPLIANT");
            assertThat(r.findByPublicKeyFingerprint("fp-c")).as("found by the key actually certified").get()
                    .extracting(RegistryEntry::getVerificationId).isEqualTo("MISMATCH");
            assertThat(r.findByPublicKeyFingerprint("fp-b")).get()
                    .extracting(RegistryEntry::getVerificationId).isEqualTo("MISMATCH");
            assertThat(r.findByPublicKeyFingerprint("fp-none")).isEmpty();
            assertThat(r.findByPublicKeyFingerprint(" ")).isEmpty();
            assertThat(r.findByPublicKeyFingerprint(null)).isEmpty();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void anIssuedCertificateIsFoundBySerialAndIssuer(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        register(registry, "ID", true, "fp", "SE");
        registry.confirm("ID", "nonce-ID", true, "fp", true, new IssuedCertificate("PEM", "0a1b", ISSUER));

        for (ApprovalRegistry r : new ApprovalRegistry[] {registry, reopen(implementation, registry)}) {
            assertThat(r.findByIssuedCertificate(new BigInteger("0a1b", 16), new X500Principal(ISSUER))).get()
                    .extracting(RegistryEntry::getVerificationId).isEqualTo("ID");
            assertThat(r.findByIssuedCertificate(new BigInteger("0a1c", 16), new X500Principal(ISSUER))).isEmpty();
            assertThat(r.findByIssuedCertificate(new BigInteger("0a1b", 16), new X500Principal("CN=Other"))).isEmpty();
        }
    }
}
