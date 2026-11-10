package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry.CertificateAlreadyRegisteredException;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry.IssuedCertificate;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry.RegistryEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An issued certificate is stored on one registry entry only.
 *
 * <p>Until 1.7.0 a second confirmation carrying a certificate that another
 * entry already stored created a second holder, and settlement and the
 * key-lifecycle events followed the more recent one. Repeating verification
 * and confirmation therefore brought a revoked certificate back, and a
 * second client could take a certificate's lifecycle over. Both registries
 * now refuse the second confirmation without any state transition; a journal
 * that already holds one certificate on two entries is read with a lifecycle
 * status outranking recency.</p>
 */
class ApprovalRegistryCertificateUniquenessTest {

    private static final String ISSUER = "CN=Swish Customer CA1 v2 for Swish,O=Getswish AB,C=SE";
    private static final X500Principal ISSUER_NAME = new X500Principal(ISSUER);

    @TempDir
    Path tempDir;

    private Path journal() {
        return tempDir.resolve("registry.jsonl");
    }

    private ApprovalRegistry open(String implementation) throws Exception {
        if (implementation.equals("memory")) {
            return new InMemoryApprovalRegistry();
        }
        AppendOnlyFileApprovalRegistry registry = new AppendOnlyFileApprovalRegistry(journal().toString());
        registry.initialise();
        return registry;
    }

    /** The file registry replayed from its journal; the in-memory one as it is. */
    private ApprovalRegistry reopen(String implementation, ApprovalRegistry current) throws Exception {
        return implementation.equals("memory") ? current : open(implementation);
    }

    private static void awaiting(ApprovalRegistry registry, String id, boolean compliant) {
        registry.register(id, "n-" + id, compliant, "fp-" + id, "5569743098", "Supplier AB", "SECUROSYS",
                "Primus HSM", "SE");
    }

    private static IssuedCertificate certificate(String serialHex, String issuerDn) {
        return new IssuedCertificate("PEM-" + serialHex, serialHex, issuerDn);
    }

    private static RegistryEntry confirm(ApprovalRegistry registry, String id, IssuedCertificate certificate) {
        return registry.confirm(id, "n-" + id, true, "fp-" + id, true, certificate).orElseThrow();
    }

    private static RegistryEntry issued(ApprovalRegistry registry, String id, String serialHex) {
        awaiting(registry, id, true);
        return confirm(registry, id, certificate(serialHex, ISSUER));
    }

    private static RegistryEntry holderOf(ApprovalRegistry registry, String serialHex) {
        return registry.findByIssuedCertificate(new BigInteger(serialHex, 16), ISSUER_NAME).orElseThrow();
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void aSecondConfirmationOfTheSameCertificateIsRefusedAndChangesNothing(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        issued(registry, "FIRST", "a1");
        awaiting(registry, "SECOND", true);

        // The same certificate, its serial and issuer written differently.
        IssuedCertificate same = certificate("00A1", "CN=Swish Customer CA1 v2 for Swish, O=Getswish AB, C=SE");
        assertThatThrownBy(() -> confirm(registry, "SECOND", same))
                .isInstanceOf(CertificateAlreadyRegisteredException.class)
                .hasMessageContaining("verificationId=SECOND")
                .hasMessageContaining("already registered under verificationId=FIRST");

        ApprovalRegistry replayed = reopen(implementation, registry);
        RegistryEntry second = replayed.lookup("SECOND").orElseThrow();
        assertThat(second.getStatus()).isNull();
        assertThat(second.getConfirmationTimestamp()).isNull();
        assertThat(second.getIssuedCertificateSerial()).isNull();
        assertThat(second.getIssuedCertificatePem()).isNull();
        assertThat(second.getConfirmationNonce()).as("the nonce is unspent").isEqualTo("n-SECOND");
        assertThat(holderOf(replayed, "a1").getVerificationId()).isEqualTo("FIRST");

        // A refusal is not a state transition: the entry is still confirmable,
        // and another certificate is stored as before.
        assertThat(confirm(replayed, "SECOND", certificate("b2", ISSUER)).getStatus())
                .isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(holderOf(reopen(implementation, replayed), "b2").getVerificationId()).isEqualTo("SECOND");
    }

    @Test
    void aRefusedConfirmationIsNotJournalled() throws Exception {
        ApprovalRegistry registry = open("file");
        issued(registry, "FIRST", "a1");
        awaiting(registry, "SECOND", true);
        long before = Files.size(journal());

        assertThatThrownBy(() -> confirm(registry, "SECOND", certificate("a1", ISSUER)))
                .isInstanceOf(CertificateAlreadyRegisteredException.class);

        assertThat(Files.size(journal())).isEqualTo(before);
    }

    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void aLifecycleEventOnTheHolderStaysInForce(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        issued(registry, "ORIGINAL", "a1");
        assertThat(registry.changeStatus("ORIGINAL", RegistryStatus.REVOKED, "key compromise", null).isApplied())
                .isTrue();
        awaiting(registry, "AGAIN", true);

        assertThatThrownBy(() -> confirm(registry, "AGAIN", certificate("a1", ISSUER)))
                .isInstanceOf(CertificateAlreadyRegisteredException.class);

        RegistryEntry holder = holderOf(reopen(implementation, registry), "a1");
        assertThat(holder.getVerificationId()).isEqualTo("ORIGINAL");
        assertThat(holder.getStatus()).isEqualTo(RegistryStatus.REVOKED);
    }

    /**
     * Only a confirmation that ends in {@code VERIFIED_AND_ISSUED} stores the
     * certificate, so only that one can be refused. The others are recorded
     * with the outcome they had before; refusing them would hide the anomaly.
     */
    @ParameterizedTest
    @ValueSource(strings = {"memory", "file"})
    void aConfirmationThatStoresNoCertificateIsRecordedAsBefore(String implementation) throws Exception {
        ApprovalRegistry registry = open(implementation);
        issued(registry, "HOLDER", "a1");
        IssuedCertificate held = certificate("a1", ISSUER);

        awaiting(registry, "REJECTED", false);
        assertThat(registry.confirm("REJECTED", "n-REJECTED", true, "fp", true, held).orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.ANOMALY_ISSUED_DESPITE_REJECTION);
        awaiting(registry, "MISMATCH", true);
        assertThat(registry.confirm("MISMATCH", "n-MISMATCH", true, "fp", false, held).orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
        awaiting(registry, "NOT-ISSUED", true);
        assertThat(registry.confirm("NOT-ISSUED", "n-NOT-ISSUED", false, null, true, held).orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.VERIFIED_NOT_ISSUED);
        awaiting(registry, "NO-CERTIFICATE", true);
        assertThat(registry.confirm("NO-CERTIFICATE", "n-NO-CERTIFICATE", true, "fp", true, null).orElseThrow()
                .getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);

        ApprovalRegistry replayed = reopen(implementation, registry);
        assertThat(holderOf(replayed, "a1").getVerificationId()).isEqualTo("HOLDER");
        for (String id : new String[] {"REJECTED", "MISMATCH", "NOT-ISSUED", "NO-CERTIFICATE"}) {
            assertThat(replayed.lookup(id).orElseThrow().getIssuedCertificateSerial()).as(id).isNull();
        }
    }

    static Stream<Arguments> identifiersThatMatchNoLookup() {
        return Stream.of("memory", "file").flatMap(implementation -> Stream.of(
                Arguments.of(implementation, null, ISSUER),
                Arguments.of(implementation, "a1", null),
                Arguments.of(implementation, "not-hex", ISSUER),
                Arguments.of(implementation, "a1", "not a distinguished name")));
    }

    /**
     * A serial or issuer that is absent or does not parse matches no lookup,
     * so no entry can hold such a certificate and nothing is refused. The
     * verification service never produces one: it takes both from the parsed
     * certificate.
     */
    @ParameterizedTest
    @MethodSource("identifiersThatMatchNoLookup")
    void aCertificateIdentifierThatMatchesNoLookupIsNotRefused(String implementation, String serialHex,
                                                               String issuerDn) throws Exception {
        ApprovalRegistry registry = open(implementation);
        issued(registry, "HOLDER", "a1");
        IssuedCertificate unusable = new IssuedCertificate("PEM", serialHex, issuerDn);
        awaiting(registry, "ONE", true);
        awaiting(registry, "TWO", true);

        assertThat(confirm(registry, "ONE", unusable).getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(confirm(registry, "TWO", unusable).getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(holderOf(registry, "a1").getVerificationId()).isEqualTo("HOLDER");
    }

    /**
     * A journal written by 1.7.0 or earlier in which the certificate of a
     * revoked entry was confirmed again on a later entry. Built by writing
     * two certificates through the registry and giving the later one the
     * earlier one's serial in the journal.
     */
    private ApprovalRegistry legacyJournalWithTwoHolders(RegistryStatus statusOfTheEarlier) throws Exception {
        ApprovalRegistry writer = open("file");
        issued(writer, "EARLIER", "a1");
        Thread.sleep(5);
        issued(writer, "LATER", "b2");
        if (statusOfTheEarlier != RegistryStatus.VERIFIED_AND_ISSUED) {
            assertThat(writer.changeStatus("EARLIER", statusOfTheEarlier, "reported", null).isApplied()).isTrue();
        }
        String written = Files.readString(journal());
        String rewritten = written.replace("\"issuedCertificateSerial\":\"b2\"", "\"issuedCertificateSerial\":\"a1\"");
        assertThat(rewritten).isNotEqualTo(written);
        Files.writeString(journal(), rewritten);

        ApprovalRegistry legacy = open("file");
        assertThat(legacy.lookup("EARLIER").orElseThrow().getIssuedCertificateSerial()).isEqualTo("a1");
        assertThat(legacy.lookup("LATER").orElseThrow().getIssuedCertificateSerial()).isEqualTo("a1");
        return legacy;
    }

    @ParameterizedTest
    @ValueSource(strings = {"SUPERSEDED", "REVOKED", "DECOMMISSIONED"})
    void inAnEarlierJournalALifecycleStatusOutranksALaterConfirmation(RegistryStatus status) throws Exception {
        RegistryEntry followed = holderOf(legacyJournalWithTwoHolders(status), "a1");

        assertThat(followed.getVerificationId()).isEqualTo("EARLIER");
        assertThat(followed.getStatus()).isEqualTo(status);
    }

    @Test
    void inAnEarlierJournalTheMoreRecentOfTwoIssuedHoldersIsFollowedAsBefore() throws Exception {
        RegistryEntry followed = holderOf(legacyJournalWithTwoHolders(RegistryStatus.VERIFIED_AND_ISSUED), "a1");

        assertThat(followed.getVerificationId()).isEqualTo("LATER");
        assertThat(followed.getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
    }

    @Test
    void anEarlierJournalAcceptsNoThirdHolder() throws Exception {
        ApprovalRegistry legacy = legacyJournalWithTwoHolders(RegistryStatus.REVOKED);
        awaiting(legacy, "THIRD", true);

        assertThatThrownBy(() -> confirm(legacy, "THIRD", certificate("a1", ISSUER)))
                .isInstanceOf(CertificateAlreadyRegisteredException.class);
    }
}
