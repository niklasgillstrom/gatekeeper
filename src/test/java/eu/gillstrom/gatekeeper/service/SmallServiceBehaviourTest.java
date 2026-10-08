package eu.gillstrom.gatekeeper.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry.RegistryEntry;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

/** Journal replay, registry defaults, the key directory, the issuer-CA bundle and the vendor names. */
class SmallServiceBehaviourTest {

    @TempDir
    Path tempDir;

    private static ListAppender<ILoggingEvent> capture(Class<?> type) {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        ((Logger) LoggerFactory.getLogger(type)).addAppender(appender);
        return appender;
    }

    private static void release(Class<?> type, ListAppender<ILoggingEvent> appender) {
        ((Logger) LoggerFactory.getLogger(type)).detachAppender(appender);
    }

    @Test
    void aNewJournalIsCreatedWithItsDirectoriesAnd0640() throws Exception {
        Path journal = tempDir.resolve("a/b/registry.jsonl");
        new AppendOnlyFileApprovalRegistry(journal.toString()).initialise();

        assertThat(Files.exists(journal)).isTrue();
        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(journal))).isEqualTo("rw-r-----");
    }

    @Test
    void replayCountsRegistersConfirmsAndSkippedLines() throws Exception {
        Path journal = tempDir.resolve("replay.jsonl");
        AppendOnlyFileApprovalRegistry first = new AppendOnlyFileApprovalRegistry(journal.toString());
        first.initialise();
        first.register("A", "nonce-A", true, "fp-a", "5569743098", "Supplier AB", "SECUROSYS", "Primus HSM", "SE");
        first.register("B", "nonce-B", true, "fp-b", "5569743098", "Supplier AB", "SECUROSYS", "Primus HSM", "SE");
        first.confirm("A", "nonce-A", true, "fp-a", true);
        Files.writeString(journal, String.join("\n",
                "{\"op\":\"CONFIRM\",\"verificationId\":\"UNKNOWN\",\"issued\":true}",
                "{\"op\":\"SOMETHING_ELSE\"}",
                "not json",
                "",
                ""), StandardCharsets.UTF_8, StandardOpenOption.APPEND);

        ListAppender<ILoggingEvent> appender = capture(AppendOnlyFileApprovalRegistry.class);
        try {
            AppendOnlyFileApprovalRegistry replayed = new AppendOnlyFileApprovalRegistry(journal.toString());
            replayed.initialise();

            assertThat(appender.list).anySatisfy(e -> assertThat(e.getFormattedMessage())
                    .startsWith("AppendOnlyFileApprovalRegistry initialised: replayed 2 REGISTER + 1 CONFIRM ops")
                    .endsWith("(2 entries in index, 3 skipped)"));
            assertThat(replayed.lookup("A").orElseThrow().getStatus()).isNotNull();
            assertThat(replayed.lookup("B").orElseThrow().getStatus()).isNull();
        } finally {
            release(AppendOnlyFileApprovalRegistry.class, appender);
        }
    }

    @Test
    void theDefaultRegisterOverloadsDelegateWithEveryArgument() {
        ApprovalRegistry registry = mock(ApprovalRegistry.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        RegistryEntry entry = RegistryEntry.builder().verificationId("V").build();
        when(registry.register(anyString(), anyString(), anyBoolean(), anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString())).thenReturn(entry);
        ApprovalRegistry.Parties parties = ApprovalRegistry.Parties.supplierOnly("5569743098", "Supplier AB");

        assertThat(registry.register("V", "n", true, "fp", parties, "Securosys", "Primus HSM", "SE", "CN=FE"))
                .isSameAs(entry);
        assertThat(registry.register("V", "n", true, "fp", parties, null, "Securosys", "Primus HSM", "SE", "CN=FE"))
                .isSameAs(entry);
        verify(registry, org.mockito.Mockito.times(2)).register(eq("V"), eq("n"), eq(true), eq("fp"),
                eq("5569743098"), eq("Supplier AB"), eq("Securosys"), eq("Primus HSM"), eq("SE"), eq("CN=FE"));
    }

    @Test
    void anIssuedCertificateSerialThatIsNotHexMatchesNothing() {
        RegistryEntry entry = RegistryEntry.builder()
                .issuedCertificateSerial("not-hex")
                .issuedCertificateIssuerDn("CN=Issuer")
                .build();

        assertThat(ApprovalRegistry.issuedCertificateMatches(entry, BigInteger.ONE, new X500Principal("CN=Issuer")))
                .isFalse();
    }

    @Test
    void theKeyDirectoryFindsActiveAndRetiredKeysByFingerprint() throws Exception {
        EphemeralReceiptSigner active = new EphemeralReceiptSigner(2048);
        EphemeralReceiptSigner retired = new EphemeralReceiptSigner(2048);
        GatekeeperKeyDirectory directory = new GatekeeperKeyDirectory(active, retired.getSigningCertificatePem());
        assertThat(directory.activeFingerprintHex()).as("before initialisation").isEmpty();
        directory.initialise();

        String activeFingerprint = directory.activeFingerprintHex();
        assertThat(activeFingerprint).hasSize(64).matches("[0-9a-f]+");
        assertThat(directory.findByFingerprint(activeFingerprint)).get()
                .extracting(GatekeeperKeyDirectory.KeyEntry::status).isEqualTo("ACTIVE");
        String retiredFingerprint = directory.allKeys().get(1).publicKeyFingerprintHex();
        assertThat(directory.findByFingerprint(retiredFingerprint)).get()
                .extracting(GatekeeperKeyDirectory.KeyEntry::status).isEqualTo("RETIRED");
        assertThat(directory.findByFingerprint("00".repeat(32))).isEmpty();
        assertThat(directory.findByFingerprint(" ")).isEmpty();
        assertThat(directory.findByFingerprint(null)).isEmpty();
    }

    @Test
    void aBundleCertificateWhoseSignatureDoesNotVerifyUnderItsNamedIssuerIsAnAnchor() throws Exception {
        KeyPair rootKey = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKey, "Bundle Root");
        X509Certificate genuine = TestPki.subordinateCa(TestPki.newRsaKeyPair(2048), "Genuine Intermediate",
                root, rootKey.getPrivate());
        // Names "Bundle Root" as issuer but is signed by another key.
        X509Certificate impostor = TestPki.subordinateCa(TestPki.newRsaKeyPair(2048), "Impostor",
                TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), "Bundle Root"),
                TestPki.newRsaKeyPair(2048).getPrivate());
        Path bundle = tempDir.resolve("bundle.pem");
        Files.writeString(bundle, TestPki.toPem(root) + TestPki.toPem(genuine) + TestPki.toPem(impostor));

        IssuerCaValidator validator = new IssuerCaValidator(bundle.toString());

        assertThat(validator.trustAnchorCount()).as("root and impostor; the genuine one is an intermediate")
                .isEqualTo(2);
    }

    @Test
    void aBundleOfTwoCertificatesIssuingEachOtherHasNoAnchorAndSaysSo() throws Exception {
        KeyPair a = TestPki.newRsaKeyPair(2048);
        KeyPair b = TestPki.newRsaKeyPair(2048);
        X509Certificate certA = TestPki.subordinateCa(a, "Loop A", TestPki.selfSignedCa(b, "Loop B"), b.getPrivate());
        X509Certificate certB = TestPki.subordinateCa(b, "Loop B", certA, a.getPrivate());
        Path bundle = tempDir.resolve("loop.pem");
        Files.writeString(bundle, TestPki.toPem(certA) + TestPki.toPem(certB));
        ListAppender<ILoggingEvent> appender = capture(IssuerCaValidator.class);
        try {
            IssuerCaValidator validator = new IssuerCaValidator(bundle.toString());

            assertThat(validator.trustAnchorCount()).isZero();
            assertThat(appender.list).anySatisfy(e -> assertThat(e.getFormattedMessage())
                    .startsWith("IssuerCaValidator constructed with an EMPTY trust-anchor set"));
            assertThat(validator.validateChain(List.of(certA, certB))).as("no anchor, no valid chain").isFalse();
        } finally {
            release(IssuerCaValidator.class, appender);
        }
    }

    @Test
    void aNonEmptyBundleReportsItsAnchorsAndNotTheEmptyWarning() throws Exception {
        Path bundle = tempDir.resolve("one.pem");
        Files.writeString(bundle, TestPki.toPem(TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), "Root")));
        ListAppender<ILoggingEvent> appender = capture(IssuerCaValidator.class);
        try {
            new IssuerCaValidator(bundle.toString());
            assertThat(appender.list).noneSatisfy(e -> assertThat(e.getFormattedMessage()).contains("EMPTY"));
        } finally {
            release(IssuerCaValidator.class, appender);
        }
    }

    @Test
    void anRsaKeyIsDescribedByItsAlgorithmIdentifier() throws Exception {
        assertThat(KeyPolicy.describeKey(java.security.KeyPairGenerator.getInstance("DSA").generateKeyPair().getPublic()))
                .isEqualTo("1.2.840.10040.4.1");
    }

    @Test
    void everyVendorHasItsNames() {
        assertThat(HsmVendor.SECUROSYS.getVendorName()).isEqualTo("Securosys");
        assertThat(HsmVendor.SECUROSYS.getProductName()).isEqualTo("Primus HSM");
        assertThat(HsmVendor.ENTRUST.getVendorName()).isEqualTo("Entrust");
        assertThat(HsmVendor.ENTRUST.getProductName()).isEqualTo("nShield");
    }
}
