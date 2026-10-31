package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link ConfiguredReceiptSigner} with a key that is only reachable through a
 * JCA provider ({@link TestHsmProvider}): keystore type, provider class,
 * provider configuration, a keystore without a file, and the fail-closed
 * refusals.
 */
class ConfiguredReceiptSignerHsmTest {

    @TempDir
    Path tempDir;

    @BeforeEach
    void freshDevice() throws Exception {
        TestHsmProvider.reset("1234");
    }

    @AfterEach
    void unregister() {
        for (Provider p : Security.getProviders()) {
            if (p.getName().startsWith(TestHsmProvider.BASE_NAME)) {
                Security.removeProvider(p.getName());
            }
        }
    }

    private Path config(String name, String pin) throws Exception {
        Path cfg = tempDir.resolve(name + ".cfg");
        Files.writeString(cfg, "name=" + name + "\npin=" + pin + "\n", StandardCharsets.UTF_8);
        return cfg;
    }

    private static ConfiguredReceiptSigner hsmSigner(String keystorePath, String pin, String providerClass,
                                                     String providerConfig) {
        return new ConfiguredReceiptSigner(keystorePath, pin, TestHsmProvider.ALIAS, pin, "SHA256withRSA",
                TestHsmProvider.KEYSTORE_TYPE, providerClass, providerConfig);
    }

    private static boolean verifies(ConfiguredReceiptSigner signer, byte[] data, byte[] sig) throws Exception {
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(signer.getSigningCertificatePem().getBytes(StandardCharsets.UTF_8)));
        Signature v = Signature.getInstance("SHA256withRSA");
        v.initVerify(cert.getPublicKey());
        v.update(data);
        return v.verify(sig);
    }

    @Test
    void aKeyHeldByAProviderSignsWithoutAKeystoreFileAndItsSignatureVerifies() throws Exception {
        Path cfg = config("slot7", "4711");

        ConfiguredReceiptSigner signer = hsmSigner("", "4711", TestHsmProvider.class.getName(), cfg.toString());

        assertThat(TestHsmProvider.lastConfigArg).as("Provider.configure got the config path").isEqualTo(cfg.toString());
        assertThat(signer.getProvider().getName()).isEqualTo("GatekeeperTestHSM-slot7");
        assertThat(Security.getProvider("GatekeeperTestHSM-slot7")).as("registered").isNotNull();
        assertThat(signer.getKeystoreType()).isEqualTo(TestHsmProvider.KEYSTORE_TYPE);
        assertThat(signer.getSigningCertificatePem())
                .isEqualTo(TestPki.toPem(TestHsmProvider.certificate));

        byte[] data = "receipt bytes".getBytes(StandardCharsets.UTF_8);
        assertThat(verifies(signer, data, signer.sign(data))).isTrue();
    }

    @Test
    void aProviderWithoutConfigurationIsUsedAsInstantiated() throws Exception {
        ConfiguredReceiptSigner signer = hsmSigner(null, "1234", TestHsmProvider.class.getName(), null);

        assertThat(signer.getProvider().getName()).isEqualTo(TestHsmProvider.BASE_NAME);
        byte[] data = {1, 2, 3};
        assertThat(verifies(signer, data, signer.sign(data))).isTrue();
    }

    @Test
    void theAuditLogChainsAndVerifiesUnderTheHsmKey() throws Exception {
        ConfiguredReceiptSigner signer = hsmSigner("", "1234", TestHsmProvider.class.getName(), null);
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(tempDir.resolve("a.jsonl").toString(), signer);
        log.initialise();
        log.append(new AuditAppendRequest("CN=x", "VERIFY", "v-1", "cmVx", null, true));
        log.append(new AuditAppendRequest("CN=x", "VERIFY", "v-2", "cmVx", null, true));

        assertThat(log.verifyChainIntegrity()).isTrue();
    }

    @Test
    void aWrongPinFailsStartUp() throws Exception {
        assertThatThrownBy(() -> hsmSigner("", "0000", TestHsmProvider.class.getName(), null))
                .isInstanceOf(IllegalStateException.class)
                .hasRootCauseMessage("CKR_PIN_INCORRECT");
    }

    @Test
    void anUnknownProviderClassFailsStartUp() {
        assertThatThrownBy(() -> hsmSigner("", "1234", "com.example.NoSuchProvider", null))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("was not found");
    }

    @Test
    void aClassThatIsNotAProviderFailsStartUp() {
        assertThatThrownBy(() -> hsmSigner("", "1234", NotAProvider.class.getName(), null))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("is not a java.security.Provider");
    }

    @Test
    void aProviderConfigWithoutAProviderClassFailsStartUp() throws Exception {
        Path cfg = config("x", "1234");
        assertThatThrownBy(() -> hsmSigner("", "1234", "", cfg.toString()))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("provider-config is set but");
    }

    @Test
    void aConfigurationTheProviderRejectsFailsStartUp() {
        assertThatThrownBy(() -> hsmSigner("", "1234", TestHsmProvider.class.getName(),
                tempDir.resolve("missing.cfg").toString()))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("could not be configured");
    }

    @Test
    void aProviderThatDoesNotSupportConfigureFailsStartUp() throws Exception {
        // BouncyCastle's provider does not implement Provider.configure().
        Path cfg = config("x", "1234");
        assertThatThrownBy(() -> new ConfiguredReceiptSigner("", "1234", "a", "1234", "SHA256withRSA",
                "PKCS12", org.bouncycastle.jce.provider.BouncyCastleProvider.class.getName(), cfg.toString()))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("could not be configured");
    }

    @Test
    void aFileKeystoreTypeWithoutAPathFailsStartUp() {
        assertThatThrownBy(() -> new ConfiguredReceiptSigner("", "pw", "seal", "pw", "SHA256withRSA",
                "PKCS12", null, null))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("keystore-path is required for keystore-type PKCS12");
    }

    @Test
    void anUnknownKeystoreTypeFailsStartUp() {
        assertThatThrownBy(() -> new ConfiguredReceiptSigner("", "pw", "seal", "pw", "SHA256withRSA",
                "NO-SUCH-TYPE", null, null))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("NO-SUCH-TYPE");
    }

    @Test
    void anAliasWithoutAKeyFailsStartUp() {
        assertThatThrownBy(() -> new ConfiguredReceiptSigner("", "1234", "other-alias", "1234", "SHA256withRSA",
                TestHsmProvider.KEYSTORE_TYPE, TestHsmProvider.class.getName(), null))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("is not a key entry");
    }

    @Test
    void aCertificateThatDoesNotBelongToTheKeyFailsTheStartUpSelfTest() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate foreign = TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), "Not the seal");
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("seal", kp.getPrivate(), "pw".toCharArray(), new Certificate[] {foreign});
        Path keystore = tempDir.resolve("mismatch.p12");
        try (OutputStream out = Files.newOutputStream(keystore)) {
            store.store(out, "pw".toCharArray());
        }

        assertThatThrownBy(() -> new ConfiguredReceiptSigner(keystore.toString(), "pw", "seal", "pw",
                "SHA256withRSA"))
                .isInstanceOf(IllegalStateException.class)
                .hasStackTraceContaining("self-test failed");
    }
}
