package eu.gillstrom.gatekeeper.signing;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.gatekeeper.testsupport.TestKeystores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link ConfiguredReceiptSigner} with providers and keystores beyond the
 * test HSM: a keystore that reports its certificate only as a certificate,
 * a provider that offers no {@code Signature}, a provider found through
 * {@link java.util.ServiceLoader}, and what the start-up line names.
 */
class ConfiguredReceiptSignerProviderTest {

    @TempDir
    Path tempDir;

    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() throws Exception {
        SoftKeyStoreProvider.reset(SoftKeyStoreProvider.Certificates.CHAIN);
        TestHsmProvider.reset("1234");
        logs = new ListAppender<>();
        logs.start();
        ((Logger) LoggerFactory.getLogger(ConfiguredReceiptSigner.class)).addAppender(logs);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(ConfiguredReceiptSigner.class)).detachAppender(logs);
        for (Provider p : Security.getProviders()) {
            if (p.getName().startsWith(SoftKeyStoreProvider.NAME) || p.getName().startsWith(TestHsmProvider.BASE_NAME)) {
                Security.removeProvider(p.getName());
            }
        }
    }

    private static ConfiguredReceiptSigner softSigner() {
        return new ConfiguredReceiptSigner("", "pin", SoftKeyStoreProvider.ALIAS, "pin", "SHA256withRSA",
                SoftKeyStoreProvider.KEYSTORE_TYPE, SoftKeyStoreProvider.class.getName(), "");
    }

    private static boolean verifies(ConfiguredReceiptSigner signer, byte[] data) throws Exception {
        Signature v = Signature.getInstance("SHA256withRSA");
        v.initVerify(SoftKeyStoreProvider.certificate.getPublicKey());
        v.update(data);
        return v.verify(signer.sign(data));
    }

    @Test
    void aProviderWithoutTheSignatureAlgorithmSignsThroughTheDefaultProviders() throws Exception {
        ConfiguredReceiptSigner signer = softSigner();
        assertThat(verifies(signer, "receipt".getBytes(StandardCharsets.UTF_8))).isTrue();
    }

    @Test
    void aCertificateReportedWithoutAChainIsUsedAsTheChain() throws Exception {
        for (SoftKeyStoreProvider.Certificates mode : new SoftKeyStoreProvider.Certificates[] {
                SoftKeyStoreProvider.Certificates.NULL_CHAIN_AND_CERTIFICATE,
                SoftKeyStoreProvider.Certificates.EMPTY_CHAIN_AND_CERTIFICATE}) {
            SoftKeyStoreProvider.reset(mode);
            ConfiguredReceiptSigner signer = softSigner();
            assertThat(signer.getSigningCertificatePem()).as(mode.name()).contains("BEGIN CERTIFICATE");
            assertThat(verifies(signer, "receipt".getBytes(StandardCharsets.UTF_8))).as(mode.name()).isTrue();
        }

        SoftKeyStoreProvider.reset(SoftKeyStoreProvider.Certificates.NONE);
        assertThatThrownBy(ConfiguredReceiptSignerProviderTest::softSigner)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Failed to initialise ConfiguredReceiptSigner from keystore type SOFTKS")
                .hasRootCauseMessage("Keystore alias 'log-seal' has no certificate chain");
    }

    @Test
    void failuresAndTheStartUpLineNameTheKeystoreFileOrTypeAndTheProvider() throws Exception {
        TestKeystores.Written written = TestKeystores.pkcs12(tempDir, "seal", "Seal", "secret");
        assertThatThrownBy(() -> new ConfiguredReceiptSigner(written.path().toString(), "secret", "other", "secret",
                "SHA256withRSA"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Failed to initialise ConfiguredReceiptSigner from " + written.path());

        new ConfiguredReceiptSigner(written.path().toString(), "secret", "seal", "secret", "SHA256withRSA");
        softSigner();
        assertThat(logs.list).filteredOn(e -> e.getLevel() == Level.INFO)
                .map(ILoggingEvent::getFormattedMessage)
                .filteredOn(m -> m.startsWith("ConfiguredReceiptSigner initialised"))
                .satisfiesExactly(
                        m -> assertThat(m).contains("keystore-type='PKCS12', provider='(default providers)'")
                                .endsWith("private-key encoding visible to the JVM=true"),
                        m -> assertThat(m).contains("keystore-type='SOFTKS', provider='" + SoftKeyStoreProvider.NAME + "'"));
    }

    @Test
    void aProviderDeclaredForTheServiceLoaderIsTakenFromIt() throws Exception {
        Path services = tempDir.resolve("META-INF").resolve("services");
        Files.createDirectories(services);
        Files.writeString(services.resolve("java.security.Provider"), SoftKeyStoreProvider.class.getName() + "\n",
                StandardCharsets.UTF_8);
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        try (URLClassLoader loader = new URLClassLoader(new URL[] {tempDir.toUri().toURL()}, previous)) {
            Thread.currentThread().setContextClassLoader(loader);
            Provider p = ConfiguredReceiptSigner.loadProvider(SoftKeyStoreProvider.class.getName(), null);
            assertThat(p).isInstanceOf(SoftKeyStoreProvider.class);
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }

    @Test
    void withoutAContextClassLoaderTheProviderClassIsLoadedByTheSignersOwnLoader() {
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(null);
            assertThat(ConfiguredReceiptSigner.loadProvider(TestHsmProvider.class.getName(), null))
                    .isInstanceOf(TestHsmProvider.class);
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }
}
