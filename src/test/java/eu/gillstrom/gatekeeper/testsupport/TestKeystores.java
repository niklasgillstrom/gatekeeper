package eu.gillstrom.gatekeeper.testsupport;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Writes throwaway PKCS#12 keystores, so that a profile configured with
 * {@code gatekeeper.signing.mode=configured} can be started in a test with
 * a real {@code ConfiguredReceiptSigner}.
 */
public final class TestKeystores {

    private TestKeystores() {
    }

    /** A keystore at {@code dir/<alias>.p12} holding one RSA-2048 key and a self-signed certificate. */
    public static Written pkcs12(Path dir, String alias, String commonName, String password) throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate certificate = TestPki.selfSignedCa(kp, commonName);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), new Certificate[] {certificate});
        Path path = dir.resolve(alias + ".p12");
        try (OutputStream out = Files.newOutputStream(path)) {
            ks.store(out, password.toCharArray());
        }
        return new Written(path, certificate);
    }

    public record Written(Path path, X509Certificate certificate) {
    }
}
