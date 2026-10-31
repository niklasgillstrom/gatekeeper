package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Test-only JCA provider that behaves like an HSM provider as far as
 * {@link ConfiguredReceiptSigner} can tell: a {@code KeyStore} of type
 * {@value #KEYSTORE_TYPE} that must be loaded with a {@code null} stream and
 * the right PIN, a private key that is only a handle ({@code getEncoded()}
 * returns {@code null}), and a {@code SHA256withRSA} signature that accepts
 * only that handle. The key material stays in this class's static state —
 * "inside the device".
 *
 * <p>{@link #configure(String)} reads a properties file ({@code name},
 * {@code pin}) the way SunPKCS11 reads its config, and returns a new,
 * configured instance named {@code GatekeeperTestHSM-<name>}.</p>
 */
public final class TestHsmProvider extends Provider {

    public static final String BASE_NAME = "GatekeeperTestHSM";
    public static final String KEYSTORE_TYPE = "TESTHSM";
    public static final String ALIAS = "log-seal";

    static volatile KeyPair keyPair;
    static volatile X509Certificate certificate;
    static volatile String requiredPin = "1234";
    static volatile String lastConfigArg;

    public TestHsmProvider() {
        this(BASE_NAME);
    }

    private TestHsmProvider(String name) {
        super(name, "1.0", "gatekeeper test HSM provider");
        putService(new Service(this, "KeyStore", KEYSTORE_TYPE, TestHsmKeyStoreSpi.class.getName(), null, null));
        putService(new Service(this, "Signature", "SHA256withRSA", TestHsmSignatureSpi.class.getName(), null, null));
    }

    /** Fresh key "generated in the device" and a self-signed certificate for it. */
    public static synchronized void reset(String pin) throws Exception {
        keyPair = TestPki.newRsaKeyPair(2048);
        certificate = TestPki.selfSignedCa(keyPair, "NCA Log Seal (test HSM)");
        requiredPin = pin;
        lastConfigArg = null;
    }

    @Override
    public Provider configure(String configArg) {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(Paths.get(configArg))) {
            p.load(in);
        } catch (IOException e) {
            throw new InvalidParameterException("cannot read test HSM config " + configArg + ": " + e);
        }
        lastConfigArg = configArg;
        if (p.getProperty("pin") != null) {
            requiredPin = p.getProperty("pin");
        }
        return new TestHsmProvider(BASE_NAME + "-" + p.getProperty("name", "slot0"));
    }

    /** A key handle; the material is never encoded. */
    public static final class HandleKey implements PrivateKey {
        @Override
        public String getAlgorithm() {
            return "RSA";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

    public static final class TestHsmKeyStoreSpi extends KeyStoreSpi {
        private boolean loaded;

        @Override
        public void engineLoad(InputStream stream, char[] password) throws IOException {
            if (stream != null) {
                throw new IOException("the test HSM keystore is not a file; load it with a null stream");
            }
            if (password == null || !requiredPin.equals(new String(password))) {
                throw new IOException("CKR_PIN_INCORRECT");
            }
            loaded = true;
        }

        private void requireLoaded() {
            if (!loaded) {
                throw new IllegalStateException("not logged in");
            }
        }

        @Override
        public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
            requireLoaded();
            return ALIAS.equals(alias) ? new HandleKey() : null;
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            requireLoaded();
            return ALIAS.equals(alias) ? new Certificate[] {certificate} : null;
        }

        @Override
        public Certificate engineGetCertificate(String alias) {
            requireLoaded();
            return ALIAS.equals(alias) ? certificate : null;
        }

        @Override
        public Date engineGetCreationDate(String alias) {
            return null;
        }

        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineSetCertificateEntry(String alias, Certificate cert) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineDeleteEntry(String alias) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Enumeration<String> engineAliases() {
            return Collections.enumeration(java.util.List.of(ALIAS));
        }

        @Override
        public boolean engineContainsAlias(String alias) {
            return ALIAS.equals(alias);
        }

        @Override
        public int engineSize() {
            return 1;
        }

        @Override
        public boolean engineIsKeyEntry(String alias) {
            return ALIAS.equals(alias);
        }

        @Override
        public boolean engineIsCertificateEntry(String alias) {
            return false;
        }

        @Override
        public String engineGetCertificateAlias(Certificate cert) {
            return certificate.equals(cert) ? ALIAS : null;
        }

        @Override
        public void engineStore(OutputStream stream, char[] password) {
            throw new UnsupportedOperationException();
        }
    }

    /** Signs with the device key; accepts only a {@link HandleKey}. Sign-only. */
    public static final class TestHsmSignatureSpi extends SignatureSpi {
        private Signature delegate;

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            throw new InvalidKeyException("the test HSM only signs");
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            if (!(privateKey instanceof HandleKey)) {
                throw new InvalidKeyException("not a test HSM key handle");
            }
            try {
                delegate = Signature.getInstance("SHA256withRSA", "SunRsaSign");
                delegate.initSign(keyPair.getPrivate());
            } catch (Exception e) {
                throw new InvalidKeyException(e);
            }
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            delegate.update(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            delegate.update(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            return delegate.sign();
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            throw new SignatureException("the test HSM only signs");
        }

        @Override
        @Deprecated
        protected void engineSetParameter(String param, Object value) {
            throw new InvalidParameterException();
        }

        @Override
        @Deprecated
        protected Object engineGetParameter(String param) {
            throw new InvalidParameterException();
        }
    }
}
