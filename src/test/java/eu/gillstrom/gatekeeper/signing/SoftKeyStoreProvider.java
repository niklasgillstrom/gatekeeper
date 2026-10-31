package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

/**
 * A test provider that offers a {@code KeyStore} holding a software RSA key
 * and no {@code Signature}, so signatures fall back to the default providers;
 * and whose keystore can report its certificate in several ways.
 */
public final class SoftKeyStoreProvider extends Provider {

    public static final String NAME = "GatekeeperSoftKeyStore";
    public static final String KEYSTORE_TYPE = "SOFTKS";
    public static final String ALIAS = "log-seal";

    /** How the keystore answers getCertificateChain and getCertificate. */
    public enum Certificates { CHAIN, NULL_CHAIN_AND_CERTIFICATE, EMPTY_CHAIN_AND_CERTIFICATE, NONE }

    static volatile KeyPair keyPair;
    static volatile X509Certificate certificate;
    static volatile Certificates certificates = Certificates.CHAIN;

    public SoftKeyStoreProvider() {
        super(NAME, "1.0", "gatekeeper test keystore without a Signature service");
        putService(new Service(this, "KeyStore", KEYSTORE_TYPE, SoftKeyStoreSpi.class.getName(), null, null));
    }

    public static synchronized void reset(Certificates mode) throws Exception {
        keyPair = TestPki.newRsaKeyPair(2048);
        certificate = TestPki.selfSignedCa(keyPair, "NCA Log Seal (soft keystore)");
        certificates = mode;
    }

    public static final class SoftKeyStoreSpi extends KeyStoreSpi {

        @Override
        public void engineLoad(InputStream stream, char[] password) {
        }

        @Override
        public Key engineGetKey(String alias, char[] password) {
            return ALIAS.equals(alias) ? keyPair.getPrivate() : null;
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            if (!ALIAS.equals(alias)) {
                return null;
            }
            return switch (certificates) {
                case CHAIN -> new Certificate[] {certificate};
                case EMPTY_CHAIN_AND_CERTIFICATE -> new Certificate[0];
                case NULL_CHAIN_AND_CERTIFICATE, NONE -> null;
            };
        }

        @Override
        public Certificate engineGetCertificate(String alias) {
            return ALIAS.equals(alias) && certificates != Certificates.NONE ? certificate : null;
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
            return null;
        }

        @Override
        public void engineStore(OutputStream stream, char[] password) throws IOException {
            throw new IOException("read-only");
        }
    }
}
