package eu.gillstrom.gatekeeper.signing;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Locale;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Production-shaped {@link ReceiptSigner} that loads a signing key and
 * certificate chain from a JCA {@link KeyStore} configured via Spring
 * properties — by default a PKCS#12 file, or a key held in an HSM and reached
 * through a JCA provider (PKCS#11 or a vendor JCE).
 *
 * <p>Active when {@code gatekeeper.signing.mode=configured}. Properties:</p>
 *
 * <pre>
 * gatekeeper.signing.mode=configured
 * gatekeeper.signing.keystore-type=PKCS12           # default; e.g. PKCS11 or a vendor type for an HSM
 * gatekeeper.signing.keystore-path=/etc/gatekeeper/nca-seal.p12   # optional for non-file keystore types
 * gatekeeper.signing.keystore-password=&lt;secret&gt;   # the keystore password, or the HSM PIN
 * gatekeeper.signing.key-alias=nca-seal
 * gatekeeper.signing.key-password=&lt;secret&gt;        # optional, defaults to keystore password
 * gatekeeper.signing.algorithm=SHA256withRSA         # or e.g. SHA384withRSA, SHA256withECDSA, SHA384withECDSA
 * gatekeeper.signing.provider-class=                 # optional java.security.Provider class to load and register
 * gatekeeper.signing.provider-config=                # optional argument to Provider.configure(), e.g. a SunPKCS11 config file
 * </pre>
 *
 * <h2>HSM keys</h2>
 *
 * <p>With {@code provider-class} set, the class is instantiated — first
 * through {@link ServiceLoader} (which reaches JDK module providers such as
 * {@code sun.security.pkcs11.SunPKCS11}, whose package is not exported), then
 * by its public no-argument constructor — and, if {@code provider-config} is
 * set, replaced by {@code provider.configure(providerConfig)}. The result is
 * registered with {@link Security#addProvider} when no provider of that name
 * is registered yet, and is used explicitly for the {@link KeyStore} and, when
 * it offers the algorithm, for {@link Signature}. A private key that lives in
 * the HSM is then only a handle: signing happens inside the device and the
 * key material never enters this process. Whether the key is in fact
 * non-exportable is not something this class can see; that is what
 * {@code gatekeeper.signing.attestation.*} ({@link SigningKeyAttestation})
 * verifies.</p>
 *
 * <p>{@code keystore-path} is required for the file-based types
 * ({@value #FILE_TYPES_DOC}) and optional for every other type; when it is
 * blank the keystore is loaded with {@code KeyStore.load(null, pin)}.</p>
 *
 * <h2>Fail closed</h2>
 *
 * <p>The constructor throws {@link IllegalStateException} — so the
 * application does not start — when: {@code provider-config} is set without
 * {@code provider-class}; the provider class cannot be found, is not a
 * {@link Provider}, or cannot be instantiated or configured; a file-based
 * keystore type has no path; the keystore cannot be loaded; the alias is not
 * a key entry or has no certificate; or a start-up test signature does not
 * verify under the certificate's public key (wrong certificate for the key,
 * wrong algorithm for the key, or a provider that does not sign).</p>
 *
 * <p>At startup the chosen certificate's subject is logged so operators can
 * verify at a glance that the expected NCA seal is wired up.</p>
 */
@Component
@ConditionalOnProperty(name = "gatekeeper.signing.mode", havingValue = "configured")
public class ConfiguredReceiptSigner implements ReceiptSigner {

    private static final Logger log = LoggerFactory.getLogger(ConfiguredReceiptSigner.class);

    /** Keystore types that are files and therefore need {@code keystore-path}. */
    static final Set<String> FILE_TYPES = Set.of("PKCS12", "JKS", "JCEKS", "BCFKS", "BKS", "UBER");
    static final String FILE_TYPES_DOC = "PKCS12, JKS, JCEKS, BCFKS, BKS, UBER";

    private static final byte[] SELF_TEST_PROBE =
            "gatekeeper ConfiguredReceiptSigner start-up self-test".getBytes(StandardCharsets.UTF_8);

    private final PrivateKey privateKey;
    private final Certificate[] chain;
    private final String signerIdentifier;
    private final String algorithm;
    private final String certificatePem;
    private final Provider provider;
    private final String keystoreType;

    /** PKCS#12 file, default providers — the constructor before HSM support. */
    public ConfiguredReceiptSigner(String keystorePath, String keystorePassword, String alias,
                                   String keyPassword, String algorithm) {
        this(keystorePath, keystorePassword, alias, keyPassword, algorithm, "PKCS12", null, null);
    }

    @Autowired
    public ConfiguredReceiptSigner(
            @Value("${gatekeeper.signing.keystore-path:}") String keystorePath,
            @Value("${gatekeeper.signing.keystore-password}") String keystorePassword,
            @Value("${gatekeeper.signing.key-alias}") String alias,
            @Value("${gatekeeper.signing.key-password:${gatekeeper.signing.keystore-password}}") String keyPassword,
            @Value("${gatekeeper.signing.algorithm:SHA256withRSA}") String algorithm,
            @Value("${gatekeeper.signing.keystore-type:PKCS12}") String keystoreType,
            @Value("${gatekeeper.signing.provider-class:}") String providerClass,
            @Value("${gatekeeper.signing.provider-config:}") String providerConfig) {
        this.algorithm = algorithm;
        this.keystoreType = keystoreType == null || keystoreType.isBlank() ? "PKCS12" : keystoreType.trim();
        String where = isBlank(keystorePath) ? "keystore type " + this.keystoreType : keystorePath;
        try {
            this.provider = loadProvider(providerClass, providerConfig);
            KeyStore ks = provider == null
                    ? KeyStore.getInstance(this.keystoreType)
                    : KeyStore.getInstance(this.keystoreType, provider);
            char[] pin = keystorePassword == null ? null : keystorePassword.toCharArray();
            if (isBlank(keystorePath)) {
                if (FILE_TYPES.contains(this.keystoreType.toUpperCase(Locale.ROOT))) {
                    throw new IllegalStateException("gatekeeper.signing.keystore-path is required for keystore-type "
                            + this.keystoreType);
                }
                ks.load(null, pin);
            } else {
                try (InputStream in = new FileInputStream(keystorePath)) {
                    ks.load(in, pin);
                }
            }
            if (!ks.isKeyEntry(alias)) {
                throw new IllegalStateException(
                        "Keystore alias '" + alias + "' is not a key entry in " + where);
            }
            this.privateKey = (PrivateKey) ks.getKey(alias, keyPassword == null ? null : keyPassword.toCharArray());
            if (privateKey == null) {
                throw new IllegalStateException("Keystore alias '" + alias + "' yields no private key in " + where);
            }
            Certificate[] loaded = ks.getCertificateChain(alias);
            if ((loaded == null || loaded.length == 0) && ks.getCertificate(alias) != null) {
                loaded = new Certificate[] {ks.getCertificate(alias)};
            }
            this.chain = loaded;
            if (chain == null || chain.length == 0) {
                throw new IllegalStateException(
                        "Keystore alias '" + alias + "' has no certificate chain");
            }
            X509Certificate leaf = (X509Certificate) chain[0];
            selfTest(leaf);
            this.signerIdentifier = leaf.getSubjectX500Principal().getName()
                    + "/serial=" + leaf.getSerialNumber().toString(16);
            this.certificatePem = encodeChain(chain);
            log.info("ConfiguredReceiptSigner initialised: alias='{}', subject='{}', issuer='{}', algorithm='{}', "
                            + "keystore-type='{}', provider='{}', private-key encoding visible to the JVM={}",
                    alias, leaf.getSubjectX500Principal().getName(),
                    leaf.getIssuerX500Principal().getName(), algorithm, this.keystoreType,
                    provider == null ? "(default providers)" : provider.getName(),
                    privateKey.getEncoded() != null);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to initialise ConfiguredReceiptSigner from " + where, e);
        }
    }

    /**
     * Instantiate, configure and register {@code provider-class}, or return
     * {@code null} when none is configured.
     */
    static Provider loadProvider(String providerClass, String providerConfig) {
        if (isBlank(providerClass)) {
            if (!isBlank(providerConfig)) {
                throw new IllegalStateException("gatekeeper.signing.provider-config is set but "
                        + "gatekeeper.signing.provider-class is not; the configuration has no provider to apply to");
            }
            return null;
        }
        String className = providerClass.trim();
        Provider p = instantiate(className);
        if (!isBlank(providerConfig)) {
            try {
                p = p.configure(providerConfig.trim());
            } catch (RuntimeException e) {
                throw new IllegalStateException("Provider " + className + " could not be configured with '"
                        + providerConfig + "': " + e, e);
            }
            if (p == null) {
                throw new IllegalStateException("Provider " + className + ".configure returned null");
            }
        }
        if (Security.getProvider(p.getName()) == null) {
            Security.addProvider(p);
            log.info("ConfiguredReceiptSigner: registered JCA provider '{}' ({})", p.getName(), className);
        } else {
            log.info("ConfiguredReceiptSigner: a JCA provider named '{}' is already registered; using the "
                    + "instance created from {} explicitly", p.getName(), className);
        }
        return p;
    }

    private static Provider instantiate(String className) {
        try {
            for (ServiceLoader.Provider<Provider> candidate : ServiceLoader.load(Provider.class).stream().toList()) {
                if (candidate.type().getName().equals(className)) {
                    return candidate.get();
                }
            }
        } catch (java.util.ServiceConfigurationError ignored) {
            // A broken unrelated provider declaration; fall through to reflection.
        }
        Class<?> type;
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            type = Class.forName(className, true, loader != null ? loader : ConfiguredReceiptSigner.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("gatekeeper.signing.provider-class " + className + " was not found", e);
        }
        if (!Provider.class.isAssignableFrom(type)) {
            throw new IllegalStateException("gatekeeper.signing.provider-class " + className
                    + " is not a java.security.Provider");
        }
        try {
            return (Provider) type.getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IllegalStateException("gatekeeper.signing.provider-class " + className
                    + " could not be instantiated: " + e, e);
        }
    }

    /**
     * Sign a fixed probe with the configured key and verify it, with the
     * default providers, under the certificate's public key.
     */
    private void selfTest(X509Certificate leaf) throws Exception {
        byte[] sig = rawSign(SELF_TEST_PROBE);
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(leaf.getPublicKey());
        verifier.update(SELF_TEST_PROBE);
        if (!verifier.verify(sig)) {
            throw new IllegalStateException("start-up self-test failed: a signature made with the key under the "
                    + "configured alias does not verify under that alias's certificate");
        }
    }

    private Signature newSignature() throws NoSuchAlgorithmException {
        if (provider != null) {
            try {
                return Signature.getInstance(algorithm, provider);
            } catch (NoSuchAlgorithmException notOffered) {
                // The provider holds the key but leaves the algorithm to JCA's
                // delayed provider selection, which picks one that accepts the key.
                return Signature.getInstance(algorithm);
            }
        }
        return Signature.getInstance(algorithm);
    }

    private byte[] rawSign(byte[] data) throws Exception {
        Signature sig = newSignature();
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    @Override
    public String getSignerIdentifier() {
        return signerIdentifier;
    }

    @Override
    public byte[] sign(byte[] canonicalReceipt) {
        try {
            return rawSign(canonicalReceipt);
        } catch (Exception e) {
            throw new IllegalStateException("ConfiguredReceiptSigner signing failure", e);
        }
    }

    @Override
    public String getSigningCertificatePem() {
        return certificatePem;
    }

    @Override
    public String getSignatureAlgorithm() {
        return algorithm;
    }

    /** The configured keystore type ({@code PKCS12} unless set). */
    public String getKeystoreType() {
        return keystoreType;
    }

    /** The provider loaded from {@code provider-class}, or {@code null}. */
    public Provider getProvider() {
        return provider;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String encodeChain(Certificate[] chain) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (Certificate c : chain) {
            sb.append("-----BEGIN CERTIFICATE-----\n")
              .append(Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                      .encodeToString(c.getEncoded()))
              .append("\n-----END CERTIFICATE-----\n");
        }
        return sb.toString();
    }
}
