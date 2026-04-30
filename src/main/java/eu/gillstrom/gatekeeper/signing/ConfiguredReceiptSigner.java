package eu.gillstrom.gatekeeper.signing;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Production-shaped {@link ReceiptSigner} that loads a signing key and
 * certificate chain from a PKCS#12 keystore configured via Spring properties.
 *
 * <p>Active when {@code gatekeeper.signing.mode=configured}. Expected
 * properties:</p>
 *
 * <pre>
 * gatekeeper.signing.mode=configured
 * gatekeeper.signing.keystore-path=/etc/gatekeeper/nca-seal.p12
 * gatekeeper.signing.keystore-password=&lt;secret&gt;
 * gatekeeper.signing.key-alias=nca-seal
 * gatekeeper.signing.key-password=&lt;secret&gt;   # optional, defaults to keystore password
 * gatekeeper.signing.algorithm=SHA256withRSA    # or SHA384withECDSA, SHA256withRSAandMGF1 for PSS
 * </pre>
 *
 * <p>At startup the chosen certificate's subject is logged so operators can
 * verify at a glance that the expected NCA seal is wired up. The constructor
 * throws {@link IllegalStateException} if the keystore cannot be loaded or the
 * alias does not yield an appropriate key entry.</p>
 */
@Component
@ConditionalOnProperty(name = "gatekeeper.signing.mode", havingValue = "configured")
public class ConfiguredReceiptSigner implements ReceiptSigner {

    private static final Logger log = LoggerFactory.getLogger(ConfiguredReceiptSigner.class);

    private final PrivateKey privateKey;
    private final Certificate[] chain;
    private final String signerIdentifier;
    private final String algorithm;
    private final String certificatePem;

    public ConfiguredReceiptSigner(
            @Value("${gatekeeper.signing.keystore-path}") String keystorePath,
            @Value("${gatekeeper.signing.keystore-password}") String keystorePassword,
            @Value("${gatekeeper.signing.key-alias}") String alias,
            @Value("${gatekeeper.signing.key-password:${gatekeeper.signing.keystore-password}}") String keyPassword,
            @Value("${gatekeeper.signing.algorithm:SHA256withRSA}") String algorithm) {
        this.algorithm = algorithm;
        try (FileInputStream in = new FileInputStream(keystorePath)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, keystorePassword.toCharArray());
            if (!ks.isKeyEntry(alias)) {
                throw new IllegalStateException(
                        "Keystore alias '" + alias + "' is not a key entry in " + keystorePath);
            }
            this.privateKey = (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());
            this.chain = ks.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                throw new IllegalStateException(
                        "Keystore alias '" + alias + "' has no certificate chain");
            }
            X509Certificate leaf = (X509Certificate) chain[0];
            this.signerIdentifier = leaf.getSubjectX500Principal().getName()
                    + "/serial=" + leaf.getSerialNumber().toString(16);
            this.certificatePem = encodeChain(chain);
            log.info("ConfiguredReceiptSigner initialised: alias='{}', subject='{}', issuer='{}', algorithm='{}'",
                    alias, leaf.getSubjectX500Principal().getName(),
                    leaf.getIssuerX500Principal().getName(), algorithm);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to initialise ConfiguredReceiptSigner from " + keystorePath, e);
        }
    }

    @Override
    public String getSignerIdentifier() {
        return signerIdentifier;
    }

    @Override
    public byte[] sign(byte[] canonicalReceipt) {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initSign(privateKey);
            sig.update(canonicalReceipt);
            return sig.sign();
        } catch (Exception e) {
            throw new IllegalStateException("ConfiguredReceiptSigner signing failure", e);
        }
    }

    @Override
    public String getSigningCertificatePem() {
        return certificatePem;
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
