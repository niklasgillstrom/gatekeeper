package eu.gillstrom.gatekeeper.signing;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Reference-only {@link ReceiptSigner} that generates a fresh 3072-bit RSA key
 * pair at application startup and self-signs a stand-in certificate.
 *
 * <p>This bean is the Spring-default for the reference implementation. It is
 * structurally incapable of producing receipts signed under the NCA's
 * organisation certificate, and it emits a {@code WARN} log at every startup
 * and every signing operation so its use in production cannot be overlooked.
 * The return value of {@link #getSigningCertificatePem()} is flagged
 * {@code CN=REFERENCE-EPHEMERAL} so downstream consumers can filter
 * ephemeral receipts explicitly.</p>
 *
 * <p>In production this bean is disabled by setting
 * {@code gatekeeper.signing.mode=configured}; the
 * {@link ConfiguredReceiptSigner} is selected instead.</p>
 */
@Component
@ConditionalOnProperty(name = "gatekeeper.signing.mode", havingValue = "ephemeral", matchIfMissing = true)
public class EphemeralReceiptSigner implements ReceiptSigner {

    private static final Logger log = LoggerFactory.getLogger(EphemeralReceiptSigner.class);

    private final PrivateKey privateKey;
    private final String certificatePem;
    private final String signerIdentifier;

    public EphemeralReceiptSigner(
            @Value("${gatekeeper.signing.ephemeral.key-size:3072}") int keySize) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            this.privateKey = kp.getPrivate();

            X509Certificate cert = buildSelfSignedCert(kp);
            this.certificatePem = "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
            this.signerIdentifier = "REFERENCE-EPHEMERAL/serial=" + cert.getSerialNumber().toString(16);

            log.warn("EphemeralReceiptSigner initialised: a throwaway RSA-{} key pair was generated and "
                    + "a self-signed CN=REFERENCE-EPHEMERAL certificate will be used to sign every receipt. "
                    + "This is the REFERENCE configuration and MUST NOT be used in production. "
                    + "Set gatekeeper.signing.mode=configured and supply a real PKCS#12 keystore "
                    + "(gatekeeper.signing.keystore-path, gatekeeper.signing.keystore-password, "
                    + "gatekeeper.signing.key-alias) before any consumer treats receipts as authoritative.",
                    keySize);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialise EphemeralReceiptSigner", e);
        }
    }

    @Override
    public String getSignerIdentifier() {
        return signerIdentifier;
    }

    @Override
    public byte[] sign(byte[] canonicalReceipt) {
        try {
            log.warn("Signing receipt with EphemeralReceiptSigner — NOT the NCA's production organisation certificate.");
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(canonicalReceipt);
            return sig.sign();
        } catch (Exception e) {
            throw new IllegalStateException("EphemeralReceiptSigner signing failure", e);
        }
    }

    @Override
    public String getSigningCertificatePem() {
        return certificatePem;
    }

    private static X509Certificate buildSelfSignedCert(KeyPair kp) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now);
        // Ephemeral certs are valid for 24h — long enough for a dev session,
        // short enough that a process restart visibly rotates the key.
        Date notAfter = new Date(now + 24L * 60L * 60L * 1000L);
        BigInteger serial = BigInteger.valueOf(now).xor(BigInteger.valueOf(kp.hashCode() & 0xFFFFFFFFL));

        X500Name subject = new X500Name("CN=REFERENCE-EPHEMERAL,O=gatekeeper (reference)");

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, kp.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    /**
     * Exposed for tests.
     */
    public PublicKey getPublicKey() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(certificatePem.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            return cert.getPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to re-parse ephemeral certificate", e);
        }
    }
}
