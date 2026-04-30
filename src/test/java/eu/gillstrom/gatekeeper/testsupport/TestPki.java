package eu.gillstrom.gatekeeper.testsupport;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Pure-BouncyCastle test PKI builder. Builds throwaway RSA key pairs and issues
 * self-signed roots and issuer-signed leaves entirely in-memory, so tests are
 * self-contained and never need external fixtures.
 */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    private TestPki() {
    }

    public static KeyPair newRsaKeyPair(int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(bits, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static X509Certificate selfSignedCa(KeyPair kp, String cn) throws Exception {
        X500Name subject = new X500Name("CN=" + cn);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + 3600_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                subject, nextSerial(), notBefore, notAfter, subject, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    public static X509Certificate subordinateCa(
            KeyPair subjectKp, String subjectCn,
            X509Certificate issuerCert, PrivateKey issuerKey) throws Exception {
        X500Name subject = new X500Name("CN=" + subjectCn);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + 3600_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuerCert.getSubjectX500Principal().getName()),
                nextSerial(), notBefore, notAfter, subject, subjectKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    public static X509Certificate endEntity(
            KeyPair subjectKp, String subjectCn,
            X509Certificate issuerCert, PrivateKey issuerKey) throws Exception {
        X500Name subject = new X500Name("CN=" + subjectCn);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + 3600_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuerCert.getSubjectX500Principal().getName()),
                nextSerial(), notBefore, notAfter, subject, subjectKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    public static String toPem(X509Certificate cert) throws Exception {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    private static BigInteger nextSerial() {
        return BigInteger.valueOf(SERIAL.incrementAndGet());
    }
}
