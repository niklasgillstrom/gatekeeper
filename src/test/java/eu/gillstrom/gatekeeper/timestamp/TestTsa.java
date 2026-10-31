package eu.gillstrom.gatekeeper.timestamp;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-process RFC 3161 Time-Stamping Authority for tests, built on
 * BouncyCastle's {@link TimeStampTokenGenerator} and
 * {@link TimeStampResponseGenerator}: a test root CA and a TSA certificate
 * with the critical {@code id-kp-timeStamping} extended key usage, issued
 * by that root. Usable directly as a {@link TsaClient}, or behind HTTP via
 * {@link #respond(byte[])}.
 */
public final class TestTsa implements TsaClient {

    public static final String POLICY = "1.3.6.1.4.1.99999.1.1";
    private static final AtomicLong SERIAL = new AtomicLong(1);

    private final KeyPair rootKp;
    private final X509Certificate root;
    private final KeyPair tsaKp;
    private final X509Certificate tsaCert;
    private final TimeStampResponseGenerator responder;
    /** When set, every request fails with an IOException (a TSA outage). */
    public final AtomicBoolean down = new AtomicBoolean();
    public final AtomicLong requests = new AtomicLong();

    public TestTsa() throws Exception {
        rootKp = TestPki.newRsaKeyPair(2048);
        root = TestPki.selfSignedCa(rootKp, "Test TSA Root");
        tsaKp = TestPki.newRsaKeyPair(2048);
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(root.getSubjectX500Principal().getName()), BigInteger.valueOf(now),
                new Date(now - 60_000L), new Date(now + 3600_000L), new X500Name("CN=Test TSA"), tsaKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        tsaCert = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(rootKp.getPrivate())));

        TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", tsaKp.getPrivate(), tsaCert),
                new JcaDigestCalculatorProviderBuilder().build()
                        .get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                new ASN1ObjectIdentifier(POLICY));
        tokenGenerator.addCertificates(new JcaCertStore(List.of(tsaCert)));
        responder = new TimeStampResponseGenerator(tokenGenerator, TSPAlgorithms.ALLOWED);
    }

    public X509Certificate root() {
        return root;
    }

    public X509Certificate tsaCertificate() {
        return tsaCert;
    }

    /** Write the root as a PEM trust file. */
    public Path writeTrustPem(Path file) throws Exception {
        Files.writeString(file, TestPki.toPem(root), StandardCharsets.UTF_8);
        return file;
    }

    /** Verifier trusting this TSA's root. */
    public TimestampTokenVerifier verifier() {
        return new TimestampTokenVerifier(List.of(root));
    }

    /** Answer a DER TimeStampReq with a DER TimeStampResp. */
    public byte[] respond(byte[] requestDer) throws Exception {
        requests.incrementAndGet();
        TimeStampRequest request = new TimeStampRequest(requestDer);
        TimeStampResponse response = responder.generate(request, BigInteger.valueOf(SERIAL.getAndIncrement()),
                new Date());
        return response.getEncoded();
    }

    @Override
    public byte[] timestamp(byte[] sha256Imprint) throws IOException {
        if (down.get()) {
            requests.incrementAndGet();
            throw new IOException("test TSA is down");
        }
        try {
            TimeStampRequestGenerator g = new TimeStampRequestGenerator();
            g.setCertReq(true);
            TimeStampRequest request = g.generate(TSPAlgorithms.SHA256, sha256Imprint,
                    BigInteger.valueOf(SERIAL.get()));
            byte[] response = respond(request.getEncoded());
            return HttpTsaClient.tokenFrom(request, response);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}
