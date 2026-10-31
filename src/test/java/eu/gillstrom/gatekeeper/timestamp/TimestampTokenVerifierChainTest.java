package eu.gillstrom.gatekeeper.timestamp;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link TimestampTokenVerifier} on chains that are not just a trusted TSA
 * certificate: an intermediate that only the token carries, and a TSA
 * certificate that has expired since the token was issued.
 */
class TimestampTokenVerifierChainTest {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());
    private static final byte[] DATA = "chain head".getBytes(StandardCharsets.UTF_8);

    private static X509Certificate issue(String subject, PublicKey key, X509Certificate issuer, PrivateKey issuerKey,
                                         Instant from, Instant to, boolean ca) throws Exception {
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuer.getSubjectX500Principal().getName()), BigInteger.valueOf(SERIAL.incrementAndGet()),
                Date.from(from), Date.from(to), new X500Name(subject), key);
        if (ca) {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } else {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            b.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
    }

    /** A token over {@link #DATA}, generated at {@code genTime}, carrying {@code carried}. */
    private static byte[] token(KeyPair tsaKeys, X509Certificate tsaCert, List<X509Certificate> carried, Instant genTime)
            throws Exception {
        // The CMS signing time is the genTime too, as a TSA issuing at genTime would set it.
        Hashtable<ASN1ObjectIdentifier, Attribute> signed = new Hashtable<>();
        signed.put(CMSAttributes.signingTime,
                new Attribute(CMSAttributes.signingTime, new DERSet(new Time(Date.from(genTime)))));
        TimeStampTokenGenerator generator = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signed)))
                        .build("SHA256withRSA", tsaKeys.getPrivate(), tsaCert),
                new JcaDigestCalculatorProviderBuilder().build()
                        .get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                new ASN1ObjectIdentifier(TestTsa.POLICY));
        generator.addCertificates(new JcaCertStore(carried));
        TimeStampRequestGenerator requests = new TimeStampRequestGenerator();
        requests.setCertReq(true);
        TimeStampRequest request = requests.generate(TSPAlgorithms.SHA256,
                MessageDigest.getInstance("SHA-256").digest(DATA));
        return generator.generate(request, BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(genTime))
                .getEncoded();
    }

    @Test
    void anIntermediateCarriedOnlyInTheTokenCompletesTheChain() throws Exception {
        Instant now = Instant.now();
        KeyPair rootKeys = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKeys, "Chain Test Root");
        KeyPair caKeys = TestPki.newRsaKeyPair(2048);
        X509Certificate intermediate = issue("CN=Chain Test Intermediate", caKeys.getPublic(), root,
                rootKeys.getPrivate(), now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(1)), true);
        KeyPair tsaKeys = TestPki.newRsaKeyPair(2048);
        X509Certificate tsaCert = issue("CN=Chain Test TSA", tsaKeys.getPublic(), intermediate, caKeys.getPrivate(),
                now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(1)), false);

        TimestampTokenVerifier verifier = new TimestampTokenVerifier(List.of(root));
        assertThat(verifier.trustedCertificates()).containsExactly(root);

        TimestampTokenVerifier.Verification v = verifier.verify(token(tsaKeys, tsaCert, List.of(tsaCert, intermediate),
                now), DATA);
        assertThat(v.valid()).as(String.valueOf(v.error())).isTrue();

        TimestampTokenVerifier.Verification withoutIntermediate =
                verifier.verify(token(tsaKeys, tsaCert, List.of(tsaCert), now), DATA);
        assertThat(withoutIntermediate.chainValid()).isFalse();
    }

    @Test
    void aTsaCertificateThatHasExpiredSinceIsCheckedAtTheTokensGenTime() throws Exception {
        Instant now = Instant.now();
        KeyPair rootKeys = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKeys, "Expiry Test Root");
        KeyPair tsaKeys = TestPki.newRsaKeyPair(2048);
        X509Certificate expired = issue("CN=Expired TSA", tsaKeys.getPublic(), root, rootKeys.getPrivate(),
                now.minus(Duration.ofDays(10)), now.minus(Duration.ofDays(5)), false);

        TimestampTokenVerifier.Verification v = new TimestampTokenVerifier(List.of(root))
                .verify(token(tsaKeys, expired, List.of(expired), now.minus(Duration.ofDays(7))), DATA);
        assertThat(v.valid()).as(String.valueOf(v.error())).isTrue();
    }
}
