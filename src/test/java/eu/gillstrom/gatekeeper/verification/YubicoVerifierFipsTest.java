package eu.gillstrom.gatekeeper.verification;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Where {@link YubicoVerifier} reads the FIPS indicator ({@code 41482.4.10},
 * INTEGER) and the FIPS-approved flag ({@code 41482.4.12}, BOOLEAN): the key
 * certificate first, then {@code chain[1]}, nowhere else; a value of the
 * wrong type is ignored, never read as a different value.
 */
class YubicoVerifierFipsTest {

    private static final ASN1ObjectIdentifier INDICATOR = new ASN1ObjectIdentifier("1.3.6.1.4.1.41482.4.10");
    private static final ASN1ObjectIdentifier APPROVED = new ASN1ObjectIdentifier("1.3.6.1.4.1.41482.4.12");

    private static KeyPair kp;

    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void captureLogs() {
        logs = new ListAppender<>();
        logs.start();
        ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(YubicoVerifier.class)).addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(YubicoVerifier.class)).detachAppender(logs);
    }

    @BeforeAll
    static void key() throws Exception {
        kp = TestPki.newRsaKeyPair(2048);
    }

    /** A certificate carrying the given values (null: extension absent; byte[]: raw extension value). */
    private static X509Certificate cert(Object indicator, Object approved) throws Exception {
        X500Name name = new X500Name("CN=t");
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                new Date(now - 60_000L), new Date(now + 3_600_000L), name, kp.getPublic());
        add(b, INDICATOR, indicator);
        add(b, APPROVED, approved);
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    private static void add(X509v3CertificateBuilder b, ASN1ObjectIdentifier oid, Object value) throws Exception {
        if (value instanceof byte[] raw) {
            b.addExtension(oid, false, raw);
        } else if (value instanceof org.bouncycastle.asn1.ASN1Encodable asn1) {
            b.addExtension(oid, false, asn1);
        }
    }

    private static X509Certificate[] chain(X509Certificate... certs) {
        return certs;
    }

    @Test
    void theKeyCertificateIsReadBeforeTheDeviceCertificate() throws Exception {
        X509Certificate[] c = chain(cert(new ASN1Integer(6), ASN1Boolean.FALSE),
                cert(new ASN1Integer(5), ASN1Boolean.TRUE));
        assertThat(YubicoVerifier.fipsIndicator(c)).isEqualTo(6);
        assertThat(YubicoVerifier.fipsApprovedMode(c)).isFalse();
    }

    @Test
    void theDeviceCertificateIsReadWhenTheKeyCertificateHasNoValue() throws Exception {
        X509Certificate[] c = chain(cert(null, null), cert(new ASN1Integer(5), ASN1Boolean.TRUE));
        assertThat(YubicoVerifier.fipsIndicator(c)).isEqualTo(5);
        assertThat(YubicoVerifier.fipsApprovedMode(c)).isTrue();
    }

    @Test
    void noValueInTheFirstTwoCertificatesIsNull() throws Exception {
        X509Certificate[] c = chain(cert(null, null), cert(null, null),
                cert(new ASN1Integer(5), ASN1Boolean.TRUE));
        assertThat(YubicoVerifier.fipsIndicator(c)).isNull();
        assertThat(YubicoVerifier.fipsApprovedMode(c)).isNull();

        X509Certificate[] keyOnly = chain(cert(null, null));
        assertThat(YubicoVerifier.fipsIndicator(keyOnly)).isNull();
        assertThat(YubicoVerifier.fipsApprovedMode(keyOnly)).isNull();
    }

    @Test
    void aValueOfTheWrongTypeIsIgnored() throws Exception {
        // INTEGER where a BOOLEAN belongs, UTF8String where an INTEGER belongs.
        X509Certificate[] wrongType = chain(cert(new DERUTF8String("5"), new ASN1Integer(1)), cert(null, null));
        assertThat(YubicoVerifier.fipsIndicator(wrongType)).isNull();
        assertThat(YubicoVerifier.fipsApprovedMode(wrongType)).isNull();

        // A truncated encoding, and a well-formed value followed by trailing bytes.
        X509Certificate[] malformed = chain(cert(new byte[] {0x02, 0x01}, new byte[] {0x01, 0x01, (byte) 0xFF, 0x00}),
                cert(new ASN1Integer(5), null));
        assertThat(YubicoVerifier.fipsIndicator(malformed)).as("falls back to chain[1]").isEqualTo(5);
        assertThat(YubicoVerifier.fipsApprovedMode(malformed)).isNull();

        // An INTEGER too large for an int.
        X509Certificate[] huge = chain(cert(new ASN1Integer(BigInteger.ONE.shiftLeft(40)), null));
        assertThat(YubicoVerifier.fipsIndicator(huge)).isNull();
    }

    @Test
    void verificationReportsTheValuesTheChainCarries() throws Exception {
        YubicoVerifier.YubicoAttestationResult on = new YubicoVerifier().verifyYubicoAttestation(
                List.of(TrustAnchorsTest.pem("CERTIFICATE", cert(new ASN1Integer(5), ASN1Boolean.TRUE).getEncoded())),
                kp.getPublic());
        assertThat(on.getFipsIndicator()).isEqualTo(5);
        assertThat(on.getFipsApprovedMode()).isTrue();

        YubicoVerifier.YubicoAttestationResult off = new YubicoVerifier().verifyYubicoAttestation(
                List.of(TrustAnchorsTest.pem("CERTIFICATE", cert(null, ASN1Boolean.FALSE).getEncoded())),
                kp.getPublic());
        assertThat(off.getFipsIndicator()).isNull();
        assertThat(off.getFipsApprovedMode()).isFalse();
    }

    @Test
    void aValueThatIsIgnoredIsWarnedAboutAndAnAbsentOneIsNot() throws Exception {
        YubicoVerifier.fipsIndicator(chain(cert(null, null), cert(null, null)));
        YubicoVerifier.fipsApprovedMode(chain(cert(null, null), cert(null, null)));
        assertThat(warnings()).isEmpty();

        YubicoVerifier.fipsIndicator(chain(cert(null, null), cert(new DERUTF8String("5"), null)));
        assertThat(warnings()).containsExactly("Yubico FIPS indicator (" + INDICATOR.getId()
                + ") in certificate 1 is not an int-sized INTEGER; ignored");

        YubicoVerifier.fipsApprovedMode(chain(cert(null, new ASN1Integer(1))));
        assertThat(warnings()).containsExactly("Yubico FIPS-approved flag (" + APPROVED.getId()
                + ") in certificate 0 is not a BOOLEAN; ignored");

        // An extension value that is not one DER object is ignored and warned about the same way.
        YubicoVerifier.fipsIndicator(chain(cert(new byte[] {0x02, 0x01}, null)));
        assertThat(warnings()).containsExactly("Yubico FIPS indicator (" + INDICATOR.getId()
                + ") in certificate 0 is not an int-sized INTEGER; ignored");
    }

    @Test
    void theIndicatorIsReadOnlyWhenItFitsInAnInt() throws Exception {
        BigInteger max = BigInteger.valueOf(Integer.MAX_VALUE);
        assertThat(YubicoVerifier.fipsIndicator(chain(cert(new ASN1Integer(max), null)))).isEqualTo(Integer.MAX_VALUE);
        assertThat(YubicoVerifier.fipsIndicator(chain(cert(new ASN1Integer(BigInteger.valueOf(Integer.MIN_VALUE)), null))))
                .isEqualTo(Integer.MIN_VALUE);
        assertThat(YubicoVerifier.fipsIndicator(chain(cert(new ASN1Integer(max.add(BigInteger.ONE)), null)))).isNull();
    }

    /** The WARN messages logged since the last call, then cleared. */
    private List<String> warnings() {
        List<String> out = logs.list.stream().filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage).toList();
        logs.list.clear();
        return out;
    }
}
