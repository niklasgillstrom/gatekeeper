package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Each chain rule and refusal reason of {@link ThalesLunaVerifier}, on
 * synthetic PKCS#7 PKCs built with real RSA keys under a throwaway root passed
 * to the test constructor, plus the serial in Thales's own PKC.
 */
class ThalesLunaVerifierMutationTest {

    private static final String[] EKUS = ThalesLunaVerifier.RSA_CHAIN_EKUS.toArray(new String[0]);
    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    private static KeyPair root;
    private static KeyPair mfg;
    private static KeyPair hw;
    private static KeyPair dev;
    private static KeyPair leaf;
    private static X509Certificate rootCert;
    private static X509Certificate mfgCert;
    private static X509Certificate hwCert;
    private static X509Certificate devCert;
    private static X509Certificate leafCert;

    @BeforeAll
    static void pki() throws Exception {
        root = TestPki.newRsaKeyPair(2048);
        mfg = TestPki.newRsaKeyPair(2048);
        hw = TestPki.newRsaKeyPair(2048);
        dev = TestPki.newRsaKeyPair(2048);
        leaf = TestPki.newRsaKeyPair(2048);
        long now = System.currentTimeMillis();
        rootCert = cert(root, "ROOT", "ROOT", root.getPrivate(), "1.3.6.1.4.1.12383.1.1", -1, now);
        mfgCert = cert(mfg, "MFG", "ROOT", root.getPrivate(), EKUS[3], -1, now);
        hwCert = cert(hw, "HW", "MFG", mfg.getPrivate(), EKUS[2], -1, now);
        devCert = cert(dev, "DEV", "HW", hw.getPrivate(), EKUS[1], -1, now);
        leafCert = cert(leaf, "LEAF", "DEV", dev.getPrivate(), EKUS[0], null, now);
    }

    private static ThalesLunaVerifier verifier() {
        return new ThalesLunaVerifier(root.getPublic());
    }

    // ---- interface methods ------------------------------------------------------------

    @Test
    @DisplayName("Vendor is THALES; the generic certificate path refuses; model is reported")
    void interfaceMethods() {
        ThalesLunaVerifier v = verifier();
        assertThat(v.getVendor()).isEqualTo(HsmVendor.THALES);
        assertThat(v.verifyAttestation(leafCert, leaf.getPublic())).isFalse();
        assertThat(v.extractModel(leafCert)).isEqualTo("Thales Luna");
    }

    @Test
    @DisplayName("The serial is the leaf's 12383.2.1 extension; a leaf without it has none")
    void serialNumberFromTheLeafExtension() throws Exception {
        List<X509Certificate> real = new ArrayList<>();
        for (var c : CertificateFactory.getInstance("X.509").generateCertPath(new ByteArrayInputStream(
                Files.readAllBytes(Path.of("src/test/resources/vendor-fixtures/thales-luna/rsa-pkc.p7b"))), "PKCS7")
                .getCertificates()) {
            real.add((X509Certificate) c);
        }
        ThalesLunaVerifier v = new ThalesLunaVerifier();
        assertThat(v.extractSerialNumber(real.get(0))).isEqualTo("521174");
        assertThat(v.extractSerialNumber(leafCert)).isNull();
    }

    @Test
    @DisplayName("verifyChain without a chain refuses")
    void verifyChainWithoutChainRefuses() {
        assertThat(verifier().verifyChain(leafCert, null)).isFalse();
        assertThat(verifier().verifyChain(leafCert, new X509Certificate[] {devCert, hwCert, mfgCert})).isTrue();
    }

    // ---- PKC envelope -----------------------------------------------------------------

    @Test
    @DisplayName("A PKC of exactly the size limit is parsed; one byte more is refused for its size")
    void sizeLimitIsInclusive() {
        ThalesLunaVerifier.ThalesLunaResult atLimit = verifier().verifyLunaAttestation(
                Base64.getEncoder().encodeToString(new byte[ThalesLunaVerifier.MAX_PKC_SIZE]), leaf.getPublic());
        assertThat(atLimit.isValid()).isFalse();
        assertThat(atLimit.getErrors()).isNotEmpty().noneMatch(e -> e.contains("exceeds"));

        ThalesLunaVerifier.ThalesLunaResult over = verifier().verifyLunaAttestation(
                Base64.getEncoder().encodeToString(new byte[ThalesLunaVerifier.MAX_PKC_SIZE + 1]), leaf.getPublic());
        assertThat(over.getErrors()).containsExactly("LUNA_PKC_MALFORMED: PKC exceeds 65536 bytes");
    }

    @Test
    @DisplayName("A synthetic four-certificate PKC verifies for its leaf key, with or without a copy of the root")
    void syntheticPkcVerifies() throws Exception {
        for (List<X509Certificate> chain : List.of(
                List.of(leafCert, devCert, hwCert, mfgCert), List.of(leafCert, devCert, hwCert, mfgCert, rootCert))) {
            ThalesLunaVerifier.ThalesLunaResult r = verifier().verifyLunaAttestation(pkc(chain), leaf.getPublic());
            assertThat(r.getErrors()).isEmpty();
            assertThat(r.isValid()).isTrue();
            assertThat(r.isPublicKeyMatch()).isTrue();
            assertThat(r.isExportable()).isFalse();
            assertThat(r.getHsmSerial()).isNull();
        }
    }

    @Test
    @DisplayName("A PKC for another key is refused, reports no key match and claims nothing about exportability")
    void anotherKeyIsRefused() throws Exception {
        ThalesLunaVerifier.ThalesLunaResult r = verifier().verifyLunaAttestation(
                pkc(List.of(leafCert, devCert, hwCert, mfgCert)), TestPki.newRsaKeyPair(2048).getPublic());
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).containsExactly(
                "LUNA_PUBLIC_KEY_MISMATCH: the Proof of Origin certificate is for another key");
    }

    // ---- chain rules ------------------------------------------------------------------

    @Test
    @DisplayName("A chain of the wrong length is refused with the count")
    void wrongLengthIsRefused() throws Exception {
        ThalesLunaVerifier.ThalesLunaResult r = verifier().verifyLunaAttestation(
                pkc(List.of(leafCert, devCert, hwCert)), leaf.getPublic());
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.isExportable()).isTrue();
        assertThat(r.getErrors()).containsExactly(
                "LUNA_CHAIN_INVALID: expected 4 certificates below the root, found 3");
    }

    @Test
    @DisplayName("A leaf without the Proof of Origin EKU is refused with the expected EKU")
    void missingEkuIsRefused() throws Exception {
        X509Certificate noEku = cert(leaf, "LEAF", "DEV", dev.getPrivate(), null, null, System.currentTimeMillis());
        assertThat(verifier().verifyLunaAttestation(pkc(List.of(noEku, devCert, hwCert, mfgCert)), leaf.getPublic())
                .getErrors()).containsExactly(
                "LUNA_CHAIN_INVALID: certificate 0 has EKU null, expected 1.3.6.1.4.1.12383.1.13");
    }

    @Test
    @DisplayName("A leaf that is a CA, or an intermediate that is not, is refused with which one")
    void caFlagIsChecked() throws Exception {
        long now = System.currentTimeMillis();
        X509Certificate caLeaf = cert(leaf, "LEAF", "DEV", dev.getPrivate(), EKUS[0], -1, now);
        assertThat(verifier().verifyLunaAttestation(pkc(List.of(caLeaf, devCert, hwCert, mfgCert)), leaf.getPublic())
                .getErrors()).containsExactly("LUNA_CHAIN_INVALID: certificate 0 is a CA");

        X509Certificate notCaDev = cert(dev, "DEV", "HW", hw.getPrivate(), EKUS[1], null, now);
        assertThat(verifier().verifyLunaAttestation(pkc(List.of(leafCert, notCaDev, hwCert, mfgCert)), leaf.getPublic())
                .getErrors()).containsExactly("LUNA_CHAIN_INVALID: certificate 1 is not a CA");
    }

    @Test
    @DisplayName("An intermediate with path length 0 is a CA")
    void pathLengthZeroIsACa() throws Exception {
        X509Certificate dev0 = cert(dev, "DEV", "HW", hw.getPrivate(), EKUS[1], 0, System.currentTimeMillis());
        assertThat(dev0.getBasicConstraints()).isZero();
        ThalesLunaVerifier.ThalesLunaResult r = verifier().verifyLunaAttestation(
                pkc(List.of(leafCert, dev0, hwCert, mfgCert)), leaf.getPublic());
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
    }

    @Test
    @DisplayName("A certificate that names another issuer than the next certificate is refused")
    void issuerNameMustMatch() throws Exception {
        X509Certificate otherIssuer = cert(leaf, "LEAF", "SOMEONE", dev.getPrivate(), EKUS[0], null,
                System.currentTimeMillis());
        assertThat(verifier().verifyLunaAttestation(pkc(List.of(otherIssuer, devCert, hwCert, mfgCert)), leaf.getPublic())
                .getErrors()).containsExactly("LUNA_CHAIN_INVALID: certificate 0 does not name certificate 1 as issuer");
    }

    @Test
    @DisplayName("A certificate with the right issuer name but signed by another key is refused")
    void issuerMustHaveSigned() throws Exception {
        X509Certificate forged = cert(leaf, "LEAF", "DEV", TestPki.newRsaKeyPair(2048).getPrivate(), EKUS[0], null,
                System.currentTimeMillis());
        ThalesLunaVerifier.ThalesLunaResult r = verifier().verifyLunaAttestation(
                pkc(List.of(forged, devCert, hwCert, mfgCert)), leaf.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).singleElement()
                .satisfies(e -> assertThat(e).startsWith("LUNA_CHAIN_INVALID: certificate 0: "));
    }

    @Test
    @DisplayName("An expired Proof of Origin certificate is refused")
    void expiredLeafIsRefused() throws Exception {
        X509Certificate expired = cert(leaf, "LEAF", "DEV", dev.getPrivate(), EKUS[0], null,
                System.currentTimeMillis() - 7_200_000L);
        ThalesLunaVerifier.ThalesLunaResult r = verifier().verifyLunaAttestation(
                pkc(List.of(expired, devCert, hwCert, mfgCert)), leaf.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).singleElement()
                .satisfies(e -> assertThat(e).startsWith("LUNA_CHAIN_INVALID: certificate 0: "));
    }

    // ---- builders ---------------------------------------------------------------------

    /**
     * The chain as a degenerate PKCS#7 SignedData whose certificate SET keeps
     * the given order (DER would sort it), leaf first as Luna writes it.
     */
    private static String pkc(List<X509Certificate> chain) throws Exception {
        ASN1EncodableVector certs = new ASN1EncodableVector();
        for (X509Certificate c : chain) {
            certs.add(Certificate.getInstance(c.getEncoded()));
        }
        SignedData sd = new SignedData(new DLSet(), new ContentInfo(CMSObjectIdentifiers.data, null),
                new BERSet(certs), null, new DLSet());
        return Base64.getEncoder().encodeToString(
                new ContentInfo(CMSObjectIdentifiers.signedData, sd).getEncoded(ASN1Encoding.DL));
    }

    /**
     * @param pathLen null for an end entity, -1 for a CA without a path length, else the CA's path length
     */
    private static X509Certificate cert(KeyPair subject, String cn, String issuerCn, PrivateKey issuerKey,
                                        String eku, Integer pathLen, long now) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=" + issuerCn),
                BigInteger.valueOf(SERIAL.incrementAndGet()), new Date(now - 60_000L), new Date(now + 3_600_000L),
                new X500Name("CN=" + cn), subject.getPublic());
        b.addExtension(Extension.basicConstraints, true, pathLen == null ? new BasicConstraints(false)
                : pathLen < 0 ? new BasicConstraints(true) : new BasicConstraints(pathLen));
        if (eku != null) {
            b.addExtension(Extension.extendedKeyUsage, true,
                    new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(eku))));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
    }
}
