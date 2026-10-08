package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link ThalesLunaVerifier} against Thales's own PKC test vector from a
 * Luna K7 HSM (see {@code src/test/resources/vendor-fixtures/thales-luna/NOTICE.md}).
 */
class ThalesLunaVerifierTest {

    private static final Path DIR = Path.of("src/test/resources/vendor-fixtures/thales-luna");

    private static String pkc() throws Exception {
        return Base64.getEncoder().encodeToString(Files.readAllBytes(DIR.resolve("rsa-pkc.p7b")));
    }

    private static PublicKey csrKey() throws Exception {
        // cmu writes "BEGIN NEW CERTIFICATE REQUEST" with CRLF line ends.
        try (PEMParser p = new PEMParser(Files.newBufferedReader(DIR.resolve("rsa-test.csr"), StandardCharsets.US_ASCII))) {
            return new JcaPKCS10CertificationRequest((PKCS10CertificationRequest) p.readObject()).getPublicKey();
        }
    }

    private static List<X509Certificate> chain() throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        for (var c : CertificateFactory.getInstance("X.509").generateCertPath(
                new ByteArrayInputStream(Files.readAllBytes(DIR.resolve("rsa-pkc.p7b"))), "PKCS7").getCertificates()) {
            out.add((X509Certificate) c);
        }
        return out;
    }

    @Test
    @DisplayName("Thales's real PKC verifies under the pinned Chrysalis-ITS Root for the key in its CSR")
    void realPkcVerifiesForItsCsr() throws Exception {
        ThalesLunaVerifier.ThalesLunaResult r = new ThalesLunaVerifier().verifyLunaAttestation(pkc(), csrKey());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getHsmSerial()).isEqualTo("521174");
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.isExportable()).isFalse();
    }

    @Test
    @DisplayName("The same PKC does not confirm another key")
    void realPkcForAnotherKeyIsRefused() throws Exception {
        ThalesLunaVerifier.ThalesLunaResult r = new ThalesLunaVerifier()
                .verifyLunaAttestation(pkc(), TestPki.newRsaKeyPair(2048).getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("LUNA_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("Under another root key the chain is refused")
    void anotherRootIsRefused() throws Exception {
        ThalesLunaVerifier.ThalesLunaResult r = new ThalesLunaVerifier(TestPki.newRsaKeyPair(2048).getPublic())
                .verifyLunaAttestation(pkc(), csrKey());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("LUNA_CHAIN_INVALID"));
    }

    @Test
    @DisplayName("Root shipped in the PKC (serial 804500000007) and the pinned root (80450000000D) share one key")
    void pinnedRootKeyIsTheKeyInThePkc() throws Exception {
        List<X509Certificate> c = chain();
        X509Certificate shipped = c.get(c.size() - 1);
        assertThat(shipped.getSerialNumber().toString(16)).isEqualTo("804500000007");
        assertThat(ThalesLunaVerifier.sha256(shipped.getPublicKey().getEncoded()))
                .isEqualTo(ThalesLunaVerifier.CHRYSALIS_ROOT_KEY_SHA256);
    }

    @Test
    @DisplayName("A chain with a certificate missing or out of order is refused")
    void incompleteOrReorderedChainIsRefused() throws Exception {
        List<X509Certificate> c = chain();
        ThalesLunaVerifier v = new ThalesLunaVerifier();
        assertThat(v.verifyChain(c.get(0), c.subList(1, c.size()).toArray(new X509Certificate[0]))).isTrue();

        // Hardware Origin removed.
        assertThat(v.verifyChain(c.get(0), new X509Certificate[] {c.get(1), c.get(3), c.get(4)})).isFalse();
        // Device Authentication certificate presented as the leaf.
        assertThat(v.verifyChain(c.get(1), new X509Certificate[] {c.get(0), c.get(2), c.get(3), c.get(4)})).isFalse();
        // The leaf alone, presented with the root.
        assertThat(v.verifyChain(c.get(0), new X509Certificate[] {c.get(4)})).isFalse();
    }

    @Test
    @DisplayName("Garbage and oversized input are refused without an exception")
    void malformedInputIsRefused() throws Exception {
        ThalesLunaVerifier v = new ThalesLunaVerifier();
        assertThat(v.verifyLunaAttestation(Base64.getEncoder().encodeToString(new byte[64]), csrKey()).getErrors())
                .anyMatch(e -> e.startsWith("LUNA_PKC_MALFORMED"));
        assertThat(v.verifyLunaAttestation(
                Base64.getEncoder().encodeToString(new byte[ThalesLunaVerifier.MAX_PKC_SIZE + 1]), csrKey()).getErrors())
                .anyMatch(e -> e.startsWith("LUNA_PKC_MALFORMED"));
    }

    @Test
    @DisplayName("Without the pinned root key's signature the four-certificate chain is refused")
    void chainWithoutRootSignatureIsRefused() throws Exception {
        List<X509Certificate> c = chain();
        X509Certificate[] below = {c.get(1), c.get(2), c.get(3)};
        assertThat(new ThalesLunaVerifier().verifyChain(c.get(0), below)).isTrue();
        assertThat(new ThalesLunaVerifier(TestPki.newRsaKeyPair(2048).getPublic()).verifyChain(c.get(0), below)).isFalse();
    }

    @Test
    @DisplayName("Synthetic chains: each EKU, CA flag and the full length are required")
    void syntheticChainChecks() throws Exception {
        KeyPair root = TestPki.newRsaKeyPair(2048);
        ThalesLunaVerifier v = new ThalesLunaVerifier(root.getPublic());

        X509Certificate[] good = chainOf(root, EKUS, true);
        assertThat(v.verifyChain(good[0], rest(good))).as("well-formed synthetic chain").isTrue();

        X509Certificate[] noEku = chainOf(root, new String[] {null, null, null, null}, true);
        assertThat(v.verifyChain(noEku[0], rest(noEku))).as("no EKUs").isFalse();

        X509Certificate[] leafIsCa = chainOf(root, EKUS, false);
        assertThat(v.verifyChain(leafIsCa[0], rest(leafIsCa))).as("leaf marked CA").isFalse();

        // Hardware Origin signed directly by the root: Mfg Integrity missing.
        KeyPair hw = TestPki.newRsaKeyPair(2048);
        KeyPair dev = TestPki.newRsaKeyPair(2048);
        KeyPair leaf = TestPki.newRsaKeyPair(2048);
        X509Certificate hwCert = cert(hw, "HW", "ROOT", root.getPrivate(), EKUS[2], true);
        X509Certificate devCert = cert(dev, "DEV", "HW", hw.getPrivate(), EKUS[1], true);
        X509Certificate leafCert = cert(leaf, "LEAF", "DEV", dev.getPrivate(), EKUS[0], false);
        assertThat(v.verifyChain(leafCert, new X509Certificate[] {devCert, hwCert})).as("three certificates").isFalse();
    }

    private static final String[] EKUS = ThalesLunaVerifier.RSA_CHAIN_EKUS.toArray(new String[0]);

    private static X509Certificate[] rest(X509Certificate[] c) {
        return java.util.Arrays.copyOfRange(c, 1, c.length);
    }

    /** Leaf, Device, Hardware Origin, Mfg Integrity, signed by {@code root}; the leaf is a CA unless {@code leafNotCa}. */
    private static X509Certificate[] chainOf(KeyPair root, String[] ekus, boolean leafNotCa) throws Exception {
        KeyPair mfg = TestPki.newRsaKeyPair(2048);
        KeyPair hw = TestPki.newRsaKeyPair(2048);
        KeyPair dev = TestPki.newRsaKeyPair(2048);
        KeyPair leaf = TestPki.newRsaKeyPair(2048);
        X509Certificate mfgCert = cert(mfg, "MFG", "ROOT", root.getPrivate(), ekus[3], true);
        X509Certificate hwCert = cert(hw, "HW", "MFG", mfg.getPrivate(), ekus[2], true);
        X509Certificate devCert = cert(dev, "DEV", "HW", hw.getPrivate(), ekus[1], true);
        X509Certificate leafCert = cert(leaf, "LEAF", "DEV", dev.getPrivate(), ekus[0], !leafNotCa);
        return new X509Certificate[] {leafCert, devCert, hwCert, mfgCert};
    }

    private static X509Certificate cert(KeyPair subject, String cn, String issuerCn, java.security.PrivateKey issuerKey,
                                        String eku, boolean ca) throws Exception {
        long now = System.currentTimeMillis();
        var b = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                new org.bouncycastle.asn1.x500.X500Name("CN=" + issuerCn), java.math.BigInteger.valueOf(now),
                new java.util.Date(now - 60_000L), new java.util.Date(now + 3_600_000L),
                new org.bouncycastle.asn1.x500.X500Name("CN=" + cn), subject.getPublic());
        b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                new org.bouncycastle.asn1.x509.BasicConstraints(ca));
        if (eku != null) {
            b.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, true,
                    new org.bouncycastle.asn1.x509.ExtendedKeyUsage(org.bouncycastle.asn1.x509.KeyPurposeId.getInstance(
                            new org.bouncycastle.asn1.ASN1ObjectIdentifier(eku))));
        }
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(
                b.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
    }
}
