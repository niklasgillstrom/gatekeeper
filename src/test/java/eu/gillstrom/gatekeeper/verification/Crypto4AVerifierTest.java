package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
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

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link Crypto4AVerifier} against the PKI Consortium's published QASM
 * attestation (see {@code src/test/resources/vendor-fixtures/crypto4a/NOTICE.md})
 * and against synthetic messages that isolate each required claim.
 */
class Crypto4AVerifierTest {

    private static final Path MESSAGE = Path.of("src/test/resources/vendor-fixtures/crypto4a/attestation.der");
    private static final String C = "1.3.6.1.4.1.39901.6.";
    private static final byte[] UUID = new byte[16];

    private static KeyPair root;
    private static KeyPair sca;
    private static KeyPair aa;
    private static X509Certificate scaCert;
    private static X509Certificate aaCert;
    private static KeyPair csr;

    @BeforeAll
    static void pki() throws Exception {
        root = ec();
        sca = ec();
        aa = ec();
        scaCert = cert(sca.getPublic(), "SCA", "ROOT", root.getPrivate(), true, null);
        aaCert = cert(aa.getPublic(), "AA", "SCA", sca.getPrivate(), false, Crypto4AVerifier.EKU_ATTESTATION);
        csr = TestPki.newRsaKeyPair(2048);
        UUID[15] = 7;
    }

    private static byte[] real() throws Exception {
        return Files.readAllBytes(MESSAGE);
    }

    /** The EC key whose SPKI the published message attests. */
    private static PublicKey realKey() throws Exception {
        for (Crypto4AVerifier.Claim c : Crypto4AVerifier.claims(
                ASN1Sequence.getInstance(ASN1Sequence.getInstance(real()).getObjectAt(1)))) {
            if (Crypto4AVerifier.KEY_SPKI.equals(c.predicate())) {
                byte[] spki = ASN1OctetString.getInstance((ASN1TaggedObject) c.complement(), false).getOctets();
                return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
            }
        }
        throw new IllegalStateException("no key-spki claim");
    }

    @Test
    @DisplayName("The published QASM message verifies under the pinned C4A_RCA, both signatures included")
    void realMessageVerifies() throws Exception {
        Crypto4AVerifier.Crypto4AResult r = new Crypto4AVerifier()
                .verifyCrypto4AAttestation(Base64.getEncoder().encodeToString(real()), realKey());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.isExportable()).isFalse();
        assertThat(r.getHsmSerial()).isNotBlank();
    }

    @Test
    @DisplayName("The PEM form of the message is accepted")
    void pemFormIsAccepted() throws Exception {
        String pem = "-----BEGIN ATTESTATION MESSAGE-----\n"
                + Base64.getMimeEncoder().encodeToString(real())
                + "\n-----END ATTESTATION MESSAGE-----\n";
        assertThat(new Crypto4AVerifier().verifyCrypto4AAttestation(pem, realKey()).isValid()).isTrue();
    }

    @Test
    @DisplayName("The published message does not attest another key")
    void anotherKeyIsRefused() throws Exception {
        Crypto4AVerifier.Crypto4AResult r = new Crypto4AVerifier()
                .verifyCrypto4AAttestation(Base64.getEncoder().encodeToString(real()), csr.getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("C4A_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("One changed byte in the claims breaks the signatures")
    void tamperedClaimsAreRefused() throws Exception {
        byte[] m = real();
        m[75] ^= 0x01; // inside the qasm-serial claim's UTF-8 complement
        Crypto4AVerifier.Crypto4AResult r = new Crypto4AVerifier()
                .verifyCrypto4AAttestation(Base64.getEncoder().encodeToString(m), realKey());

        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("C4A_SIGNATURE_INVALID"));
    }

    @Test
    @DisplayName("Under another root key the published message is refused")
    void anotherRootIsRefused() throws Exception {
        Crypto4AVerifier.Crypto4AResult r = new Crypto4AVerifier(ec().getPublic())
                .verifyCrypto4AAttestation(Base64.getEncoder().encodeToString(real()), realKey());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.contains("pinned root"));
    }

    @Test
    @DisplayName("Synthetic: the full claim set verifies; each required claim is needed")
    void eachRequiredClaimIsNeeded() throws Exception {
        Crypto4AVerifier v = new Crypto4AVerifier(root.getPublic());
        assertThat(v.verifyCrypto4AAttestation(message(fullClaims(), aa, aaCert), csr.getPublic()).getErrors())
                .as("full claim set").isEmpty();

        for (String[] drop : new String[][] {
                {"1.4", "C4A_NOT_CERTIFIED_PRODUCTION"},
                {"2.0", "C4A_ATTESTATION_KEYS_NOT_UNIQUE"},
                {"2.1", "C4A_PUBLIC_KEY_MISMATCH"},
                {"2.4", "C4A_NOT_A_PRIVATE_KEY"},
                {"2.7", "C4A_KEY_EXTRACTABLE"},
                {"2.8", "C4A_KEY_NOT_GENERATED"},
                {"2.9", "C4A_KEY_EXTRACTABLE"}}) {
            List<ASN1Sequence> claims = new ArrayList<>(fullClaims());
            claims.removeIf(c -> ((ASN1ObjectIdentifier) c.getObjectAt(0)).getId().equals(C + drop[0]));
            Crypto4AVerifier.Crypto4AResult r = v.verifyCrypto4AAttestation(message(claims, aa, aaCert), csr.getPublic());
            assertThat(r.isValid()).as("without ." + drop[0]).isFalse();
            assertThat(r.getErrors()).as("without ." + drop[0]).anyMatch(e -> e.startsWith(drop[1]));
        }
    }

    @Test
    @DisplayName("Synthetic: a public-key object, or two objects with the CSR key, are refused")
    void objectClassAndUniqueness() throws Exception {
        Crypto4AVerifier v = new Crypto4AVerifier(root.getPublic());

        List<ASN1Sequence> publicKey = new ArrayList<>(fullClaims());
        publicKey.removeIf(c -> ((ASN1ObjectIdentifier) c.getObjectAt(0)).getId().equals(C + "2.4"));
        publicKey.add(claim("2.4", UUID, new DERTaggedObject(false, 3, new ASN1Integer(3))));
        assertThat(v.verifyCrypto4AAttestation(message(publicKey, aa, aaCert), csr.getPublic()).getErrors())
                .anyMatch(e -> e.startsWith("C4A_NOT_A_PRIVATE_KEY"));

        List<ASN1Sequence> twice = new ArrayList<>(fullClaims());
        byte[] other = UUID.clone();
        other[0] = 1;
        twice.add(claim("2.1", other, new DERTaggedObject(false, 0, new DEROctetString(csr.getPublic().getEncoded()))));
        assertThat(v.verifyCrypto4AAttestation(message(twice, aa, aaCert), csr.getPublic()).getErrors())
                .anyMatch(e -> e.startsWith("C4A_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("Synthetic: a signer without the attestation EKU, or an intermediate that is no CA, is refused")
    void signerAndChainChecks() throws Exception {
        Crypto4AVerifier v = new Crypto4AVerifier(root.getPublic());

        X509Certificate noEku = cert(aa.getPublic(), "AA", "SCA", sca.getPrivate(), false, null);
        assertThat(v.verifyCrypto4AAttestation(message(fullClaims(), aa, noEku), csr.getPublic()).getErrors())
                .anyMatch(e -> e.contains("attestation EKU"));

        KeyPair badSca = ec();
        X509Certificate notCa = cert(badSca.getPublic(), "SCA", "ROOT", root.getPrivate(), false, null);
        X509Certificate aaUnderNotCa = cert(aa.getPublic(), "AA", "SCA", badSca.getPrivate(), false,
                Crypto4AVerifier.EKU_ATTESTATION);
        assertThat(v.verifyCrypto4AAttestation(message(fullClaims(), aa, aaUnderNotCa, notCa), csr.getPublic())
                .getErrors()).anyMatch(e -> e.contains("is not a CA"));
    }

    @Test
    @DisplayName("Synthetic: every signature block must verify, not only the first")
    void everyBlockMustVerify() throws Exception {
        Crypto4AVerifier v = new Crypto4AVerifier(root.getPublic());
        Crypto4AVerifier.Crypto4AResult r = v.verifyCrypto4AAttestation(
                message(fullClaims(), aa, aaCert, true), csr.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("C4A_SIGNATURE_INVALID: block 1"));
    }

    @Test
    @DisplayName("Synthetic: an expired signer certificate is refused")
    void expiredSignerIsRefused() throws Exception {
        X509Certificate expired = cert(aa.getPublic(), "AA", "SCA", sca.getPrivate(), false,
                Crypto4AVerifier.EKU_ATTESTATION, System.currentTimeMillis() - 7_200_000L);
        Crypto4AVerifier.Crypto4AResult r = new Crypto4AVerifier(root.getPublic())
                .verifyCrypto4AAttestation(message(fullClaims(), aa, expired), csr.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("C4A_SIGNATURE_INVALID"));
    }

    // ---- synthetic message builder -------------------------------------------------

    private static List<ASN1Sequence> fullClaims() throws Exception {
        List<ASN1Sequence> out = new ArrayList<>();
        out.add(claim("1.4", null, null));
        out.add(claim("2.0", null, null));
        out.add(claim("2.1", UUID, new DERTaggedObject(false, 0, new DEROctetString(csr.getPublic().getEncoded()))));
        out.add(claim("2.4", UUID, new DERTaggedObject(false, 3, new ASN1Integer(4))));
        out.add(claim("2.7", UUID, null));
        out.add(claim("2.8", UUID, null));
        out.add(claim("2.9", UUID, null));
        return out;
    }

    private static ASN1Sequence claim(String suffix, byte[] uuid, DERTaggedObject complement) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1ObjectIdentifier(C + suffix));
        if (uuid != null) {
            v.add(new DERTaggedObject(false, 0, new DERSequence(new DERTaggedObject(false, 0, new DEROctetString(uuid)))));
        }
        if (complement != null) {
            v.add(new DERTaggedObject(true, 1, complement));
        }
        return new DERSequence(v);
    }

    private static String message(List<ASN1Sequence> claims, KeyPair signer, X509Certificate signerCert,
                                  X509Certificate... extraRelated) throws Exception {
        return message(claims, signer, signerCert, false, extraRelated);
    }

    /** With {@code badSecondBlock}, a second ECDSA block signs other bytes than the claims. */
    private static String message(List<ASN1Sequence> claims, KeyPair signer, X509Certificate signerCert,
                                  boolean badSecondBlock, X509Certificate... extraRelated) throws Exception {
        ASN1EncodableVector cv = new ASN1EncodableVector();
        claims.forEach(cv::add);
        DERSequence setOfClaims = new DERSequence(new ASN1EncodableVector() {{
            add(new ASN1Integer(1));
            add(new DERSequence(cv));
        }});
        Signature s = Signature.getInstance("SHA384withECDSA");
        s.initSign(signer.getPrivate());
        s.update(setOfClaims.getEncoded("DER"));
        DERSequence sid = new DERSequence(new DERTaggedObject(true, 2,
                ASN1Sequence.getInstance(signerCert.getEncoded())));
        DERSequence block = new DERSequence(new ASN1EncodableVector() {{
            add(sid);
            add(new DERSequence(new ASN1ObjectIdentifier(Crypto4AVerifier.OID_ECDSA_SHA384)));
            add(new DERBitString(s.sign()));
        }});
        ASN1EncodableVector related = new ASN1EncodableVector();
        related.add(ASN1Sequence.getInstance(extraRelated.length > 0 ? extraRelated[0].getEncoded() : scaCert.getEncoded()));
        ASN1EncodableVector blocks = new ASN1EncodableVector();
        blocks.add(block);
        if (badSecondBlock) {
            Signature other = Signature.getInstance("SHA384withECDSA");
            other.initSign(signer.getPrivate());
            other.update(new byte[] {1, 2, 3});
            byte[] wrong = other.sign();
            blocks.add(new DERSequence(new ASN1EncodableVector() {{
                add(sid);
                add(new DERSequence(new ASN1ObjectIdentifier(Crypto4AVerifier.OID_ECDSA_SHA384)));
                add(new DERBitString(wrong));
            }}));
        }
        DERSequence msg = new DERSequence(new ASN1EncodableVector() {{
            add(new ASN1Integer(1));
            add(setOfClaims);
            add(new DERSequence(blocks));
            add(new DERTaggedObject(false, 0, new DERSequence(related)));
        }});
        return Base64.getEncoder().encodeToString(msg.getEncoded("DER"));
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        return g.generateKeyPair();
    }

    private static X509Certificate cert(PublicKey subject, String cn, String issuerCn, PrivateKey issuerKey,
                                        boolean ca, String eku) throws Exception {
        return cert(subject, cn, issuerCn, issuerKey, ca, eku, System.currentTimeMillis());
    }

    private static X509Certificate cert(PublicKey subject, String cn, String issuerCn, PrivateKey issuerKey,
                                        boolean ca, String eku, long now) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=" + issuerCn),
                BigInteger.valueOf(now), new Date(now - 60_000L), new Date(now + 3_600_000L),
                new X500Name("CN=" + cn), subject);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (eku != null) {
            b.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(eku))));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA384withECDSA").build(issuerKey)));
    }
}
