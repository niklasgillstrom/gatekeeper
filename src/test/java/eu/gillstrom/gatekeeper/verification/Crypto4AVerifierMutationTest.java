package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Each parse step, refusal reason and chain rule of {@link Crypto4AVerifier},
 * on synthetic QASM attestation messages signed with real ECDSA P-384 keys
 * under a throwaway root passed to the test constructor.
 */
class Crypto4AVerifierMutationTest {

    private static final String C = "1.3.6.1.4.1.39901.6.";
    private static final byte[] UUID = new byte[16];
    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

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
        scaCert = cert(sca.getPublic(), "SCA", "ROOT", root.getPrivate(), true, null, System.currentTimeMillis());
        aaCert = cert(aa.getPublic(), "AA", "SCA", sca.getPrivate(), false, Crypto4AVerifier.EKU_ATTESTATION,
                System.currentTimeMillis());
        csr = TestPki.newRsaKeyPair(2048);
        UUID[15] = 9;
    }

    private static Crypto4AVerifier verifier() {
        return new Crypto4AVerifier(root.getPublic());
    }

    // ---- interface methods ------------------------------------------------------------

    @Test
    @DisplayName("Vendor is CRYPTO4A; the generic certificate path refuses; model and serial are reported")
    void interfaceMethods() {
        Crypto4AVerifier v = verifier();
        assertThat(v.getVendor()).isEqualTo(HsmVendor.CRYPTO4A);
        assertThat(v.verifyAttestation(aaCert, aa.getPublic())).isFalse();
        assertThat(v.extractModel(aaCert)).isEqualTo("Crypto4A QASM");
        assertThat(v.extractSerialNumber(aaCert)).isEqualTo(aaCert.getSerialNumber().toString(16));
    }

    @Test
    @DisplayName("verifyChain walks the given intermediates to the pinned root and refuses without them")
    void verifyChainWalksToThePinnedRoot() throws Exception {
        Crypto4AVerifier v = verifier();
        assertThat(v.verifyChain(aaCert, new X509Certificate[] {scaCert})).isTrue();
        assertThat(v.verifyChain(aaCert, null)).isFalse();
        assertThat(v.verifyChain(aaCert, new X509Certificate[0])).isFalse();

        X509Certificate direct = cert(aa.getPublic(), "AA", "ROOT", root.getPrivate(), false,
                Crypto4AVerifier.EKU_ATTESTATION, System.currentTimeMillis());
        assertThat(v.verifyChain(direct, null)).as("signed by the root itself").isTrue();
        assertThat(new Crypto4AVerifier(ec().getPublic()).verifyChain(aaCert, new X509Certificate[] {scaCert}))
                .as("other root").isFalse();
    }

    // ---- message envelope -------------------------------------------------------------

    @Test
    @DisplayName("A message of exactly the size limit is parsed; one byte more is refused for its size")
    void sizeLimitIsInclusive() {
        Crypto4AVerifier v = verifier();
        Crypto4AVerifier.Crypto4AResult atLimit = v.verifyCrypto4AAttestation(
                Base64.getEncoder().encodeToString(new byte[Crypto4AVerifier.MAX_MESSAGE_SIZE]), csr.getPublic());
        assertThat(atLimit.isValid()).isFalse();
        assertThat(atLimit.getErrors()).isNotEmpty().noneMatch(e -> e.contains("exceeds"));

        Crypto4AVerifier.Crypto4AResult over = v.verifyCrypto4AAttestation(
                Base64.getEncoder().encodeToString(new byte[Crypto4AVerifier.MAX_MESSAGE_SIZE + 1]), csr.getPublic());
        assertThat(over).isNotNull();
        assertThat(over.isValid()).isFalse();
        assertThat(over.getErrors()).containsExactly("C4A_MESSAGE_MALFORMED: message exceeds 262144 bytes");
    }

    @Test
    @DisplayName("Input that is not DER is refused as malformed without an exception")
    void garbageIsMalformed() {
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation("AAAA", csr.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).singleElement().satisfies(e -> assertThat(e).startsWith("C4A_MESSAGE_MALFORMED: "));
    }

    @Test
    @DisplayName("An AttestationMessage with fewer than three or more than four elements is refused")
    void elementCountIsChecked() throws Exception {
        Crypto4AVerifier v = verifier();
        assertThat(v.verifyCrypto4AAttestation(encode(new ASN1Integer(1), setOfClaims(fullClaims())), csr.getPublic())
                .getErrors()).containsExactly("C4A_MESSAGE_MALFORMED: AttestationMessage has 2 elements");

        ASN1Sequence claims = setOfClaims(fullClaims());
        Crypto4AVerifier.Crypto4AResult five = v.verifyCrypto4AAttestation(encode(new ASN1Integer(1), claims,
                new DERSequence(signedBlock(claims, aa, aaCert)), related(scaCert), new ASN1Integer(0)), csr.getPublic());
        assertThat(five).isNotNull();
        assertThat(five.getErrors()).containsExactly("C4A_MESSAGE_MALFORMED: AttestationMessage has 5 elements");
    }

    @Test
    @DisplayName("Without relatedCertificates, a signer certified directly by the root verifies")
    void threeElementMessageVerifies() throws Exception {
        X509Certificate direct = cert(aa.getPublic(), "AA", "ROOT", root.getPrivate(), false,
                Crypto4AVerifier.EKU_ATTESTATION, System.currentTimeMillis());
        ASN1Sequence claims = setOfClaims(fullClaims());
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(
                encode(new ASN1Integer(1), claims, new DERSequence(signedBlock(claims, aa, direct))), csr.getPublic());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.getKeyId()).isEqualTo(HexFormat.of().formatHex(UUID));
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
    }

    @Test
    @DisplayName("relatedCertificates under a tag other than [0] is refused")
    void relatedCertificatesMustBeTagZero() throws Exception {
        ASN1Sequence claims = setOfClaims(fullClaims());
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(encode(new ASN1Integer(1), claims,
                new DERSequence(signedBlock(claims, aa, aaCert)),
                new DERTaggedObject(false, 1, new DERSequence(ASN1Sequence.getInstance(scaCert.getEncoded())))),
                csr.getPublic());
        assertThat(r).isNotNull();
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).containsExactly("C4A_MESSAGE_MALFORMED: relatedCertificates is not [0]");
    }

    // ---- signature blocks -------------------------------------------------------------

    @Test
    @DisplayName("A message without any signature block is refused")
    void noSignatureBlockIsRefused() throws Exception {
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(
                encode(new ASN1Integer(1), setOfClaims(fullClaims()), new DERSequence(), related(scaCert)),
                csr.getPublic());
        assertThat(r).isNotNull();
        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.getErrors()).containsExactly("C4A_SIGNATURE_INVALID: no signature block");
    }

    @Test
    @DisplayName("A SignatureBlock that is not three elements is refused")
    void blockOfWrongSizeIsRefused() throws Exception {
        ASN1Sequence claims = setOfClaims(fullClaims());
        ASN1Sequence good = signedBlock(claims, aa, aaCert);
        DERSequence twoElements = new DERSequence(new ASN1Encodable[] {good.getObjectAt(0), good.getObjectAt(1)});
        assertThat(verifier().verifyCrypto4AAttestation(
                encode(new ASN1Integer(1), claims, new DERSequence(twoElements), related(scaCert)), csr.getPublic())
                .getErrors()).containsExactly("C4A_SIGNATURE_INVALID: block 0: SignatureBlock has 2 elements");
    }

    @Test
    @DisplayName("A signer identifier without a certificate ([2]) is refused")
    void signerWithoutCertificateIsRefused() throws Exception {
        ASN1Sequence claims = setOfClaims(fullClaims());
        ASN1Sequence good = signedBlock(claims, aa, aaCert);
        DERSequence sidWithoutCert = new DERSequence(new DERTaggedObject(true, 1, new DEROctetString(new byte[20])));
        DERSequence block = new DERSequence(new ASN1Encodable[] {sidWithoutCert, good.getObjectAt(1), good.getObjectAt(2)});
        assertThat(verifier().verifyCrypto4AAttestation(
                encode(new ASN1Integer(1), claims, new DERSequence(block), related(scaCert)), csr.getPublic())
                .getErrors()).containsExactly("C4A_SIGNATURE_INVALID: block 0: signer identifier carries no certificate");
    }

    @Test
    @DisplayName("A block in an algorithm other than ECDSA P-384/SHA-384 or HSS/LMS is refused")
    void unsupportedAlgorithmIsRefused() throws Exception {
        ASN1Sequence claims = setOfClaims(fullClaims());
        ASN1Sequence good = signedBlock(claims, aa, aaCert);
        String sha256WithEcdsa = "1.2.840.10045.4.3.2";
        DERSequence block = new DERSequence(new ASN1Encodable[] {good.getObjectAt(0),
                new DERSequence(new ASN1ObjectIdentifier(sha256WithEcdsa)), good.getObjectAt(2)});
        assertThat(verifier().verifyCrypto4AAttestation(
                encode(new ASN1Integer(1), claims, new DERSequence(block), related(scaCert)), csr.getPublic())
                .getErrors()).containsExactly(
                "C4A_SIGNATURE_INVALID: block 0: unsupported signature algorithm " + sha256WithEcdsa);
    }

    @Test
    @DisplayName("A signature over other bytes than the claims is refused with that reason")
    void signatureOverOtherBytesIsRefused() throws Exception {
        ASN1Sequence claims = setOfClaims(fullClaims());
        ASN1Sequence other = setOfClaims(List.of(claim("1.4", null, null)));
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(
                encode(new ASN1Integer(1), claims, new DERSequence(signedBlock(other, aa, aaCert)), related(scaCert)),
                csr.getPublic());
        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.getErrors()).containsExactly(
                "C4A_SIGNATURE_INVALID: block 0: signature over the claims does not verify");
    }

    // ---- chain to the pinned root -----------------------------------------------------

    @Test
    @DisplayName("Three intermediates below the root are accepted; a fourth exceeds the depth limit")
    void chainDepthIsLimited() throws Exception {
        ASN1Sequence claims = setOfClaims(fullClaims());
        List<X509Certificate> three = signerUnder(3);
        Crypto4AVerifier.Crypto4AResult ok = verifier().verifyCrypto4AAttestation(encode(new ASN1Integer(1), claims,
                new DERSequence(signedBlock(claims, aa, three.get(0))), related(three.subList(1, 4))), csr.getPublic());
        assertThat(ok.getErrors()).isEmpty();
        assertThat(ok.isValid()).isTrue();

        List<X509Certificate> four = signerUnder(4);
        Crypto4AVerifier.Crypto4AResult tooDeep = verifier().verifyCrypto4AAttestation(encode(new ASN1Integer(1), claims,
                new DERSequence(signedBlock(claims, aa, four.get(0))), related(four.subList(1, 5))), csr.getPublic());
        assertThat(tooDeep.isValid()).isFalse();
        assertThat(tooDeep.getErrors()).containsExactly(
                "C4A_SIGNATURE_INVALID: block 0: chain longer than " + Crypto4AVerifier.MAX_CHAIN_DEPTH);
    }

    @Test
    @DisplayName("An intermediate with the issuer's name but another key is not taken as the issuer")
    void issuerMustHaveSignedTheCertificate() throws Exception {
        X509Certificate impostor = cert(ec().getPublic(), "SCA", "ROOT", root.getPrivate(), true, null,
                System.currentTimeMillis());
        ASN1Sequence claims = setOfClaims(fullClaims());
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(encode(new ASN1Integer(1), claims,
                new DERSequence(signedBlock(claims, aa, aaCert)), related(impostor)), csr.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).containsExactly(
                "C4A_SIGNATURE_INVALID: block 0: no issuer for CN=AA leads to the pinned root");

        Crypto4AVerifier.Crypto4AResult both = verifier().verifyCrypto4AAttestation(encode(new ASN1Integer(1), claims,
                new DERSequence(signedBlock(claims, aa, aaCert)), related(impostor, scaCert)), csr.getPublic());
        assertThat(both.getErrors()).as("the genuine issuer after the impostor").isEmpty();
    }

    @Test
    @DisplayName("An expired signer certificate is refused with the validity error")
    void expiredSignerReportsTheValidityError() throws Exception {
        X509Certificate expired = cert(aa.getPublic(), "AA", "SCA", sca.getPrivate(), false,
                Crypto4AVerifier.EKU_ATTESTATION, System.currentTimeMillis() - 7_200_000L);
        ASN1Sequence claims = setOfClaims(fullClaims());
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(encode(new ASN1Integer(1), claims,
                new DERSequence(signedBlock(claims, aa, expired)), related(scaCert)), csr.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).singleElement().satisfies(e -> {
            assertThat(e).startsWith("C4A_SIGNATURE_INVALID: block 0: ");
            assertThat(e).containsIgnoringCase("expired");
        });
    }

    // ---- claims -----------------------------------------------------------------------

    @Test
    @DisplayName("key-spki-sha256 (.2.3) binds the CSR key in place of key-spki (.2.1)")
    void spkiSha256BindsTheKey() throws Exception {
        List<ASN1Sequence> claims = new ArrayList<>(fullClaims());
        claims.removeIf(c -> predicate(c).equals(C + "2.1"));
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(csr.getPublic().getEncoded());
        claims.add(claim("2.3", UUID, new DERTaggedObject(false, 0, new DEROctetString(digest))));
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(message(claims), csr.getPublic());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
    }

    @Test
    @DisplayName("Without a CSR key no attested object matches")
    void missingCsrKeyIsAMismatch() throws Exception {
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(message(fullClaims()), null);
        assertThat(r.isValid()).isFalse();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.getErrors()).containsExactly("C4A_PUBLIC_KEY_MISMATCH: 0 attested objects carry the CSR key's "
                + "SPKI; exactly one is required");
    }

    @Test
    @DisplayName("A message for another key does not report a public-key match")
    void anotherKeyIsNoMatch() throws Exception {
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(message(fullClaims()),
                TestPki.newRsaKeyPair(2048).getPublic());
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.isExportable()).isTrue();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    @DisplayName("The subject in the specification's [0] EXPLICIT form is read as well")
    void explicitSubjectIsRead() throws Exception {
        List<ASN1Sequence> claims = new ArrayList<>();
        for (ASN1Sequence c : fullClaims()) {
            if (c.size() == 1) {
                claims.add(c);
                continue;
            }
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(c.getObjectAt(0));
            v.add(new DERTaggedObject(true, 0, new DERSequence(new DERTaggedObject(false, 0, new DEROctetString(UUID)))));
            for (int i = 2; i < c.size(); i++) {
                v.add(c.getObjectAt(i));
            }
            claims.add(new DERSequence(v));
        }
        Crypto4AVerifier.Crypto4AResult r = verifier().verifyCrypto4AAttestation(message(claims), csr.getPublic());
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getKeyId()).isEqualTo(HexFormat.of().formatHex(UUID));
    }

    @Test
    @DisplayName("C4A_KEY_EXTRACTABLE names which of key-is-confined and key-never-extracted is absent")
    void extractableErrorNamesTheMissingClaim() throws Exception {
        List<ASN1Sequence> noConfined = new ArrayList<>(fullClaims());
        noConfined.removeIf(c -> predicate(c).equals(C + "2.7"));
        Crypto4AVerifier.Crypto4AResult r1 = verifier().verifyCrypto4AAttestation(message(noConfined), csr.getPublic());
        assertThat(r1.isExportable()).isTrue();
        assertThat(r1.getKeyOrigin()).isEqualTo("unverified");
        assertThat(r1.getErrors()).containsExactly(
                "C4A_KEY_EXTRACTABLE: key-is-confined (.2.7) absent, key-never-extracted (.2.9) present");

        List<ASN1Sequence> extracted = new ArrayList<>(fullClaims());
        extracted.removeIf(c -> predicate(c).equals(C + "2.9"));
        Crypto4AVerifier.Crypto4AResult r2 = verifier().verifyCrypto4AAttestation(message(extracted), csr.getPublic());
        assertThat(r2.isExportable()).isTrue();
        assertThat(r2.getErrors()).containsExactly(
                "C4A_KEY_EXTRACTABLE: key-is-confined (.2.7) present, key-never-extracted (.2.9) absent");
    }

    // ---- builders ---------------------------------------------------------------------

    private static String predicate(ASN1Sequence claim) {
        return ((ASN1ObjectIdentifier) claim.getObjectAt(0)).getId();
    }

    private static List<ASN1Sequence> fullClaims() {
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

    /** Subject in the implicit form of Crypto4A's published message. */
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

    private static ASN1Sequence setOfClaims(List<ASN1Sequence> claims) {
        ASN1EncodableVector cv = new ASN1EncodableVector();
        claims.forEach(cv::add);
        return new DERSequence(new ASN1Encodable[] {new ASN1Integer(1), new DERSequence(cv)});
    }

    /** ECDSA P-384 block over {@code claims} by {@code signer}, identified by {@code signerCert}. */
    private static ASN1Sequence signedBlock(ASN1Sequence claims, KeyPair signer, X509Certificate signerCert)
            throws Exception {
        Signature s = Signature.getInstance("SHA384withECDSA");
        s.initSign(signer.getPrivate());
        s.update(claims.getEncoded("DER"));
        DERSequence sid = new DERSequence(new DERTaggedObject(true, 2, ASN1Sequence.getInstance(signerCert.getEncoded())));
        return new DERSequence(new ASN1Encodable[] {sid,
                new DERSequence(new ASN1ObjectIdentifier(Crypto4AVerifier.OID_ECDSA_SHA384)),
                new DERBitString(s.sign())});
    }

    private static DERTaggedObject related(X509Certificate... certs) throws Exception {
        return related(List.of(certs));
    }

    private static DERTaggedObject related(List<X509Certificate> certs) throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (X509Certificate c : certs) {
            v.add(ASN1Sequence.getInstance(c.getEncoded()));
        }
        return new DERTaggedObject(false, 0, new DERSequence(v));
    }

    /** The standard four-element message: AA signs, SCA is related, SCA under the root. */
    private static String message(List<ASN1Sequence> claims) throws Exception {
        ASN1Sequence set = setOfClaims(claims);
        return encode(new ASN1Integer(1), set, new DERSequence(signedBlock(set, aa, aaCert)), related(scaCert));
    }

    private static String encode(ASN1Encodable... elements) throws Exception {
        return Base64.getEncoder().encodeToString(new DERSequence(elements).getEncoded("DER"));
    }

    /**
     * The AA signer certificate followed by CA certificates I0 ... I(n-1):
     * I0 issues AA, I(k+1) issues I(k), the root issues I(n-1).
     */
    private static List<X509Certificate> signerUnder(int n) throws Exception {
        List<KeyPair> keys = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            keys.add(ec());
        }
        long now = System.currentTimeMillis();
        List<X509Certificate> out = new ArrayList<>();
        out.add(cert(aa.getPublic(), "AA", "I0", keys.get(0).getPrivate(), false, Crypto4AVerifier.EKU_ATTESTATION, now));
        for (int i = 0; i < n; i++) {
            boolean last = i == n - 1;
            out.add(cert(keys.get(i).getPublic(), "I" + i, last ? "ROOT" : "I" + (i + 1),
                    last ? root.getPrivate() : keys.get(i + 1).getPrivate(), true, null, now));
        }
        return out;
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        return g.generateKeyPair();
    }

    private static X509Certificate cert(PublicKey subject, String cn, String issuerCn, PrivateKey issuerKey,
                                        boolean ca, String eku, long now) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=" + issuerCn),
                BigInteger.valueOf(SERIAL.incrementAndGet()), new Date(now - 60_000L), new Date(now + 3_600_000L),
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
