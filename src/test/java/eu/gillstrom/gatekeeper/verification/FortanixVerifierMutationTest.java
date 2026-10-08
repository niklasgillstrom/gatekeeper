package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link FortanixVerifier}: the input limits, each structural refusal of the
 * key attestation JSON and its authority chain, the policy constraint, the
 * key id and the {@link HsmAttestationVerifier} entry points, on synthetic
 * chains under a throwaway root.
 */
class FortanixVerifierMutationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long HOUR = 3_600_000L;
    private static final String KEY_ID_OID = "1.3.6.1.4.1.49690.1.2.2";

    private static KeyPair rootKp;
    private static X509Certificate root;
    private static KeyPair caKp;
    /** An intermediate with pathLenConstraint 0, as a one-level attestation PKI issues it. */
    private static X509Certificate ca;
    private static KeyPair authKp;
    private static X509Certificate authority;
    private static KeyPair target;
    private static long now;

    @BeforeAll
    static void pki() throws Exception {
        now = System.currentTimeMillis();
        rootKp = TestPki.newRsaKeyPair(2048);
        root = TestPki.selfSignedCa(rootKp, "TEST-FORTANIX-ROOT");
        caKp = TestPki.newRsaKeyPair(2048);
        ca = cert(caKp.getPublic(), "CN=CA", root, rootKp.getPrivate(), new BasicConstraints(0), null,
                FortanixVerifier.POLICY_KEY_ATTESTATION_PKI);
        authKp = TestPki.newRsaKeyPair(2048);
        authority = cert(authKp.getPublic(), "CN=AUTH", ca, caKp.getPrivate(), new BasicConstraints(false),
                FortanixVerifier.EKU_KEY_ATTESTATION_SIGNING, FortanixVerifier.POLICY_KEY_ATTESTATION_PKI);
        target = TestPki.newRsaKeyPair(2048);
    }

    private static FortanixVerifier verifier() {
        return new FortanixVerifier(root);
    }

    // ---- HsmAttestationVerifier entry points -------------------------------------------

    @Test
    @DisplayName("Vendor is FORTANIX; the certificate-only entry point never accepts; serial and model are reported")
    void entryPoints() {
        FortanixVerifier v = verifier();
        assertThat(v.getVendor()).isEqualTo(HsmVendor.FORTANIX);
        assertThat(v.verifyAttestation(authority, target.getPublic())).isFalse();
        assertThat(v.extractSerialNumber(authority)).isEqualTo(authority.getSerialNumber().toString(16));
        assertThat(v.extractModel(authority)).isEqualTo("Fortanix DSM");
    }

    @Test
    @DisplayName("verifyChain accepts the authority over its CA and refuses it without one")
    void verifyChain() {
        FortanixVerifier v = verifier();
        assertThat(v.verifyChain(authority, new X509Certificate[] {ca})).isTrue();
        assertThat(v.verifyChain(authority, null)).isFalse();
        assertThat(v.verifyChain(authority, new X509Certificate[0])).isFalse();
    }

    // ---- input limits and structure ----------------------------------------------------

    @Test
    @DisplayName("A statement under a pathLen-0 intermediate verifies, also with a copy of the root in the chain")
    void wellFormedStatementVerifies() throws Exception {
        X509Certificate statement = statement(new X500Name("CN=Fortanix DSM Key Attestation"), authKp.getPrivate());

        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority, ca), statement, "x509_certificate"), target.getPublic());
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();

        FortanixVerifier.FortanixResult withRoot = verifier().verifyFortanixAttestation(
                json(List.of(root, authority, ca), statement, "x509_certificate"), target.getPublic());
        assertThat(withRoot.getErrors()).isEmpty();
        assertThat(withRoot.isValid()).isTrue();
    }

    @Test
    @DisplayName("JSON of exactly 64 KiB is read; one byte more is refused before parsing")
    void sizeLimit() throws Exception {
        String json = json(List.of(authority, ca),
                statement(new X500Name("CN=Fortanix DSM Key Attestation"), authKp.getPrivate()), "x509_certificate");
        String atLimit = json + " ".repeat(FortanixVerifier.MAX_JSON_SIZE - json.length());
        assertThat(atLimit).hasSize(FortanixVerifier.MAX_JSON_SIZE);

        FortanixVerifier.FortanixResult ok = verifier().verifyFortanixAttestation(atLimit, target.getPublic());
        assertThat(ok.getErrors()).isEmpty();
        assertThat(ok.isValid()).isTrue();

        FortanixVerifier.FortanixResult tooBig = verifier().verifyFortanixAttestation(atLimit + " ", target.getPublic());
        assertThat(tooBig.isValid()).isFalse();
        assertThat(tooBig.getErrors()).containsExactly("FORTANIX_STATEMENT_MALFORMED: JSON exceeds 65536 bytes");
    }

    @Test
    @DisplayName("authority_chain (an array) and attestation_statement are required")
    void requiredFields() {
        String required = "FORTANIX_STATEMENT_MALFORMED: authority_chain and attestation_statement are required";
        for (String json : List.of(
                "{}",
                "{\"attestation_statement\":{\"format\":\"x509_certificate\"}}",
                "{\"authority_chain\":\"not-an-array\",\"attestation_statement\":{\"format\":\"x509_certificate\"}}",
                "{\"authority_chain\":[]}")) {
            FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(json, target.getPublic());
            assertThat(r.isValid()).as(json).isFalse();
            assertThat(r.isExportable()).as("unverified counts as exportable").isTrue();
            assertThat(r.getKeyOrigin()).isEqualTo("unverified");
            assertThat(r.getErrors()).as(json).containsExactly(required);
        }
    }

    @Test
    @DisplayName("A statement format other than x509_certificate is refused and named")
    void unsupportedFormat() throws Exception {
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority, ca),
                        statement(new X500Name("CN=Fortanix DSM Key Attestation"), authKp.getPrivate()), "pkcs7"),
                target.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).containsExactly("FORTANIX_STATEMENT_MALFORMED: unsupported format pkcs7");
    }

    @Test
    @DisplayName("Input that is neither JSON nor base64 JSON, or a certificate that is not DER, is refused as malformed")
    void unparseableInput() {
        for (String input : List.of("{not json", "%%% not base64 %%%",
                "{\"authority_chain\":[\"AAAA\"],\"attestation_statement\":"
                        + "{\"format\":\"x509_certificate\",\"statement\":\"AAAA\"}}")) {
            FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(input, target.getPublic());
            assertThat(r.isValid()).as(input).isFalse();
            assertThat(r.getErrors()).as(input).singleElement()
                    .satisfies(e -> assertThat(e).startsWith("FORTANIX_STATEMENT_MALFORMED: "));
        }
    }

    // ---- authority chain structure ------------------------------------------------------

    @Test
    @DisplayName("Two certificates that are not CAs in authority_chain are refused")
    void twoAuthoritiesAreRefused() throws Exception {
        X509Certificate second = cert(TestPki.newRsaKeyPair(2048).getPublic(), "CN=AUTH-2", ca, caKp.getPrivate(),
                new BasicConstraints(false), FortanixVerifier.EKU_KEY_ATTESTATION_SIGNING,
                FortanixVerifier.POLICY_KEY_ATTESTATION_PKI);
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority, second, ca),
                        statement(new X500Name("CN=Fortanix DSM Key Attestation"), authKp.getPrivate()),
                        "x509_certificate"),
                target.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).containsExactly(
                "FORTANIX_CHAIN_INVALID: more than one non-CA certificate in authority_chain");
    }

    @Test
    @DisplayName("An authority_chain without a Key Attestation Authority certificate is refused")
    void noAuthorityIsRefused() throws Exception {
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(ca, root), statement(new X500Name("CN=Fortanix DSM Key Attestation"), authKp.getPrivate()),
                        "x509_certificate"),
                target.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).containsExactly("FORTANIX_CHAIN_INVALID: no Key Attestation Authority certificate");
    }

    @Test
    @DisplayName("A statement the authority did not sign is refused with the verifier's reason")
    void statementSignedByAnotherKey() throws Exception {
        X509Certificate forged = statement(new X500Name("CN=Fortanix DSM Key Attestation"),
                TestPki.newRsaKeyPair(2048).getPrivate());
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority, ca), forged, "x509_certificate"), target.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.getErrors()).singleElement().satisfies(e -> {
            assertThat(e).startsWith("FORTANIX_STATEMENT_INVALID: ");
            assertThat(e).containsIgnoringCase("signature");
        });
    }

    @Test
    @DisplayName("Without its intermediate the authority does not chain to the pinned root")
    void missingIntermediate() throws Exception {
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority), statement(new X500Name("CN=Fortanix DSM Key Attestation"), authKp.getPrivate()),
                        "x509_certificate"),
                target.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).singleElement().satisfies(e -> {
            assertThat(e).startsWith("FORTANIX_CHAIN_INVALID: ");
            assertThat(e).containsIgnoringCase("trust anchor");
        });
    }

    @Test
    @DisplayName("A chain whose CA certificates do not include the authority's issuer names the missing issuer")
    void issuerNotInChain() throws Exception {
        KeyPair otherKp = TestPki.newRsaKeyPair(2048);
        X509Certificate unrelated = cert(otherKp.getPublic(), "CN=UNRELATED-CA", root, rootKp.getPrivate(),
                new BasicConstraints(0), null, FortanixVerifier.POLICY_KEY_ATTESTATION_PKI);
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority, unrelated),
                        statement(new X500Name("CN=Fortanix DSM Key Attestation"), authKp.getPrivate()),
                        "x509_certificate"),
                target.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).containsExactly("FORTANIX_CHAIN_INVALID: no CA certificate for CN=CA");
    }

    @Test
    @DisplayName("A chain under another certificate policy than fortanixKeyAttestationPkiCertificatePolicy is refused")
    void otherPolicyIsRefused() throws Exception {
        String otherPolicy = "1.3.6.1.4.1.99999.1";
        X509Certificate otherCa = cert(caKp.getPublic(), "CN=CA-OTHER-POLICY", root, rootKp.getPrivate(),
                new BasicConstraints(0), null, otherPolicy);
        X509Certificate otherAuthority = cert(authKp.getPublic(), "CN=AUTH", otherCa, caKp.getPrivate(),
                new BasicConstraints(false), FortanixVerifier.EKU_KEY_ATTESTATION_SIGNING, otherPolicy);
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(otherAuthority, otherCa),
                        statement(new X500Name("CN=Fortanix DSM Key Attestation"), authKp.getPrivate()),
                        "x509_certificate"),
                target.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).singleElement()
                .satisfies(e -> assertThat(e).startsWith("FORTANIX_CHAIN_INVALID: "));
    }

    @Test
    @DisplayName("A statement for another key than the CSR's is refused as a key mismatch")
    void otherCsrKeyIsRefused() throws Exception {
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority, ca), statement(new X500Name("CN=Fortanix DSM Key Attestation"),
                        authKp.getPrivate()), "x509_certificate"),
                TestPki.newRsaKeyPair(2048).getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.getErrors()).containsExactly("FORTANIX_PUBLIC_KEY_MISMATCH: the statement attests another key");

        FortanixVerifier.FortanixResult noCsr = verifier().verifyFortanixAttestation(
                json(List.of(authority, ca), statement(new X500Name("CN=Fortanix DSM Key Attestation"),
                        authKp.getPrivate()), "x509_certificate"),
                null);
        assertThat(noCsr.isValid()).isFalse();
        assertThat(noCsr.isPublicKeyMatch()).isFalse();
    }

    // ---- key id -------------------------------------------------------------------------

    @Test
    @DisplayName("The key id is read from the statement subject's Fortanix key-id attribute")
    void keyIdIsRead() throws Exception {
        X500Name subject = new X500Name(new RDN[] {
                new RDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String("Fortanix DSM Key Attestation"))),
                new RDN(new AttributeTypeAndValue(new ASN1ObjectIdentifier(KEY_ID_OID),
                        new DERUTF8String("0b1c2d3e-0000-4000-8000-123456789abc")))});
        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority, ca), statement(subject, authKp.getPrivate()), "x509_certificate"),
                target.getPublic());
        assertThat(r.isValid()).isTrue();
        assertThat(r.getKeyId()).isEqualTo("0b1c2d3e-0000-4000-8000-123456789abc");
    }

    @Test
    @DisplayName("A subject the key-id reader cannot decode leaves the key id absent and the verdict unchanged")
    void unreadableSubjectHasNoKeyId() throws Exception {
        byte[] marker = {'Q', '7', 'Z'};
        X500Name subject = new X500Name(new RDN[] {
                new RDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String("Fortanix DSM Key Attestation"))),
                new RDN(new AttributeTypeAndValue(BCStyle.O, new DEROctetString(marker)))});
        X509Certificate built = statement(subject, authKp.getPrivate());
        // Retag the 3-byte OCTET STRING as a BMPString: valid DER the JDK keeps as an opaque
        // attribute value, but an odd-length BMPString that Bouncy Castle refuses to decode.
        byte[] tbs = built.getTBSCertificate();
        int at = indexOf(tbs, new byte[] {0x04, 0x03, 'Q', '7', 'Z'});
        assertThat(at).isGreaterThan(0);
        tbs[at] = 0x1E;
        X509Certificate oddSubject = resign(tbs, authKp.getPrivate());

        FortanixVerifier.FortanixResult r = verifier().verifyFortanixAttestation(
                json(List.of(authority, ca), oddSubject, "x509_certificate"), target.getPublic());
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getKeyId()).isNull();
    }

    // ---- builders -----------------------------------------------------------------------

    private static X509Certificate statement(X500Name subject, PrivateKey signer) throws Exception {
        long signedAt = now - 60_000L;
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(authority.getSubjectX500Principal().getEncoded()), BigInteger.valueOf(signedAt),
                new Date(signedAt), new Date(253402300799000L), subject, target.getPublic());
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.KEY_GENERATED_IN_DSM), false, new DERSequence());
        b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.KEY_NEVER_EXPORTABLE), false, new DERSequence());
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer)));
    }

    private static String json(List<X509Certificate> chain, X509Certificate statement, String format) throws Exception {
        ObjectNode n = MAPPER.createObjectNode();
        ArrayNode array = n.putArray("authority_chain");
        for (X509Certificate c : chain) {
            array.add(Base64.getEncoder().encodeToString(c.getEncoded()));
        }
        ObjectNode s = n.putObject("attestation_statement");
        s.put("format", format);
        s.put("statement", Base64.getEncoder().encodeToString(statement.getEncoded()));
        return MAPPER.writeValueAsString(n);
    }

    private static X509Certificate cert(PublicKey subject, String dn, X509Certificate issuer, PrivateKey issuerKey,
                                        BasicConstraints bc, String eku, String policy) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(System.nanoTime()),
                new Date(now - HOUR), new Date(now + 24 * HOUR), new X500Name(dn), subject);
        b.addExtension(Extension.basicConstraints, true, bc);
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(bc.isCA() ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (eku != null) {
            b.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(eku))));
        }
        b.addExtension(Extension.certificatePolicies, false,
                new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(policy))));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
    }

    /** A certificate over {@code tbs} as given, signed SHA256withRSA by {@code key}. */
    private static X509Certificate resign(byte[] tbs, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(tbs);
        byte[] alg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE)
                .getEncoded();
        byte[] sig = new DERBitString(s.sign()).getEncoded();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes(tbs);
        body.writeBytes(alg);
        body.writeBytes(sig);
        ByteArrayOutputStream der = new ByteArrayOutputStream();
        der.write(0x30);
        int len = body.size();
        if (len < 0x80) {
            der.write(len);
        } else if (len < 0x100) {
            der.write(0x81);
            der.write(len);
        } else {
            der.write(0x82);
            der.write(len >> 8);
            der.write(len & 0xff);
        }
        der.writeBytes(body.toByteArray());
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der.toByteArray()));
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
