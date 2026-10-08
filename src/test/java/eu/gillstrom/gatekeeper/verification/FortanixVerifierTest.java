package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
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

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link FortanixVerifier} against the sample statement in Fortanix's
 * documentation (see {@code src/test/resources/vendor-fixtures/fortanix/NOTICE.md})
 * and against synthetic chains that isolate each check.
 */
class FortanixVerifierTest {

    private static final Path SAMPLE = Path.of("src/test/resources/vendor-fixtures/fortanix/key_attestation.json");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long HOUR = 3_600_000L;

    private static KeyPair rootKp;
    private static X509Certificate root;
    private static KeyPair caKp;
    private static X509Certificate ca;
    private static KeyPair authKp;
    private static X509Certificate authority;
    private static KeyPair target;

    @BeforeAll
    static void pki() throws Exception {
        long now = System.currentTimeMillis();
        rootKp = TestPki.newRsaKeyPair(2048);
        root = TestPki.selfSignedCa(rootKp, "TEST-FORTANIX-ROOT");
        caKp = TestPki.newRsaKeyPair(2048);
        ca = cert(caKp.getPublic(), "CN=CA", root, rootKp.getPrivate(), true, null, true, now - HOUR, now + 24 * HOUR);
        authKp = TestPki.newRsaKeyPair(2048);
        authority = cert(authKp.getPublic(), "CN=AUTH", ca, caKp.getPrivate(), false,
                FortanixVerifier.EKU_KEY_ATTESTATION_SIGNING, true, now - HOUR, now + 24 * HOUR);
        target = TestPki.newRsaKeyPair(2048);
    }

    private static String sample() throws Exception {
        return Files.readString(SAMPLE);
    }

    private static PublicKey sampleKey() throws Exception {
        return statementOf(sample()).getPublicKey();
    }

    private static X509Certificate statementOf(String json) throws Exception {
        byte[] der = Base64.getDecoder().decode(MAPPER.readTree(json).path("attestation_statement").path("statement").asText());
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    @Test
    @DisplayName("Fortanix's documented statement verifies under the pinned root at its signing time")
    void sampleStatementVerifies() throws Exception {
        FortanixVerifier.FortanixResult r = new FortanixVerifier().verifyFortanixAttestation(sample(), sampleKey());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.isExportable()).isFalse();
        assertThat(r.getKeyId()).isEqualTo("18ec8b96-8845-4ce3-9fd1-50407b4b1fc0");
    }

    @Test
    @DisplayName("The documented statement does not attest another key, and fails under another root")
    void sampleRefusesOtherKeyAndRoot() throws Exception {
        assertThat(new FortanixVerifier().verifyFortanixAttestation(sample(), target.getPublic()).getErrors())
                .anyMatch(e -> e.startsWith("FORTANIX_PUBLIC_KEY_MISMATCH"));
        assertThat(new FortanixVerifier(root).verifyFortanixAttestation(sample(), sampleKey()).getErrors())
                .anyMatch(e -> e.startsWith("FORTANIX_CHAIN_INVALID"));
    }

    @Test
    @DisplayName("One changed byte in the documented statement breaks its signature")
    void tamperedSampleIsRefused() throws Exception {
        ObjectNode n = (ObjectNode) MAPPER.readTree(sample());
        byte[] der = Base64.getDecoder().decode(n.path("attestation_statement").path("statement").asText());
        der[200] ^= 0x01;
        ((ObjectNode) n.get("attestation_statement")).put("statement", Base64.getEncoder().encodeToString(der));

        FortanixVerifier.FortanixResult r = new FortanixVerifier().verifyFortanixAttestation(
                MAPPER.writeValueAsString(n), sampleKey());
        assertThat(r.isValid()).isFalse();
    }

    @Test
    @DisplayName("Synthetic: a well-formed statement verifies; each claim is required")
    void claimsAreRequired() throws Exception {
        FortanixVerifier v = new FortanixVerifier(root);
        long now = System.currentTimeMillis();
        assertThat(v.verifyFortanixAttestation(json(statement(true, true, false, now - 60_000L)), target.getPublic())
                .getErrors()).as("well-formed").isEmpty();

        assertThat(v.verifyFortanixAttestation(json(statement(false, true, false, now - 60_000L)), target.getPublic())
                .getErrors()).anyMatch(e -> e.startsWith("FORTANIX_KEY_NOT_GENERATED"));
        assertThat(v.verifyFortanixAttestation(json(statement(true, false, false, now - 60_000L)), target.getPublic())
                .getErrors()).anyMatch(e -> e.startsWith("FORTANIX_KEY_EXPORTABLE"));
        assertThat(v.verifyFortanixAttestation(json(statement(true, true, true, now - 60_000L)), target.getPublic())
                .getErrors()).anyMatch(e -> e.contains("unknown critical extension"));
    }

    @Test
    @DisplayName("Synthetic: signing time in the future or outside the authority's validity is refused")
    void signingTimeIsChecked() throws Exception {
        FortanixVerifier v = new FortanixVerifier(root);
        long now = System.currentTimeMillis();
        assertThat(v.verifyFortanixAttestation(json(statement(true, true, false, now + HOUR)), target.getPublic())
                .getErrors()).anyMatch(e -> e.contains("future"));
        assertThat(v.verifyFortanixAttestation(json(statement(true, true, false, now - 2 * HOUR)), target.getPublic())
                .getErrors()).anyMatch(e -> e.startsWith("FORTANIX_STATEMENT_INVALID"));
    }

    @Test
    @DisplayName("Synthetic: an authority without the EKU or the attestation policy is refused")
    void authorityChecks() throws Exception {
        FortanixVerifier v = new FortanixVerifier(root);
        long now = System.currentTimeMillis();
        X509Certificate noEku = cert(authKp.getPublic(), "CN=AUTH", ca, caKp.getPrivate(), false, null, true,
                now - HOUR, now + 24 * HOUR);
        assertThat(v.verifyFortanixAttestation(json(noEku, statement(true, true, false, now - 60_000L)), target.getPublic())
                .getErrors()).anyMatch(e -> e.contains("EKU"));

        X509Certificate noPolicy = cert(authKp.getPublic(), "CN=AUTH", ca, caKp.getPrivate(), false,
                FortanixVerifier.EKU_KEY_ATTESTATION_SIGNING, false, now - HOUR, now + 24 * HOUR);
        assertThat(v.verifyFortanixAttestation(json(noPolicy, statement(true, true, false, now - 60_000L)), target.getPublic())
                .getErrors()).anyMatch(e -> e.startsWith("FORTANIX_CHAIN_INVALID"));
    }

    @Test
    @DisplayName("Synthetic: a statement naming another issuer, or an authority whose Key Usage excludes signing, is refused")
    void issuerNameAndKeyUsage() throws Exception {
        FortanixVerifier v = new FortanixVerifier(root);
        long now = System.currentTimeMillis();

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=Someone Else"),
                BigInteger.ONE, new Date(now - 60_000L), new Date(253402300799000L),
                new X500Name("CN=Fortanix DSM Key Attestation"), target.getPublic());
        b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.KEY_GENERATED_IN_DSM), false, new DERSequence());
        b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.KEY_NEVER_EXPORTABLE), false, new DERSequence());
        X509Certificate otherIssuer = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(authKp.getPrivate())));
        assertThat(v.verifyFortanixAttestation(json(otherIssuer), target.getPublic()).getErrors())
                .anyMatch(e -> e.contains("issuer is not the Key Attestation Authority"));

        JcaX509v3CertificateBuilder a = new JcaX509v3CertificateBuilder(ca, BigInteger.TWO,
                new Date(now - HOUR), new Date(now + 24 * HOUR), new X500Name("CN=AUTH"), authKp.getPublic());
        a.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        a.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyEncipherment));
        a.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.getInstance(
                new ASN1ObjectIdentifier(FortanixVerifier.EKU_KEY_ATTESTATION_SIGNING))));
        a.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(
                new PolicyInformation(new ASN1ObjectIdentifier(FortanixVerifier.POLICY_KEY_ATTESTATION_PKI))));
        X509Certificate noSigning = new JcaX509CertificateConverter().getCertificate(
                a.build(new JcaContentSignerBuilder("SHA256withRSA").build(caKp.getPrivate())));
        assertThat(v.verifyFortanixAttestation(json(noSigning, statement(true, true, false, now - 60_000L)),
                target.getPublic()).getErrors()).anyMatch(e -> e.contains("Key Usage"));
    }

    // ---- synthetic builders ---------------------------------------------------------

    private static X509Certificate statement(boolean generated, boolean neverExportable, boolean extraCritical,
                                             long signedAt) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(authority.getSubjectX500Principal().getEncoded()), BigInteger.valueOf(signedAt),
                new Date(signedAt), new Date(253402300799000L), new X500Name("CN=Fortanix DSM Key Attestation"),
                target.getPublic());
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        if (generated) {
            b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.KEY_GENERATED_IN_DSM), false, new DERSequence());
        }
        if (neverExportable) {
            b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.KEY_NEVER_EXPORTABLE), false, new DERSequence());
        }
        if (extraCritical) {
            b.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.49690.9.9"), true, new DERSequence());
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(authKp.getPrivate())));
    }

    private static String json(X509Certificate statement) throws Exception {
        return json(authority, statement);
    }

    private static String json(X509Certificate auth, X509Certificate statement) throws Exception {
        ObjectNode n = MAPPER.createObjectNode();
        ArrayNode chain = n.putArray("authority_chain");
        chain.add(Base64.getEncoder().encodeToString(auth.getEncoded()));
        chain.add(Base64.getEncoder().encodeToString(ca.getEncoded()));
        ObjectNode s = n.putObject("attestation_statement");
        s.put("format", "x509_certificate");
        s.put("statement", Base64.getEncoder().encodeToString(statement.getEncoded()));
        return MAPPER.writeValueAsString(n);
    }

    private static X509Certificate cert(PublicKey subject, String dn, X509Certificate issuer, PrivateKey issuerKey,
                                        boolean isCa, String eku, boolean policy, long from, long to) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(System.nanoTime()),
                new Date(from), new Date(to), new X500Name(dn), subject);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(isCa ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (eku != null) {
            b.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(eku))));
        }
        if (policy) {
            b.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(
                    new PolicyInformation(new ASN1ObjectIdentifier(FortanixVerifier.POLICY_KEY_ATTESTATION_PKI))));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
    }
}
