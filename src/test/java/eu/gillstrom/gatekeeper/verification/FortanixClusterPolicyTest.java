package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
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
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The statement in a Fortanix attestation about what the cluster's nodes run on:
 * {@code fortanixClusterNodeEnrollmentPolicy} in the Key Attestation Authority
 * certificate. Until 1.7.0 it was not read, and a statement from a cluster
 * that claimed no protection profile for its nodes was accepted. Every chain
 * here is valid under a throwaway root, so only the policy decides.
 */
class FortanixClusterPolicyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long HOUR = 3_600_000L;
    private static final String SITE_OPERATOR_APPROVAL = "1.3.6.1.4.1.49690.2.5.2";

    private static KeyPair rootKp;
    private static X509Certificate root;
    private static KeyPair caKp;
    private static X509Certificate ca;
    private static KeyPair authKp;
    private static KeyPair target;
    private static long now;

    @BeforeAll
    static void pki() throws Exception {
        now = System.currentTimeMillis();
        rootKp = TestPki.newRsaKeyPair(2048);
        root = TestPki.selfSignedCa(rootKp, "TEST-FORTANIX-ROOT");
        caKp = TestPki.newRsaKeyPair(2048);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(root, BigInteger.valueOf(System.nanoTime()),
                new Date(now - HOUR), new Date(now + 24 * HOUR), new X500Name("CN=CA"), caKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        b.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(
                new PolicyInformation(new ASN1ObjectIdentifier(FortanixVerifier.POLICY_KEY_ATTESTATION_PKI))));
        ca = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(rootKp.getPrivate())));
        authKp = TestPki.newRsaKeyPair(2048);
        target = TestPki.newRsaKeyPair(2048);
    }

    private static ASN1Encodable item(String policyItem, ASN1Encodable... qualifier) {
        ASN1Encodable[] fields = new ASN1Encodable[1 + qualifier.length];
        fields[0] = new ASN1ObjectIdentifier(policyItem);
        System.arraycopy(qualifier, 0, fields, 1, qualifier.length);
        return new DERSequence(fields);
    }

    private static ASN1Encodable fx2200() {
        return item(FortanixVerifier.POLICY_ITEM_MINIMUM_PROTECTION_PROFILE,
                new ASN1ObjectIdentifier(FortanixVerifier.PROTECTION_PROFILE_FX2200));
    }

    /** An authority certificate whose enrolment policy has {@code items}; none at all omits the extension. */
    private static X509Certificate authority(ASN1Encodable... items) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(ca, BigInteger.valueOf(System.nanoTime()),
                new Date(now - HOUR), new Date(now + 24 * HOUR), new X500Name("CN=AUTH"), authKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.getInstance(
                new ASN1ObjectIdentifier(FortanixVerifier.EKU_KEY_ATTESTATION_SIGNING))));
        b.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(
                new PolicyInformation(new ASN1ObjectIdentifier(FortanixVerifier.POLICY_KEY_ATTESTATION_PKI))));
        if (items.length > 0) {
            b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.CLUSTER_NODE_ENROLLMENT_POLICY), false,
                    new DERSequence(items));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(caKp.getPrivate())));
    }

    private static FortanixVerifier.FortanixResult verify(X509Certificate authority) throws Exception {
        long signedAt = now - 60_000L;
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(authority.getSubjectX500Principal().getEncoded()), BigInteger.valueOf(signedAt),
                new Date(signedAt), new Date(253402300799000L), new X500Name("CN=Fortanix DSM Key Attestation"),
                target.getPublic());
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.KEY_GENERATED_IN_DSM), false, new DERSequence());
        b.addExtension(new ASN1ObjectIdentifier(FortanixVerifier.KEY_NEVER_EXPORTABLE), false, new DERSequence());
        X509Certificate statement = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(authKp.getPrivate())));

        ObjectNode n = MAPPER.createObjectNode();
        ArrayNode chain = n.putArray("authority_chain");
        chain.add(Base64.getEncoder().encodeToString(authority.getEncoded()));
        chain.add(Base64.getEncoder().encodeToString(ca.getEncoded()));
        ObjectNode s = n.putObject("attestation_statement");
        s.put("format", "x509_certificate");
        s.put("statement", Base64.getEncoder().encodeToString(statement.getEncoded()));
        return new FortanixVerifier(root).verifyFortanixAttestation(MAPPER.writeValueAsString(n), target.getPublic());
    }

    private static String notStated(String found) {
        return "FORTANIX_CLUSTER_PROFILE_NOT_STATED: the Key Attestation Authority certificate does not state "
                + "fortanixFX2200 as the minimum protection profile of the cluster's nodes "
                + "(fortanixClusterNodeEnrollmentPolicy; found " + found + ")";
    }

    @Test
    void aClusterWhoseNodesMustBeFx2200IsAccepted() throws Exception {
        for (X509Certificate authority : new X509Certificate[] {
                authority(fx2200()),
                authority(fx2200(), item(SITE_OPERATOR_APPROVAL)),
                authority(item(SITE_OPERATOR_APPROVAL), fx2200())}) {
            FortanixVerifier.FortanixResult r = verify(authority);

            assertThat(r.getErrors()).isEmpty();
            assertThat(r.isValid()).isTrue();
            assertThat(r.getMinimumProtectionProfile()).isEqualTo("1.3.6.1.4.1.49690.2.5.1.1");
        }
    }

    @Test
    void anAuthorityCertificateWithoutTheEnrolmentPolicyIsRefused() throws Exception {
        FortanixVerifier.FortanixResult r = verify(authority());

        assertThat(r.getErrors()).containsExactly(notStated("none"));
        assertThat(r.isChainValid()).as("the chain is valid; the claim is missing").isTrue();
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.getMinimumProtectionProfile()).isNull();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void aPolicyThatNamesNoProtectionProfileIsRefused() throws Exception {
        assertThat(verify(authority(item(SITE_OPERATOR_APPROVAL))).getErrors())
                .as("site-operator approval alone").containsExactly(notStated("none"));
        assertThat(verify(authority(item(FortanixVerifier.POLICY_ITEM_MINIMUM_PROTECTION_PROFILE))).getErrors())
                .as("the item without its qualifier").containsExactly(notStated("none"));
    }

    @Test
    void anotherProtectionProfileThanFx2200IsRefusedAndNamed() throws Exception {
        FortanixVerifier.FortanixResult r = verify(authority(item(
                FortanixVerifier.POLICY_ITEM_MINIMUM_PROTECTION_PROFILE,
                new ASN1ObjectIdentifier("1.3.6.1.4.1.49690.2.5.1.99"))));

        assertThat(r.getErrors()).containsExactly(notStated("1.3.6.1.4.1.49690.2.5.1.99"));
        assertThat(r.getMinimumProtectionProfile()).isEqualTo("1.3.6.1.4.1.49690.2.5.1.99");
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void aProfileThatIsNotAnObjectIdentifierIsMalformed() throws Exception {
        FortanixVerifier.FortanixResult r = verify(authority(item(
                FortanixVerifier.POLICY_ITEM_MINIMUM_PROTECTION_PROFILE, new DERUTF8String("FX2200"))));

        assertThat(r.getErrors()).singleElement().asString().startsWith("FORTANIX_STATEMENT_MALFORMED: ");
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void fortanixsDocumentedAuthorityCertificateStatesFx2200() throws Exception {
        String sample = Files.readString(Path.of("src/test/resources/vendor-fixtures/fortanix/key_attestation.json"));
        byte[] statement = Base64.getDecoder().decode(
                MAPPER.readTree(sample).path("attestation_statement").path("statement").asText());
        X509Certificate attested = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(statement));

        FortanixVerifier.FortanixResult r = new FortanixVerifier().verifyFortanixAttestation(
                sample, attested.getPublicKey());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.getMinimumProtectionProfile()).isEqualTo(FortanixVerifier.PROTECTION_PROFILE_FX2200);
    }
}
