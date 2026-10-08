package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behaviour of {@link SecurosysVerifier} that the main test leaves open: an
 * attestation without a usable public key, a mismatched CSR key, the wording
 * of the key-origin refusal, a lone attestation certificate, a root-only
 * chain, and the generic {@link HsmAttestationVerifier} entry points.
 */
class SecurosysVerifierMutationTest {

    /** The Securosys Primus HSM root CA the verifier pins (CN=PRIMUS_HSM_ROOTKEY). */
    private static final String SECUROSYS_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            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
            4WzEkJhoDVG+m/ScmyguyvqBkkYBEuX0Yg==
            -----END CERTIFICATE-----
            """;

    private final SecurosysVerifier verifier = new SecurosysVerifier();

    private KeyPair attestationKp;
    private String attestationCertPem;
    private List<String> chainPem;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKp, "TEST-SECUROSYS-ROOT");
        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate device = TestPki.subordinateCa(
                deviceKp, "PRIMUS HSM KEY (SN: 18386101)", root, rootKp.getPrivate());
        attestationKp = TestPki.newRsaKeyPair(2048);
        X509Certificate leaf = TestPki.endEntity(
                attestationKp, "attestation-key", device, deviceKp.getPrivate());
        attestationCertPem = TestPki.toPem(leaf);
        chainPem = List.of(attestationCertPem, TestPki.toPem(device), TestPki.toPem(root));
    }

    // ---- attested public key -----------------------------------------------------------------

    @Test
    void anAttestationWithoutAPublicKeyIsRefused() throws Exception {
        Signed s = sign(privateKeyXml("generated", null));

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xml, s.signature, chainPem, attestationKp.getPublic());

        assertThat(r.getErrors()).contains("Could not extract public_key from XML");
        assertThat(r.getErrors()).noneMatch(e -> e.startsWith("Public key mismatch"));
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void aPublicKeyThatIsNotBase64IsRefused() throws Exception {
        Signed s = sign(privateKeyXml("generated", "not*base64!"));

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xml, s.signature, chainPem, attestationKp.getPublic());

        assertThat(r.getErrors()).contains("Could not extract public_key from XML");
        assertThat(r.isPublicKeyMatch()).isFalse();
    }

    @Test
    void aCsrKeyOtherThanTheAttestedKeyIsRefused() throws Exception {
        String attested = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        Signed s = sign(privateKeyXml("generated", attested));
        KeyPair otherKp = TestPki.newRsaKeyPair(2048);

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xml, s.signature, chainPem, otherKp.getPublic());

        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.getErrors()).contains("Public key mismatch: CSR key does not match attested key");
        assertThat(r.isValid()).isFalse();
    }

    // ---- key origin wording ------------------------------------------------------------------

    @Test
    void theOriginRefusalNamesTheStatedCreationOrMissing() throws Exception {
        String attested = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());

        Signed imported = sign(privateKeyXml("imported", attested));
        assertThat(verifier.verifySecurosysAttestation(imported.xml, imported.signature, chainPem,
                attestationKp.getPublic()).getErrors())
                .anyMatch(e -> e.startsWith("SECUROSYS_KEY_NOT_GENERATED") && e.endsWith("(creation=imported)"));

        Signed missing = sign(privateKeyXml(null, attested));
        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                missing.xml, missing.signature, chainPem, attestationKp.getPublic());
        assertThat(r.getErrors())
                .anyMatch(e -> e.startsWith("SECUROSYS_KEY_NOT_GENERATED") && e.endsWith("(creation=<missing>)"));
        assertThat(r.getKeyOrigin()).isNull();
    }

    // ---- chain shapes ------------------------------------------------------------------------

    @Test
    void aLoneAttestationCertificateIsVerifiedWithoutAnHsmSerial() throws Exception {
        String attested = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        Signed s = sign(privateKeyXml("generated", attested));

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xml, s.signature, List.of(attestationCertPem), attestationKp.getPublic());

        assertThat(r.getHsmSerialNumber()).isNull();
        assertThat(r.getKeyLabel()).isEqualTo("signing-key");
        // Not rooted at Securosys; every other check passes.
        assertThat(r.getErrors()).containsExactly("Certificate chain verification failed");
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void aChainOfOnlyThePinnedRootIsRefused() throws Exception {
        String attested = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        Signed s = sign(privateKeyXml("generated", attested));

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xml, s.signature, List.of(SECUROSYS_ROOT_PEM), attestationKp.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).contains("Certificate chain verification failed");
        assertThat(r.isValid()).isFalse();
    }

    // ---- XML parsing: every entity route is closed by the DOCTYPE refusal ---------------------

    @Test
    void anExternalDtdOrParameterEntityIsRefusedAtTheDoctype() throws Exception {
        String body = "<private_key creation=\"generated\"><label>x</label></private_key>";
        String[] doctypes = {
                "<!DOCTYPE private_key SYSTEM \"http://127.0.0.1:1/attack.dtd\">",
                "<!DOCTYPE private_key [<!ENTITY % p SYSTEM \"file:///etc/hostname\"> %p;]>"};
        for (String doctype : doctypes) {
            Signed s = sign("<?xml version=\"1.0\"?>" + doctype + body);

            SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                    s.xml, s.signature, chainPem, attestationKp.getPublic());

            assertThat(r.getErrors()).as(doctype)
                    .anyMatch(e -> e.startsWith("Verification error") && e.contains("DOCTYPE"));
            assertThat(r.getKeyLabel()).as(doctype).isNull();
            assertThat(r.isValid()).isFalse();
        }
    }

    @Test
    void anEntityReferenceWithoutADoctypeIsRefused() throws Exception {
        Signed s = sign("<private_key creation=\"generated\"><label>&x;</label></private_key>");

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xml, s.signature, chainPem, attestationKp.getPublic());

        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("Verification error") && e.contains("\"x\""));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void theParserIsTheJdksWithSecureProcessingAndItsResourceLimits() throws Exception {
        assertThat(javax.xml.parsers.DocumentBuilderFactory.newDefaultInstance()
                .getFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING)).isTrue();

        StringBuilder attributes = new StringBuilder();
        for (int i = 0; i <= 10_000; i++) {
            attributes.append(" a").append(i).append("=\"x\"");
        }
        Signed s = sign("<private_key creation=\"generated\"" + attributes + "><label>l</label></private_key>");

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xml, s.signature, chainPem, attestationKp.getPublic());

        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("Verification error") && e.contains("JAXP00010002"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void anXIncludeElementIsNotProcessed() throws Exception {
        String attested = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        Signed s = sign("<private_key creation=\"generated\" xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
                + "<public_key>" + attested + "</public_key>"
                + "<label><xi:include href=\"file:///etc/hostname\" parse=\"text\"/></label>"
                + "</private_key>");

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xml, s.signature, chainPem, attestationKp.getPublic());

        assertThat(r.getKeyLabel()).isEmpty();
        assertThat(r.isPublicKeyMatch()).isTrue();
    }

    // ---- HsmAttestationVerifier entry points -------------------------------------------------

    @Test
    void vendorModelAndSerial() throws Exception {
        JsonNode fixture;
        try (InputStream in = SecurosysVerifierMutationTest.class.getResourceAsStream("/fixtures/securosys/request.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        X509Certificate realLeaf = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(fixture.get("attestationCertChain").get(0).asText()
                        .getBytes(StandardCharsets.UTF_8)));

        assertThat(verifier.getVendor()).isEqualTo(HsmVendor.SECUROSYS);
        assertThat(verifier.extractModel(realLeaf)).isEqualTo("Primus HSM");
        assertThat(verifier.extractSerialNumber(realLeaf)).isEqualTo("d5627f7c9bf96af8fed5ec8858345b91");
    }

    // ---- helpers -----------------------------------------------------------------------------

    private record Signed(String xml, String signature) {
    }

    /**
     * Securosys-shape attestation for a non-extractable, sensitive key labelled
     * {@code signing-key}. {@code creation == null} omits the attribute,
     * {@code publicKey == null} omits the element.
     */
    private static String privateKeyXml(String creation, String publicKey) {
        return "<private_key" + (creation == null ? "" : " creation=\"" + creation + "\"") + ">"
                + (publicKey == null ? "" : "<public_key>" + publicKey + "</public_key>")
                + "<label>signing-key</label>"
                + "<attributes>"
                + "<extractable>false</extractable>"
                + "<never_extractable>true</never_extractable>"
                + "<sensitive>true</sensitive>"
                + "<always_sensitive>true</always_sensitive>"
                + "</attributes>"
                + "</private_key>";
    }

    private Signed sign(String xml) throws Exception {
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(attestationKp.getPrivate());
        sig.update(bytes);
        return new Signed(Base64.getEncoder().encodeToString(bytes), Base64.getEncoder().encodeToString(sig.sign()));
    }
}
