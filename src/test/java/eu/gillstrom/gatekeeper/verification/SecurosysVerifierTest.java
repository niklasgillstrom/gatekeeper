package eu.gillstrom.gatekeeper.verification;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurosysVerifierTest {

    private SecurosysVerifier verifier;
    private KeyPair attestationKp;
    private List<String> chainPem;
    private String xmlBase64;
    private String signatureBase64;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new SecurosysVerifier();

        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate fakeRoot = TestPki.selfSignedCa(rootKp, "FAKE-SECUROSYS-ROOT");

        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate deviceCert = TestPki.subordinateCa(
                deviceKp, "FAKE-DEVICE SN: 12345", fakeRoot, rootKp.getPrivate());

        attestationKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = TestPki.endEntity(
                attestationKp, "FAKE-ATTEST-LEAF", deviceCert, deviceKp.getPrivate());

        chainPem = List.of(
                TestPki.toPem(attestCert),
                TestPki.toPem(deviceCert),
                TestPki.toPem(fakeRoot));

        String pubKeyB64 = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        String xml = "<attestation>"
                + "<public_key>" + pubKeyB64 + "</public_key>"
                + "<extractable>false</extractable>"
                + "<never_extractable>true</never_extractable>"
                + "<sensitive>true</sensitive>"
                + "<always_sensitive>true</always_sensitive>"
                + "</attestation>";
        byte[] xmlBytes = xml.getBytes(StandardCharsets.UTF_8);
        xmlBase64 = Base64.getEncoder().encodeToString(xmlBytes);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(attestationKp.getPrivate());
        sig.update(xmlBytes);
        signatureBase64 = Base64.getEncoder().encodeToString(sig.sign());
    }

    @Test
    void fakeChainIsNotRootedAtPinnedSecurosysRoot() {
        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                xmlBase64, signatureBase64, chainPem, attestationKp.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.contains("chain"));
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void tamperedSignatureIsRejected() {
        byte[] tampered = Base64.getDecoder().decode(signatureBase64);
        tampered[tampered.length - 1] ^= 0x01;
        String tamperedB64 = Base64.getEncoder().encodeToString(tampered);

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                xmlBase64, tamperedB64, chainPem, attestationKp.getPublic());

        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("signature"));
    }

    @Test
    void importedKeyIsRejectedEvenWithAllFlagsSet() throws Exception {
        // The four flags all have their passing values, but the attestation
        // says the key was imported. never_extractable/always_sensitive are
        // not origin attributes; only creation states where the key came from.
        Signed s = signedXml("imported");

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xmlBase64, s.signatureBase64, chainPem, attestationKp.getPublic());

        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("SECUROSYS_KEY_NOT_GENERATED"));
    }

    @Test
    void missingCreationAttributeIsRejected() throws Exception {
        Signed s = signedXml(null);

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xmlBase64, s.signatureBase64, chainPem, attestationKp.getPublic());

        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("SECUROSYS_KEY_NOT_GENERATED"));
    }

    @Test
    void generatedKeyRaisesNoOriginError() throws Exception {
        Signed s = signedXml("generated");

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                s.xmlBase64, s.signatureBase64, chainPem, attestationKp.getPublic());

        assertThat(r.getErrors()).noneMatch(e -> e.startsWith("SECUROSYS_KEY_NOT_GENERATED"));
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
    }

    private record Signed(String xmlBase64, String signatureBase64) {
    }

    /** Securosys-shape XML with a {@code private_key} root; {@code creation == null} omits the attribute. */
    private Signed signedXml(String creation) throws Exception {
        String pubKeyB64 = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        String xml = "<private_key" + (creation == null ? "" : " creation=\"" + creation + "\"") + ">"
                + "<public_key>" + pubKeyB64 + "</public_key>"
                + "<attributes>"
                + "<extractable>false</extractable>"
                + "<never_extractable>true</never_extractable>"
                + "<sensitive>true</sensitive>"
                + "<always_sensitive>true</always_sensitive>"
                + "</attributes>"
                + "</private_key>";
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(attestationKp.getPrivate());
        sig.update(bytes);
        return new Signed(Base64.getEncoder().encodeToString(bytes),
                Base64.getEncoder().encodeToString(sig.sign()));
    }

    @Test
    void emptyChainProducesError() {
        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                xmlBase64, signatureBase64, Collections.emptyList(), attestationKp.getPublic());

        assertThat(r.getErrors()).isNotEmpty();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("no certificates"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void verifyChainValidatesAgainstThePinnedRoot() throws Exception {
        // It returned true for any input until 1.6.0.
        var node = new com.fasterxml.jackson.databind.ObjectMapper().readTree(java.nio.file.Files.readString(java.nio.file.Path.of("src/test/resources/fixtures/securosys/request.json")));
        java.util.List<X509Certificate> real = new java.util.ArrayList<>();
        var cf = java.security.cert.CertificateFactory.getInstance("X.509");
        for (var pem : node.get("attestationCertChain")) {
            real.add((X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(
                    pem.asText().getBytes(StandardCharsets.UTF_8))));
        }
        assertThat(verifier.verifyChain(real.get(0), real.subList(1, real.size()).toArray(new X509Certificate[0])))
                .isTrue();

        var fakeLeaf = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(
                chainPem.get(0).getBytes(StandardCharsets.UTF_8)));
        var fakeRest = new X509Certificate[] {
                (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(chainPem.get(1).getBytes(StandardCharsets.UTF_8))),
                (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(chainPem.get(2).getBytes(StandardCharsets.UTF_8)))};
        assertThat(verifier.verifyChain(fakeLeaf, fakeRest)).isFalse();
        assertThat(verifier.verifyChain(null, fakeRest)).isFalse();
        assertThat(verifier.verifyChain(real.get(0), null)).as("the leaf alone does not reach the root").isFalse();
    }

    /** Securosys-shape XML, generated key, with the four attributes as given. */
    private Signed signedXmlWith(String extractable, String neverExtractable, String sensitive,
            String alwaysSensitive) throws Exception {
        String pubKeyB64 = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        String xml = "<private_key creation=\"generated\">"
                + "<public_key>" + pubKeyB64 + "</public_key>"
                + "<attributes>"
                + "<extractable>" + extractable + "</extractable>"
                + "<never_extractable>" + neverExtractable + "</never_extractable>"
                + "<sensitive>" + sensitive + "</sensitive>"
                + "<always_sensitive>" + alwaysSensitive + "</always_sensitive>"
                + "</attributes>"
                + "</private_key>";
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(attestationKp.getPrivate());
        sig.update(bytes);
        return new Signed(Base64.getEncoder().encodeToString(bytes),
                Base64.getEncoder().encodeToString(sig.sign()));
    }

    @Test
    void eachKeyAttributeIsChecked() throws Exception {
        String[][] cases = {
                {"true", "true", "true", "true", "Key attribute extractable must be false"},
                {"false", "false", "true", "true", "Key attribute never_extractable must be true"},
                {"false", "true", "false", "true", "Key attribute sensitive must be true"},
                {"false", "true", "true", "false", "Key attribute always_sensitive must be true"}};
        for (String[] c : cases) {
            Signed s = signedXmlWith(c[0], c[1], c[2], c[3]);
            SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                    s.xmlBase64, s.signatureBase64, chainPem, attestationKp.getPublic());
            assertThat(r.getErrors()).as(c[4]).contains(c[4]);
            assertThat(r.getErrors()).as(c[4]).filteredOn(e -> e.startsWith("Key attribute")).hasSize(1);
            assertThat(r.isExtractable()).isEqualTo(Boolean.parseBoolean(c[0]));
            assertThat(r.isNeverExtractable()).isEqualTo(Boolean.parseBoolean(c[1]));
            assertThat(r.isSensitive()).isEqualTo(Boolean.parseBoolean(c[2]));
            assertThat(r.isAlwaysSensitive()).isEqualTo(Boolean.parseBoolean(c[3]));
        }
        Signed good = signedXmlWith("false", "true", "true", "true");
        assertThat(verifier.verifySecurosysAttestation(good.xmlBase64, good.signatureBase64, chainPem,
                attestationKp.getPublic()).getErrors()).noneMatch(e -> e.startsWith("Key attribute"));
    }

    @Test
    void theRealAttestationIsValidAndReportsItsKey() throws Exception {
        var node = new com.fasterxml.jackson.databind.ObjectMapper().readTree(
                java.nio.file.Files.readString(java.nio.file.Path.of("src/test/resources/fixtures/securosys/request.json")));
        List<String> chain = new java.util.ArrayList<>();
        node.get("attestationCertChain").forEach(n -> chain.add(n.asText()));
        java.security.PublicKey csrKey;
        try (var parser = new org.bouncycastle.openssl.PEMParser(new java.io.StringReader(node.get("csr").asText()))) {
            csrKey = new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest(
                    (org.bouncycastle.pkcs.PKCS10CertificationRequest) parser.readObject()).getPublicKey();
        }

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                node.get("attestationData").asText(), node.get("attestationSignature").asText(), chain, csrKey);

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isExtractable()).isFalse();
        assertThat(r.isNeverExtractable()).isTrue();
        assertThat(r.isSensitive()).isTrue();
        assertThat(r.isAlwaysSensitive()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.getKeyLabel()).isEqualTo("rsa_4096_sign");
        assertThat(r.getAlgorithm()).isEqualTo("RSA");
        assertThat(r.getKeySize()).isEqualTo("4096");
        assertThat(r.getCreateTime()).isEqualTo("2025-10-01T20:31:53Z");
        assertThat(r.getHsmSerialNumber()).isNotBlank();
    }

    @Test
    void aDoctypeInTheAttestationIsRefusedByTheParser() throws Exception {
        // Even a correctly signed attestation is parsed with DOCTYPE refused, so an
        // external entity (XXE) is never resolved.
        String pubKeyB64 = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE p [<!ENTITY x SYSTEM \"file:///etc/hostname\">]>"
                + "<private_key creation=\"generated\"><label>&x;</label>"
                + "<public_key>" + pubKeyB64 + "</public_key></private_key>";
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(attestationKp.getPrivate());
        sig.update(bytes);

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                Base64.getEncoder().encodeToString(bytes), Base64.getEncoder().encodeToString(sig.sign()),
                chainPem, attestationKp.getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("Verification error") && e.contains("DOCTYPE"));
    }
}
