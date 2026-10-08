package eu.gillstrom.gatekeeper.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.VerificationRequest;
import eu.gillstrom.gatekeeper.model.VerificationResponse;
import eu.gillstrom.gatekeeper.model.VerificationResponse.DoraCompliance;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.verification.AzureHsmVerifier;
import eu.gillstrom.gatekeeper.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AttestationSignatureValidityTest {

    @TempDir
    Path tempDir;

    private VerificationService service;
    /**
     * The published vendor samples attest RSA-2048 and EC P-256 keys, not the
     * RSA-4096 the default policy requires; this service also allows those.
     */
    private VerificationService sampleService;
    private JsonNode fixture;

    @BeforeEach
    void setUp() throws Exception {
        try (InputStream in = AttestationSignatureValidityTest.class
                .getResourceAsStream("/fixtures/securosys/request.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        service = service(KeyPolicy.defaults(), "audit.jsonl");
        sampleService = service(new KeyPolicy("RSA-4096,RSA-2048,EC-secp256r1"), "samples.jsonl");
    }

    private VerificationService service(KeyPolicy keyPolicy, String auditFile) throws Exception {
        AppendOnlyFileAuditLog auditLog = new AppendOnlyFileAuditLog(
                tempDir.resolve(auditFile).toString(), new EphemeralReceiptSigner(2048));
        auditLog.initialise();
        return new VerificationService(
                new SecurosysVerifier(),
                new YubicoVerifier(),
                mock(AzureHsmVerifier.class),
                mock(GoogleCloudHsmVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.MarvellHsmVerifier.class),
                new eu.gillstrom.gatekeeper.verification.ThalesLunaVerifier(),
                new eu.gillstrom.gatekeeper.verification.Crypto4AVerifier(),
                new eu.gillstrom.gatekeeper.verification.FortanixVerifier(),
                new eu.gillstrom.gatekeeper.verification.NShieldVerifier(),
                new InMemoryApprovalRegistry(),
                new EphemeralReceiptSigner(2048),
                mock(IssuerCaValidator.class),
                auditLog,
                new MtlsPrincipalResolver(),
                keyPolicy,
                false);
    }

    private VerificationRequest securosysRequest(String attestationDataBase64) {
        List<String> chain = new ArrayList<>();
        for (JsonNode pem : fixture.get("attestationCertChain")) {
            chain.add(pem.asText());
        }
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey(fixture.get("csr").asText());
        request.setHsmVendor("SECUROSYS");
        request.setAttestationData(attestationDataBase64);
        request.setAttestationSignature(fixture.get("attestationSignature").asText());
        request.setAttestationCertChain(chain);
        request.setSupplierIdentifier("556000-0000");
        request.setSupplierName("Svensk TL");
        request.setCountryCode("SE");
        return request;
    }

    @Test
    void genuineSecurosysAttestationSetsEveryArticleBit() {
        VerificationResponse receipt = service.verify(
                securosysRequest(fixture.get("attestationData").asText()));

        assertThat(receipt.getErrors()).isEmpty();
        assertThat(receipt.isCompliant()).isTrue();
        assertThat(receipt.getKeyProperties().isGeneratedOnDevice()).isTrue();
        DoraCompliance dora = receipt.getDoraCompliance();
        assertThat(dora.isArticle5_2b()).isTrue();
        assertThat(dora.isArticle6_10()).isTrue();
        assertThat(dora.isArticle9_3c()).isTrue();
        assertThat(dora.isArticle9_3d()).isTrue();
        assertThat(dora.isArticle9_4d()).isTrue();
        assertThat(dora.isArticle28_1a()).isTrue();
    }

    @Test
    void tamperedSecurosysAttestationWithGenuineChainSetsNoArticleBit() {
        String xml = new String(
                Base64.getDecoder().decode(fixture.get("attestationData").asText()), StandardCharsets.UTF_8);
        String tampered = xml.replace("<label>rsa_4096_sign</label>", "<label>rsa_4096_sigX</label>");
        assertThat(tampered).isNotEqualTo(xml);

        VerificationResponse receipt = service.verify(securosysRequest(
                Base64.getEncoder().encodeToString(tampered.getBytes(StandardCharsets.UTF_8))));

        assertThat(receipt.getKeyProperties().isAttestationChainValid()).isTrue();
        assertThat(receipt.getKeyProperties().isPublicKeyMatchesAttestation()).isTrue();
        assertThat(receipt.getErrors()).anyMatch(e -> e.contains("XML signature verification failed"));
        assertThat(receipt.isCompliant()).isFalse();
        assertThat(receipt.getKeyProperties().isGeneratedOnDevice()).isFalse();
        DoraCompliance dora = receipt.getDoraCompliance();
        assertThat(dora.isArticle5_2b()).isFalse();
        assertThat(dora.isArticle6_10()).isFalse();
        assertThat(dora.isArticle9_3c()).isFalse();
        assertThat(dora.isArticle9_3d()).isFalse();
        assertThat(dora.isArticle9_4d()).isFalse();
        assertThat(dora.isArticle28_1a()).isFalse();
    }

    @Test
    void genuineYubiHsm2AttestationSetsEveryArticleBit() throws Exception {
        // The reference YubiHSM 2's attestation of an RSA-4096 key
        // (src/test/resources/fixtures/yubico/request.json), under the default key policy.
        JsonNode yubico;
        try (InputStream in = AttestationSignatureValidityTest.class
                .getResourceAsStream("/fixtures/yubico/request.json")) {
            yubico = new ObjectMapper().readTree(in);
        }
        List<String> chain = new ArrayList<>();
        for (JsonNode pem : yubico.get("attestationCertChain")) {
            chain.add(pem.asText());
        }
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey(yubico.get("csr").asText());
        request.setHsmVendor("YUBICO");
        request.setAttestationCertChain(chain);
        request.setSupplierIdentifier("556000-0000");
        request.setSupplierName("Svensk TL");
        request.setCountryCode("SE");

        VerificationResponse receipt = service.verify(request);

        assertThat(receipt.getErrors()).isEmpty();
        assertThat(receipt.isCompliant()).isTrue();
        assertThat(receipt.getKeyProperties().isGeneratedOnDevice()).isTrue();
        DoraCompliance dora = receipt.getDoraCompliance();
        assertThat(dora.isArticle5_2b()).isTrue();
        assertThat(dora.isArticle6_10()).isTrue();
        assertThat(dora.isArticle9_3c()).isTrue();
        assertThat(dora.isArticle9_3d()).isTrue();
        assertThat(dora.isArticle9_4d()).isTrue();
        assertThat(dora.isArticle28_1a()).isTrue();
    }

    @Test
    void genuineThalesLunaPkcSetsEveryArticleBit() throws Exception {
        VerificationResponse receipt = sampleService.verify(thalesRequest());

        assertThat(receipt.getErrors()).isEmpty();
        assertThat(receipt.isCompliant()).isTrue();
        DoraCompliance dora = receipt.getDoraCompliance();
        assertThat(dora.isArticle9_3d()).isTrue();
        assertThat(dora.isArticle9_4d()).isTrue();
    }

    private static VerificationRequest thalesRequest() throws Exception {
        // Thales's own PKC test vector and the CSR its key signed
        // (src/test/resources/vendor-fixtures/thales-luna/NOTICE.md).
        java.nio.file.Path dir = java.nio.file.Path.of("src/test/resources/vendor-fixtures/thales-luna");
        String csr = java.nio.file.Files.readString(dir.resolve("rsa-test.csr"), StandardCharsets.US_ASCII)
                .replace("NEW CERTIFICATE REQUEST", "CERTIFICATE REQUEST");
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey(csr);
        request.setHsmVendor("THALES");
        request.setAttestationData(Base64.getEncoder().encodeToString(
                java.nio.file.Files.readAllBytes(dir.resolve("rsa-pkc.p7b"))));
        request.setSupplierIdentifier("556000-0000");
        request.setSupplierName("Svensk TL");
        request.setCountryCode("SE");
        return request;
    }

    @Test
    void genuineCrypto4AMessageSetsEveryArticleBit() throws Exception {
        VerificationResponse receipt = sampleService.verify(crypto4aRequest());

        assertThat(receipt.getErrors()).isEmpty();
        assertThat(receipt.isCompliant()).isTrue();
        assertThat(receipt.getDoraCompliance().isArticle9_3d()).isTrue();
    }

    private static VerificationRequest crypto4aRequest() throws Exception {
        // The PKI Consortium's published QASM attestation message
        // (src/test/resources/vendor-fixtures/crypto4a/NOTICE.md); the CSR key is
        // the EC key its key-spki claim names.
        byte[] message = java.nio.file.Files.readAllBytes(
                java.nio.file.Path.of("src/test/resources/vendor-fixtures/crypto4a/attestation.der"));
        byte[] spki = null;
        var claims = org.bouncycastle.asn1.ASN1Sequence.getInstance(org.bouncycastle.asn1.ASN1Sequence.getInstance(
                org.bouncycastle.asn1.ASN1Sequence.getInstance(message).getObjectAt(1)).getObjectAt(1));
        for (var e : claims) {
            var claim = org.bouncycastle.asn1.ASN1Sequence.getInstance(e);
            if ("1.3.6.1.4.1.39901.6.2.1".equals(claim.getObjectAt(0).toString())) {
                var complement = org.bouncycastle.asn1.ASN1TaggedObject.getInstance(claim.getObjectAt(2));
                spki = org.bouncycastle.asn1.ASN1OctetString.getInstance(org.bouncycastle.asn1.ASN1TaggedObject
                        .getInstance(complement.getExplicitBaseObject()), false).getOctets();
            }
        }
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey("-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(spki) + "\n-----END PUBLIC KEY-----");
        request.setHsmVendor("CRYPTO4A");
        request.setAttestationData(Base64.getEncoder().encodeToString(message));
        request.setSupplierIdentifier("556000-0000");
        request.setSupplierName("Svensk TL");
        request.setCountryCode("SE");
        return request;
    }

    @Test
    void genuineFortanixStatementSetsEveryArticleBit() throws Exception {
        VerificationResponse receipt = sampleService.verify(fortanixRequest());

        assertThat(receipt.getErrors()).isEmpty();
        assertThat(receipt.isCompliant()).isTrue();
        assertThat(receipt.getDoraCompliance().isArticle9_3d()).isTrue();
    }

    private static VerificationRequest fortanixRequest() throws Exception {
        // The sample statement in Fortanix's documentation
        // (src/test/resources/vendor-fixtures/fortanix/NOTICE.md); the CSR key is
        // the key the statement attests.
        String json = java.nio.file.Files.readString(
                java.nio.file.Path.of("src/test/resources/vendor-fixtures/fortanix/key_attestation.json"));
        byte[] statement = Base64.getDecoder().decode(new ObjectMapper().readTree(json)
                .path("attestation_statement").path("statement").asText());
        byte[] spki = ((java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(statement))).getPublicKey().getEncoded();
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey("-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(spki) + "\n-----END PUBLIC KEY-----");
        request.setHsmVendor("FORTANIX");
        request.setAttestationData(json);
        request.setSupplierIdentifier("556000-0000");
        request.setSupplierName("Svensk TL");
        request.setCountryCode("SE");
        return request;
    }

    @Test
    void entrustsFieldUpgradeBundlesSetNoArticleBit() throws Exception {
        // Entrust's example bundles carry FieldUpgradeModuleInformation
        // warrants, which depend on legacy DSA-1024 signatures and are refused;
        // NShieldVerifierTest verifies the rest of each bundle.
        java.math.BigInteger n = new java.math.BigInteger(
                "ad3ee904799b1c0a7376b751edb09f2ade867bafcf726703fa92713b2190e4094b58ec7c88223b2aacc008143d5348c9"
                        + "16ceeba995305c40152546b89b0dc36b95d336c2cb0cc8d885b37afd6ac8567ce77ac47912f28fe8d721d9355b2d"
                        + "26ce7ee6ef6242ea610601a541b9bb0334d5dd45fc48108a486cbe976d717f1e6762c11baff96971dd8ef39f6c8e"
                        + "3ee091b7b833f68ddd45d8f0a99feaf9c0e675bde0574b0224c1cc1bded2969b6c819cdc623303087481f1d38abc"
                        + "9f97c3e8ed96cfdbc83673cb638c4314c2fdf37b0eac38599f27cdaead8ece3f59eb81c556353577fe8be6500504"
                        + "8ae1df5f60ed52ed0bb518a2b39b18f82b7bbd7d2615234b", 16);
        byte[] rsa = java.security.KeyFactory.getInstance("RSA").generatePublic(
                new java.security.spec.RSAPublicKeySpec(n, java.math.BigInteger.valueOf(65537))).getEncoded();
        for (List<Object> c : List.<List<Object>>of(List.of("key_pkcs11_test2.att", nshieldSoftcardKey()),
                List.of("key_simple_test1.att", rsa))) {
            VerificationResponse receipt = sampleService.verify(nshieldRequest((String) c.get(0),
                    "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString((byte[]) c.get(1))
                            + "\n-----END PUBLIC KEY-----"));

            assertThat(receipt.getErrors()).containsExactly("NSHIELD_WARRANT_INVALID: FieldUpgradeModuleInformation "
                    + "warrants depend on legacy DSA-1024 signatures (Entrust) and are not accepted");
            assertThat(receipt.isCompliant()).isFalse();
            DoraCompliance dora = receipt.getDoraCompliance();
            assertThat(dora.isArticle9_3d()).isFalse();
            assertThat(dora.isArticle9_4d()).isFalse();
            assertThat(dora.isArticle28_1a()).isFalse();
        }
    }

    /** The EC P-256 key of Entrust's softcard example, as a DER SubjectPublicKeyInfo. */
    private static byte[] nshieldSoftcardKey() throws Exception {
        var parameters = java.security.AlgorithmParameters.getInstance("EC");
        parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
        return java.security.KeyFactory.getInstance("EC").generatePublic(new java.security.spec.ECPublicKeySpec(
                new java.security.spec.ECPoint(
                        new java.math.BigInteger("df62d0efed4c48300897c4dab40d26574e129cd39cd946c877494ed31bcfd0dd", 16),
                        new java.math.BigInteger("9d8e0277ea5489bae9c38769545ae65161cb3d8a02f924a62a80b5d0e683cc20", 16)),
                parameters.getParameterSpec(java.security.spec.ECParameterSpec.class))).getEncoded();
    }

    private static VerificationRequest nshieldRequest(String bundle, String publicKeyPem) throws Exception {
        // Entrust's example bundles (src/test/resources/vendor-fixtures/nshield/NOTICE.md).
        VerificationRequest request = new VerificationRequest();
        request.setPublicKey(publicKeyPem);
        request.setHsmVendor("ENTRUST");
        request.setAttestationData(java.nio.file.Files.readString(
                java.nio.file.Path.of("src/test/resources/vendor-fixtures/nshield", bundle)));
        request.setSupplierIdentifier("556000-0000");
        request.setSupplierName("Svensk TL");
        request.setCountryCode("SE");
        return request;
    }

    @Test
    void defaultPolicyRefusesEveryKeyButRsa4096() throws Exception {
        // The genuine samples verify, but their keys are not RSA-4096.
        var cases = List.of(
                List.of(thalesRequest(), "RSA-2048"),
                List.of(crypto4aRequest(), "EC-secp256r1"),
                List.of(fortanixRequest(), "RSA-2048"));
        for (List<Object> c : cases) {
            VerificationResponse receipt = service.verify((VerificationRequest) c.get(0));
            assertThat(receipt.getErrors()).containsExactly(
                    "KEY_NOT_ALLOWED: key " + c.get(1) + " is not in the allowed keys [rsa-4096]");
            assertThat(receipt.getKeyProperties().isAttestationChainValid()).isTrue();
            assertThat(receipt.getKeyProperties().isPublicKeyMatchesAttestation()).isTrue();
            assertThat(receipt.isCompliant()).isFalse();
            // The article bits describe the attestation, which verified; 28(1)(a)
            // follows the overall finding.
            assertThat(receipt.getDoraCompliance().isArticle9_3d()).isTrue();
            assertThat(receipt.getDoraCompliance().isArticle28_1a()).isFalse();
            assertThat(receipt.getDoraCompliance().getSummary()).isEqualTo("Non-compliant: key " + c.get(1)
                    + " is not in the allowed keys [rsa-4096]. The attestation evidence verified, but the key "
                    + "is not one the scheme accepts.");
        }
        // The Securosys sample is an RSA-4096 key and passes the default policy
        // (genuineSecurosysAttestationSetsEveryArticleBit).
    }

    @Test
    void keyPolicyFailureIsListedWithAttestationFailures() throws Exception {
        VerificationRequest request = fortanixRequest();
        request.setAttestationData(request.getAttestationData().replace("x509_certificate", "jwt"));
        VerificationResponse receipt = service.verify(request);
        assertThat(receipt.isCompliant()).isFalse();
        assertThat(receipt.getDoraCompliance().getSummary()).startsWith("Non-compliant: attestation chain invalid, "
                + "attestation signature invalid, public key does not match attestation, key not generated on device, "
                + "key is exportable, key RSA-2048 is not in the allowed keys [rsa-4096]. ");
    }
}
