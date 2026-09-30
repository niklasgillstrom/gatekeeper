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
    private JsonNode fixture;

    @BeforeEach
    void setUp() throws Exception {
        try (InputStream in = AttestationSignatureValidityTest.class
                .getResourceAsStream("/fixtures/securosys/request.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        AppendOnlyFileAuditLog auditLog = new AppendOnlyFileAuditLog(
                tempDir.resolve("audit.jsonl").toString(), new EphemeralReceiptSigner(2048));
        auditLog.initialise();
        service = new VerificationService(
                new SecurosysVerifier(),
                mock(YubicoVerifier.class),
                mock(AzureHsmVerifier.class),
                mock(GoogleCloudHsmVerifier.class),
                new InMemoryApprovalRegistry(),
                new EphemeralReceiptSigner(2048),
                mock(IssuerCaValidator.class),
                auditLog,
                new MtlsPrincipalResolver(),
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
}
