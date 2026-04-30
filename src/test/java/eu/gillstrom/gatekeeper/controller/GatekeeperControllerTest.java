package eu.gillstrom.gatekeeper.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Unit tests for {@link GatekeeperController} using {@link MockMvcBuilders#standaloneSetup}
 * so the test runs without bringing up the full Spring context. Each test
 * builds the controller with a real {@link AppendOnlyFileAuditLog} backed
 * by a {@link TempDir}, exercising the same code path production uses.
 */
class GatekeeperControllerTest {

    @TempDir
    Path tempDir;

    private EphemeralReceiptSigner signer;
    private AppendOnlyFileAuditLog auditLog;
    private GatekeeperKeyDirectory keyDirectory;
    private MockMvc mockMvc;
    private ObjectMapper json;

    @BeforeEach
    void setUp() {
        signer = new EphemeralReceiptSigner(2048);
        auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(), signer);
        auditLog.initialise();
        keyDirectory = new GatekeeperKeyDirectory(signer, "");
        keyDirectory.initialise();
        GatekeeperController controller = new GatekeeperController(keyDirectory, auditLog, signer, "ephemeral");
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        json = new ObjectMapper();
        json.registerModule(new JavaTimeModule());
    }

    @Test
    void keysEndpointReturnsActiveSigningCert() throws Exception {
        MvcResult result = mockMvc.perform(get("/v1/gatekeeper/keys"))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);

        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.isArray()).isTrue();
        assertThat(body.size()).isGreaterThanOrEqualTo(1);

        JsonNode active = body.get(0);
        assertThat(active.get("status").asText()).isEqualTo("ACTIVE");
        assertThat(active.get("certificatePem").asText())
                .contains("-----BEGIN CERTIFICATE-----");
        assertThat(active.get("publicKeyFingerprintHex").asText())
                .matches("^[0-9a-f]{64}$");
    }

    @Test
    void anchorEndpointReturnsCurrentChainHead() throws Exception {
        // Append a few entries so the anchor reflects a real head.
        auditLog.append(new AuditAppendRequest(
                "CN=test", "VERIFY", "v-1",
                base64Sha256("req-1"), base64Sha256("rcpt-1"), true));
        auditLog.append(new AuditAppendRequest(
                "CN=test", "VERIFY", "v-2",
                base64Sha256("req-2"), base64Sha256("rcpt-2"), false));

        MvcResult result = mockMvc.perform(get("/v1/gatekeeper/anchor")).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);

        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("headSequenceNumber").asLong()).isEqualTo(2L);
        assertThat(body.get("totalEntries").asLong()).isEqualTo(2L);

        AuditEntry head = auditLog.head().orElseThrow();
        assertThat(body.get("headHashHex").asText()).isEqualTo(head.thisEntryHashHex());
        assertThat(body.get("signingKeyFingerprintHex").asText())
                .isEqualTo(keyDirectory.activeFingerprintHex());
    }

    @Test
    void anchorSignatureVerifiesUnderActiveKey() throws Exception {
        auditLog.append(new AuditAppendRequest(
                "CN=test", "VERIFY", "v-anchor",
                base64Sha256("req"), base64Sha256("rcpt"), true));

        MvcResult result = mockMvc.perform(get("/v1/gatekeeper/anchor")).andReturn();
        JsonNode body = json.readTree(result.getResponse().getContentAsString());

        String headHashHex = body.get("headHashHex").asText();
        byte[] sigBytes = Base64.getDecoder().decode(body.get("headSignatureBase64").asText());

        // Verify the signature against the active key from the directory.
        String pem = keyDirectory.activeKeys().get(0).certificatePem();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(cert.getPublicKey());
        verifier.update(headHashHex.getBytes(StandardCharsets.UTF_8));
        assertThat(verifier.verify(sigBytes))
                .as("anchor signature must verify under the active gatekeeper key")
                .isTrue();
    }

    @Test
    void anchorOnEmptyLogReturnsSentinelHash() throws Exception {
        // No appends at all. The anchor endpoint MUST still produce a
        // signed commitment so a supervisor can prove the gatekeeper
        // observed an empty trail.
        MvcResult result = mockMvc.perform(get("/v1/gatekeeper/anchor")).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("headSequenceNumber").asLong()).isEqualTo(0L);
        assertThat(body.get("totalEntries").asLong()).isEqualTo(0L);
        assertThat(body.get("headHashHex").asText()).isEqualTo(AuditEntry.SENTINEL_PREV_HASH_HEX);
    }

    @Test
    void healthEndpointReportsChainIntactAndMode() throws Exception {
        auditLog.append(new AuditAppendRequest(
                "CN=test", "VERIFY", "v-h",
                base64Sha256("req"), base64Sha256("rcpt"), true));

        MvcResult result = mockMvc.perform(get("/v1/gatekeeper/health")).andReturn();
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("auditLogReadable").asBoolean()).isTrue();
        assertThat(body.get("chainIntact").asBoolean()).isTrue();
        assertThat(body.get("totalEntries").asLong()).isEqualTo(1L);
        assertThat(body.get("mode").asText()).isEqualTo("ephemeral");
    }

    private static String base64Sha256(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(s.getBytes(StandardCharsets.UTF_8)));
    }
}
