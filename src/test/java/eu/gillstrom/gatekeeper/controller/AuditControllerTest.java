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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests for {@link AuditController}. Each test exercises a property a
 * supervisory inspection team relies on:
 * <ul>
 *   <li>witness lookup is stable per verification ID</li>
 *   <li>404 on unknown ID</li>
 *   <li>range queries are correctly half-open</li>
 *   <li>range &gt; 90 days is rejected</li>
 *   <li>principal queries return only that principal's entries</li>
 *   <li>export is signed and the signature verifies under the active key</li>
 * </ul>
 */
class AuditControllerTest {

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
        AuditController controller = new AuditController(auditLog, signer, keyDirectory);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
        json = new ObjectMapper();
        json.registerModule(new JavaTimeModule());
    }

    private AuditEntry append(String principal, String op, String verifId, boolean compliant) throws Exception {
        return auditLog.append(new AuditAppendRequest(
                principal, op, verifId,
                base64Sha256("req-" + verifId),
                op.equals("CONFIRM") ? null : base64Sha256("rcpt-" + verifId),
                compliant));
    }

    @Test
    void findEntryReturnsCorrectEntry() throws Exception {
        append("CN=swish", "VERIFY", "v-find-1", true);
        AuditEntry target = append("CN=swish", "VERIFY", "v-find-2", false);
        append("CN=swish", "VERIFY", "v-find-3", true);

        MvcResult result = mockMvc.perform(get("/v1/audit/witness/v-find-2")).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("verificationId").asText()).isEqualTo("v-find-2");
        assertThat(body.get("sequenceNumber").asLong()).isEqualTo(target.sequenceNumber());
        assertThat(body.get("compliant").asBoolean()).isFalse();
    }

    @Test
    void findEntryReturns404ForUnknownId() throws Exception {
        append("CN=swish", "VERIFY", "v-known", true);

        MvcResult result = mockMvc.perform(get("/v1/audit/witness/v-not-here")).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(404);
    }

    @Test
    void rangeQueryFiltersByTimestamp() throws Exception {
        AuditEntry e1 = append("CN=a", "VERIFY", "vr-1", true);
        append("CN=a", "VERIFY", "vr-2", true);
        AuditEntry e3 = append("CN=a", "VERIFY", "vr-3", true);

        // Wide window: every entry must be present.
        Instant from = e1.timestamp().minusSeconds(1);
        Instant to = e3.timestamp().plusSeconds(1);

        MvcResult result = mockMvc.perform(get("/v1/audit/range")
                        .param("from", DateTimeFormatter.ISO_INSTANT.format(from))
                        .param("to", DateTimeFormatter.ISO_INSTANT.format(to)))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        List<String> ids = new ArrayList<>();
        body.forEach(n -> ids.add(n.get("verificationId").asText()));
        assertThat(ids).contains("vr-1", "vr-2", "vr-3");

        // Window that ends before any entry returns empty.
        MvcResult empty = mockMvc.perform(get("/v1/audit/range")
                        .param("from", DateTimeFormatter.ISO_INSTANT.format(from))
                        .param("to", DateTimeFormatter.ISO_INSTANT.format(from.plusMillis(1))))
                .andReturn();
        assertThat(empty.getResponse().getStatus()).isEqualTo(200);
        assertThat(json.readTree(empty.getResponse().getContentAsString()).size()).isEqualTo(0);
    }

    @Test
    void rangeQueryRejectsRangeOver90Days() throws Exception {
        Instant from = Instant.parse("2024-01-01T00:00:00Z");
        Instant to = from.plusSeconds(91L * 24 * 60 * 60); // 91 days

        MvcResult result = mockMvc.perform(get("/v1/audit/range")
                        .param("from", DateTimeFormatter.ISO_INSTANT.format(from))
                        .param("to", DateTimeFormatter.ISO_INSTANT.format(to)))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void entityQueryReturnsAllForPrincipal() throws Exception {
        append("CN=swish,O=GetSwish", "VERIFY", "ve-1", true);
        append("CN=other", "VERIFY", "ve-2", true);
        append("CN=swish,O=GetSwish", "CONFIRM", "ve-1", true);
        append("CN=swish,O=GetSwish", "VERIFY", "ve-3", false);

        String encoded = URLEncoder.encode("CN=swish,O=GetSwish", StandardCharsets.UTF_8);
        MvcResult result = mockMvc.perform(get("/v1/audit/entity/" + encoded)).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.size()).isEqualTo(3);
        body.forEach(n -> assertThat(n.get("mtlsClientPrincipal").asText())
                .isEqualTo("CN=swish,O=GetSwish"));
    }

    @Test
    void exportContainsValidSignatureOverAllEntries() throws Exception {
        AuditEntry e1 = append("CN=swish", "VERIFY", "ve-x-1", true);
        AuditEntry e2 = append("CN=swish", "VERIFY", "ve-x-2", true);
        AuditEntry e3 = append("CN=swish", "CONFIRM", "ve-x-1", true);

        Instant from = e1.timestamp().minusSeconds(1);
        Instant to = e3.timestamp().plusSeconds(1);

        MvcResult result = mockMvc.perform(get("/v1/audit/export")
                        .param("from", DateTimeFormatter.ISO_INSTANT.format(from))
                        .param("to", DateTimeFormatter.ISO_INSTANT.format(to))
                        .param("inspectionId", "INSPECTION-2026-001"))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);

        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("inspectionId").asText()).isEqualTo("INSPECTION-2026-001");
        assertThat(body.get("entryCount").asLong()).isEqualTo(3L);
        assertThat(body.get("signingKeyFingerprintHex").asText())
                .isEqualTo(keyDirectory.activeFingerprintHex());

        // Reconstruct the canonical bytes and verify the signature.
        List<AuditEntry> exportedEntries = new ArrayList<>();
        exportedEntries.add(e1);
        exportedEntries.add(e2);
        exportedEntries.add(e3);

        Instant generatedAt = Instant.parse(body.get("generatedAt").asText());
        byte[] canonical = AuditExport.canonicalBytesForSignature(
                "INSPECTION-2026-001",
                generatedAt,
                from, to,
                3,
                exportedEntries,
                body.get("chainHeadHashAtExport").asText(),
                body.get("signingKeyFingerprintHex").asText());

        byte[] sig = Base64.getDecoder().decode(body.get("exportSignatureBase64").asText());
        String pem = keyDirectory.activeKeys().get(0).certificatePem();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(cert.getPublicKey());
        verifier.update(canonical);
        assertThat(verifier.verify(sig))
                .as("export signature must verify under the active gatekeeper key")
                .isTrue();
    }

    @Test
    void exportGeneratesInspectionIdWhenAbsent() throws Exception {
        append("CN=swish", "VERIFY", "ve-noid", true);

        Instant from = Instant.now().minusSeconds(60);
        Instant to = Instant.now().plusSeconds(60);
        MvcResult result = mockMvc.perform(get("/v1/audit/export")
                        .param("from", DateTimeFormatter.ISO_INSTANT.format(from))
                        .param("to", DateTimeFormatter.ISO_INSTANT.format(to)))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("inspectionId").asText()).isNotBlank();
    }

    private static String base64Sha256(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(s.getBytes(StandardCharsets.UTF_8)));
    }
}
