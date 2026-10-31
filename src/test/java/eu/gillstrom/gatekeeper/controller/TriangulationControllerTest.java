package eu.gillstrom.gatekeeper.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.service.InMemoryApprovalRegistry;
import eu.gillstrom.gatekeeper.service.TriangulationService;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** HTTP behaviour and input validation of {@code /v1/triangulation/{countryCode}/inquiries}. */
class TriangulationControllerTest {

    private static final String ISSUER = "CN=Swish Customer CA1 v2 for Swish,O=Getswish AB,C=SE";

    @TempDir
    Path tempDir;

    private MockMvc mvc;
    private final ObjectMapper json = new ObjectMapper();

    @BeforeEach
    void setUp() throws Exception {
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
        GatekeeperKeyDirectory keys = new GatekeeperKeyDirectory(signer, "");
        keys.initialise();
        AppendOnlyFileAuditLog auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(), signer);
        auditLog.initialise();
        TriangulationService service = new TriangulationService(new InMemoryApprovalRegistry(), auditLog,
                new MtlsPrincipalResolver(), signer, keys, 10, 1000);
        mvc = MockMvcBuilders.standaloneSetup(new TriangulationController(service)).build();
    }

    private String createInquiry() throws Exception {
        String body = mvc.perform(MockMvcRequestBuilders.post("/v1/triangulation/se/inquiries"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.countryCode").value("SE"))
                .andExpect(jsonPath("$.createdAt").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body).get("inquiryId").asText();
    }

    private ResultActions postJson(String path, Object body) throws Exception {
        return mvc.perform(MockMvcRequestBuilders.post(path)
                .contentType("application/json")
                .content(json.writeValueAsString(body)));
    }

    private static Map<String, Object> bankEntry(String org, String swish) {
        return Map.of("organisationNumber", org, "swishNumber", swish);
    }

    @Test
    void aWholeInquiryOverHttp() throws Exception {
        String id = createInquiry();
        String base = "/v1/triangulation/SE/inquiries/" + id;

        postJson(base + "/bank-reports", Map.of("bankId", "bank-1", "entries", List.of(
                bankEntry("5569743098", "1231015932"), bankEntry("5560000001", "1230000001"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reporterId").value("bank-1"))
                .andExpect(jsonPath("$.entriesAccepted").value(2))
                .andExpect(jsonPath("$.entriesHeld").value(2))
                .andExpect(jsonPath("$.sha256Hex").isNotEmpty());
        postJson(base + "/operator-report", Map.of("operatorId", "op-1", "entries", List.of(
                Map.of("swishNumber", "1231015932", "certSerial", "0xab", "issuerDn", ISSUER))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.inquiryId").value(id))
                .andExpect(jsonPath("$.reporterId").value("op-1"))
                .andExpect(jsonPath("$.entriesAccepted").value(1))
                .andExpect(jsonPath("$.entriesHeld").value(1))
                .andExpect(jsonPath("$.sha256Hex").isNotEmpty());

        mvc.perform(MockMvcRequestBuilders.get(base + "/discrepancies"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.canonicalVersion").value("tr1"))
                .andExpect(jsonPath("$.inquiryId").value(id))
                .andExpect(jsonPath("$.swishNumbersMissingFromOperatorReport[0].swishNumber").value("1230000001"))
                .andExpect(jsonPath("$.certificatesWithoutVerifiedAttestation[0].registryStatus")
                        .value("NOT_IN_REGISTRY"))
                .andExpect(jsonPath("$.discrepancyCount").value(2))
                .andExpect(jsonPath("$.zeroDiscrepancies").value(false))
                .andExpect(jsonPath("$.inputDigests.bankReports[0].reporterId").value("bank-1"))
                .andExpect(jsonPath("$.inputDigests.operatorReport.entryCount").value(1))
                .andExpect(jsonPath("$.reportSignatureBase64").isNotEmpty())
                .andExpect(jsonPath("$.signatureAlgorithm").value("SHA256withRSA"))
                .andExpect(jsonPath("$.auditEntryHashHex").isNotEmpty());

        postJson(base + "/bank-reports", Map.of("bankId", "bank-2", "entries", List.of(
                bankEntry("5569743098", "1231015932"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("BANK_PHASE_CLOSED"));

        mvc.perform(MockMvcRequestBuilders.delete(base)).andExpect(status().isNoContent());
        mvc.perform(MockMvcRequestBuilders.get(base + "/discrepancies"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("INQUIRY_NOT_FOUND"));
    }

    @Test
    void reportsAreValidatedWithTheVerificationRequestPatterns() throws Exception {
        String base = "/v1/triangulation/SE/inquiries/" + createInquiry();

        for (Object invalid : List.of(
                Map.of("bankId", "b", "entries", List.of(bankEntry("5569743098", "9871234567"))),
                Map.of("bankId", "b", "entries", List.of(bankEntry("556974309", "1231015932"))),
                Map.of("bankId", "b", "entries", List.of(Map.of("organisationNumber", "5569743098",
                        "swishNumber", "1231015932", "certSerial", "ab"))),
                Map.of("bankId", "b", "entries", List.of(Map.of("organisationNumber", "5569743098",
                        "swishNumber", "1231015932", "certSerial", "not-hex", "issuerDn", ISSUER))),
                Map.of("bankId", "", "entries", List.of()),
                Map.of("bankId", "b"))) {
            postJson(base + "/bank-reports", invalid).andExpect(status().isBadRequest());
        }
        for (Object invalid : List.of(
                Map.of("operatorId", "op", "entries", List.of(Map.of("swishNumber", "1231015932",
                        "issuerDn", ISSUER))),
                Map.of("operatorId", "op", "entries", List.of(Map.of("swishNumber", "1231015932",
                        "organisationNumber", "55697430981", "certSerial", "ab", "issuerDn", ISSUER))),
                Map.of("operatorId", "op", "entries", List.of(Map.of("swishNumber", "123101593",
                        "certSerial", "ab", "issuerDn", ISSUER))))) {
            postJson(base + "/operator-report", invalid).andExpect(status().isBadRequest());
        }
        postJson(base + "/operator-report", Map.of("operatorId", "op", "entries", List.of(
                Map.of("swishNumber", "1231015932", "certSerial", "ab", "issuerDn", "not a dn"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("MALFORMED_INPUT"));
    }

    @Test
    void anotherJurisdictionDoesNotSeeTheInquiry() throws Exception {
        String id = createInquiry();
        mvc.perform(MockMvcRequestBuilders.get("/v1/triangulation/DE/inquiries/" + id + "/discrepancies"))
                .andExpect(status().isNotFound());
    }
}
