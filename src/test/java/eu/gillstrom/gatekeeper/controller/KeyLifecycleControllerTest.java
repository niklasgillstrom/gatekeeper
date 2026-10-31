package eu.gillstrom.gatekeeper.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.KeyLifecycleRequest;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.service.InMemoryApprovalRegistry;
import eu.gillstrom.gatekeeper.service.KeyLifecycleService;
import eu.gillstrom.gatekeeper.service.SignatureVerificationService;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.util.Fingerprints;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** HTTP behaviour of {@code POST /v1/attestation/{countryCode}/lifecycle}. */
class KeyLifecycleControllerTest {

    @TempDir
    Path tempDir;

    private MockMvc mvc;
    private final ObjectMapper json = new ObjectMapper();
    private InMemoryApprovalRegistry registry;
    private KeyPair leafKp;
    private X509Certificate leaf;

    @BeforeEach
    void setUp() throws Exception {
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
        GatekeeperKeyDirectory keys = new GatekeeperKeyDirectory(signer, "");
        keys.initialise();
        AppendOnlyFileAuditLog auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(), signer);
        auditLog.initialise();
        registry = new InMemoryApprovalRegistry();
        SignatureVerificationService settlement =
                new SignatureVerificationService(registry, auditLog, new MtlsPrincipalResolver(), signer, keys);
        KeyLifecycleService service =
                new KeyLifecycleService(settlement, registry, auditLog, new MtlsPrincipalResolver(), false);
        mvc = MockMvcBuilders.standaloneSetup(new KeyLifecycleController(service)).build();

        KeyPair issuerKp = TestPki.newRsaKeyPair(2048);
        X509Certificate issuer = TestPki.selfSignedCa(issuerKp, "Controller Issuer CA");
        leafKp = TestPki.newRsaKeyPair(2048);
        leaf = TestPki.endEntity(leafKp, "Controller Leaf", issuer, issuerKp.getPrivate());
        String fp = Fingerprints.ofPublicKey(leafKp.getPublic());
        registry.register("VID-C", "n", true, fp, "5569743098", "TL AB", "SECUROSYS", "Primus HSM", "SE", "fe");
        registry.confirm("VID-C", "n", true, fp, true, ApprovalRegistry.IssuedCertificate.of(leaf));
    }

    private Map<String, Object> body(String eventType) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("eventType", eventType);
        b.put("certSerial", leaf.getSerialNumber().toString(16));
        b.put("issuerDn", leaf.getIssuerX500Principal().getName());
        if (!KeyLifecycleRequest.SIGNED.equals(eventType)) {
            b.put("reason", "test");
        }
        return b;
    }

    private ResultActions send(String countryCode, Map<String, Object> body) throws Exception {
        return mvc.perform(MockMvcRequestBuilders.post("/v1/attestation/" + countryCode + "/lifecycle")
                .contentType("application/json")
                .content(json.writeValueAsString(body)));
    }

    @Test
    void anAppliedChangeIs200AndARefusedOne409() throws Exception {
        send("se", body("ROTATED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eventType").value("ROTATED"))
                .andExpect(jsonPath("$.applied").value(true))
                .andExpect(jsonPath("$.reason").value("OK"))
                .andExpect(jsonPath("$.verificationId").value("VID-C"))
                .andExpect(jsonPath("$.previousStatus").value("VERIFIED_AND_ISSUED"))
                .andExpect(jsonPath("$.registryStatus").value("SUPERSEDED"))
                .andExpect(jsonPath("$.auditEntryHashHex").isNotEmpty());

        send("SE", body("ROTATED"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.applied").value(false))
                .andExpect(jsonPath("$.reason").value("TRANSITION_NOT_ALLOWED"))
                .andExpect(jsonPath("$.registryStatus").value("SUPERSEDED"));
    }

    @Test
    void anUnknownCertificateIs404AndAnUnknownSuccessor409() throws Exception {
        Map<String, Object> unknown = body("REVOKED");
        unknown.put("certSerial", "ffffff");
        send("SE", unknown)
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("CERT_NOT_FOUND"));

        Map<String, Object> rotation = body("ROTATED");
        rotation.put("successorVerificationId", "VID-NOBODY");
        send("SE", rotation)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("SUCCESSOR_NOT_FOUND"));
    }

    @Test
    void anIssuerThatDoesNotParseIs400MalformedInput() throws Exception {
        Map<String, Object> b = body("DECOMMISSIONED");
        b.put("issuerDn", "no equals sign");
        send("SE", b)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("MALFORMED_INPUT"));
    }

    @Test
    void anIncompleteOrInconsistentBodyIs400() throws Exception {
        Map<String, Object> noReason = body("REVOKED");
        noReason.remove("reason");
        send("SE", noReason).andExpect(status().isBadRequest());

        send("SE", body("SIGNED")).andExpect(status().isBadRequest());

        send("SE", body("EXPIRED")).andExpect(status().isBadRequest());

        Map<String, Object> successorOnRevocation = body("REVOKED");
        successorOnRevocation.put("successorVerificationId", "VID-X");
        send("SE", successorOnRevocation).andExpect(status().isBadRequest());

        Map<String, Object> noSerial = body("REVOKED");
        noSerial.remove("certSerial");
        send("SE", noSerial).andExpect(status().isBadRequest());
    }

    @Test
    void aSignedEventAnswersWithTheSettlementShapePlusTheEventType() throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest("x".getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("SHA512withRSA");
        s.initSign(leafKp.getPrivate());
        s.update(digest);
        Map<String, Object> b = body("SIGNED");
        b.put("digestHex", HexFormat.of().formatHex(digest));
        b.put("signatureBase64", Base64.getEncoder().encodeToString(s.sign()));

        send("SE", b)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eventType").value("SIGNED"))
                .andExpect(jsonPath("$.signatureValid").value(true))
                .andExpect(jsonPath("$.compliant").value(true))
                .andExpect(jsonPath("$.auditEntryId").value("VID-C"))
                .andExpect(jsonPath("$.reason").value("OK"))
                .andExpect(jsonPath("$.auditEntryHashHex").isNotEmpty())
                .andExpect(jsonPath("$.verifiedAt").isNotEmpty())
                .andExpect(jsonPath("$.verdictSignatureBase64").isNotEmpty())
                .andExpect(jsonPath("$.verdictSignatureAlgorithm").value("SHA256withRSA"))
                .andExpect(jsonPath("$.signingKeyFingerprintHex").isNotEmpty())
                .andExpect(jsonPath("$.verdict").doesNotExist());

        // A denial is still 200, as on /api/v1/verify.
        send("DE", b)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("CERT_NOT_FOUND"));
    }

}
