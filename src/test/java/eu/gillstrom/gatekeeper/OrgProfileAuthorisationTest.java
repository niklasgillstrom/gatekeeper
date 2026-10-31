package eu.gillstrom.gatekeeper;

import eu.gillstrom.gatekeeper.signing.ConfiguredReceiptSigner;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import eu.gillstrom.gatekeeper.testsupport.TestKeystores;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The role matrix of the mTLS filter chain as the {@code org} profile's
 * template mappings configure it, in the manner of
 * {@link NcaProfileAuthorisationTest}: internal audit and the CISO tool are
 * {@code SUPERVISOR}, the issuance and signing services {@code FE}, and
 * nothing is {@code SETTLEMENT_RAIL}. The organisation's seal is a throwaway
 * PKCS#12 keystore, so the configured signer is the one that loads.
 *
 * <p>"Reached" means the request passed authorisation: the controller
 * answered, with whatever status the empty or minimal input earns. "Refused"
 * means 403 from the filter chain.</p>
 */
class OrgProfileAuthorisationTest {

    private static final String SUPERVISOR_AUDIT = "internal-audit-1";
    private static final String SUPERVISOR_CISO = "ciso-tool-1";
    private static final String FE_ISSUANCE = "issuance-service-1";
    private static final String FE_SIGNING = "signing-service-1";
    private static final String RAIL = "RAIL-riksbank";
    private static final String UNMAPPED = "Unmapped-client";

    private static final Map<String, X509Certificate> CERTIFICATES = new HashMap<>();

    private MockMvc mvc;

    @BeforeAll
    static void certificates() throws Exception {
        for (String cn : new String[] {SUPERVISOR_AUDIT, SUPERVISOR_CISO, FE_ISSUANCE, FE_SIGNING, RAIL, UNMAPPED}) {
            CERTIFICATES.put(cn, TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), cn));
        }
    }

    @Test
    void theOrgProfileGrantsEachRoleExactlyItsEndpoints() throws Exception {
        Path dir = Files.createTempDirectory("gatekeeper-org-authz-test");
        TestKeystores.Written seal = TestKeystores.pkcs12(dir, "org-seal", "Example Organisation Seal", "pw");
        try (org.springframework.context.ConfigurableApplicationContext context =
                     new org.springframework.boot.builder.SpringApplicationBuilder(
                             DoraAttestationGatekeeperApplication.class)
                             .profiles("org")
                             .run("--gatekeeper.audit.path=" + dir + "/audit-log.jsonl",
                                     "--gatekeeper.registry.path=" + dir + "/approval-registry.jsonl",
                                     "--gatekeeper.signing.keystore-path=" + seal.path(),
                                     "--gatekeeper.signing.keystore-password=pw",
                                     "--server.ssl.enabled=false",
                                     "--server.port=0")) {
            assertThat(context.getBean(ReceiptSigner.class)).isInstanceOf(ConfiguredReceiptSigner.class);
            mvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) context)
                    .addFilters(context.getBean("springSecurityFilterChain", Filter.class))
                    .build();
            publicEndpointsNeedNoCertificate();
            auditRegistryHealthAndTriangulationAreForInternalAuditAndTheCisoTool();
            verificationConfirmationAndLifecycleAreForTheServicesAndTheSupervisor();
            settlementVerificationIsForTheSupervisorOnlyWithoutARailMapping();
            theAnchorTimestampsArePublicAndTheCoseExportIsForInternalAuditAndTheCisoTool();
            everyEndpointAddedWithTheEvidenceChainAndTheLifecycleIsRateLimited();
            anythingElseIsDenied();
        }
    }

    private int status(MockHttpServletRequestBuilder request, String cn) throws Exception {
        if (cn != null) {
            X509Certificate certificate = CERTIFICATES.get(cn);
            request.with(r -> {
                r.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[] {certificate});
                return r;
            });
        }
        return mvc.perform(request).andReturn().getResponse().getStatus();
    }

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder request) {
        return request.contentType(MediaType.APPLICATION_JSON).content("{}");
    }

    private void reached(MockHttpServletRequestBuilder request, String cn) throws Exception {
        assertThat(status(request, cn)).as(cn + " reaches it").isNotIn(401, 403);
    }

    private void refused(MockHttpServletRequestBuilder request, String cn) throws Exception {
        assertThat(status(request, cn)).as(cn + " is refused").isEqualTo(403);
    }

    private void publicEndpointsNeedNoCertificate() throws Exception {
        for (String path : new String[] {"/v1/attestation/health", "/v1/attestation/supported-vendors",
                "/v1/gatekeeper/keys", "/v1/gatekeeper/anchor"}) {
            assertThat(status(get(path), null)).as(path).isEqualTo(200);
        }
    }

    private MockHttpServletRequestBuilder[] supervisorOnly() {
        return new MockHttpServletRequestBuilder[] {
                get("/v1/audit/export"),
                get("/v1/gatekeeper/health"),
                get("/v1/attestation/SE/registry/stats"),
                post("/v1/triangulation/SE/inquiries"),
                get("/v1/triangulation/SE/inquiries/unknown/discrepancies"),
                json(post("/v1/triangulation/SE/inquiries/unknown/bank-reports")),
                json(post("/v1/triangulation/SE/inquiries/unknown/operator-report")),
                delete("/v1/triangulation/SE/inquiries/unknown")};
    }

    private void auditRegistryHealthAndTriangulationAreForInternalAuditAndTheCisoTool() throws Exception {
        for (String cn : new String[] {SUPERVISOR_AUDIT, SUPERVISOR_CISO}) {
            for (MockHttpServletRequestBuilder request : supervisorOnly()) {
                reached(request, cn);
            }
        }
        assertThat(status(post("/v1/triangulation/SE/inquiries"), SUPERVISOR_AUDIT)).isEqualTo(201);
        for (String cn : new String[] {FE_ISSUANCE, FE_SIGNING, RAIL, UNMAPPED, null}) {
            for (MockHttpServletRequestBuilder request : supervisorOnly()) {
                refused(request, cn);
            }
        }
    }

    private void verificationConfirmationAndLifecycleAreForTheServicesAndTheSupervisor() throws Exception {
        for (String path : new String[] {"/v1/attestation/SE/verify", "/v1/attestation/SE/confirm",
                "/v1/attestation/SE/verify/batch", "/v1/attestation/SE/lifecycle"}) {
            reached(json(post(path)), FE_ISSUANCE);
            reached(json(post(path)), FE_SIGNING);
            reached(json(post(path)), SUPERVISOR_AUDIT);
            refused(json(post(path)), RAIL);
            refused(json(post(path)), UNMAPPED);
            refused(json(post(path)), null);
        }
    }

    private void settlementVerificationIsForTheSupervisorOnlyWithoutARailMapping() throws Exception {
        reached(json(post("/api/v1/verify")), SUPERVISOR_AUDIT);
        refused(json(post("/api/v1/verify")), RAIL);
        refused(json(post("/api/v1/verify")), FE_ISSUANCE);
        refused(json(post("/api/v1/verify")), FE_SIGNING);
        refused(json(post("/api/v1/verify")), null);
    }

    private MockHttpServletResponse response(MockHttpServletRequestBuilder request, String cn) throws Exception {
        if (cn != null) {
            X509Certificate certificate = CERTIFICATES.get(cn);
            request.with(r -> {
                r.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[] {certificate});
                return r;
            });
        }
        return mvc.perform(request).andReturn().getResponse();
    }

    private static MockHttpServletRequestBuilder coseExport() {
        Instant now = Instant.now();
        return get("/v1/audit/export")
                .param("from", now.minusSeconds(3600).toString())
                .param("to", now.plusSeconds(60).toString())
                .param("format", "cose");
    }

    private void theAnchorTimestampsArePublicAndTheCoseExportIsForInternalAuditAndTheCisoTool() throws Exception {
        for (String cn : new String[] {null, SUPERVISOR_AUDIT, FE_SIGNING, RAIL, UNMAPPED}) {
            assertThat(status(get("/v1/gatekeeper/anchor/timestamps"), cn)).as("anchor timestamps, " + cn)
                    .isEqualTo(200);
        }
        for (String cn : new String[] {SUPERVISOR_AUDIT, SUPERVISOR_CISO}) {
            MockHttpServletResponse cose = response(coseExport(), cn);
            assertThat(cose.getStatus()).as(cn).isEqualTo(200);
            assertThat(cose.getContentType()).startsWith("application/cbor-seq");
        }
        for (String cn : new String[] {FE_ISSUANCE, FE_SIGNING, RAIL, UNMAPPED, null}) {
            refused(coseExport(), cn);
        }
    }

    /**
     * The rate-limit interceptor is registered for each of these paths in this
     * profile: a request that passed it carries {@code X-RateLimit-Remaining}.
     * Which bucket each one draws on is asserted in {@code RateLimitNewEndpointsTest}.
     */
    private void everyEndpointAddedWithTheEvidenceChainAndTheLifecycleIsRateLimited() throws Exception {
        assertThat(response(get("/v1/gatekeeper/anchor/timestamps"), null).getHeader("X-RateLimit-Remaining"))
                .as("anchor timestamps").isNotNull();
        assertThat(response(coseExport(), SUPERVISOR_CISO).getHeader("X-RateLimit-Remaining"))
                .as("COSE export").isNotNull();
        assertThat(response(json(post("/v1/attestation/SE/lifecycle")), FE_SIGNING)
                .getHeader("X-RateLimit-Remaining")).as("lifecycle").isNotNull();
        assertThat(response(post("/v1/triangulation/SE/inquiries"), SUPERVISOR_CISO)
                .getHeader("X-RateLimit-Remaining")).as("triangulation").isNotNull();
        assertThat(response(get("/v1/triangulation/SE/inquiries/unknown/discrepancies"), SUPERVISOR_CISO)
                .getHeader("X-RateLimit-Remaining")).as("triangulation report").isNotNull();
    }

    private void anythingElseIsDenied() throws Exception {
        refused(get("/not-an-endpoint"), SUPERVISOR_AUDIT);
    }
}
