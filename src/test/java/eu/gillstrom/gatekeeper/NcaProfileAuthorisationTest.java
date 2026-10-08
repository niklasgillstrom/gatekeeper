package eu.gillstrom.gatekeeper;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The role matrix of the mTLS filter chain, as the {@code nca} profile
 * configures it: which client certificate reaches which endpoint. A
 * certificate is presented the way the servlet container presents a
 * TLS client certificate, as the {@code jakarta.servlet.request.X509Certificate}
 * request attribute.
 *
 * <p>"Reached" means the request passed authorisation: the controller
 * answered, with whatever status the empty or minimal input earns. "Refused"
 * means 403 from the filter chain.</p>
 *
 * <p>The context is started inside the test method rather than by the Spring
 * test extension, so that a mutation tool attributes the filter-chain
 * construction to this test.</p>
 */
class NcaProfileAuthorisationTest {

    private static final Map<String, X509Certificate> CERTIFICATES = new HashMap<>();

    private MockMvc mvc;

    @BeforeAll
    static void certificates() throws Exception {
        for (String cn : new String[] {"FI-supervisor", "FE-bank", "RAIL-riksbank", "Unmapped-client"}) {
            CERTIFICATES.put(cn, TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), cn));
        }
    }

    @Test
    void theNcaProfileGrantsEachRoleExactlyItsEndpoints() throws Exception {
        String dir = System.getProperty("java.io.tmpdir") + "/gatekeeper-nca-authz-test";
        try (org.springframework.context.ConfigurableApplicationContext context =
                     new org.springframework.boot.builder.SpringApplicationBuilder(
                             DoraAttestationGatekeeperApplication.class)
                             .profiles("nca")
                             .run("--gatekeeper.audit.path=" + dir + "/audit-log.jsonl",
                                     "--gatekeeper.registry.path=" + dir + "/approval-registry.jsonl",
                                     "--gatekeeper.signing.mode=ephemeral",
                                     "--server.ssl.enabled=false",
                                     "--server.port=0")) {
            mvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) context)
                    .addFilters(context.getBean("springSecurityFilterChain", Filter.class))
                    .build();
            publicEndpointsNeedNoCertificate();
            theAuditTrailAndRegistryAreForTheSupervisorOnly();
            verificationAndConfirmationAreForFinancialEntitiesAndTheSupervisor();
            settlementVerificationIsForTheSettlementRailAndTheSupervisor();
            anythingElseIsDeniedEvenToTheSupervisor();
            anUnmappedCertificateIsLoggedAndAMappedOneIsNot();
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

    private void theAuditTrailAndRegistryAreForTheSupervisorOnly() throws Exception {
        for (MockHttpServletRequestBuilder request : new MockHttpServletRequestBuilder[] {
                get("/v1/audit/export"), get("/v1/gatekeeper/health"), get("/v1/attestation/SE/registry/stats")}) {
            reached(request, "FI-supervisor");
        }
        for (String cn : new String[] {"FE-bank", "RAIL-riksbank", "Unmapped-client", null}) {
            refused(get("/v1/audit/export"), cn);
            refused(get("/v1/gatekeeper/health"), cn);
            refused(get("/v1/attestation/SE/registry/stats"), cn);
        }
    }

    private void verificationAndConfirmationAreForFinancialEntitiesAndTheSupervisor() throws Exception {
        for (String path : new String[] {"/v1/attestation/SE/verify", "/v1/attestation/SE/confirm",
                "/v1/attestation/SE/verify/batch"}) {
            reached(json(post(path)), "FE-bank");
            reached(json(post(path)), "FI-supervisor");
            refused(json(post(path)), "RAIL-riksbank");
            refused(json(post(path)), "Unmapped-client");
            refused(json(post(path)), null);
        }
    }

    private void settlementVerificationIsForTheSettlementRailAndTheSupervisor() throws Exception {
        reached(json(post("/api/v1/verify")), "RAIL-riksbank");
        reached(json(post("/api/v1/verify")), "FI-supervisor");
        refused(json(post("/api/v1/verify")), "FE-bank");
        refused(json(post("/api/v1/verify")), "Unmapped-client");
        refused(json(post("/api/v1/verify")), null);
    }

    private void anythingElseIsDeniedEvenToTheSupervisor() throws Exception {
        refused(get("/not-an-endpoint"), "FI-supervisor");
    }

    private void anUnmappedCertificateIsLoggedAndAMappedOneIsNot() throws Exception {
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger)
                org.slf4j.LoggerFactory.getLogger(eu.gillstrom.gatekeeper.security.SecurityConfig.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            reached(json(post("/v1/attestation/SE/verify")), "FE-bank");
            assertThat(appender.list).noneMatch(e -> e.getFormattedMessage().contains("did not match any role"));
            refused(json(post("/v1/attestation/SE/verify")), "Unmapped-client");
            assertThat(appender.list).anyMatch(e -> e.getFormattedMessage()
                    .startsWith("mTLS principal 'Unmapped-client' did not match any role mapping"));
        } finally {
            logger.detachAppender(appender);
        }
    }
}
