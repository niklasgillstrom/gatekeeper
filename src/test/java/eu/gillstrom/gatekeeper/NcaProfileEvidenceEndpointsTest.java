package eu.gillstrom.gatekeeper;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Under the {@code nca} profile's mTLS filter chain, the RFC 3161 anchor list
 * is public like {@code /v1/gatekeeper/anchor} (and therefore not caught by
 * the deny-all rule), and the profile starts with the new features unset.
 */
class NcaProfileEvidenceEndpointsTest {

    @Test
    void theAnchorListIsPublicAndTheKeysCarryNoAttestationWhenNoneIsConfigured() throws Exception {
        String dir = System.getProperty("java.io.tmpdir") + "/gatekeeper-nca-evidence-test";
        try (org.springframework.context.ConfigurableApplicationContext context =
                     new org.springframework.boot.builder.SpringApplicationBuilder(
                             DoraAttestationGatekeeperApplication.class)
                             .profiles("nca")
                             .run("--gatekeeper.audit.path=" + dir + "/audit-log.jsonl",
                                     "--gatekeeper.registry.path=" + dir + "/approval-registry.jsonl",
                                     "--gatekeeper.signing.mode=ephemeral",
                                     "--server.ssl.enabled=false",
                                     "--server.port=0")) {
            MockMvc mvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) context)
                    .addFilters(context.getBean("springSecurityFilterChain", Filter.class))
                    .build();

            var list = mvc.perform(get("/v1/gatekeeper/anchor/timestamps")).andReturn().getResponse();
            assertThat(list.getStatus()).as("no client certificate needed").isEqualTo(200);
            assertThat(list.getHeader("X-RateLimit-Remaining")).as("under the rate limiter").isNotNull();
            assertThat(mvc.perform(get("/v1/gatekeeper/anchor/other")).andReturn().getResponse().getStatus())
                    .as("only the named path is opened").isEqualTo(403);

            var keys = new ObjectMapper().readTree(mvc.perform(get("/v1/gatekeeper/keys")).andReturn().getResponse()
                    .getContentAsString());
            assertThat(keys.get(0).has("attestation")).isFalse();
        }
    }
}
