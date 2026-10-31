package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * The gatekeeper started without {@code gatekeeper.trust-anchors.*} (the
 * configuration of {@code ApplicationContextLoadsTest}): every verifier bean
 * holds exactly the anchor its no-argument constructor pins, the real
 * YubiHSM 2 fixture verifies through the bean as before, and
 * GET /v1/attestation/supported-vendors reports every anchor as pinned.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = {
        "gatekeeper.audit.path=${java.io.tmpdir}/gatekeeper-context-test/audit-log.jsonl",
        "gatekeeper.registry.path=${java.io.tmpdir}/gatekeeper-context-test/approval-registry.jsonl"
})
class TrustAnchorDefaultWiringTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void everyVerifierBeanHoldsItsPinnedAnchor() throws Exception {
        assertThat(context.getBean(YubicoVerifier.class).rootCa()).isEqualTo(new YubicoVerifier().rootCa());
        assertThat(context.getBean(SecurosysVerifier.class).rootCa()).isEqualTo(new SecurosysVerifier().rootCa());
        assertThat(context.getBean(AzureHsmVerifier.class).marvellRoots())
                .containsExactlyElementsOf(new AzureHsmVerifier().marvellRoots());
        assertThat(context.getBean(MarvellHsmVerifier.class).marvellRoots())
                .containsExactlyElementsOf(new MarvellHsmVerifier().marvellRoots());
        assertThat(context.getBean(GoogleCloudHsmVerifier.class).marvellRoots())
                .containsExactlyElementsOf(new GoogleCloudHsmVerifier().marvellRoots());
        assertThat(context.getBean(GoogleCloudHsmVerifier.class).ownerRoot())
                .isEqualTo(new GoogleCloudHsmVerifier().ownerRoot());
        assertThat(context.getBean(ThalesLunaVerifier.class).rootKey()).isEqualTo(new ThalesLunaVerifier().rootKey());
        assertThat(context.getBean(Crypto4AVerifier.class).rootKey()).isEqualTo(new Crypto4AVerifier().rootKey());
        assertThat(context.getBean(FortanixVerifier.class).root()).isEqualTo(new FortanixVerifier().root());
        assertThat(context.getBean(NShieldVerifier.class).rootKey().getEncoded())
                .isEqualTo(new NShieldVerifier().rootKey().getEncoded());

        JsonNode fixture = TrustAnchorsTest.fixture("/fixtures/yubico/request.json");
        assertThat(context.getBean(YubicoVerifier.class).verifyYubicoAttestation(
                TrustAnchorsTest.texts(fixture.get("attestationCertChain")),
                TrustAnchorsTest.csrKey(fixture.get("csr").asText())).isValid()).isTrue();
    }

    @Test
    void supportedVendorsReportsEveryAnchorAsPinned() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) context).build();
        JsonNode vendors = new ObjectMapper().readTree(mvc.perform(get("/v1/attestation/supported-vendors"))
                .andReturn().getResponse().getContentAsString());

        Map<String, List<String>> anchorsByVendor = new LinkedHashMap<>();
        TrustAnchors pinned = TrustAnchors.pinned();
        for (JsonNode v : vendors) {
            List<String> keys = new ArrayList<>();
            for (JsonNode a : v.get("trustAnchors")) {
                String key = a.get("anchor").asText();
                keys.add(key);
                assertThat(a.get("origin").asText()).as(key).isEqualTo("pinned");
                assertThat(a.hasNonNull("path")).as(key).isFalse();
                assertThat(a.get("matchesPinned").asBoolean()).as(key).isTrue();
                List<String> sha256 = new ArrayList<>();
                a.get("sha256").forEach(s -> sha256.add(s.asText()));
                assertThat(sha256).as(key).isEqualTo(pinned.active(key).sha256());
                assertThat(a.get("sha256Of").asText()).as(key).isEqualTo(pinned.active(key).sha256Of());
            }
            anchorsByVendor.put(v.get("vendorId").asText(), keys);
        }
        assertThat(anchorsByVendor).containsExactly(
                Map.entry("SECUROSYS", List.of("securosys")),
                Map.entry("YUBICO", List.of("yubico")),
                Map.entry("AZURE", List.of("marvell")),
                Map.entry("GOOGLE", List.of("marvell", "google-owner")),
                Map.entry("MARVELL", List.of("marvell")),
                Map.entry("THALES", List.of("thales")),
                Map.entry("CRYPTO4A", List.of("crypto4a")),
                Map.entry("FORTANIX", List.of("fortanix")),
                Map.entry("ENTRUST", List.of("entrust")));
    }
}
