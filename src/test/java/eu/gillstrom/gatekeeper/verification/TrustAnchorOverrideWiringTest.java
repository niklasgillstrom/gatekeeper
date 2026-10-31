package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * The gatekeeper started with {@code gatekeeper.trust-anchors.yubico} naming
 * a test root: the YubicoVerifier bean, the one VerificationService and
 * SigningKeyAttestation are built with, starts from that root. A test-PKI
 * attestation verifies, the real YubiHSM 2 fixture does not, and
 * GET /v1/attestation/supported-vendors reports the override (without its
 * server path) for YUBICO and the pinned anchors for every other vendor.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = {
        "gatekeeper.audit.path=${java.io.tmpdir}/gatekeeper-trust-anchor-test/${random.uuid}/audit-log.jsonl",
        "gatekeeper.registry.path=${java.io.tmpdir}/gatekeeper-trust-anchor-test/approval-registry.jsonl"
})
class TrustAnchorOverrideWiringTest {

    private static KeyPair rootKeys;
    private static X509Certificate root;
    private static Path rootFile;

    @DynamicPropertySource
    static void yubicoOverride(DynamicPropertyRegistry registry) throws Exception {
        rootKeys = TrustAnchorsTest.rsa();
        root = TrustAnchorsTest.certificate("CN=Wiring Test Root", rootKeys.getPublic(), "CN=Wiring Test Root",
                rootKeys.getPrivate(), true);
        rootFile = Files.createTempDirectory("gatekeeper-trust-anchor-wiring").resolve("yubico-root.pem");
        Files.writeString(rootFile, TrustAnchorsTest.pem("CERTIFICATE", root.getEncoded()));
        registry.add("gatekeeper.trust-anchors.yubico", rootFile::toString);
    }

    @Autowired
    private ApplicationContext context;

    @Test
    void theYubicoVerifierBeanStartsFromTheOperatorsFile() throws Exception {
        assertThat(context.getBeansOfType(YubicoVerifier.class)).hasSize(1);
        YubicoVerifier bean = context.getBean(YubicoVerifier.class);
        assertThat(bean.rootCa()).isEqualTo(root);

        KeyPair attested = TrustAnchorsTest.rsa();
        YubicoVerifier.YubicoAttestationResult test = bean.verifyYubicoAttestation(
                TrustAnchorsTest.yubicoChain(rootKeys.getPrivate(), root, attested.getPublic()), attested.getPublic());
        assertThat(test.getErrors()).isEmpty();
        assertThat(test.isValid()).isTrue();

        JsonNode fixture = TrustAnchorsTest.fixture("/fixtures/yubico/request.json");
        PublicKey realKey = TrustAnchorsTest.csrKey(fixture.get("csr").asText());
        YubicoVerifier.YubicoAttestationResult real = bean.verifyYubicoAttestation(
                TrustAnchorsTest.texts(fixture.get("attestationCertChain")), realKey);
        assertThat(real.isChainValid()).isFalse();
        assertThat(real.isValid()).isFalse();

        assertThat(context.getBean(SecurosysVerifier.class).rootCa()).isEqualTo(new SecurosysVerifier().rootCa());
        assertThat(context.getBean(GoogleCloudHsmVerifier.class).ownerRoot())
                .isEqualTo(new GoogleCloudHsmVerifier().ownerRoot());
    }

    @Test
    void supportedVendorsShowsTheOverrideAndItsPath() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) context).build();
        JsonNode vendors = new ObjectMapper().readTree(mvc.perform(get("/v1/attestation/supported-vendors"))
                .andReturn().getResponse().getContentAsString());
        Map<String, JsonNode> byId = new HashMap<>();
        vendors.forEach(v -> byId.put(v.get("vendorId").asText(), v));

        JsonNode yubico = byId.get("YUBICO").get("trustAnchors");
        assertThat(yubico).hasSize(1);
        assertThat(yubico.get(0).get("anchor").asText()).isEqualTo("yubico");
        assertThat(yubico.get(0).get("origin").asText()).isEqualTo("override");
        // The override file's server path is not published on this unauthenticated endpoint.
        assertThat(yubico.get(0).has("path")).isFalse();
        assertThat(yubico.get(0).get("sha256").get(0).asText()).isEqualTo(TrustAnchors.fingerprint(root.getEncoded()));
        assertThat(yubico.get(0).get("matchesPinned").asBoolean()).isFalse();

        JsonNode securosys = byId.get("SECUROSYS").get("trustAnchors").get(0);
        assertThat(securosys.get("origin").asText()).isEqualTo("pinned");
        assertThat(securosys.hasNonNull("path")).isFalse();
        assertThat(securosys.get("matchesPinned").asBoolean()).isTrue();
    }
}
