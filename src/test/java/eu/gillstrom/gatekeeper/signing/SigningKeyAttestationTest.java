package eu.gillstrom.gatekeeper.signing;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.controller.GatekeeperController;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.TestRootVerifiers;
import eu.gillstrom.gatekeeper.verification.TestRootVerifiers.Root;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Start-up verification and publication of the HSM attestation of the
 * gatekeeper's own signing key ({@link SigningKeyAttestation}), with
 * vendor-shaped evidence built on a test PKI and verifiers anchored at the
 * test root.
 */
class SigningKeyAttestationTest {

    @TempDir
    Path tempDir;

    private static Root root;
    private static EphemeralReceiptSigner signer;

    @BeforeAll
    static void pki() throws Exception {
        root = Root.create("Test HSM Vendor Root");
        signer = new EphemeralReceiptSigner(2048);
    }

    private Path write(String name, String content) throws Exception {
        Path p = tempDir.resolve(name);
        Files.writeString(p, content, StandardCharsets.UTF_8);
        return p;
    }

    private Path yubicoChainFile(java.security.PublicKey attested) throws Exception {
        return write("chain.pem", String.join("", TestRootVerifiers.yubicoChain(root, attested, "12345678")));
    }

    private SigningKeyAttestation yubico(Path chain) {
        return new SigningKeyAttestation(signer, TestRootVerifiers.yubico(root.certificate()), new SecurosysVerifier(),
                "YUBICO", chain.toString(), "", "", "");
    }

    private SigningKeyAttestation securosys(TestRootVerifiers.SecurosysEvidence ev) throws Exception {
        Path xml = tempDir.resolve("att.xml");
        Files.write(xml, ev.xml());
        Path sig = write("att.sig.b64", ev.signatureBase64() + "\n");
        Path chain = write("att-chain.pem", String.join("", ev.chainPem()));
        return new SigningKeyAttestation(signer, new YubicoVerifier(), TestRootVerifiers.securosys(root.certificate()),
                "securosys", "", xml.toString(), sig.toString(), chain.toString());
    }

    private static String rootSha256() throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(root.certificate().getEncoded()));
    }

    @Test
    void aYubicoAttestationOfTheSigningKeyVerifiesAndCarriesItsEvidence() throws Exception {
        Path chain = yubicoChainFile(signer.getPublicKey());

        SigningKeyAttestation attestation = yubico(chain);

        KeyAttestation a = attestation.attestation().orElseThrow();
        assertThat(attestation.isActiveKeyAttested()).isTrue();
        assertThat(a.vendor()).isEqualTo("YUBICO");
        assertThat(a.valid()).isTrue();
        assertThat(a.chainValid()).isTrue();
        assertThat(a.publicKeyMatch()).isTrue();
        assertThat(a.attestationSignatureValid()).isNull();
        assertThat(a.hsmSerial()).isEqualTo("12345678");
        assertThat(a.keyOrigin()).isEqualTo("generated");
        assertThat(a.exportable()).isFalse();
        assertThat(a.firmwareVersion()).isEqualTo("2.4.0");
        assertThat(a.errors()).isEmpty();
        assertThat(a.verifiedAgainstRootSha256Hex()).isEqualTo(rootSha256());
        assertThat(String.join("", a.evidence().certificateChainPem())).isEqualTo(Files.readString(chain));
    }

    @Test
    void aYubicoAttestationOfAnotherKeyStopsStartUp() throws Exception {
        Path chain = yubicoChainFile(TestPki.newRsaKeyPair(2048).getPublic());

        assertThatThrownBy(() -> yubico(chain))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("did not verify")
                .hasMessageContaining("chainValid=true")
                .hasMessageContaining("publicKeyMatch=false");
    }

    @Test
    void theProductionVerifierRefusesATestPkiChainAndStartUpStops() throws Exception {
        // The same evidence, but the verifier pins the real Yubico root.
        Path chain = yubicoChainFile(signer.getPublicKey());

        assertThatThrownBy(() -> new SigningKeyAttestation(signer, new YubicoVerifier(), new SecurosysVerifier(),
                "YUBICO", chain.toString(), "", "", ""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("chainValid=false");
    }

    @Test
    void aSecurosysAttestationOfTheSigningKeyVerifies() throws Exception {
        TestRootVerifiers.SecurosysEvidence ev =
                TestRootVerifiers.securosysEvidence(root, signer.getPublicKey(), "18386101");

        KeyAttestation a = securosys(ev).attestation().orElseThrow();

        assertThat(a.vendor()).isEqualTo("SECUROSYS");
        assertThat(a.valid()).isTrue();
        assertThat(a.chainValid()).isTrue();
        assertThat(a.publicKeyMatch()).isTrue();
        assertThat(a.attestationSignatureValid()).isTrue();
        assertThat(a.hsmSerial()).isEqualTo("18386101");
        assertThat(a.keyOrigin()).isEqualTo("generated");
        assertThat(a.exportable()).isFalse();
        assertThat(a.evidence().attestationXmlBase64()).isEqualTo(Base64.getEncoder().encodeToString(ev.xml()));
        assertThat(a.evidence().attestationSignatureBase64()).isEqualTo(ev.signatureBase64());
        assertThat(a.evidence().certificateChainPem()).hasSize(3);
    }

    @Test
    void aSecurosysAttestationOfAnotherKeyStopsStartUp() throws Exception {
        TestRootVerifiers.SecurosysEvidence ev =
                TestRootVerifiers.securosysEvidence(root, TestPki.newRsaKeyPair(2048).getPublic(), "18386101");

        assertThatThrownBy(() -> securosys(ev))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("publicKeyMatch=false");
    }

    @Test
    void notConfiguredWarnsAtStartUpAndPublishesNothing() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        Logger logger = (Logger) LoggerFactory.getLogger(SigningKeyAttestation.class);
        logger.addAppender(appender);
        try {
            SigningKeyAttestation none = new SigningKeyAttestation(signer, new YubicoVerifier(),
                    new SecurosysVerifier(), "", "", "", "", "");
            assertThat(none.isConfigured()).isFalse();
            assertThat(none.isActiveKeyAttested()).isFalse();
            assertThat(none.attestation()).isEmpty();
            assertThat(appender.list).anyMatch(e -> e.getLevel() == Level.WARN
                    && e.getFormattedMessage().contains("signing key is NOT attested"));
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void aMisconfiguredAttestationStopsStartUp() throws Exception {
        assertThatThrownBy(() -> new SigningKeyAttestation(signer, new YubicoVerifier(), new SecurosysVerifier(),
                "THALES", "", "", "", ""))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("YUBICO or SECUROSYS");
        assertThatThrownBy(() -> new SigningKeyAttestation(signer, new YubicoVerifier(), new SecurosysVerifier(),
                "YUBICO", "", "", "", ""))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("yubico.chain-path is required");
        assertThatThrownBy(() -> new SigningKeyAttestation(signer, new YubicoVerifier(), new SecurosysVerifier(),
                "SECUROSYS", "", tempDir.resolve("x.xml").toString(), "", ""))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("securosys.signature-path is required");
        assertThatThrownBy(() -> new SigningKeyAttestation(signer, new YubicoVerifier(), new SecurosysVerifier(),
                "YUBICO", tempDir.resolve("missing.pem").toString(), "", "", ""))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("could not be read");
        Path notPem = write("not.pem", "not a certificate");
        assertThatThrownBy(() -> new SigningKeyAttestation(signer, new YubicoVerifier(), new SecurosysVerifier(),
                "YUBICO", notPem.toString(), "", "", ""))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("could not be read");
    }

    @Test
    void theKeysEndpointPublishesTheResultAndEvidenceAndHealthReportsTheKeyAttested() throws Exception {
        SigningKeyAttestation attestation = yubico(yubicoChainFile(signer.getPublicKey()));
        GatekeeperKeyDirectory directory = new GatekeeperKeyDirectory(signer, "", attestation);
        directory.initialise();
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(tempDir.resolve("a.jsonl").toString(), signer);
        log.initialise();
        MockMvc mvc = MockMvcBuilders.standaloneSetup(
                new GatekeeperController(directory, log, signer, "configured", attestation, null, null)).build();
        ObjectMapper json = new ObjectMapper();

        JsonNode keys = json.readTree(mvc.perform(get("/v1/gatekeeper/keys")).andReturn().getResponse()
                .getContentAsString());
        JsonNode a = keys.get(0).get("attestation");
        assertThat(keys.get(0).get("status").asText()).isEqualTo("ACTIVE");
        assertThat(a.get("vendor").asText()).isEqualTo("YUBICO");
        assertThat(a.get("hsmSerial").asText()).isEqualTo("12345678");
        assertThat(a.get("valid").asBoolean()).isTrue();
        assertThat(a.get("chainValid").asBoolean()).isTrue();
        assertThat(a.get("publicKeyMatch").asBoolean()).isTrue();
        assertThat(a.get("keyOrigin").asText()).isEqualTo("generated");
        assertThat(a.get("exportable").asBoolean()).isFalse();
        assertThat(a.get("verifiedAgainstRootSha256Hex").asText()).isEqualTo(rootSha256());
        assertThat(a.has("attestationSignatureValid")).as("Securosys only").isFalse();

        // A relying party re-verifies the published evidence against the
        // vendor root and the published certificate's key.
        List<String> published = new ArrayList<>();
        a.get("evidence").get("certificateChainPem").forEach(n -> published.add(n.asText()));
        YubicoVerifier.YubicoAttestationResult again = TestRootVerifiers.yubico(root.certificate())
                .verifyYubicoAttestation(published, parse(keys.get(0).get("certificatePem").asText()).getPublicKey());
        assertThat(again.isValid()).isTrue();

        JsonNode health = json.readTree(mvc.perform(get("/v1/gatekeeper/health")).andReturn().getResponse()
                .getContentAsString());
        assertThat(health.get("activeKeyAttested").asBoolean()).isTrue();
    }

    private static java.security.cert.X509Certificate parse(String pem) throws Exception {
        return (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void anInvalidAttestationStopsTheApplicationContext() throws Exception {
        // End to end through Spring: the real pinned Yubico root refuses a
        // test-PKI chain, so configuring it must keep the application down.
        Path chain = yubicoChainFile(signer.getPublicKey());
        String dir = tempDir.resolve("ctx").toString();
        assertThatThrownBy(() -> new org.springframework.boot.builder.SpringApplicationBuilder(
                eu.gillstrom.gatekeeper.DoraAttestationGatekeeperApplication.class)
                .run("--gatekeeper.audit.path=" + dir + "/audit-log.jsonl",
                        "--gatekeeper.registry.path=" + dir + "/approval-registry.jsonl",
                        "--server.port=0",
                        "--gatekeeper.signing.attestation.vendor=YUBICO",
                        "--gatekeeper.signing.attestation.yubico.chain-path=" + chain))
                .hasStackTraceContaining("gatekeeper.signing.attestation: the YUBICO attestation of the active "
                        + "signing key did not verify");
    }
}
