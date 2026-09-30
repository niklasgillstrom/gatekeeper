package eu.gillstrom.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EndToEndTest {

    private static final List<String> SERVICES = List.of("gatekeeper", "hsm", "railgate");

    private static final List<String> VENDORS = List.of("yubico", "securosys");

    private static final String COUNTRY = "SE";

    private static final String RAILGATE_USER = "e2e-settlement-rail";

    private static final Set<String> RECEIPT_STAGE_FAILURES = Set.of(
            "REJECTED_GATEKEEPER_VERIFY_FAILED",
            "REJECTED_GATEKEEPER_NOT_COMPLIANT",
            "REJECTED_GATEKEEPER_RECEIPT_INVALID",
            "REJECTED_RECEIPT_KEY_MISMATCH");

    private static final String STEP7_DETAIL = "hsm issues through MockIssuanceClient with the harness CA "
            + "(swish.issuance.mock.ca-keystore) and gatekeeper trusts that CA (issuer-ca-bundle-path);";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final List<ServiceProcess> started = new ArrayList<>();
    private final Map<String, Fixture> fixtures = new LinkedHashMap<>();
    private final Map<String, Set<String>> verificationIds = new HashMap<>();
    private final Map<String, Issued> issued = new LinkedHashMap<>();
    private final Map<String, JsonNode> hsmResults = new HashMap<>();

    private ServiceProcess gatekeeper;
    private ServiceProcess hsm;
    private ServiceProcess railgate;
    private LocalIssuerCa issuerCa;
    private X509Certificate gatekeeperSigningCertificate;
    private String railgateAuthorization;
    private Path paymentNetworkFile;

    private record Issued(String label, String vendor, X509Certificate certificate, String verificationId) {

        String serialHex() {
            return certificate.getSerialNumber().toString(16);
        }

        String issuerDn() {
            return certificate.getIssuerX500Principal().getName();
        }
    }

    private record SignedDigest(String digestHex, String signatureBase64) {
    }

    @BeforeAll
    void startServices() throws Exception {
        List<String> missing = SERVICES.stream()
                .map(E2eConfig::jar)
                .filter(jar -> !Files.isRegularFile(jar))
                .map(Path::toString)
                .toList();
        if (!missing.isEmpty()) {
            fail("Missing fat jar(s): " + missing + ". Build each service first with 'mvn verify' in "
                    + E2eConfig.GATEKEEPER_DIR + ", " + E2eConfig.repoDir("hsm") + " and "
                    + E2eConfig.repoDir("railgate") + ".");
        }

        deleteRecursively(E2eConfig.WORK_DIR);
        Files.createDirectories(E2eConfig.WORK_DIR);
        Files.createDirectories(E2eConfig.LOG_DIR);
        Files.deleteIfExists(E2eConfig.PID_FILE);

        Runtime.getRuntime().addShutdownHook(new Thread(this::stopServices, "e2e-stop-services"));

        for (String vendor : VENDORS) {
            fixtures.put(vendor, Fixture.load(vendor));
        }

        issuerCa = LocalIssuerCa.create(E2eConfig.WORK_DIR.resolve("issuer-ca"));

        gatekeeper = track(ServiceProcess.start("gatekeeper", ServiceProcess.freePort(), List.of(
                "--gatekeeper.security.mtls.enabled=false",
                "--gatekeeper.signing.mode=ephemeral",
                "--gatekeeper.registry.mode=in-memory",
                "--gatekeeper.audit.path=" + E2eConfig.WORK_DIR.resolve("gatekeeper").resolve("audit-log.jsonl"),
                "--gatekeeper.confirmation.issuer-ca-bundle-path=" + issuerCa.bundle())));
        gatekeeper.awaitReady("/v1/attestation/health", null);

        String trustedKeyPem = activeGatekeeperKeyPem();
        gatekeeperSigningCertificate = Pem.certificate(trustedKeyPem);
        Path hsmWork = E2eConfig.WORK_DIR.resolve("hsm");
        Files.createDirectories(hsmWork);
        Files.writeString(hsmWork.resolve("gatekeeper-trusted-keys.pem"), trustedKeyPem, StandardCharsets.UTF_8);
        Path signatoryRegistry = writeSignatoryRegistry(hsmWork.resolve("signatory-rights.json"));

        hsm = track(ServiceProcess.start("hsm", ServiceProcess.freePort(), List.of(
                "--spring.profiles.active=dev",
                "--swish.gatekeeper.mode=http",
                "--swish.gatekeeper.url=" + gatekeeper.baseUri(),
                "--swish.gatekeeper.country-code=" + COUNTRY,
                "--swish.gatekeeper.trusted-keys=" + trustedKeyPem,
                "--swish.issuance.mode=mock",
                "--swish.signatory-rights.mode=mock-registry",
                "--swish.signatory-rights.mock-registry.path=file:" + signatoryRegistry,
                "--swish.issuance.mock.ca-keystore=" + issuerCa.keystore(),
                "--swish.issuance.mock.ca-keystore-password=" + LocalIssuerCa.PASSWORD,
                "--swish.issuance.mock.ca-alias=" + LocalIssuerCa.ALIAS)));

        paymentNetworkFile = E2eConfig.WORK_DIR.resolve("railgate").resolve("payment-network.tsv");
        Files.createDirectories(paymentNetworkFile.getParent());
        Files.writeString(paymentNetworkFile, "", StandardCharsets.UTF_8);

        String railgatePassword = UUID.randomUUID().toString();
        railgateAuthorization = Http.basicAuth(RAILGATE_USER, railgatePassword);
        railgate = track(ServiceProcess.start("railgate", ServiceProcess.freePort(), List.of(
                "--railgate.gatekeeper.base-url=" + gatekeeper.baseUri(),
                "--railgate.gatekeeper.allow-insecure-http=true",
                "--railgate.payment-network.mode=file",
                "--railgate.payment-network.file=" + paymentNetworkFile,
                "--spring.security.user.name=" + RAILGATE_USER,
                "--spring.security.user.password=" + railgatePassword)));

        hsm.awaitReady("/api/v1/attestation/health", null);
        railgate.awaitReady("/api/v1/audit/health", railgateAuthorization);

        System.out.println("[e2e] gatekeeper " + gatekeeper.baseUri() + ", hsm " + hsm.baseUri()
                + ", railgate " + railgate.baseUri() + "; logs in " + E2eConfig.LOG_DIR);
        System.out.println("[e2e] local issuer CA: " + issuerCa.keystore() + " (PKCS12, alias "
                + LocalIssuerCa.ALIAS + ", password " + LocalIssuerCa.PASSWORD + "), bundle " + issuerCa.bundle());
        for (Fixture fixture : fixtures.values()) {
            System.out.println("[e2e] BankID userNonVisibleData (before base64) for " + fixture.vendor() + ": "
                    + fixture.bankIdBinding());
        }
    }

    @AfterAll
    void stopServicesAfterAll() {
        stopServices();
    }

    @Test
    @Order(1)
    void gatekeeperPublishesReceiptKeyAndHsmIsStartedWithIt() throws Exception {
        String fingerprintHex = HexFormat.of().formatHex(
                Pem.sha256(gatekeeperSigningCertificate.getPublicKey().getEncoded()));
        String hsmLog = hsm.log();
        assertAll(
                () -> assertTrue(gatekeeperSigningCertificate.getSubjectX500Principal().getName()
                                .contains("REFERENCE-EPHEMERAL"),
                        "gatekeeper is expected to run with the ephemeral reference signer, got "
                                + gatekeeperSigningCertificate.getSubjectX500Principal()),
                () -> assertTrue(hsmLog.contains(fingerprintHex),
                        "hsm log does not show the gatekeeper key " + fingerprintHex
                                + " registered from swish.gatekeeper.trusted-keys; see " + hsm.logFile()),
                () -> assertTrue(hsmLog.contains("HttpGatekeeperClient configured"),
                        "hsm did not select HttpGatekeeperClient (swish.gatekeeper.mode=http); see " + hsm.logFile()));
    }

    @ParameterizedTest(name = "hsm path, {0}: gatekeeper receipt verifies in hsm and the certificate is issued")
    @Order(2)
    @ValueSource(strings = {"yubico", "securosys"})
    void hsmPathReceiptVerifiesInHsmAndCertificateIsIssued(String vendor) throws Exception {
        Fixture fixture = fixtures.get(vendor);
        String signatureFile = E2eConfig.property("e2e.bankid." + vendor + ".signature");
        String ocspFile = E2eConfig.property("e2e.bankid." + vendor + ".ocsp");
        String personalNumber = E2eConfig.property("e2e.bankid.personalNumber");
        if (signatureFile == null || ocspFile == null || personalNumber == null) {
            Assumptions.abort("hsm path for " + vendor + " needs a real BankID signature bound to this exact "
                    + "request, which cannot be produced locally. Supply -De2e.bankid." + vendor + ".signature=<file> "
                    + "-De2e.bankid." + vendor + ".ocsp=<file> -De2e.bankid.personalNumber=<signer's 12-digit "
                    + "personnummer>. The BankID sign order's userNonVisibleData must be base64 of the UTF-8 string '"
                    + fixture.bankIdBinding() + "'. See README.md.");
        }

        ObjectNode request = fixture.hsmCertificateRequest(compactFile(signatureFile), compactFile(ocspFile));
        Http.Response response = Http.postJson(hsm.uri("/api/v1/attestation/verifyAndIssue"), request, null);
        assertEquals(200, response.status(), response.body());
        JsonNode result = response.json();
        String stage = result.path("stage").asText();
        JsonNode receipt = result.path("verifyReceipt");

        assertNotEquals("REJECTED_LOCAL_VERIFICATION", stage,
                "hsm Phase 1 (CSR, BankID, binding, signatory rights, attestation) rejected the request: "
                        + result.path("errors"));
        assertTrue(receipt.path("compliant").asBoolean(false),
                "gatekeeper receipt not compliant (stage " + stage + "): " + result.path("errors"));
        assertFalse(RECEIPT_STAGE_FAILURES.contains(stage),
                "hsm did not accept the gatekeeper receipt (stage " + stage + "): " + result.path("errors"));
        assertTrue(result.path("issued").asBoolean(false),
                "hsm did not issue (stage " + stage + "): " + result.path("errors"));

        X509Certificate advertised = Pem.certificate(receipt.path("signingCertificatePem").asText());
        X509Certificate certificate = Pem.certificate(result.path("certificate").path("certificatePem").asText());
        assertAll(
                () -> assertArrayEquals(gatekeeperSigningCertificate.getPublicKey().getEncoded(),
                        advertised.getPublicKey().getEncoded(),
                        "receipt was not signed under the key published at /v1/gatekeeper/keys"),
                () -> assertEquals(fixture.expectedFingerprint(), receipt.path("publicKeyFingerprint").asText()),
                () -> assertEquals(fixture.expectedFingerprint(), Pem.fingerprint(certificate.getPublicKey())),
                () -> assertEquals(receipt.path("verificationId").asText(),
                        result.path("certificate").path("verifyReceiptId").asText()));

        recordVerificationId(vendor, receipt.path("verificationId").asText());
        hsmResults.put(vendor, result);
    }

    @ParameterizedTest(name = "hsm path, {0}: Step 7 closes the loop")
    @Order(3)
    @ValueSource(strings = {"yubico", "securosys"})
    void hsmPathStep7ClosesTheLoop(String vendor) {
        JsonNode result = hsmResults.get(vendor);
        if (result == null) {
            Assumptions.abort("hsm path for " + vendor + " did not reach issuance; nothing to confirm.");
        }
        JsonNode confirm = result.path("confirmResponse");
        String detail = " stage=" + result.path("stage").asText() + ", confirm=" + confirm
                + ", errors=" + result.path("errors");
        assertAll(
                () -> assertEquals("VERIFIED_ISSUED_AND_CONFIRMED", result.path("stage").asText(), STEP7_DETAIL + detail),
                () -> assertTrue(confirm.path("loopClosed").asBoolean(false), STEP7_DETAIL + detail),
                () -> assertEquals("VERIFIED_AND_ISSUED", confirm.path("registryStatus").asText(), STEP7_DETAIL + detail));

        X509Certificate certificate = Pem.certificate(result.path("certificate").path("certificatePem").asText());
        issued.put("hsm-" + vendor, new Issued("hsm-" + vendor, vendor, certificate,
                result.path("verifyReceipt").path("verificationId").asText()));
    }

    @ParameterizedTest(name = "gatekeeper-direct, {0}: Steps 2-7 with the real attestation and a locally issued certificate")
    @Order(4)
    @ValueSource(strings = {"yubico", "securosys"})
    void gatekeeperDirectStepsTwoToSevenCloseTheLoop(String vendor) throws Exception {
        Fixture fixture = fixtures.get(vendor);

        Http.Response verify = Http.postJson(
                gatekeeper.uri("/v1/attestation/" + COUNTRY + "/verify"), fixture.gatekeeperVerifyRequest(), null);
        assertEquals(200, verify.status(), verify.body());
        JsonNode receipt = verify.json();
        assertTrue(receipt.path("compliant").asBoolean(false),
                "gatekeeper did not accept the real " + vendor + " attestation: " + receipt.path("errors"));
        X509Certificate advertised = Pem.certificate(receipt.path("signingCertificate").asText());
        assertAll(
                () -> assertEquals(fixture.expectedFingerprint(), receipt.path("publicKeyFingerprint").asText()),
                () -> assertEquals(fixture.expectedVendorName(), receipt.path("hsmVendor").asText()),
                () -> assertArrayEquals(gatekeeperSigningCertificate.getPublicKey().getEncoded(),
                        advertised.getPublicKey().getEncoded(),
                        "receipt signingCertificate is not the key published at /v1/gatekeeper/keys"),
                () -> assertTrue(ReceiptCheck.signatureVerifies(receipt, gatekeeperSigningCertificate),
                        "receipt signature does not verify over the v2 canonical form under the published key"));

        String verificationId = receipt.path("verificationId").asText();
        recordVerificationId(vendor, verificationId);

        X509Certificate leaf = issuerCa.issue("direct-" + vendor, fixture.csrPem());
        assertEquals(fixture.expectedFingerprint(), Pem.fingerprint(leaf.getPublicKey()));

        ObjectNode confirmation = Http.JSON.createObjectNode();
        confirmation.put("verificationId", verificationId);
        confirmation.put("confirmationNonce", receipt.path("confirmationNonce").asText());
        confirmation.put("issued", true);
        confirmation.put("signingCertificatePem", Pem.of(leaf));
        confirmation.put("timestamp", Instant.now().toString());
        confirmation.put("swishNumber", Fixture.SWISH_NUMBER);
        confirmation.put("organisationNumber", Fixture.ORGANISATION_NUMBER);

        Http.Response confirm = Http.postJson(
                gatekeeper.uri("/v1/attestation/" + COUNTRY + "/confirm"), confirmation, null);
        assertEquals(200, confirm.status(), confirm.body());
        JsonNode closed = confirm.json();
        assertAll(
                () -> assertTrue(closed.path("loopClosed").asBoolean(false), closed.toString()),
                () -> assertEquals("VERIFIED_AND_ISSUED", closed.path("registryStatus").asText(), closed.toString()),
                () -> assertTrue(closed.path("publicKeyMatch").asBoolean(false), closed.toString()),
                () -> assertEquals(0, closed.path("anomalies").size(), closed.toString()),
                () -> assertEquals(fixture.expectedFingerprint(), closed.path("actualPublicKeyFingerprint").asText()));

        issued.put("direct-" + vendor, new Issued("direct-" + vendor, vendor, leaf, verificationId));
    }

    @Test
    @Order(5)
    void settlementFindsTheCertificateStoredAtStep7() {
        assertFalse(issued.isEmpty(), "No certificate reached VERIFIED_AND_ISSUED at Step 7; Phase 5 has nothing to find.");
        assertAll(issued.values().stream().map(entry -> (Executable) () -> {
            JsonNode result = settle(entry.serialHex(), entry.issuerDn(), randomDigestHex(), randomSignature(entry));
            assertNotEquals("CERT_NOT_FOUND", result.path("reason").asText(), entry.label() + ": " + result);
            assertTrue(verificationIds.getOrDefault(entry.vendor(), Set.of())
                            .contains(result.path("auditEntryId").asText()),
                    entry.label() + ": auditEntryId does not name a registry entry for this key: " + result);
        }));
    }

    @Test
    @Order(6)
    void settlementForUnknownCertificateIsCertNotFound() throws Exception {
        String unknownSerial = new BigInteger(159, RANDOM).setBit(158).toString(16);
        JsonNode unknown = settle(unknownSerial, issuerCa.certificate().getSubjectX500Principal().getName(),
                randomDigestHex(), Base64.getEncoder().encodeToString(randomBytes(512)));
        List<Executable> checks = new ArrayList<>();
        checks.add(() -> assertEquals("CERT_NOT_FOUND", unknown.path("reason").asText(), unknown.toString()));
        checks.add(() -> assertFalse(unknown.path("signatureValid").asBoolean(true), unknown.toString()));
        checks.add(() -> assertFalse(unknown.path("compliant").asBoolean(true), unknown.toString()));
        for (Issued entry : issued.values()) {
            JsonNode wrongIssuer = settle(entry.serialHex(), "CN=Not The Issuer,O=e2e-harness,C=SE",
                    randomDigestHex(), randomSignature(entry));
            checks.add(() -> assertEquals("CERT_NOT_FOUND", wrongIssuer.path("reason").asText(),
                    entry.label() + " with a foreign issuerDn: " + wrongIssuer));
        }
        assertAll(checks);
    }

    @Test
    @Order(7)
    void settlementWithSignatureThatDoesNotVerifyIsSignatureInvalid() throws Exception {
        assertFalse(issued.isEmpty(), "No certificate reached VERIFIED_AND_ISSUED at Step 7.");
        List<Executable> checks = new ArrayList<>();
        for (Issued entry : issued.values()) {
            JsonNode result = settle(entry.serialHex(), entry.issuerDn(), randomDigestHex(), randomSignature(entry));
            checks.add(() -> assertEquals("SIGNATURE_INVALID", result.path("reason").asText(), entry.label() + ": " + result));
            checks.add(() -> assertFalse(result.path("signatureValid").asBoolean(true), entry.label() + ": " + result));
            checks.add(() -> assertFalse(result.path("compliant").asBoolean(true), entry.label() + ": " + result));
        }
        Optional<SignedDigest> supplied = suppliedSignedDigest();
        Optional<Issued> target = positiveTarget();
        if (supplied.isPresent() && target.isPresent()) {
            byte[] digest = HexFormat.of().parseHex(supplied.get().digestHex());
            digest[0] ^= 0x01;
            JsonNode tampered = settle(target.get().serialHex(), target.get().issuerDn(),
                    HexFormat.of().formatHex(digest), supplied.get().signatureBase64());
            checks.add(() -> assertEquals("SIGNATURE_INVALID", tampered.path("reason").asText(),
                    "real signature over a tampered digest: " + tampered));
        }
        assertAll(checks);
    }

    @Test
    @Order(8)
    void settlementWithOwnerSuppliedSignatureFromTheAttestedKeyIsAllowed() throws Exception {
        Optional<SignedDigest> supplied = suppliedSignedDigest();
        if (supplied.isEmpty()) {
            Assumptions.abort("No positive settlement pair supplied. The fixtures contain no private key, so an "
                    + "allowed settlement needs (digestHex, signatureBase64) produced by the attested HSM key: "
                    + "-De2e.positive.file=<json> [-De2e.positive.vendor=securosys|yubico]. See README.md.");
        }
        Issued target = positiveTarget().orElse(null);
        assertNotNull(target, "No VERIFIED_AND_ISSUED certificate for vendor " + positiveVendor());

        Signature local = Signature.getInstance("SHA512withRSA");
        local.initVerify(target.certificate().getPublicKey());
        local.update(HexFormat.of().parseHex(supplied.get().digestHex()));
        assertTrue(local.verify(Base64.getDecoder().decode(supplied.get().signatureBase64())),
                "The supplied pair does not verify as SHA512withRSA over the raw digest bytes under the attested "
                        + positiveVendor() + " key " + Pem.fingerprint(target.certificate().getPublicKey())
                        + ". Either it was made by another key or with another construction; gatekeeper would "
                        + "answer SIGNATURE_INVALID.");

        JsonNode result = settle(target.serialHex(), target.issuerDn(),
                supplied.get().digestHex(), supplied.get().signatureBase64());
        assertAll(
                () -> assertTrue(result.path("signatureValid").asBoolean(false), result.toString()),
                () -> assertTrue(result.path("compliant").asBoolean(false), result.toString()),
                () -> assertEquals("OK", result.path("reason").asText(), result.toString()),
                () -> assertTrue(verificationIds.getOrDefault(target.vendor(), Set.of())
                        .contains(result.path("auditEntryId").asText()), result.toString()));
    }

    @Test
    @Order(9)
    void railgateAuthenticatesAndDefaultDeniesWithoutPaymentNetworkArtefacts() throws Exception {
        ObjectNode request = Http.JSON.createObjectNode();
        request.put("transactionReference", "e2e-" + UUID.randomUUID());
        request.put("localInstrumentCode", "SWISH");
        request.put("debtorIsOrganization", true);
        request.put("creditorIsPrivatePerson", true);

        Http.Response anonymous = Http.postJson(railgate.uri("/api/v1/settle/precheck"), request, null);
        Http.Response authenticated = Http.postJson(railgate.uri("/api/v1/settle/precheck"), request,
                railgateAuthorization);
        assertAll(
                () -> assertEquals(401, anonymous.status(), anonymous.body()),
                () -> assertEquals(403, authenticated.status(), authenticated.body()),
                () -> assertFalse(authenticated.json().path("allow").asBoolean(true), authenticated.body()),
                () -> assertEquals("DORA_32_AUDIT_MISSING", authenticated.json().path("reasonCode").asText(),
                        authenticated.body()));
    }

    @Test
    @Order(10)
    void railgateCallsGatekeeperAndPassesItsVerdictsThrough() throws Exception {
        assertFalse(issued.isEmpty(), "No certificate reached VERIFIED_AND_ISSUED at Step 7.");
        List<Executable> checks = new ArrayList<>();
        for (Issued entry : issued.values()) {
            String reference = recordPayment(entry.serialHex(), entry.issuerDn(), randomDigestHex(),
                    randomSignature(entry));
            Http.Response response = precheck(reference);
            checks.add(() -> assertEquals(403, response.status(), entry.label() + ": " + response.body()));
            checks.add(() -> assertEquals("SIGNATURE_INVALID", response.json().path("reasonCode").asText(),
                    entry.label() + ": " + response.body()));
            checks.add(() -> assertTrue(verificationIds.getOrDefault(entry.vendor(), Set.of())
                            .contains(response.json().path("auditEntryId").asText()),
                    entry.label() + ": railgate did not carry gatekeeper's registry id: " + response.body()));
            checks.add(() -> assertTrue(response.json().path("auditEntryHashHex").asText("").matches("^[0-9a-f]{64}$"),
                    entry.label() + ": railgate did not carry gatekeeper's audit-entry hash: " + response.body()));
        }
        String unknownSerial = new BigInteger(159, RANDOM).setBit(158).toString(16);
        String unknownReference = recordPayment(unknownSerial,
                issuerCa.certificate().getSubjectX500Principal().getName(), randomDigestHex(),
                Base64.getEncoder().encodeToString(randomBytes(512)));
        Http.Response unknown = precheck(unknownReference);
        checks.add(() -> assertEquals(403, unknown.status(), unknown.body()));
        checks.add(() -> assertEquals("CERT_NOT_FOUND", unknown.json().path("reasonCode").asText(), unknown.body()));
        assertAll(checks);
    }

    @Test
    @Order(11)
    void railgateAllowsSettlementWithOwnerSuppliedSignatureFromTheAttestedKey() throws Exception {
        Optional<SignedDigest> supplied = suppliedSignedDigest();
        if (supplied.isEmpty()) {
            Assumptions.abort("No positive settlement pair supplied; see settlementWithOwnerSuppliedSignature"
                    + "FromTheAttestedKeyIsAllowed and README.md.");
        }
        Issued target = positiveTarget().orElse(null);
        assertNotNull(target, "No VERIFIED_AND_ISSUED certificate for vendor " + positiveVendor());
        String reference = recordPayment(target.serialHex(), target.issuerDn(),
                supplied.get().digestHex(), supplied.get().signatureBase64());
        Http.Response response = precheck(reference);
        assertAll(
                () -> assertEquals(200, response.status(), response.body()),
                () -> assertTrue(response.json().path("allow").asBoolean(false), response.body()),
                () -> assertEquals("ALLOWED", response.json().path("reasonCode").asText(), response.body()));
    }

    private synchronized String recordPayment(String certSerial, String issuerDn, String digestHex,
                                              String signatureBase64) throws IOException {
        String reference = "e2e-" + UUID.randomUUID();
        String line = String.join("\t", reference, certSerial, issuerDn, digestHex, signatureBase64) + "\n";
        Files.writeString(paymentNetworkFile, line, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);
        return reference;
    }

    private Http.Response precheck(String reference) throws Exception {
        ObjectNode request = Http.JSON.createObjectNode();
        request.put("transactionReference", reference);
        request.put("localInstrumentCode", "SWISH");
        request.put("debtorIsOrganization", true);
        request.put("creditorIsPrivatePerson", true);
        return Http.postJson(railgate.uri("/api/v1/settle/precheck"), request, railgateAuthorization);
    }

    private ServiceProcess track(ServiceProcess process) {
        started.add(process);
        return process;
    }

    private synchronized void stopServices() {
        for (int i = started.size() - 1; i >= 0; i--) {
            started.get(i).close();
        }
        started.clear();
    }

    private String activeGatekeeperKeyPem() throws Exception {
        Http.Response keys = Http.get(gatekeeper.uri("/v1/gatekeeper/keys"), null);
        if (keys.status() != 200) {
            fail("GET /v1/gatekeeper/keys answered HTTP " + keys.status() + ": " + keys.body());
        }
        for (JsonNode entry : keys.json()) {
            if ("ACTIVE".equals(entry.path("status").asText())) {
                return entry.path("certificatePem").asText();
            }
        }
        throw new AssertionError("No ACTIVE key in /v1/gatekeeper/keys: " + keys.body());
    }

    private Path writeSignatoryRegistry(Path file) throws IOException {
        ObjectNode root = Http.JSON.createObjectNode();
        ObjectNode entry = root.putArray("entries").addObject();
        entry.put("organisationNumber", Fixture.ORGANISATION_NUMBER);
        entry.put("organisationName", "e2e harness");
        String personalNumber = E2eConfig.property("e2e.bankid.personalNumber");
        var authorised = entry.putArray("authorisedPersonalNumbers");
        if (personalNumber != null) {
            authorised.add(personalNumber);
        }
        Http.JSON.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), root);
        return file;
    }

    private void recordVerificationId(String vendor, String verificationId) {
        verificationIds.computeIfAbsent(vendor, v -> new LinkedHashSet<>()).add(verificationId);
    }

    private JsonNode settle(String certSerial, String issuerDn, String digestHex, String signatureBase64) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("certSerial", certSerial);
        body.put("issuerDn", issuerDn);
        body.put("digestHex", digestHex);
        body.put("signatureBase64", signatureBase64);
        try {
            Http.Response response = Http.postJson(gatekeeper.uri("/api/v1/verify"), body, null);
            assertEquals(200, response.status(), response.body());
            return response.json();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private Optional<SignedDigest> suppliedSignedDigest() throws IOException {
        String file = E2eConfig.property("e2e.positive.file");
        if (file == null) {
            return Optional.empty();
        }
        JsonNode node = Http.JSON.readTree(Path.of(file).toFile());
        String digestHex = node.path("digestHex").asText("").trim();
        String signatureBase64 = node.path("signatureBase64").asText("").replaceAll("\\s+", "");
        assertTrue(digestHex.matches("^[0-9a-fA-F]{128}$"),
                "e2e.positive.file: digestHex must be 128 hex characters (SHA-512), as railgate requires");
        assertFalse(signatureBase64.isEmpty(), "e2e.positive.file: signatureBase64 is empty");
        return Optional.of(new SignedDigest(digestHex, signatureBase64));
    }

    private String positiveVendor() {
        String vendor = E2eConfig.property("e2e.positive.vendor");
        return vendor == null ? "securosys" : vendor.toLowerCase();
    }

    private Optional<Issued> positiveTarget() {
        String vendor = positiveVendor();
        return issued.values().stream()
                .filter(entry -> entry.vendor().equals(vendor))
                .max(Comparator.comparing(entry -> entry.label().startsWith("direct-")));
    }

    private static String randomDigestHex() {
        return HexFormat.of().formatHex(randomBytes(64));
    }

    private static String randomSignature(Issued entry) {
        int length = 512;
        if (entry.certificate().getPublicKey() instanceof RSAPublicKey rsa) {
            length = (rsa.getModulus().bitLength() + 7) / 8;
        }
        byte[] signature = randomBytes(length);
        signature[0] = 0;
        return Base64.getEncoder().encodeToString(signature);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static String compactFile(String file) throws IOException {
        return Files.readString(Path.of(file), StandardCharsets.UTF_8).replaceAll("\\s+", "");
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        }
    }
}
