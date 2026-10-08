package eu.gillstrom.gatekeeper.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.VerificationRequest;
import eu.gillstrom.gatekeeper.model.VerificationResponse;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.signing.ReceiptCanonicalizer;
import eu.gillstrom.gatekeeper.verification.AzureHsmVerifier;
import eu.gillstrom.gatekeeper.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The customer and, when there is one, the technical supplier are recorded in
 * the registry and carried in the signed receipt, so the supervisor can compare
 * who holds a verified key with the banks' customer registers. A customer
 * without a technical supplier has no supplier fields.
 */
class PartiesRecordedTest {

    private static final String CUSTOMER_ORG = "5569743098";
    private static final String CUSTOMER_SWISH = "1231015932";
    private static final String SUPPLIER_ORG = "5566778899";
    private static final String SUPPLIER_NUMBER = "9871234567";

    @TempDir
    Path tempDir;

    private InMemoryApprovalRegistry registry;
    private AppendOnlyFileAuditLog auditLog;
    private VerificationService service;
    private JsonNode fixture;
    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

    @BeforeEach
    void setUp() throws Exception {
        try (InputStream in = PartiesRecordedTest.class.getResourceAsStream("/fixtures/securosys/request.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        registry = new InMemoryApprovalRegistry();
        auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(),
                new EphemeralReceiptSigner(2048));
        auditLog.initialise();
        service = new VerificationService(
                new SecurosysVerifier(),
                new YubicoVerifier(),
                mock(AzureHsmVerifier.class),
                mock(GoogleCloudHsmVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.MarvellHsmVerifier.class),
                new eu.gillstrom.gatekeeper.verification.ThalesLunaVerifier(),
                new eu.gillstrom.gatekeeper.verification.Crypto4AVerifier(),
                new eu.gillstrom.gatekeeper.verification.FortanixVerifier(),
                new eu.gillstrom.gatekeeper.verification.NShieldVerifier(),
                registry,
                signer,
                mock(IssuerCaValidator.class),
                auditLog,
                new MtlsPrincipalResolver(),
                KeyPolicy.defaults(),
                false);
    }

    private VerificationRequest request(boolean viaSupplier) {
        List<String> chain = new ArrayList<>();
        for (JsonNode pem : fixture.get("attestationCertChain")) {
            chain.add(pem.asText());
        }
        VerificationRequest r = new VerificationRequest();
        r.setPublicKey(fixture.get("csr").asText());
        r.setHsmVendor("SECUROSYS");
        r.setAttestationData(fixture.get("attestationData").asText());
        r.setAttestationSignature(fixture.get("attestationSignature").asText());
        r.setAttestationCertChain(chain);
        r.setCustomerOrganisationNumber(CUSTOMER_ORG);
        r.setCustomerSwishNumber(CUSTOMER_SWISH);
        if (viaSupplier) {
            r.setSupplierIdentifier(SUPPLIER_ORG);
            r.setSupplierNumber(SUPPLIER_NUMBER);
            r.setSupplierName("Teknisk leverantor AB");
        }
        r.setCountryCode("SE");
        return r;
    }

    @Test
    void customerAndSupplierAreRecordedAndSigned() {
        VerificationResponse receipt = service.verify(request(true));

        assertThat(receipt.isCompliant()).as("errors: %s", receipt.getErrors()).isTrue();
        ApprovalRegistry.RegistryEntry entry = registry.lookup(receipt.getVerificationId()).orElseThrow();
        assertThat(entry.getCustomerOrganisationNumber()).isEqualTo(CUSTOMER_ORG);
        assertThat(entry.getCustomerSwishNumber()).isEqualTo(CUSTOMER_SWISH);
        assertThat(entry.getSupplierIdentifier()).isEqualTo(SUPPLIER_ORG);
        assertThat(entry.getSupplierNumber()).isEqualTo(SUPPLIER_NUMBER);
        assertThat(entry.getSupplierName()).isEqualTo("Teknisk leverantor AB");

        assertThat(receipt.getCustomerOrganisationNumber()).isEqualTo(CUSTOMER_ORG);
        assertThat(receipt.getCustomerSwishNumber()).isEqualTo(CUSTOMER_SWISH);
        assertThat(receipt.getSupplierIdentifier()).isEqualTo(SUPPLIER_ORG);
        assertThat(receipt.getSupplierNumber()).isEqualTo(SUPPLIER_NUMBER);
        String canonical = new String(ReceiptCanonicalizer.canonicalize(receipt), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(canonical).contains("|" + CUSTOMER_ORG + "|" + CUSTOMER_SWISH + "|" + SUPPLIER_ORG + "|"
                + SUPPLIER_NUMBER + "|Teknisk leverantor AB|");
    }

    @Test
    void aCustomerWithoutSupplierHasNoSupplierFields() {
        VerificationResponse receipt = service.verify(request(false));

        ApprovalRegistry.RegistryEntry entry = registry.lookup(receipt.getVerificationId()).orElseThrow();
        assertThat(entry.getCustomerOrganisationNumber()).isEqualTo(CUSTOMER_ORG);
        assertThat(entry.getCustomerSwishNumber()).isEqualTo(CUSTOMER_SWISH);
        assertThat(entry.getSupplierIdentifier()).isNull();
        assertThat(entry.getSupplierNumber()).isNull();
        assertThat(entry.getSupplierName()).isNull();
        assertThat(receipt.getSupplierIdentifier()).isNull();
        assertThat(receipt.getSupplierNumber()).isNull();
    }

    @Test
    void thePartiesAreInTheAuditedRequestDigest() {
        VerificationResponse a = service.verify(request(true));
        VerificationRequest other = request(true);
        other.setCustomerSwishNumber("1239999999");
        VerificationResponse b = service.verify(other);
        VerificationRequest otherSupplier = request(true);
        otherSupplier.setSupplierNumber("9879999999");
        VerificationResponse c = service.verify(otherSupplier);
        VerificationRequest otherCustomer = request(true);
        otherCustomer.setCustomerOrganisationNumber("5561234567");
        VerificationResponse d = service.verify(otherCustomer);

        String digestA = auditLog.findByVerificationId(a.getVerificationId()).orElseThrow().requestDigestBase64();
        for (VerificationResponse r : List.of(b, c, d)) {
            assertThat(auditLog.findByVerificationId(r.getVerificationId()).orElseThrow().requestDigestBase64())
                    .isNotEqualTo(digestA);
        }
    }

    @Test
    void numbersAreValidated() {
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        assertThat(validator.validate(request(true))).isEmpty();
        assertThat(validator.validate(request(false))).isEmpty();

        VerificationRequest r = request(true);
        r.setCustomerSwishNumber(SUPPLIER_NUMBER);
        assertThat(messages(validator.validate(r))).anyMatch(m -> m.startsWith("customerSwishNumber"));
        r = request(true);
        r.setSupplierNumber(CUSTOMER_SWISH);
        assertThat(messages(validator.validate(r))).anyMatch(m -> m.startsWith("supplierNumber must"));
        r = request(true);
        r.setCustomerOrganisationNumber("556974-3098");
        assertThat(messages(validator.validate(r))).anyMatch(m -> m.startsWith("customerOrganisationNumber"));
        r = request(true);
        r.setSupplierIdentifier(null);
        assertThat(messages(validator.validate(r))).contains("supplierNumber requires supplierIdentifier");
        r = request(true);
        r.setSupplierIdentifier(" ");
        assertThat(messages(validator.validate(r))).contains("supplierNumber requires supplierIdentifier");
    }

    private static List<String> messages(Set<ConstraintViolation<VerificationRequest>> violations) {
        return violations.stream().map(ConstraintViolation::getMessage).toList();
    }

    @Test
    void theAttestationEvidenceIsKeptAndMatchesTheAuditedDigest() {
        VerificationRequest sent = request(true);
        VerificationResponse receipt = service.verify(sent);

        VerificationRequest kept = registry.lookup(receipt.getVerificationId()).orElseThrow().getSubmission();
        assertThat(kept).isNotNull();
        assertThat(kept.getAttestationData()).isEqualTo(fixture.get("attestationData").asText());
        assertThat(kept.getAttestationSignature()).isEqualTo(fixture.get("attestationSignature").asText());
        assertThat(kept.getAttestationCertChain()).hasSize(fixture.get("attestationCertChain").size());
        assertThat(kept.getPublicKey()).isEqualTo(fixture.get("csr").asText());
        // What is kept is what was verified: its digest is the audit entry's.
        assertThat(VerificationService.requestDigestBase64(kept))
                .isEqualTo(auditLog.findByVerificationId(receipt.getVerificationId()).orElseThrow()
                        .requestDigestBase64());
        // And the verification can be run again from it.
        assertThat(service.verify(kept).isCompliant()).isTrue();
    }

    private boolean signatureVerifies(VerificationResponse receipt) throws Exception {
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(
                        new java.io.ByteArrayInputStream(receipt.getSigningCertificate()
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        java.security.Signature sig = java.security.Signature.getInstance(signer.getSignatureAlgorithm());
        sig.initVerify(cert.getPublicKey());
        sig.update(ReceiptCanonicalizer.canonicalize(receipt));
        return sig.verify(java.util.Base64.getDecoder().decode(receipt.getSignature()));
    }

    @Test
    void everyReceiptIsSignedCompliantOrNot() throws Exception {
        VerificationResponse compliant = service.verify(request(true));
        VerificationRequest tampered = request(true);
        tampered.setAttestationSignature(java.util.Base64.getEncoder().encodeToString(new byte[512]));
        VerificationResponse refused = service.verify(tampered);

        assertThat(compliant.isCompliant()).isTrue();
        assertThat(refused.isCompliant()).isFalse();
        for (VerificationResponse r : List.of(compliant, refused)) {
            assertThat(r.getSigningCertificate()).isEqualTo(signer.getSigningCertificatePem());
            assertThat(signatureVerifies(r)).isTrue();
        }
    }

    @Test
    void aRefusedKeyIsNotAttributedToAVendor() {
        VerificationRequest tampered = request(true);
        tampered.setAttestationSignature(java.util.Base64.getEncoder().encodeToString(new byte[512]));

        VerificationResponse refused = service.verify(tampered);

        assertThat(refused.isCompliant()).isFalse();
        assertThat(refused.getHsmVendor()).isNull();
        assertThat(refused.getHsmModel()).isNull();
        assertThat(refused.getHsmSerialNumber()).isNull();
        ApprovalRegistry.RegistryEntry entry = registry.lookup(refused.getVerificationId()).orElseThrow();
        assertThat(entry.getHsmVendor()).isNull();
        assertThat(entry.getHsmModel()).isNull();
        VerificationResponse accepted = service.verify(request(true));
        assertThat(accepted.getHsmVendor()).isNotNull();
        assertThat(registry.lookup(accepted.getVerificationId()).orElseThrow().getHsmModel()).isNotNull();
    }

    @Test
    void confirmationNoncesAreRandom256BitValues() {
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < 3; i++) {
            String nonce = service.verify(request(true)).getConfirmationNonce();
            byte[] raw = java.util.Base64.getUrlDecoder().decode(nonce);
            assertThat(raw).hasSize(32);
            assertThat(raw).as("not all zero").isNotEqualTo(new byte[32]);
            seen.add(nonce);
        }
        assertThat(seen).hasSize(3);
    }
}
