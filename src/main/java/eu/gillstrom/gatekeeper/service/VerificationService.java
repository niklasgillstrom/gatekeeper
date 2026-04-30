package eu.gillstrom.gatekeeper.service;

import org.bouncycastle.openssl.PEMParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.*;
import eu.gillstrom.gatekeeper.signing.ReceiptCanonicalizer;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import eu.gillstrom.gatekeeper.model.VerificationResponse.DoraCompliance;
import eu.gillstrom.gatekeeper.model.VerificationResponse.KeyProperties;
import eu.gillstrom.gatekeeper.verification.AzureHsmVerifier;
import eu.gillstrom.gatekeeper.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

/**
 * NCA Independent Verification Service.
 *
 * <p>Performs cryptographic verification of HSM attestation evidence without
 * requiring the entity's cooperation. The verification is purely mathematical
 * — the attestation chain either validates against the HSM manufacturer's
 * root CA or it does not.</p>
 *
 * <p>This is the practical manifestation of the distinction between
 * contractual and cryptographic compliance: contractual compliance requires
 * trust in the counterparty's statements, while cryptographic compliance
 * through HSM attestation is independently verifiable.</p>
 *
 * <p>The primary operator of this service is the NCA (Finansinspektionen in
 * Sweden; the equivalent supervisor in other Member States). EBA does not
 * execute verifications itself but has read-access to the NCA's registry
 * under:</p>
 * <ul>
 *   <li>Article 17(4)/(6) of Regulation 1093/2010 (breach of Union law
 *       investigation; recommendations addressed to the NCA).</li>
 *   <li>Article 29 of Regulation 1093/2010 (supervisory convergence).</li>
 * </ul>
 */
@Service
public class VerificationService {

    private static final Logger log = LoggerFactory.getLogger(VerificationService.class);

    private final SecurosysVerifier securosysVerifier;
    private final YubicoVerifier yubicoVerifier;
    private final AzureHsmVerifier azureVerifier;
    private final GoogleCloudHsmVerifier googleVerifier;
    private final ApprovalRegistry approvalRegistry;
    private final ReceiptSigner receiptSigner;
    private final IssuerCaValidator issuerCaValidator;
    private final AuditLog auditLog;
    private final MtlsPrincipalResolver principalResolver;

    public VerificationService(
            SecurosysVerifier securosysVerifier,
            YubicoVerifier yubicoVerifier,
            AzureHsmVerifier azureVerifier,
            GoogleCloudHsmVerifier googleVerifier,
            ApprovalRegistry approvalRegistry,
            ReceiptSigner receiptSigner,
            IssuerCaValidator issuerCaValidator,
            AuditLog auditLog,
            MtlsPrincipalResolver principalResolver) {
        this.securosysVerifier = securosysVerifier;
        this.yubicoVerifier = yubicoVerifier;
        this.azureVerifier = azureVerifier;
        this.googleVerifier = googleVerifier;
        this.approvalRegistry = approvalRegistry;
        this.receiptSigner = receiptSigner;
        this.issuerCaValidator = issuerCaValidator;
        this.auditLog = auditLog;
        this.principalResolver = principalResolver;
    }

    /**
     * Independently verify HSM attestation evidence.
     * 
     * @param request The attestation evidence to verify
     * @return Binary compliance determination with DORA article mapping
     */
    public VerificationResponse verify(VerificationRequest request) {
        return verifyInternal(request, "VERIFY");
    }

    /**
     * Internal verify that takes the operation label so {@link #verifyBatch}
     * can record each entry as {@code BATCH_VERIFY} while reusing the
     * full single-verify pipeline.
     */
    private VerificationResponse verifyInternal(VerificationRequest request, String operationLabel) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Instant timestamp = Instant.now();

        // Parse public key
        PublicKey publicKey;
        String keyAlgorithm;
        try {
            publicKey = parsePublicKey(request.getPublicKey());
            keyAlgorithm = publicKey.getAlgorithm();
        } catch (Exception e) {
            errors.add("Invalid public key: " + e.getMessage());
            return buildNonCompliantResponse(errors, warnings, timestamp, request, operationLabel);
        }

        String publicKeyFingerprint = fingerprint(publicKey);

        // Determine vendor
        HsmVendor vendor;
        try {
            vendor = HsmVendor.valueOf(request.getHsmVendor().toUpperCase());
        } catch (Exception e) {
            errors.add("Unsupported or invalid HSM vendor: " + request.getHsmVendor()
                    + ". Supported: YUBICO, SECUROSYS, AZURE, GOOGLE");
            return buildNonCompliantResponse(errors, warnings, timestamp, request, operationLabel);
        }

        // Perform vendor-specific attestation verification
        boolean publicKeyMatch = false;
        boolean attestationChainValid = false;
        boolean generatedOnDevice = false;
        boolean exportable = true;
        String hsmModel = null;
        String hsmSerial = null;

        switch (vendor) {
            case SECUROSYS -> {
                if (request.getAttestationData() == null) {
                    errors.add("attestationData (XML) is required for Securosys verification");
                    break;
                }
                if (request.getAttestationSignature() == null) {
                    errors.add("attestationSignature is required for Securosys verification");
                    break;
                }
                if (request.getAttestationCertChain() == null || request.getAttestationCertChain().isEmpty()) {
                    errors.add("attestationCertChain is required for Securosys verification");
                    break;
                }
                var result = securosysVerifier.verifySecurosysAttestation(
                        request.getAttestationData(),
                        request.getAttestationSignature(),
                        request.getAttestationCertChain(),
                        publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                generatedOnDevice = true; // Securosys: never_extractable=true means generated on device
                exportable = result.isExtractable();
                hsmModel = "Primus HSM";
                hsmSerial = result.getHsmSerialNumber();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
            case YUBICO -> {
                if (request.getAttestationCertChain() == null || request.getAttestationCertChain().isEmpty()) {
                    errors.add("attestationCertChain is required for Yubico verification");
                    break;
                }
                var result = yubicoVerifier.verifyYubicoAttestation(
                        request.getAttestationCertChain(),
                        publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isKeyExportable();
                hsmModel = "YubiHSM 2";
                hsmSerial = result.getDeviceSerial();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
            case AZURE -> {
                if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
                    errors.add("attestationData (JSON) is required for Azure verification");
                    break;
                }
                var result = azureVerifier.verifyAzureAttestation(
                        request.getAttestationData(),
                        publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isExportable();
                hsmModel = "Azure Managed HSM";
                hsmSerial = result.getHsmPool();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
            case GOOGLE -> {
                if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
                    errors.add("attestationData is required for Google Cloud HSM verification");
                    break;
                }
                var result = googleVerifier.verifyGoogleAttestation(
                        request.getAttestationData(),
                        request.getAttestationCertChain(),
                        publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isExtractable();
                hsmModel = "Google Cloud HSM";
                hsmSerial = result.getKeyId();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
        }

        // Determine compliance
        boolean compliant = errors.isEmpty() && publicKeyMatch && attestationChainValid
                && generatedOnDevice && !exportable;

        // Build DORA compliance mapping
        DoraCompliance doraCompliance = buildDoraCompliance(
                compliant, publicKeyMatch, attestationChainValid, generatedOnDevice, exportable);

        // Key properties
        KeyProperties keyProperties = KeyProperties.builder()
                .generatedOnDevice(generatedOnDevice)
                .exportable(exportable)
                .attestationChainValid(attestationChainValid)
                .publicKeyMatchesAttestation(publicKeyMatch)
                .build();

        // Warnings for edge cases
        if (exportable && attestationChainValid) {
            warnings.add("CRITICAL: Key is marked as exportable. Even though HSM attestation is valid, "
                    + "an exportable key provides no security guarantee as it may have been copied outside the HSM boundary.");
        }
        if (!generatedOnDevice && attestationChainValid) {
            warnings.add("Key was imported into HSM, not generated on-device. "
                    + "Key may have existed in software before import, compromising security guarantees.");
        }

        // Generate unique verification ID (Step 4)
        String verificationId = UUID.randomUUID().toString();

        // Generate single-use confirmation nonce (Step 4 anti-replay binding).
        // The FE must echo this nonce back at Step 7; the registry compares
        // it constant-time and rejects mismatches as Step-7 replay attempts.
        String confirmationNonce = generateConfirmationNonce();

        // Register in approval registry (Step 4)
        approvalRegistry.register(
                verificationId, confirmationNonce, compliant, publicKeyFingerprint,
                request.getSupplierIdentifier(), request.getSupplierName(),
                compliant ? vendor.getVendorName() : null,
                compliant ? hsmModel : null,
                request.getCountryCode());

        // Build signed verification receipt (Step 5)
        VerificationResponse receipt = VerificationResponse.builder()
                .verificationId(verificationId)
                .confirmationNonce(confirmationNonce)
                .compliant(compliant)
                .verificationTimestamp(timestamp)
                .publicKeyFingerprint(publicKeyFingerprint)
                .publicKeyAlgorithm(keyAlgorithm)
                .hsmVendor(compliant ? vendor.getVendorName() : null)
                .hsmModel(compliant ? hsmModel : null)
                .hsmSerialNumber(compliant ? hsmSerial : null)
                .keyProperties(keyProperties)
                .doraCompliance(doraCompliance)
                .supplierIdentifier(request.getSupplierIdentifier())
                .supplierName(request.getSupplierName())
                .keyPurpose(request.getKeyPurpose())
                .countryCode(request.getCountryCode())
                .errors(errors)
                .warnings(warnings)
                .build();

        // Sign the receipt with the NCA's signing key (Step 5).
        // Primary operator is the NCA (e.g. Finansinspektionen); receipts
        // are signed in production with the NCA's organisation-certificate-
        // backed signing key — the certificate the NCA uses for ordinary
        // administrative signing of supervisory acts. The reference
        // implementation uses whichever ReceiptSigner bean is active —
        // ConfiguredReceiptSigner loads a real PKCS#12 keystore;
        // EphemeralReceiptSigner generates a throwaway key at startup and
        // logs prominent warnings so it cannot be deployed to production
        // unnoticed.
        receiptSigner.signInto(receipt);

        // Append a tamper-evident audit-log entry. DORA Article 28(6)
        // mandates 5-year retention; the audit log is the artefact a
        // supervisor reads under EBA Reg 1093/2010 Art 35(1).
        appendAuditEntry(operationLabel, verificationId, request, receipt);

        return receipt;
    }

    /**
     * Batch verification for multiple entities.
     * Returns individual results plus aggregate statistics.
     * A compliance rate significantly below 100% indicates a systemic
     * supervisory failure — precisely the type of finding that triggers
     * EBA's obligations under Article 17 of Regulation 1093/2010.
     */
    public BatchVerificationResponse verifyBatch(List<VerificationRequest> requests) {
        List<VerificationResponse> results = new ArrayList<>();
        int compliantCount = 0;
        int nonCompliantCount = 0;

        for (VerificationRequest request : requests) {
            // Each batch element gets its own audit-log entry tagged
            // BATCH_VERIFY so supervisors can distinguish batch
            // submissions from interactive single verifications.
            VerificationResponse result = verifyInternal(request, "BATCH_VERIFY");
            results.add(result);
            if (result.isCompliant()) {
                compliantCount++;
            } else {
                nonCompliantCount++;
            }
        }

        return BatchVerificationResponse.builder()
                .verificationTimestamp(Instant.now())
                .totalEntities(requests.size())
                .compliantCount(compliantCount)
                .nonCompliantCount(nonCompliantCount)
                .complianceRate(requests.isEmpty() ? 0.0
                        : (double) compliantCount / requests.size() * 100)
                .results(results)
                .build();
    }

    private DoraCompliance buildDoraCompliance(boolean compliant, boolean publicKeyMatch,
            boolean chainValid, boolean generatedOnDevice, boolean exportable) {

        // Article 5(2)(b): High standards for authenticity and integrity
        // Cannot be maintained without verified HSM protection
        boolean art5_2b = chainValid && publicKeyMatch && !exportable;

        // Article 6(10): Full responsibility for verification of compliance
        // "The verification" in definite form presupposes verification occurs
        boolean art6_10 = chainValid && publicKeyMatch && generatedOnDevice && !exportable;

        // Article 9(3)(c): PREVENT impairment of authenticity and integrity
        // Verb is "prevent" — requires active measure, not passive contractual term
        boolean art9_3c = chainValid && publicKeyMatch && !exportable;

        // Article 9(3)(d): Protection against poor administration,
        // processing-related risks and the human factor
        boolean art9_3d = chainValid && generatedOnDevice && !exportable;

        // Article 9(4)(d): Strong authentication mechanisms with dedicated control systems
        boolean art9_4d = chainValid && publicKeyMatch && generatedOnDevice && !exportable;

        // Article 28(1)(a): Full responsibility at all times regardless of
        // contractual arrangements
        boolean art28_1a = compliant;

        String summary;
        if (compliant) {
            summary = "Signing key is cryptographically proven to be generated and stored in a certified HSM "
                    + "with non-exportable attribute. All DORA requirements for cryptographic key management "
                    + "are independently verifiable.";
        } else {
            List<String> failures = new ArrayList<>();
            if (!chainValid)
                failures.add("attestation chain invalid");
            if (!publicKeyMatch)
                failures.add("public key does not match attestation");
            if (!generatedOnDevice)
                failures.add("key not generated on device");
            if (exportable)
                failures.add("key is exportable");

            summary = "Non-compliant: " + String.join(", ", failures) + ". "
                    + "The absence of valid attestation means the financial entity cannot demonstrate compliance "
                    + "with DORA Articles 5(2)(b), 6(10), 9(3)(c)-(d), 9(4)(d), or 28(1)(a). "
                    + "The entity must provide cryptographic attestation evidence or be considered non-compliant.";
        }

        return DoraCompliance.builder()
                .article5_2b(art5_2b)
                .article6_10(art6_10)
                .article9_3c(art9_3c)
                .article9_3d(art9_3d)
                .article9_4d(art9_4d)
                .article28_1a(art28_1a)
                .summary(summary)
                .build();
    }

    private PublicKey parsePublicKey(String pemInput) throws Exception {
        String pem = pemInput.trim();
        if (pem.startsWith("-----BEGIN PUBLIC KEY-----")) {
            String base64 = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            try {
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            } catch (Exception e) {
                return KeyFactory.getInstance("EC").generatePublic(spec);
            }
        } else if (pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----")) {
            try (PEMParser parser = new PEMParser(new StringReader(pem))) {
                var csr = (org.bouncycastle.pkcs.PKCS10CertificationRequest) parser.readObject();
                var pkInfo = csr.getSubjectPublicKeyInfo();
                var keySpec = new X509EncodedKeySpec(pkInfo.getEncoded());
                String algorithm = pkInfo.getAlgorithm().getAlgorithm().getId();
                String keyAlg = algorithm.startsWith("1.2.840.10045") ? "EC" : "RSA";
                return KeyFactory.getInstance(keyAlg).generatePublic(keySpec);
            }
        }
        throw new IllegalArgumentException(
                "Input must be PEM-encoded public key or CSR");
    }

    /**
     * Generate a single-use confirmation nonce: 32 random bytes from
     * {@link SecureRandom}, base64url-encoded without padding (~43 chars).
     * The nonce is bound to the verificationId at register time and the
     * registry compares it constant-time against the submitted nonce at
     * confirm time. This is the Step-7 replay-binding primitive.
     */
    private static final SecureRandom NONCE_RNG = new SecureRandom();

    private static String generateConfirmationNonce() {
        byte[] bytes = new byte[32];
        NONCE_RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String fingerprint(PublicKey key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(key.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x:", b & 0xff));
            }
            return sb.substring(0, sb.length() - 1);
        } catch (Exception e) {
            // SHA-256 is mandatory in every JRE (JCA guarantee), so this branch
            // should be unreachable. If it ever fires we want a loud signal
            // rather than a silent "error" string propagated into a receipt.
            log.error("Unexpected SHA-256 fingerprint failure", e);
            return "error";
        }
    }

    private VerificationResponse buildNonCompliantResponse(List<String> errors,
            List<String> warnings, Instant timestamp, VerificationRequest request,
            String operationLabel) {

        String verificationId = UUID.randomUUID().toString();
        String confirmationNonce = generateConfirmationNonce();

        // Register non-compliant result in approval registry
        approvalRegistry.register(
                verificationId, confirmationNonce, false, null,
                request.getSupplierIdentifier(), request.getSupplierName(),
                null, null, request.getCountryCode());

        VerificationResponse receipt = VerificationResponse.builder()
                .verificationId(verificationId)
                .confirmationNonce(confirmationNonce)
                .compliant(false)
                .verificationTimestamp(timestamp)
                .keyProperties(KeyProperties.builder()
                        .generatedOnDevice(false)
                        .exportable(true)
                        .attestationChainValid(false)
                        .publicKeyMatchesAttestation(false)
                        .build())
                .doraCompliance(DoraCompliance.builder()
                        .article5_2b(false)
                        .article6_10(false)
                        .article9_3c(false)
                        .article9_3d(false)
                        .article9_4d(false)
                        .article28_1a(false)
                        .summary("Verification could not be completed. " + String.join("; ", errors))
                        .build())
                .supplierIdentifier(request.getSupplierIdentifier())
                .supplierName(request.getSupplierName())
                .keyPurpose(request.getKeyPurpose())
                .countryCode(request.getCountryCode())
                .errors(errors)
                .warnings(warnings)
                .build();

        // Non-compliant receipts are sealed with the same NCA/EBA seal as compliant ones —
        // otherwise a supervisee could repudiate a NON-COMPLIANT finding.
        receiptSigner.signInto(receipt);

        // Audit-log non-compliant outcomes too — a refusal to verify is
        // itself a supervisory event.
        appendAuditEntry(operationLabel, verificationId, request, receipt);

        return receipt;
    }

    /**
     * Compute the request and receipt digests, append an audit-log entry,
     * and surface persistence failures via {@link
     * eu.gillstrom.gatekeeper.audit.AuditLogException}.
     *
     * <p>The request digest is taken over a deterministic "request fingerprint"
     * built from the supplier identifier, public-key PEM, vendor and the
     * country code. Storing only a digest (rather than the full payload)
     * keeps the audit log compact while still letting a supervisor verify
     * "this was the request" given the original payload — the receipt
     * itself is the authoritative record.</p>
     */
    private void appendAuditEntry(String operationLabel,
                                  String verificationId,
                                  VerificationRequest request,
                                  VerificationResponse receipt) {
        String requestDigestB64 = sha256Base64(canonicalRequestBytes(request));
        String receiptDigestB64 = sha256Base64(ReceiptCanonicalizer.canonicalize(receipt));
        AuditAppendRequest req = new AuditAppendRequest(
                principalResolver.currentPrincipal(),
                operationLabel,
                verificationId,
                requestDigestB64,
                receiptDigestB64,
                receipt.isCompliant());
        auditLog.append(req);
    }

    /**
     * Append-only audit witness for a Step 7 confirmation. The receipt
     * digest is {@code null} because confirm responses are not signed
     * receipts — the authoritative artefact for Step 7 is the registry
     * transition, not a receipt. Compliance for the audit row is the
     * conjunction "loop closed AND public-key match (when issued) AND
     * no anomalies", reflecting the supervisor's view of "did this
     * confirmation pass?".
     */
    private void appendConfirmAuditEntry(IssuanceConfirmation confirmation,
                                         IssuanceConfirmationResponse response) {
        String requestDigestB64 = sha256Base64(canonicalConfirmationBytes(confirmation));
        boolean confirmCompliant = response.isLoopClosed()
                && (response.getAnomalies() == null || response.getAnomalies().isEmpty())
                && (response.getPublicKeyMatch() == null || response.getPublicKeyMatch());
        AuditAppendRequest req = new AuditAppendRequest(
                principalResolver.currentPrincipal(),
                "CONFIRM",
                confirmation.getVerificationId(),
                requestDigestB64,
                null,
                confirmCompliant);
        auditLog.append(req);
    }

    private static byte[] canonicalRequestBytes(VerificationRequest r) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("v1|verify|")
          .append(safeNull(r.getCountryCode())).append('|')
          .append(safeNull(r.getSupplierIdentifier())).append('|')
          .append(safeNull(r.getSupplierName())).append('|')
          .append(safeNull(r.getHsmVendor())).append('|')
          .append(safeNull(r.getKeyPurpose())).append('|')
          .append(safeNull(r.getPublicKey())).append('|')
          .append(safeNull(r.getAttestationData())).append('|')
          .append(safeNull(r.getAttestationSignature()));
        if (r.getAttestationCertChain() != null) {
            for (String cert : r.getAttestationCertChain()) {
                sb.append('|').append(safeNull(cert));
            }
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] canonicalConfirmationBytes(IssuanceConfirmation c) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("v1|confirm|")
          .append(safeNull(c.getVerificationId())).append('|')
          .append(c.isIssued()).append('|')
          .append(safeNull(c.getSigningCertificatePem()));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String safeNull(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("%", "%25").replace("|", "%7C");
    }

    private static String sha256Base64(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(md.digest(in));
        } catch (Exception e) {
            // SHA-256 is mandated; reaching this branch is a JRE config bug.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // =========================================================================
    // Step 7: Issuance Confirmation — close the verification loop
    // =========================================================================

    /**
     * Process an issuance confirmation from the certificate issuer (Step 7).
     * 
     * If the certificate was issued, extracts the public key from the
     * submitted signing certificate and verifies that it matches the
     * attestation evidence approved in Steps 2-5. The verification is
     * cryptographic: EBA does not rely on the issuer's assertion.
     * 
     * Anomalies are detected and flagged:
     * - Certificate issued despite NON-COMPLIANT attestation
     * - Public key in certificate does not match approved attestation
     * - Confirmation for unknown verification ID
     */
    public IssuanceConfirmationResponse confirmIssuance(IssuanceConfirmation confirmation) {
        List<String> anomalies = new ArrayList<>();
        Instant processedTimestamp = Instant.now();

        // Look up the original verification in the registry
        Optional<ApprovalRegistry.RegistryEntry> entryOpt =
                approvalRegistry.lookup(confirmation.getVerificationId());

        if (entryOpt.isEmpty()) {
            anomalies.add("ANOMALY: Confirmation received for unknown verification ID: "
                    + confirmation.getVerificationId());
            IssuanceConfirmationResponse unknownResp = IssuanceConfirmationResponse.builder()
                    .verificationId(confirmation.getVerificationId())
                    .loopClosed(false)
                    .registryStatus(IssuanceConfirmationResponse.RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION)
                    .processedTimestamp(processedTimestamp.toString())
                    .anomalies(anomalies)
                    .build();
            // Audit-log the anomaly so a supervisor can detect "fake
            // confirmations" that reference unknown verification IDs.
            appendConfirmAuditEntry(confirmation, unknownResp);
            return unknownResp;
        }

        ApprovalRegistry.RegistryEntry entry = entryOpt.get();
        String expectedFingerprint = entry.getPublicKeyFingerprint();
        String actualFingerprint = null;
        boolean publicKeyMatch = false;

        if (confirmation.isIssued() && confirmation.getSigningCertificatePem() != null) {
            // Extract public key from the submitted certificate and compare
            try {
                java.security.cert.X509Certificate submittedCert =
                        parseX509Certificate(confirmation.getSigningCertificatePem());

                // Bind the Step 7 confirmation to the known issuer CA set:
                // the submitted certificate must chain to a trusted issuer
                // CA (e.g. Getswish Root CA v2), otherwise an attacker who
                // knows only the verificationId can submit arbitrary
                // certificates. Fail-closed.
                if (!issuerCaValidator.validate(submittedCert)) {
                    anomalies.add("ANOMALY: Submitted signing certificate is not issued by a trusted "
                            + "issuer CA (PKIX validation failed against the configured "
                            + "gatekeeper.confirmation.issuer-ca-bundle-path trust anchors).");
                } else {
                    PublicKey certPublicKey = submittedCert.getPublicKey();
                    actualFingerprint = fingerprint(certPublicKey);
                    publicKeyMatch = actualFingerprint.equals(expectedFingerprint);

                    if (!publicKeyMatch) {
                        anomalies.add("ANOMALY: Public key in issued certificate does not match "
                                + "the attestation evidence approved in verification "
                                + confirmation.getVerificationId());
                    }
                }
            } catch (Exception e) {
                anomalies.add("Failed to extract public key from submitted certificate: "
                        + e.getMessage());
            }
        }

        if (confirmation.isIssued() && !entry.isCompliant()) {
            anomalies.add("CRITICAL ANOMALY: Certificate issued despite NON-COMPLIANT "
                    + "attestation verification. This constitutes active circumvention "
                    + "of the supervisory mechanism.");
        }

        // Update the registry entry with confirmation result. The registry
        // verifies the submitted nonce matches the one bound at verify time
        // and throws NonceMismatchException on a mismatch (replay attempt).
        approvalRegistry.confirm(
                confirmation.getVerificationId(),
                confirmation.getConfirmationNonce(),
                confirmation.isIssued(),
                actualFingerprint,
                publicKeyMatch);

        // Determine final status
        IssuanceConfirmationResponse.RegistryStatus finalStatus;
        if (entry.isCompliant() && confirmation.isIssued() && publicKeyMatch) {
            finalStatus = IssuanceConfirmationResponse.RegistryStatus.VERIFIED_AND_ISSUED;
        } else if (entry.isCompliant() && confirmation.isIssued() && !publicKeyMatch) {
            finalStatus = IssuanceConfirmationResponse.RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH;
        } else if (entry.isCompliant() && !confirmation.isIssued()) {
            finalStatus = IssuanceConfirmationResponse.RegistryStatus.VERIFIED_NOT_ISSUED;
        } else if (!entry.isCompliant() && confirmation.isIssued()) {
            finalStatus = IssuanceConfirmationResponse.RegistryStatus.ANOMALY_ISSUED_DESPITE_REJECTION;
        } else {
            finalStatus = IssuanceConfirmationResponse.RegistryStatus.REJECTED_NOT_ISSUED;
        }

        IssuanceConfirmationResponse resp = IssuanceConfirmationResponse.builder()
                .verificationId(confirmation.getVerificationId())
                .loopClosed(anomalies.isEmpty())
                .publicKeyMatch(confirmation.isIssued() ? publicKeyMatch : null)
                .expectedPublicKeyFingerprint(expectedFingerprint)
                .actualPublicKeyFingerprint(actualFingerprint)
                .registryStatus(finalStatus)
                .processedTimestamp(processedTimestamp.toString())
                .anomalies(anomalies)
                .build();

        // Append a CONFIRM audit entry. The audit-log compliance bit
        // captures "loop closed AND no anomalies" so a supervisor can
        // filter the trail by clean vs. anomalous confirmations.
        appendConfirmAuditEntry(confirmation, resp);

        return resp;
    }

    // =========================================================================
    // Receipt signing (Step 5) has moved to the ReceiptSigner interface;
    // see ConfiguredReceiptSigner for production deployments and
    // EphemeralReceiptSigner for the reference configuration.
    // =========================================================================

    /**
     * Parse a PEM-encoded X.509 certificate via the standard JCA
     * {@link java.security.cert.CertificateFactory}. Using the standard
     * factory (rather than extracting only the {@link PublicKey} via
     * BouncyCastle's {@code X509CertificateHolder}) lets callers pass the
     * parsed certificate to {@link IssuerCaValidator} for PKIX validation
     * against the issuer CA trust anchors.
     */
    private java.security.cert.X509Certificate parseX509Certificate(String certificatePem) throws Exception {
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        byte[] pemBytes = certificatePem.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return (java.security.cert.X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(pemBytes));
    }

    /**
     * Legacy helper kept only for binary compatibility in case any external
     * caller still references the PEMParser-based path; internal flow now
     * uses {@link #parseX509Certificate(String)} so the parsed certificate
     * can also be PKIX-validated against the issuer CA trust anchors.
     */
    @SuppressWarnings("unused")
    private PublicKey extractPublicKeyFromCertificate(String certificatePem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(certificatePem))) {
            Object parsed = parser.readObject();
            if (parsed instanceof org.bouncycastle.cert.X509CertificateHolder holder) {
                byte[] encoded = holder.getSubjectPublicKeyInfo().getEncoded();
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
                try {
                    return KeyFactory.getInstance("RSA").generatePublic(keySpec);
                } catch (Exception e) {
                    return KeyFactory.getInstance("EC").generatePublic(keySpec);
                }
            }
            throw new IllegalArgumentException("Could not parse X.509 certificate from PEM");
        }
    }
}
