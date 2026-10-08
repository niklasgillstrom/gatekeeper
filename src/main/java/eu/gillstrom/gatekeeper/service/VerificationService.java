package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.util.Fingerprints;

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
import eu.gillstrom.gatekeeper.verification.MarvellHsmVerifier;
import eu.gillstrom.gatekeeper.verification.ThalesLunaVerifier;
import eu.gillstrom.gatekeeper.verification.Crypto4AVerifier;
import eu.gillstrom.gatekeeper.verification.FortanixVerifier;
import eu.gillstrom.gatekeeper.verification.NShieldVerifier;
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
    private final MarvellHsmVerifier marvellVerifier;
    private final ThalesLunaVerifier thalesVerifier;
    private final Crypto4AVerifier crypto4aVerifier;
    private final FortanixVerifier fortanixVerifier;
    private final NShieldVerifier nshieldVerifier;
    private final ApprovalRegistry approvalRegistry;
    private final ReceiptSigner receiptSigner;
    private final IssuerCaValidator issuerCaValidator;
    private final AuditLog auditLog;
    private final MtlsPrincipalResolver principalResolver;
    private final KeyPolicy keyPolicy;

    /**
     * Whether the confirm-time principal binding is enforced. Follows
     * {@code gatekeeper.security.mtls.enabled}: with the permissive
     * reference filter chain there is no authenticated caller to bind to,
     * so the check is skipped and {@link #warnIfPrincipalBindingDisabled()}
     * says so at startup, in the same manner as the other permissive
     * warnings ({@code SecurityConfig}, {@code EphemeralReceiptSigner},
     * {@code InMemoryApprovalRegistry}).
     */
    private final boolean mtlsEnabled;

    public VerificationService(
            SecurosysVerifier securosysVerifier,
            YubicoVerifier yubicoVerifier,
            AzureHsmVerifier azureVerifier,
            GoogleCloudHsmVerifier googleVerifier,
            MarvellHsmVerifier marvellVerifier,
            ThalesLunaVerifier thalesVerifier,
            Crypto4AVerifier crypto4aVerifier,
            FortanixVerifier fortanixVerifier,
            NShieldVerifier nshieldVerifier,
            ApprovalRegistry approvalRegistry,
            ReceiptSigner receiptSigner,
            IssuerCaValidator issuerCaValidator,
            AuditLog auditLog,
            MtlsPrincipalResolver principalResolver,
            KeyPolicy keyPolicy,
            @org.springframework.beans.factory.annotation.Value(
                    "${gatekeeper.security.mtls.enabled:false}") boolean mtlsEnabled) {
        this.mtlsEnabled = mtlsEnabled;
        this.securosysVerifier = securosysVerifier;
        this.yubicoVerifier = yubicoVerifier;
        this.azureVerifier = azureVerifier;
        this.googleVerifier = googleVerifier;
        this.marvellVerifier = marvellVerifier;
        this.thalesVerifier = thalesVerifier;
        this.crypto4aVerifier = crypto4aVerifier;
        this.fortanixVerifier = fortanixVerifier;
        this.nshieldVerifier = nshieldVerifier;
        this.approvalRegistry = approvalRegistry;
        this.receiptSigner = receiptSigner;
        this.issuerCaValidator = issuerCaValidator;
        this.auditLog = auditLog;
        this.principalResolver = principalResolver;
        this.keyPolicy = keyPolicy;
    }

    /**
     * Startup notice when the confirm-time principal binding cannot be
     * enforced, matching the existing permissive warnings so the relaxed
     * stance cannot be deployed unnoticed.
     */
    @jakarta.annotation.PostConstruct
    void warnIfPrincipalBindingDisabled() {
        if (!mtlsEnabled) {
            log.warn("Step-7 confirm principal binding is DISABLED "
                    + "(gatekeeper.security.mtls.enabled=false). Any caller that knows a "
                    + "verificationId and its confirmationNonce can close the loop, not only "
                    + "the financial entity that performed the verification. This is the "
                    + "REFERENCE configuration and MUST NOT be deployed to production. The "
                    + "jurisdiction binding (countryCode in the path must match the registry "
                    + "entry) is enforced regardless of this setting.");
        }
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

        // A key outside the policy is NON-COMPLIANT whatever its attestation
        // shows; the attestation is still verified so the receipt reports it.
        String keyViolation = keyPolicy.violation(publicKey).orElse(null);
        if (keyViolation != null) {
            errors.add("KEY_NOT_ALLOWED: " + keyViolation);
        }

        // Determine vendor
        HsmVendor vendor;
        try {
            vendor = HsmVendor.valueOf(request.getHsmVendor().toUpperCase());
        } catch (Exception e) {
            errors.add("Unsupported or invalid HSM vendor: " + request.getHsmVendor()
                    + ". Supported: YUBICO, SECUROSYS, AZURE, GOOGLE, MARVELL, THALES, CRYPTO4A, FORTANIX, ENTRUST");
            return buildNonCompliantResponse(errors, warnings, timestamp, request, operationLabel);
        }

        // Perform vendor-specific attestation verification
        boolean publicKeyMatch = false;
        boolean attestationChainValid = false;
        boolean attestationSignatureValid = false;
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
                attestationSignatureValid = result.isSignatureValid();
                // Origin comes from the attestation's creation attribute; the
                // never_extractable/always_sensitive flags are not origin
                // attributes and no longer stand in for it.
                generatedOnDevice = result.isSignatureValid()
                        && "generated".equals(result.getKeyOrigin());
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
                attestationSignatureValid = result.isChainValid();
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
                attestationSignatureValid = result.isSignatureValid();
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
                attestationSignatureValid = result.isSignatureValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isExtractable();
                hsmModel = "Google Cloud HSM";
                hsmSerial = result.getKeyId();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
            case MARVELL -> {
                if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
                    errors.add("attestationData (base64 of attest.dat) is required for Marvell LiquidSecurity verification");
                    break;
                }
                var result = marvellVerifier.verifyMarvellAttestation(
                        request.getAttestationData(),
                        request.getAttestationCertChain(),
                        publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                attestationSignatureValid = result.isSignatureValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isExtractable();
                hsmModel = "Marvell LiquidSecurity";
                hsmSerial = result.getPartitionSerial();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
            case THALES -> {
                if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
                    errors.add("attestationData (base64 of the PKC from cmu getpkc) is required for Thales Luna verification");
                    break;
                }
                var result = thalesVerifier.verifyLunaAttestation(request.getAttestationData(), publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                // The PKC is the HSM's signed statement: its chain signatures are the attestation signature.
                attestationSignatureValid = result.isChainValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isExportable();
                hsmModel = "Thales Luna";
                hsmSerial = result.getHsmSerial();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
            case CRYPTO4A -> {
                if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
                    errors.add("attestationData (the QASM attestation message, base64 or PEM) is required for Crypto4A verification");
                    break;
                }
                var result = crypto4aVerifier.verifyCrypto4AAttestation(request.getAttestationData(), publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                attestationSignatureValid = result.isSignatureValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isExportable();
                hsmModel = "Crypto4A QASM";
                hsmSerial = result.getHsmSerial();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
            case FORTANIX -> {
                if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
                    errors.add("attestationData (the DSM key attestation JSON) is required for Fortanix verification");
                    break;
                }
                var result = fortanixVerifier.verifyFortanixAttestation(request.getAttestationData(), publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                attestationSignatureValid = result.isSignatureValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isExportable();
                hsmModel = "Fortanix DSM";
                hsmSerial = result.getKeyId();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
            case ENTRUST -> {
                if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
                    errors.add("attestationData (the nShield key attestation bundle JSON) is required for Entrust verification");
                    break;
                }
                var result = nshieldVerifier.verifyNShieldAttestation(request.getAttestationData(), publicKey);
                publicKeyMatch = result.isPublicKeyMatch();
                attestationChainValid = result.isChainValid();
                // The warrant, module state, world binding and key generation
                // signatures are all part of the chain.
                attestationSignatureValid = result.isChainValid();
                generatedOnDevice = "generated".equals(result.getKeyOrigin());
                exportable = result.isExportable();
                hsmModel = "Entrust nShield";
                hsmSerial = result.getEsn();
                if (!result.isValid()) {
                    errors.addAll(result.getErrors());
                }
            }
        }

        // Determine compliance
        boolean compliant = errors.isEmpty() && publicKeyMatch && attestationChainValid
                && attestationSignatureValid && generatedOnDevice && !exportable;

        // Build DORA compliance mapping
        DoraCompliance doraCompliance = buildDoraCompliance(
                compliant, publicKeyMatch, attestationChainValid, attestationSignatureValid,
                generatedOnDevice, exportable, keyViolation);

        // Key properties
        KeyProperties keyProperties = KeyProperties.builder()
                .generatedOnDevice(generatedOnDevice)
                .exportable(exportable)
                .attestationChainValid(attestationChainValid)
                .publicKeyMatchesAttestation(publicKeyMatch)
                .build();

        // Warnings for edge cases
        if (exportable && attestationChainValid && attestationSignatureValid) {
            warnings.add("CRITICAL: Key is marked as exportable. Even though HSM attestation is valid, "
                    + "an exportable key provides no security guarantee as it may have been copied outside the HSM boundary.");
        }
        if (!generatedOnDevice && attestationChainValid && attestationSignatureValid) {
            warnings.add("Key was imported into HSM, not generated on-device. "
                    + "Key may have existed in software before import, compromising security guarantees.");
        }

        // Generate unique verification ID (Step 4)
        String verificationId = UUID.randomUUID().toString();

        // Generate single-use confirmation nonce (Step 4 anti-replay binding).
        // The FE must echo this nonce back at Step 7; the registry compares
        // it constant-time and rejects mismatches as Step-7 replay attempts.
        String confirmationNonce = generateConfirmationNonce();

        // Register in approval registry (Step 4). The calling principal is
        // bound to the entry so that only the same client can confirm it.
        approvalRegistry.register(
                verificationId, confirmationNonce, compliant, publicKeyFingerprint,
                parties(request), request,
                compliant ? vendor.getVendorName() : null,
                compliant ? hsmModel : null,
                request.getCountryCode(),
                principalResolver.currentPrincipal());

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
                .customerOrganisationNumber(request.getCustomerOrganisationNumber())
                .customerSwishNumber(request.getCustomerSwishNumber())
                .supplierIdentifier(request.getSupplierIdentifier())
                .supplierNumber(request.getSupplierNumber())
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
            boolean chainValid, boolean signatureValid, boolean generatedOnDevice, boolean exportable,
            String keyViolation) {

        // Article 5(2)(b): High standards for authenticity and integrity
        // Cannot be maintained without verified HSM protection
        boolean art5_2b = signatureValid && chainValid && publicKeyMatch && !exportable;

        // Article 6(10): Full responsibility for verification of compliance
        // "The verification" in definite form presupposes verification occurs
        boolean art6_10 = signatureValid && chainValid && publicKeyMatch && generatedOnDevice && !exportable;

        // Article 9(3)(c): PREVENT impairment of authenticity and integrity
        // Verb is "prevent" — requires active measure, not passive contractual term
        boolean art9_3c = signatureValid && chainValid && publicKeyMatch && !exportable;

        // Article 9(3)(d): "ensure that data is protected from risks arising from
        // data management, including poor administration, processing-related
        // risks and human error"
        boolean art9_3d = signatureValid && chainValid && generatedOnDevice && !exportable;

        // Article 9(4)(d): "policies and protocols for strong authentication
        // mechanisms, based on relevant standards and dedicated control systems,
        // and protection measures of cryptographic keys"
        boolean art9_4d = signatureValid && chainValid && publicKeyMatch && generatedOnDevice && !exportable;

        // Article 28(1)(a): Full responsibility at all times regardless of
        // contractual arrangements
        boolean art28_1a = signatureValid && compliant;

        String summary;
        if (compliant) {
            summary = "Signing key is cryptographically proven to be generated and stored in a certified HSM "
                    + "with non-exportable attribute. All DORA requirements for cryptographic key management "
                    + "are independently verifiable.";
        } else if (keyViolation != null && signatureValid && chainValid && publicKeyMatch && generatedOnDevice
                && !exportable) {
            // The articles above describe the attestation; the key itself is
            // outside the scheme's key policy.
            summary = "Non-compliant: " + keyViolation + ". The attestation evidence verified, but the "
                    + "key is not one the scheme accepts.";
        } else {
            List<String> failures = new ArrayList<>();
            if (!chainValid)
                failures.add("attestation chain invalid");
            if (!signatureValid)
                failures.add("attestation signature invalid");
            if (!publicKeyMatch)
                failures.add("public key does not match attestation");
            if (!generatedOnDevice)
                failures.add("key not generated on device");
            if (exportable)
                failures.add("key is exportable");
            if (keyViolation != null)
                failures.add(keyViolation);

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
        return Fingerprints.ofPublicKey(key);
    }

    private VerificationResponse buildNonCompliantResponse(List<String> errors,
            List<String> warnings, Instant timestamp, VerificationRequest request,
            String operationLabel) {

        String verificationId = UUID.randomUUID().toString();
        String confirmationNonce = generateConfirmationNonce();

        // Register non-compliant result in approval registry
        approvalRegistry.register(
                verificationId, confirmationNonce, false, null,
                parties(request), request,
                null, null, request.getCountryCode(),
                principalResolver.currentPrincipal());

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
                .customerOrganisationNumber(request.getCustomerOrganisationNumber())
                .customerSwishNumber(request.getCustomerSwishNumber())
                .supplierIdentifier(request.getSupplierIdentifier())
                .supplierNumber(request.getSupplierNumber())
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
     * built from the country code, the customer's organisation and Swish
     * numbers, the supplier identifier, number and name, vendor, key
     * purpose, public-key PEM, attestation data and signature, and every
     * certificate of the attestation chain. Storing only a digest (rather than the full payload)
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
     * digest is {@code null}: the authoritative artefact for Step 7 is the
     * registry transition, not a receipt. Compliance for the audit row is
     * "loop closed", which every response sets exactly when there are no
     * anomalies; a failed public-key match on an issued certificate always
     * adds one, so it needs no separate term.
     */
    private void appendConfirmAuditEntry(IssuanceConfirmation confirmation,
                                         IssuanceConfirmationResponse response) {
        String requestDigestB64 = sha256Base64(canonicalConfirmationBytes(confirmation));
        boolean confirmCompliant = response.isLoopClosed();
        AuditAppendRequest req = new AuditAppendRequest(
                principalResolver.currentPrincipal(),
                "CONFIRM",
                confirmation.getVerificationId(),
                requestDigestB64,
                null,
                confirmCompliant);
        auditLog.append(req);
    }

    private static ApprovalRegistry.Parties parties(VerificationRequest r) {
        return new ApprovalRegistry.Parties(r.getCustomerOrganisationNumber(), r.getCustomerSwishNumber(),
                r.getSupplierIdentifier(), r.getSupplierNumber(), r.getSupplierName());
    }

    /**
     * Base64 SHA-256 of the canonical request bytes: the {@code requestDigestBase64}
     * of the request's audit entry. Recomputing it from a registry entry's
     * {@code submission} shows that the stored evidence is what was verified.
     */
    public static String requestDigestBase64(VerificationRequest r) {
        return sha256Base64(canonicalRequestBytes(r));
    }

    private static byte[] canonicalRequestBytes(VerificationRequest r) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("v2|verify|")
          .append(safeNull(r.getCountryCode())).append('|')
          .append(safeNull(r.getCustomerOrganisationNumber())).append('|')
          .append(safeNull(r.getCustomerSwishNumber())).append('|')
          .append(safeNull(r.getSupplierIdentifier())).append('|')
          .append(safeNull(r.getSupplierNumber())).append('|')
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
     * - Issuance confirmed without a signing certificate
     * - Confirmation for unknown verification ID
     *
     * <p>Two bindings gate the lookup before any of that runs. The
     * {@code countryCode} from the request path must match the registry
     * entry's jurisdiction, and — when mTLS is enabled — the calling
     * principal must be the one that performed the verification. A failure
     * of either is reported exactly as an unknown {@code verificationId}:
     * the caller learns nothing about entries in other jurisdictions or
     * belonging to other entities.</p>
     *
     * @param confirmation the Step 7 payload
     * @param countryCode jurisdiction from the request path, upper-cased by
     *     the controller
     */
    public IssuanceConfirmationResponse confirmIssuance(IssuanceConfirmation confirmation,
                                                        String countryCode) {
        List<String> anomalies = new ArrayList<>();
        Instant processedTimestamp = Instant.now();

        // Look up the original verification in the registry, scoped to the
        // jurisdiction in the request path. A confirmation posted to another
        // Member State's path does not resolve.
        Optional<ApprovalRegistry.RegistryEntry> entryOpt =
                approvalRegistry.lookup(confirmation.getVerificationId(), countryCode);

        // Bind the confirmation to the client that performed the
        // verification. Both this and the jurisdiction mismatch above fall
        // into the same "unknown verificationId" branch on purpose: the
        // response must not tell a caller that the entry exists but belongs
        // to somebody else, or to another Member State.
        if (entryOpt.isPresent() && !principalMatches(entryOpt.get())) {
            log.warn("Confirm rejected for verificationId={}: calling principal '{}' is not the "
                    + "principal that performed the verification. Reported as unknown "
                    + "verificationId so the entry's existence is not disclosed.",
                    confirmation.getVerificationId(), principalResolver.currentPrincipal());
            entryOpt = Optional.empty();
        }

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
            receiptSigner.signInto(unknownResp);
            // Audit-log the anomaly so a supervisor can detect "fake
            // confirmations" that reference unknown verification IDs.
            appendConfirmAuditEntry(confirmation, unknownResp);
            return unknownResp;
        }

        ApprovalRegistry.RegistryEntry entry = entryOpt.get();
        String expectedFingerprint = entry.getPublicKeyFingerprint();
        String actualFingerprint = null;
        boolean publicKeyMatch = false;

        ApprovalRegistry.IssuedCertificate issuedCertificate = null;

        if (confirmation.isIssued()
                && (confirmation.getSigningCertificatePem() == null
                        || confirmation.getSigningCertificatePem().isBlank())) {
            anomalies.add("ANOMALY: Issuance confirmed without a signing certificate. The public "
                    + "key of the issued certificate cannot be compared with the attestation "
                    + "evidence approved in verification " + confirmation.getVerificationId());
        } else if (confirmation.isIssued()) {
            // Extract public key from the submitted certificate and compare
            try {
                List<java.security.cert.X509Certificate> submittedChain =
                        parseX509Certificates(confirmation.getSigningCertificatePem());
                java.security.cert.X509Certificate submittedCert = submittedChain.get(0);

                // Bind the Step 7 confirmation to the known issuer CA set:
                // the submitted certificate must chain to a trusted issuer
                // CA (e.g. Getswish Root CA v2), otherwise an attacker who
                // knows only the verificationId can submit arbitrary
                // certificates. Fail-closed.
                if (!issuerCaValidator.validateChain(submittedChain)) {
                    anomalies.add("ANOMALY: Submitted signing certificate is not issued by a trusted "
                            + "issuer CA (PKIX validation failed against the configured "
                            + "gatekeeper.confirmation.issuer-ca-bundle-path trust anchors).");
                } else {
                    PublicKey certPublicKey = submittedCert.getPublicKey();
                    actualFingerprint = fingerprint(certPublicKey);
                    // Constant-time comparison. The values are public
                    // fingerprints rather than secrets, but the comparison
                    // decides whether an issued certificate is accepted as
                    // the attested one, and String.equals leaks a prefix
                    // length that an attacker submitting crafted
                    // certificates can measure. MessageDigest.isEqual costs
                    // nothing here and removes the question.
                    publicKeyMatch = expectedFingerprint != null
                            && MessageDigest.isEqual(
                                    actualFingerprint.getBytes(StandardCharsets.UTF_8),
                                    expectedFingerprint.getBytes(StandardCharsets.UTF_8));

                    if (!publicKeyMatch) {
                        anomalies.add("ANOMALY: Public key in issued certificate does not match "
                                + "the attestation evidence approved in verification "
                                + confirmation.getVerificationId());
                    } else {
                        issuedCertificate = ApprovalRegistry.IssuedCertificate.of(submittedCert);
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
        // and throws NonceMismatchException on a mismatch (replay attempt),
        // which is audit-logged here before it propagates.
        try {
            approvalRegistry.confirm(
                    confirmation.getVerificationId(),
                    confirmation.getConfirmationNonce(),
                    confirmation.isIssued(),
                    actualFingerprint,
                    publicKeyMatch,
                    issuedCertificate);
        } catch (ApprovalRegistry.NonceMismatchException e) {
            // Answered like every other confirmation: signed, so the financial
            // entity can tell the gatekeeper's refusal from anyone else's.
            anomalies.add("ANOMALY: Confirmation nonce does not match the nonce bound to "
                    + "verificationId at verify time. Possible Step-7 replay attempt.");
            IssuanceConfirmationResponse rejection = IssuanceConfirmationResponse.builder()
                    .verificationId(confirmation.getVerificationId())
                    .loopClosed(false)
                    .registryStatus(IssuanceConfirmationResponse.RegistryStatus.ANOMALY_NONCE_MISMATCH)
                    .processedTimestamp(processedTimestamp.toString())
                    .anomalies(anomalies)
                    .build();
            receiptSigner.signInto(rejection);
            appendConfirmAuditEntry(confirmation, rejection);
            return rejection;
        }

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

        // Signed with the receipt key: an unsigned response let anyone able to
        // answer the confirm call report the loop as closed.
        receiptSigner.signInto(resp);

        // Append a CONFIRM audit entry. The audit-log compliance bit
        // captures "loop closed AND no anomalies" so a supervisor can
        // filter the trail by clean vs. anomalous confirmations.
        appendConfirmAuditEntry(confirmation, resp);

        return resp;
    }

    /**
     * Whether the current caller may confirm this entry.
     *
     * <p>Returns {@code true} unconditionally when mTLS is disabled (no
     * authenticated caller exists to compare against — see
     * {@link #warnIfPrincipalBindingDisabled()}) or when the entry carries
     * no bound principal, which is the case for entries registered before
     * this binding existed and for entries registered under the permissive
     * chain. Fail-open on those two cases is deliberate: the alternative
     * makes every pre-existing registry entry permanently unconfirmable
     * after an upgrade.</p>
     */
    private boolean principalMatches(ApprovalRegistry.RegistryEntry entry) {
        if (!mtlsEnabled) {
            return true;
        }
        String bound = entry.getVerificationPrincipal();
        if (bound == null || bound.isBlank()) {
            return true;
        }
        String current = principalResolver.currentPrincipal();
        return current != null
                && MessageDigest.isEqual(
                        bound.getBytes(StandardCharsets.UTF_8),
                        current.getBytes(StandardCharsets.UTF_8));
    }

    // =========================================================================
    // Receipt signing (Step 5) has moved to the ReceiptSigner interface;
    // see ConfiguredReceiptSigner for production deployments and
    // EphemeralReceiptSigner for the reference configuration.
    // =========================================================================

    /**
     * Parse every PEM-encoded X.509 certificate in the submitted string via
     * the standard JCA {@link java.security.cert.CertificateFactory}, in
     * order. The first is the issued certificate; any further ones are
     * intermediates. Using the standard factory (rather than extracting
     * only the {@link PublicKey} via BouncyCastle's
     * {@code X509CertificateHolder}) lets callers pass the parsed
     * certificates to {@link IssuerCaValidator} for PKIX path building
     * against the issuer CA trust anchors.
     */
    private List<java.security.cert.X509Certificate> parseX509Certificates(String certificatePem) throws Exception {
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        byte[] pemBytes = certificatePem.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        List<java.security.cert.X509Certificate> certificates = new ArrayList<>();
        for (java.security.cert.Certificate c : cf.generateCertificates(new java.io.ByteArrayInputStream(pemBytes))) {
            certificates.add((java.security.cert.X509Certificate) c);
        }
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("No X.509 certificate in signingCertificatePem");
        }
        return certificates;
    }
}
