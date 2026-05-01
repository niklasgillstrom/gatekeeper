package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Settlement-time signature verification.
 *
 * <p>Performs deterministic cryptographic verification of a signature
 * produced by a customer's HSM-bound private key. The verification mirrors
 * the production signing flow:
 *
 * <pre>
 *   Signing:      sign(SHA-512(payload), HSM-private-key) → signature
 *   Verification: verify(signature, SHA-512(payload), public-key) → boolean
 * </pre>
 *
 * <p>The caller (railgate) supplies the digest already computed; the
 * verifier never sees the original payload. This satisfies GDPR Art 5(1)(c)
 * data minimisation while preserving cryptographic correctness — SHA-512
 * collision resistance ensures the digest uniquely binds the signature
 * to the exact transaction performed.
 *
 * <p>Compliance status is read from the approval registry by computing
 * the SHA-256 fingerprint of the SubjectPublicKeyInfo (uppercase hex,
 * colon-separated) and looking up the entry by that fingerprint. The
 * combined result {@code (signatureValid, compliant)} is what railgate
 * uses for default-deny enforcement.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SignatureVerificationService {

    private final ApprovalRegistry approvalRegistry;

    private static final String DEFAULT_ALGORITHM = "SHA512withRSA";

    public SignatureVerificationResponse verify(SignatureVerificationRequest request) {
        if (request.getSigningCertificatePem() == null
                || request.getSigningCertificatePem().isBlank()) {
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .reason("MALFORMED_INPUT")
                    .build();
        }

        // Step 1: Parse certificate, extract public key.
        X509Certificate cert;
        PublicKey publicKey;
        try {
            cert = parseCertificate(request.getSigningCertificatePem());
            publicKey = cert.getPublicKey();
        } catch (Exception e) {
            log.warn("Settlement-time verify: certificate parse failure: {}", e.getMessage());
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .reason("MALFORMED_INPUT")
                    .build();
        }

        // Step 2: Compute the public-key fingerprint and look up audit entry.
        String fingerprint;
        try {
            fingerprint = sha256Fingerprint(publicKey.getEncoded());
        } catch (Exception e) {
            log.warn("Settlement-time verify: fingerprint computation failure: {}", e.getMessage());
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .reason("MALFORMED_INPUT")
                    .build();
        }

        ApprovalRegistry.RegistryEntry registryEntry = approvalRegistry
                .findByPublicKeyFingerprint(fingerprint).orElse(null);

        // Step 3: Decode digest and signature.
        byte[] digestBytes;
        byte[] signatureBytes;
        try {
            digestBytes = HexFormat.of().parseHex(request.getDigestHex());
            signatureBytes = Base64.getDecoder().decode(request.getSignatureBase64());
        } catch (IllegalArgumentException e) {
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .reason("MALFORMED_INPUT")
                    .build();
        }

        // Step 4: Cryptographic verification.
        boolean signatureValid;
        try {
            String algorithm = request.getAlgorithm() == null ? DEFAULT_ALGORITHM : request.getAlgorithm();
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(publicKey);
            sig.update(digestBytes);
            signatureValid = sig.verify(signatureBytes);
        } catch (java.security.NoSuchAlgorithmException e) {
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .reason("ALGORITHM_NOT_SUPPORTED")
                    .build();
        } catch (Exception e) {
            log.warn("Settlement-time verify: cryptographic operation failed: {}", e.getMessage());
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .auditEntryId(registryEntry == null ? null : registryEntry.getVerificationId())
                    .reason("SIGNATURE_INVALID")
                    .build();
        }

        if (!signatureValid) {
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .auditEntryId(registryEntry == null ? null : registryEntry.getVerificationId())
                    .reason("SIGNATURE_INVALID")
                    .build();
        }

        // Step 5: Combine cryptographic result with compliance status.
        if (registryEntry == null) {
            return SignatureVerificationResponse.builder()
                    .signatureValid(true)
                    .compliant(false)
                    .reason("CERT_NOT_FOUND")
                    .build();
        }

        boolean compliant = registryEntry.isCompliant();
        return SignatureVerificationResponse.builder()
                .signatureValid(true)
                .compliant(compliant)
                .auditEntryId(registryEntry.getVerificationId())
                .reason(compliant ? "OK" : "CERT_NON_COMPLIANT")
                .build();
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * SHA-256 fingerprint of the SubjectPublicKeyInfo encoding, formatted
     * as uppercase hex with colon separators (e.g. "AB:CD:..."). This is
     * the same canonical form used elsewhere in gatekeeper for public-key
     * fingerprints.
     */
    private static String sha256Fingerprint(byte[] subjectPublicKeyInfo) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(subjectPublicKeyInfo);
        StringBuilder sb = new StringBuilder(hash.length * 3);
        for (int i = 0; i < hash.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", hash[i] & 0xFF));
        }
        return sb.toString();
    }
}
