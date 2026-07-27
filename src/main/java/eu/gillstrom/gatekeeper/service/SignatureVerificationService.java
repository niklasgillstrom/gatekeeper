package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.util.Fingerprints;

import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
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
 *
 * <p>Every call writes one entry to the same hash-chained {@link AuditLog}
 * that the issuance-time flow writes to, under operation
 * {@link #AUDIT_OPERATION}. Without it the settlement-time decision — the
 * decision that actually allows or blocks a payment — would sit outside
 * the evidence base the rest of the repository is built on.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SignatureVerificationService {

    private final ApprovalRegistry approvalRegistry;
    private final AuditLog auditLog;
    private final MtlsPrincipalResolver principalResolver;

    private static final String DEFAULT_ALGORITHM = "SHA512withRSA";

    /**
     * Audit-log operation label for settlement-time verifications. Distinct
     * from {@code VERIFY} / {@code BATCH_VERIFY} / {@code CONFIRM} so a
     * supervisor can filter issuance-time from settlement-time decisions.
     */
    public static final String AUDIT_OPERATION = "SETTLEMENT_VERIFY";

    /**
     * {@code verificationId} recorded when the presented certificate matches
     * no registry entry. {@link AuditAppendRequest} requires a non-blank
     * value, and fabricating a UUID here would suggest a registry row that
     * does not exist. The constant is deliberately conspicuous: a supervisor
     * filtering the trail on it gets exactly the settlement attempts made
     * with certificates the gatekeeper never audited.
     */
    public static final String NO_REGISTRY_MATCH = "NO-REGISTRY-MATCH";

    /**
     * Signature algorithms this endpoint will accept.
     *
     * <p>The algorithm arrives in the request, so without a whitelist the
     * caller chooses it: passing {@code SHA1withRSA} or {@code MD5withRSA}
     * downgrades settlement-time verification to a broken hash while still
     * returning signatureValid=true. Anything outside this set is rejected as
     * ALGORITHM_NOT_SUPPORTED rather than handed to
     * {@link Signature#getInstance(String)}.</p>
     */
    private static final java.util.Set<String> PERMITTED_ALGORITHMS = java.util.Set.of(
            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "RSASSA-PSS",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA");

    /**
     * Verify a settlement-time signature and record the decision in the
     * audit log.
     *
     * <p>The audit append is deliberately not wrapped in a try/catch. If the
     * chain cannot be extended the request fails with
     * {@link eu.gillstrom.gatekeeper.audit.AuditLogException}, the caller
     * receives 5xx, and a default-deny settlement layer blocks the payment.
     * Answering a settlement query that we cannot prove we answered is the
     * worse failure mode.</p>
     */
    public SignatureVerificationResponse verify(SignatureVerificationRequest request) {
        SignatureVerificationResponse response = verifyInternal(request);
        appendAuditEntry(request, response);
        return response;
    }

    private SignatureVerificationResponse verifyInternal(SignatureVerificationRequest request) {
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
            if (!PERMITTED_ALGORITHMS.contains(algorithm)) {
                log.warn("Settlement-time verify: rejected non-permitted algorithm {}", algorithm);
                return SignatureVerificationResponse.builder()
                        .signatureValid(false)
                        .compliant(false)
                        .reason("ALGORITHM_NOT_SUPPORTED")
                        .build();
            }
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

    /**
     * Append one audit entry per settlement-time verification.
     *
     * <p>Data minimisation is the same as everywhere else in the log: the
     * entry carries sequence number, timestamp, principal, operation label,
     * a SHA-256 digest of the request, a SHA-256 digest of the response, and
     * the outcome bit. No transaction data is recorded — the request never
     * contained any, and the digest that stands in for the transaction is
     * itself hashed again rather than stored.</p>
     *
     * <p>The outcome bit is the settlement decision
     * ({@code signatureValid && compliant}), not the registry's compliance
     * flag on its own, because that conjunction is what railgate acts on.</p>
     *
     * <p>{@code verificationId} points at the registry row the decision was
     * read from, so the settlement entry and the issuance entry share the
     * identifier. The relation is therefore many-to-one for
     * {@code SETTLEMENT_VERIFY} (one issuance, many settlements), unlike
     * {@code VERIFY} / {@code CONFIRM}; supervisors reading settlement rows
     * should page through {@link AuditLog#findInRange} rather than
     * {@link AuditLog#findByVerificationId}, which returns only the first
     * match.</p>
     */
    private void appendAuditEntry(SignatureVerificationRequest request,
                                  SignatureVerificationResponse response) {
        String verificationId = response.getAuditEntryId() == null
                ? NO_REGISTRY_MATCH
                : response.getAuditEntryId();
        AuditAppendRequest req = new AuditAppendRequest(
                principalResolver.currentPrincipal(),
                AUDIT_OPERATION,
                verificationId,
                sha256Base64(canonicalRequestBytes(request)),
                sha256Base64(canonicalResponseBytes(response)),
                response.isSignatureValid() && response.isCompliant());
        auditLog.append(req);
    }

    /**
     * Canonical bytes the request digest is taken over. Pipe-delimited with
     * percent-escaping, matching {@code VerificationService} and
     * {@code AuditEntry}, so a supervisor holding the original request can
     * recompute the digest and confirm "this was the query".
     */
    private static byte[] canonicalRequestBytes(SignatureVerificationRequest r) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("v1|settlement-verify|")
          .append(safeNull(r.getCertSerial())).append('|')
          .append(safeNull(r.getIssuerDn())).append('|')
          .append(safeNull(r.getDigestHex())).append('|')
          .append(safeNull(r.getSignatureBase64())).append('|')
          .append(safeNull(r.getSigningCertificatePem())).append('|')
          .append(safeNull(r.getAlgorithm()));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Canonical bytes the response digest is taken over. Stored in the
     * entry's {@code receiptDigestBase64} slot: settlement answers are not
     * signed receipts, but the slot's purpose — "digest of what we sent
     * back" — is the same, and reusing it keeps one canonical entry shape.
     */
    private static byte[] canonicalResponseBytes(SignatureVerificationResponse r) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("v1|settlement-verify-response|")
          .append(r.isSignatureValid()).append('|')
          .append(r.isCompliant()).append('|')
          .append(safeNull(r.getAuditEntryId())).append('|')
          .append(safeNull(r.getReason()));
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
            return Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(in));
        } catch (Exception e) {
            // SHA-256 is mandated by the JCA; reaching this branch is a JRE
            // configuration bug, not a runtime condition we can recover from.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * SHA-256 fingerprint of the SubjectPublicKeyInfo encoding, formatted as
     * LOWERCASE hex with colon separators (e.g. "ab:cd:..").
     *
     * <p>The case matters. Registry entries are written by
     * {@code VerificationService.fingerprint(PublicKey)} in lowercase, and
     * lookup in both {@code InMemoryApprovalRegistry} and
     * {@code AppendOnlyFileApprovalRegistry} is a case-sensitive
     * {@code equals}. This method previously emitted uppercase, so every
     * settlement-time query fell through to CERT_NOT_FOUND and
     * {@code /api/v1/verify} could never return compliant=true. The defect was
     * invisible in tests because the test double recomputed the fingerprint in
     * the same uppercase form.</p>
     */
    private static String sha256Fingerprint(byte[] subjectPublicKeyInfo) {
        return Fingerprints.ofSubjectPublicKeyInfo(subjectPublicKeyInfo);
    }
}
