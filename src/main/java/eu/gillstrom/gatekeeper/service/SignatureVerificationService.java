package eu.gillstrom.gatekeeper.service;


import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
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
 * <p>Compliance status is read from the approval registry entry found by
 * the issued certificate (serial number and issuer DN), which is stored
 * when the issuance is confirmed as {@code VERIFIED_AND_ISSUED}. The
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

    private static final String RSASSA_PSS = "RSASSA-PSS";

    private static final PSSParameterSpec PSS_PARAMETERS =
            new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);

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
        AuditEntry entry = appendAuditEntry(request, response);
        response.setAuditEntryHashHex(entry.thisEntryHashHex());
        return response;
    }

    private SignatureVerificationResponse verifyInternal(SignatureVerificationRequest request) {
        // Step 1: Decode digest and signature, so malformed input is reported as
        // such whether or not the certificate is known.
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

        // Step 2: Resolve the registry entry through the ISSUED CERTIFICATE.
        //
        // The entry is found by the certificate's (serial, issuer) and only
        // among entries whose confirmation stored an issued certificate — that
        // happens only on VERIFIED_AND_ISSUED. Two earlier designs were unsafe:
        //  - Looking the entry up by public-key fingerprint let any FE make
        //    another FE's settlements fail: confirming its own verification
        //    with the victim's (public) certificate produced a newer
        //    ANOMALY_PUBLIC_KEY_MISMATCH entry carrying the victim's key
        //    fingerprint, and that entry won the lookup.
        //  - When the request carried the certificate PEM, the PEM itself was
        //    never checked against anything, so a self-signed certificate for
        //    a key that had been verified but never issued settled.
        // A presented PEM is therefore only accepted if it is byte-identical
        // to the certificate stored at confirmation.
        BigInteger serial;
        X500Principal issuer;
        X509Certificate presented = null;
        String presentedPem = request.getSigningCertificatePem();
        if (presentedPem != null && !presentedPem.isBlank()) {
            try {
                presented = parseCertificate(presentedPem);
            } catch (Exception e) {
                log.warn("Settlement-time verify: certificate parse failure: {}", e.getMessage());
                return deny(false, null, "MALFORMED_INPUT");
            }
            serial = presented.getSerialNumber();
            issuer = presented.getIssuerX500Principal();
        } else {
            if (isBlank(request.getCertSerial()) || isBlank(request.getIssuerDn())) {
                return deny(false, null, "MALFORMED_INPUT");
            }
            try {
                serial = parseSerialHex(request.getCertSerial());
                issuer = new X500Principal(request.getIssuerDn());
            } catch (IllegalArgumentException e) {
                return deny(false, null, "MALFORMED_INPUT");
            }
        }

        ApprovalRegistry.RegistryEntry registryEntry =
                approvalRegistry.findByIssuedCertificate(serial, issuer).orElse(null);
        X509Certificate cert = registryEntry == null
                ? null
                : storedCertificate(registryEntry.getIssuedCertificatePem(), serial, issuer);
        if (cert == null) {
            return deny(false, null, "CERT_NOT_FOUND");
        }
        // Certificate.equals compares the encoded forms.
        if (presented != null && !presented.equals(cert)) {
            log.warn("Settlement-time verify: presented certificate differs from the one stored "
                    + "for verificationId={}", registryEntry.getVerificationId());
            return deny(false, null, "CERT_NOT_FOUND");
        }
        PublicKey publicKey = cert.getPublicKey();

        // Step 3: Cryptographic verification.
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
            if (RSASSA_PSS.equals(algorithm)) {
                sig.setParameter(PSS_PARAMETERS);
            }
            sig.initVerify(publicKey);
            sig.update(digestBytes);
            signatureValid = sig.verify(signatureBytes);
        } catch (Exception e) {
            log.warn("Settlement-time verify: cryptographic operation failed: {}", e.getMessage());
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .auditEntryId(registryEntry.getVerificationId())
                    .reason("SIGNATURE_INVALID")
                    .build();
        }

        if (!signatureValid) {
            return SignatureVerificationResponse.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .auditEntryId(registryEntry.getVerificationId())
                    .reason("SIGNATURE_INVALID")
                    .build();
        }

        // Step 4: Combine cryptographic result with the certificate's validity
        // period and the registry status.
        try {
            cert.checkValidity();
        } catch (java.security.cert.CertificateException e) {
            return deny(true, registryEntry.getVerificationId(), "CERT_EXPIRED");
        }

        boolean compliant = isSettlementCompliant(registryEntry);
        return SignatureVerificationResponse.builder()
                .signatureValid(true)
                .compliant(compliant)
                .auditEntryId(registryEntry.getVerificationId())
                .reason(compliant ? "OK" : "CERT_NON_COMPLIANT")
                .build();
    }

    /**
     * Whether a registry entry may still back a settlement at this moment.
     *
     * <p>The registry's {@code compliant} flag records the outcome of the
     * attestation verification at Step 3 and is never rewritten afterwards.
     * The Step-7 confirmation outcome lives in {@code status}. Reading only
     * the flag therefore kept answering {@code compliant=true} for an entry
     * whose confirmation had already been recorded as an anomaly — a
     * certificate whose public key did not match the attested key
     * ({@code ANOMALY_PUBLIC_KEY_MISMATCH}) still settled payments, which
     * is precisely the circumvention the Step-7 loop exists to detect.</p>
     *
     * <p>A settlement is therefore allowed only when the verification was
     * compliant <em>and</em> the confirmation recorded
     * {@code VERIFIED_AND_ISSUED}. Until 1.6.0 a {@code null} status
     * (Step 7 not yet received) and {@code VERIFIED_NOT_ISSUED} also settled.
     * Neither has an issued certificate stored, so the certificate presented
     * at settlement could not be checked against anything, and a self-signed
     * certificate for a key that was verified but never issued settled. The
     * integration guide already requires that a certificate is not delivered
     * before its confirmation completes.</p>
     */
    private static boolean isSettlementCompliant(ApprovalRegistry.RegistryEntry entry) {
        return entry.isCompliant() && entry.getStatus() == RegistryStatus.VERIFIED_AND_ISSUED;
    }

    private static SignatureVerificationResponse deny(boolean signatureValid, String auditEntryId,
            String reason) {
        return SignatureVerificationResponse.builder()
                .signatureValid(signatureValid)
                .compliant(false)
                .auditEntryId(auditEntryId)
                .reason(reason)
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
     * {@code VERIFY}; supervisors reading settlement rows
     * should page through {@link AuditLog#findInRange} rather than
     * {@link AuditLog#findByVerificationId}, which returns only the first
     * match. The entry's own {@code thisEntryHashHex} is returned to the
     * caller as {@code auditEntryHashHex} and identifies it uniquely.</p>
     */
    private AuditEntry appendAuditEntry(SignatureVerificationRequest request,
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
        return auditLog.append(req);
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

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static BigInteger parseSerialHex(String certSerial) {
        String hex = certSerial.strip();
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }
        return new BigInteger(hex, 16);
    }

    /** The stored certificate, or null when it is absent, unparseable or not the one looked up. */
    private static X509Certificate storedCertificate(String pem, BigInteger serial, X500Principal issuer) {
        if (pem == null) {
            return null;
        }
        try {
            X509Certificate stored = parseCertificate(pem);
            return serial.equals(stored.getSerialNumber()) && issuer.equals(stored.getIssuerX500Principal())
                    ? stored
                    : null;
        } catch (Exception e) {
            log.warn("Settlement-time verify: stored certificate could not be parsed: {}", e.getMessage());
            return null;
        }
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    }

}
