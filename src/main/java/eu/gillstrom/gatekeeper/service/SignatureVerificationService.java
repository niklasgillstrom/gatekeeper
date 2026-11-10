package eu.gillstrom.gatekeeper.service;


import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import eu.gillstrom.gatekeeper.signing.SettlementVerdictCanonicalizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.function.Predicate;

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
 *
 * <p>Every response is signed with the active {@link ReceiptSigner} over
 * {@link SettlementVerdictCanonicalizer} (fields {@code verifiedAt},
 * {@code verdictSignatureBase64}, {@code verdictSignatureAlgorithm},
 * {@code signingKeyFingerprintHex}), denials included, so the settlement
 * rail can verify that a verdict came from the gatekeeper. A response whose
 * request {@code certSerial}, {@code issuerDn} or {@code digestHex} cannot
 * be normalised is returned unsigned.</p>
 *
 * <p>The same verification serves the {@code SIGNED} key-lifecycle event
 * ({@link #verifySignedEvent}), scoped to one jurisdiction and recorded
 * under operation {@link #SIGNED_EVENT_OPERATION}.</p>
 */
@Service
@Slf4j
public class SignatureVerificationService {

    private final ApprovalRegistry approvalRegistry;
    private final AuditLog auditLog;
    private final MtlsPrincipalResolver principalResolver;

    /** Signs the verdict; {@code null} only when built with the three-argument constructor. */
    private final ReceiptSigner verdictSigner;

    /** Source of {@code signingKeyFingerprintHex}; {@code null} exactly when {@link #verdictSigner} is. */
    private final GatekeeperKeyDirectory keyDirectory;

    /**
     * The service as Spring builds it: verdicts are signed with the active
     * receipt signer, and the key fingerprint is the one
     * {@code GET /v1/gatekeeper/keys} publishes for it.
     */
    @Autowired
    public SignatureVerificationService(ApprovalRegistry approvalRegistry,
                                        AuditLog auditLog,
                                        MtlsPrincipalResolver principalResolver,
                                        ReceiptSigner verdictSigner,
                                        GatekeeperKeyDirectory keyDirectory) {
        this.approvalRegistry = approvalRegistry;
        this.auditLog = auditLog;
        this.principalResolver = principalResolver;
        this.verdictSigner = Objects.requireNonNull(verdictSigner, "verdictSigner");
        this.keyDirectory = Objects.requireNonNull(keyDirectory, "keyDirectory");
    }

    /**
     * A service that does not sign its verdicts: {@code verifiedAt} and the
     * three verdict-signature fields stay {@code null}. Kept for unit tests
     * of the verification logic that predate verdict signing; the Spring
     * bean is always built with the signing constructor above.
     */
    public SignatureVerificationService(ApprovalRegistry approvalRegistry,
                                        AuditLog auditLog,
                                        MtlsPrincipalResolver principalResolver) {
        this.approvalRegistry = approvalRegistry;
        this.auditLog = auditLog;
        this.principalResolver = principalResolver;
        this.verdictSigner = null;
        this.keyDirectory = null;
    }

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
     * Audit-log operation label for an organisation-reported {@code SIGNED}
     * key-lifecycle event ({@link #verifySignedEvent}). The manuscript's
     * "Signed" event is recorded under this label when the organisation
     * reports a signature and under {@link #AUDIT_OPERATION} when the
     * settlement rail does.
     */
    public static final String SIGNED_EVENT_OPERATION = "SIGNED";

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
        String verifiedAt = now();
        MatchedRow matched = new MatchedRow();
        SignatureVerificationResponse response = verifyInternal(request, entry -> true, matched);
        AuditEntry entry = appendAuditEntry(AUDIT_OPERATION, canonicalRequestBytes(request),
                canonicalResponseBytes("v1|settlement-verify-response|", response), response, matched.entry);
        response.setAuditEntryHashHex(entry.thisEntryHashHex());
        signVerdict(request, response, verifiedAt);
        return response;
    }

    /**
     * The registry row the decision was read from: set once the presented
     * certificate (or serial and issuer) has resolved to a stored issued
     * certificate, i.e. exactly when the response carries that row's
     * {@code verificationId} as {@code auditEntryId}.
     */
    private static final class MatchedRow {
        private ApprovalRegistry.RegistryEntry entry;
    }

    /**
     * A {@code SIGNED} key-lifecycle event: the organisation reports that its
     * key signed {@code digestHex}. Verified exactly as {@link #verify}
     * verifies a settlement — certificate looked up by serial and issuer
     * among those stored at Step 7, registry status, certificate validity,
     * signature over the digest — with two differences: a registry entry
     * outside {@code countryCode} is treated as not found
     * ({@code CERT_NOT_FOUND}), and the audit entry is recorded under
     * {@link #SIGNED_EVENT_OPERATION}. The response is signed in the same
     * way, and the audit entry carries the same inventory fields as a
     * {@code SETTLEMENT_VERIFY} entry (those of the matched registry row,
     * none without a match), so it joins that key's per-key chain.
     *
     * @param countryCode jurisdiction from the request path, upper-cased by the caller
     */
    public SignatureVerificationResponse verifySignedEvent(SignatureVerificationRequest request,
                                                           String countryCode) {
        String verifiedAt = now();
        MatchedRow matched = new MatchedRow();
        SignatureVerificationResponse response = verifyInternal(request,
                entry -> countryCode != null && countryCode.equals(entry.getCountryCode()), matched);
        AuditEntry entry = appendAuditEntry(SIGNED_EVENT_OPERATION,
                canonicalSignedEventRequestBytes(countryCode, request),
                canonicalResponseBytes("v1|lifecycle-signed-response|", response), response, matched.entry);
        response.setAuditEntryHashHex(entry.thisEntryHashHex());
        signVerdict(request, response, verifiedAt);
        return response;
    }

    private static String now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS).toString();
    }

    /**
     * Sign the verdict over {@link SettlementVerdictCanonicalizer}. Leaves the
     * response unsigned when the service has no signer, or when the request's
     * certSerial, issuerDn or digestHex cannot be normalised — the existing
     * answer (normally {@code MALFORMED_INPUT}) is then returned as it was.
     * A failure of the signer itself propagates, as a failure to extend the
     * audit chain does: a verdict that should carry a signature and does not
     * is denied by a rail that checks it.
     */
    private void signVerdict(SignatureVerificationRequest request, SignatureVerificationResponse response,
                             String verifiedAt) {
        if (verdictSigner == null) {
            return;
        }
        byte[] canonical;
        try {
            canonical = SettlementVerdictCanonicalizer.canonicalize(
                    verifiedAt,
                    request.getCertSerial(),
                    request.getIssuerDn(),
                    request.getDigestHex(),
                    response.isSignatureValid(),
                    response.isCompliant(),
                    response.getReason(),
                    response.getAuditEntryId(),
                    response.getAuditEntryHashHex());
        } catch (IllegalArgumentException e) {
            log.debug("Settlement verdict left unsigned: request fields cannot be normalised: {}", e.getMessage());
            return;
        }
        response.setVerifiedAt(verifiedAt);
        response.setVerdictSignatureBase64(Base64.getEncoder().encodeToString(verdictSigner.sign(canonical)));
        response.setVerdictSignatureAlgorithm(verdictSigner.getSignatureAlgorithm());
        response.setSigningKeyFingerprintHex(keyDirectory.activeFingerprintHex());
    }

    private SignatureVerificationResponse verifyInternal(SignatureVerificationRequest request,
                                                         Predicate<ApprovalRegistry.RegistryEntry> scope,
                                                         MatchedRow matched) {
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
        //
        // The entry is always looked up under the request's certSerial and
        // issuerDn, with or without a PEM: they are the identifiers the signed
        // verdict names. Until 1.7.0 a presented PEM replaced them in the
        // lookup while the verdict was still signed over them, so a request
        // rewritten in transit to carry another, compliant certificate and its
        // signature was answered OK, signed for the identifiers of the
        // certificate the caller had asked about.
        if (isBlank(request.getCertSerial()) || isBlank(request.getIssuerDn())) {
            return deny(false, null, "MALFORMED_INPUT");
        }
        BigInteger serial;
        X500Principal issuer;
        try {
            serial = parseSerialHex(request.getCertSerial());
            issuer = new X500Principal(request.getIssuerDn());
        } catch (IllegalArgumentException e) {
            return deny(false, null, "MALFORMED_INPUT");
        }
        X509Certificate presented = null;
        String presentedPem = request.getSigningCertificatePem();
        if (presentedPem != null && !presentedPem.isBlank()) {
            try {
                presented = parseCertificate(presentedPem);
            } catch (Exception e) {
                log.warn("Settlement-time verify: certificate parse failure: {}", e.getMessage());
                return deny(false, null, "MALFORMED_INPUT");
            }
        }

        ApprovalRegistry.RegistryEntry registryEntry =
                approvalRegistry.findByIssuedCertificate(serial, issuer).filter(scope).orElse(null);
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
        matched.entry = registryEntry;
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

        // Step 4: Combine cryptographic result with the key lifecycle, the
        // certificate's validity period and the registry status. A rotated,
        // revoked or decommissioned key stops settling: the lifecycle event
        // moved its entry out of VERIFIED_AND_ISSUED. Reported before expiry
        // because it is the deliberate act and the more specific reason.
        String lifecycleDenial = lifecycleDenialReason(registryEntry.getStatus());
        if (lifecycleDenial != null) {
            return deny(true, registryEntry.getVerificationId(), lifecycleDenial);
        }
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

    /**
     * {@code CERT_SUPERSEDED}, {@code CERT_REVOKED} or
     * {@code CERT_DECOMMISSIONED} for an entry a key-lifecycle event has
     * moved on; {@code null} for every other status.
     */
    static String lifecycleDenialReason(RegistryStatus status) {
        if (status == null) {
            return null;
        }
        return switch (status) {
            case SUPERSEDED -> "CERT_SUPERSEDED";
            case REVOKED -> "CERT_REVOKED";
            case DECOMMISSIONED -> "CERT_DECOMMISSIONED";
            default -> null;
        };
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
     *
     * <p>Inventory fields (audit entry v2), from the matched registry row
     * when there is one: the issued certificate's serial and issuer DN as
     * stored at confirmation, the row's attested key fingerprint (which joins
     * the entry to that key's per-key chain) and the row's status. All
     * {@code null} for {@link #NO_REGISTRY_MATCH}.</p>
     */
    private AuditEntry appendAuditEntry(String operation, byte[] canonicalRequest, byte[] canonicalResponse,
                                        SignatureVerificationResponse response,
                                        ApprovalRegistry.RegistryEntry matchedRow) {
        String verificationId = response.getAuditEntryId() == null
                ? NO_REGISTRY_MATCH
                : response.getAuditEntryId();
        AuditAppendRequest req = new AuditAppendRequest(
                principalResolver.currentPrincipal(),
                operation,
                verificationId,
                sha256Base64(canonicalRequest),
                sha256Base64(canonicalResponse),
                response.isSignatureValid() && response.isCompliant());
        if (matchedRow != null) {
            req = req.withKeyFingerprintHex(blankToNull(matchedRow.getPublicKeyFingerprint()))
                    .withCertificate(matchedRow.getIssuedCertificateSerial(), matchedRow.getIssuedCertificateIssuerDn())
                    .withRegistryStatus(matchedRow.getStatus() == null ? null : matchedRow.getStatus().name());
        }
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
     * Canonical bytes of a {@code SIGNED} event's request:
     * {@code v1|lifecycle-signed|countryCode|certSerial|issuerDn|digestHex|signatureBase64},
     * escaped as {@link #canonicalRequestBytes}.
     */
    private static byte[] canonicalSignedEventRequestBytes(String countryCode, SignatureVerificationRequest r) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("v1|lifecycle-signed|")
          .append(safeNull(countryCode)).append('|')
          .append(safeNull(r.getCertSerial())).append('|')
          .append(safeNull(r.getIssuerDn())).append('|')
          .append(safeNull(r.getDigestHex())).append('|')
          .append(safeNull(r.getSignatureBase64()));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Canonical bytes the response digest is taken over. Stored in the
     * entry's {@code receiptDigestBase64} slot: the slot's purpose — "digest
     * of what we sent back" — fits, and reusing it keeps one canonical entry
     * shape. It covers the four fields known before the entry exists; the
     * signed verdict (which also covers the entry's hash) is computed after.
     * {@code prefix} is {@code v1|settlement-verify-response|} for a
     * settlement and {@code v1|lifecycle-signed-response|} for a
     * {@code SIGNED} event.
     */
    private static byte[] canonicalResponseBytes(String prefix, SignatureVerificationResponse r) {
        StringBuilder sb = new StringBuilder(128);
        sb.append(prefix)
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

    private static String blankToNull(String s) {
        return isBlank(s) ? null : s;
    }

    /** Hex serial, surrounding whitespace and an optional {@code 0x}/{@code 0X} removed. Shared with {@link KeyLifecycleService}. */
    static BigInteger parseSerialHex(String certSerial) {
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
