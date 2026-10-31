package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.KeyLifecycleRequest;
import eu.gillstrom.gatekeeper.model.KeyStatusChangeResponse;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignedEventResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Key-lifecycle events for an issued signing certificate:
 * {@code POST /v1/attestation/{countryCode}/lifecycle}.
 *
 * <h2>The manuscript's lifecycle and the audit log</h2>
 *
 * <p>The manuscript describes the signing key's lifecycle as six signed,
 * chained events. Each is an entry in the hash-chained, signed audit log
 * ({@link AuditLog}) under the following operation labels:</p>
 *
 * <table>
 *   <caption>Lifecycle event to audit operation</caption>
 *   <tr><th>Manuscript event</th><th>Audit operation</th><th>Written by</th></tr>
 *   <tr><td>Generated (attestation verified)</td><td>{@code VERIFY} / {@code BATCH_VERIFY}</td>
 *       <td>{@code POST /v1/attestation/{cc}/verify}, {@code .../verify/batch}</td></tr>
 *   <tr><td>Issued</td><td>{@code CONFIRM}</td>
 *       <td>{@code POST /v1/attestation/{cc}/confirm}</td></tr>
 *   <tr><td>Signed</td><td>{@code SIGNED} (organisation-reported, verified) and
 *       {@code SETTLEMENT_VERIFY} (rail-reported)</td>
 *       <td>this endpoint with {@code eventType=SIGNED}; {@code POST /api/v1/verify}</td></tr>
 *   <tr><td>Rotated</td><td>{@code ROTATED}</td><td>this endpoint</td></tr>
 *   <tr><td>Revoked</td><td>{@code REVOKED}</td><td>this endpoint</td></tr>
 *   <tr><td>Decommissioned</td><td>{@code DECOMMISSIONED}</td><td>this endpoint</td></tr>
 * </table>
 *
 * <p>"Generated" is recorded when the gatekeeper verifies the attestation
 * that the key was generated in the HSM, not when the HSM generates it.</p>
 *
 * <p>Each of these entries that concerns a known key carries that key's
 * fingerprint ({@code keyFingerprintHex}, audit entry v2) and links to the
 * key's previous entry ({@code prevKeyEntryHashHex}), so the six events of
 * one key form its per-key chain inside the global chain. {@code SIGNED} and
 * the three status changes also carry the issued certificate's serial and
 * issuer and the registry status ({@link
 * eu.gillstrom.gatekeeper.audit.AuditAppendRequest}).</p>
 *
 * <h2>Events</h2>
 *
 * <ul>
 *   <li>{@code SIGNED} — verified as a settlement is
 *       ({@link SignatureVerificationService#verifySignedEvent}), scoped to
 *       the jurisdiction in the path; answered with the settlement answer
 *       plus {@code eventType}, signed the same way, always HTTP 200.</li>
 *   <li>{@code ROTATED}, {@code REVOKED}, {@code DECOMMISSIONED} — move the
 *       registry entry that stored the certificate at Step 7 to
 *       {@code SUPERSEDED}, {@code REVOKED} or {@code DECOMMISSIONED}
 *       ({@link ApprovalRegistry#changeStatus}). Allowed only from
 *       {@code VERIFIED_AND_ISSUED}, or from {@code SUPERSEDED} to
 *       {@code REVOKED} or {@code DECOMMISSIONED}. A refused change is
 *       answered 409 {@code TRANSITION_NOT_ALLOWED}; an unknown certificate
 *       404 {@code CERT_NOT_FOUND}. Every outcome, refusals included, is
 *       audited under the event's own operation label with
 *       {@code compliant=true} exactly when the change was applied. Once
 *       moved, the certificate no longer settles: {@code POST /api/v1/verify}
 *       answers {@code CERT_SUPERSEDED}, {@code CERT_REVOKED} or
 *       {@code CERT_DECOMMISSIONED}.</li>
 * </ul>
 *
 * <h2>Who may change an entry</h2>
 *
 * <p>The path admits {@code FE} and {@code SUPERVISOR} ({@code SecurityConfig}).
 * With mTLS enabled, a caller without the {@code SUPERVISOR} role may change
 * only an entry whose Step-3 verification it performed itself
 * ({@code verificationPrincipal}), as for Step-7 confirmation; otherwise a
 * financial entity could stop another's certificate from settling. An entry
 * outside the path's jurisdiction, or bound to another principal, is
 * answered exactly as an unknown certificate. Entries without a bound
 * principal, and every entry when mTLS is disabled, may be changed by any
 * caller that reaches the endpoint. A {@code SIGNED} event changes nothing
 * and is not bound to a principal.</p>
 */
@Service
public class KeyLifecycleService {

    private static final Logger log = LoggerFactory.getLogger(KeyLifecycleService.class);

    public static final String REASON_OK = "OK";
    public static final String REASON_CERT_NOT_FOUND = "CERT_NOT_FOUND";
    public static final String REASON_TRANSITION_NOT_ALLOWED = "TRANSITION_NOT_ALLOWED";
    public static final String REASON_SUCCESSOR_NOT_FOUND = "SUCCESSOR_NOT_FOUND";
    public static final String REASON_MALFORMED_INPUT = "MALFORMED_INPUT";

    private final SignatureVerificationService signatureVerificationService;
    private final ApprovalRegistry approvalRegistry;
    private final AuditLog auditLog;
    private final MtlsPrincipalResolver principalResolver;
    private final boolean mtlsEnabled;

    public KeyLifecycleService(SignatureVerificationService signatureVerificationService,
                               ApprovalRegistry approvalRegistry,
                               AuditLog auditLog,
                               MtlsPrincipalResolver principalResolver,
                               @Value("${gatekeeper.security.mtls.enabled:false}") boolean mtlsEnabled) {
        this.signatureVerificationService = signatureVerificationService;
        this.approvalRegistry = approvalRegistry;
        this.auditLog = auditLog;
        this.principalResolver = principalResolver;
        this.mtlsEnabled = mtlsEnabled;
    }

    /** The registry status a status-changing event moves an entry to. */
    public static RegistryStatus targetStatus(String eventType) {
        return switch (eventType) {
            case KeyLifecycleRequest.ROTATED -> RegistryStatus.SUPERSEDED;
            case KeyLifecycleRequest.REVOKED -> RegistryStatus.REVOKED;
            case KeyLifecycleRequest.DECOMMISSIONED -> RegistryStatus.DECOMMISSIONED;
            default -> throw new IllegalArgumentException("Not a status-changing event: " + eventType);
        };
    }

    /**
     * A {@code SIGNED} event: the request's certSerial, issuerDn, digestHex
     * and signatureBase64 are verified as a four-field settlement request
     * (algorithm {@code SHA512withRSA}, no certificate PEM).
     *
     * @param countryCode upper-cased jurisdiction from the path
     */
    public SignedEventResponse signed(String countryCode, KeyLifecycleRequest request) {
        SignatureVerificationRequest verification = SignatureVerificationRequest.builder()
                .certSerial(request.getCertSerial())
                .issuerDn(request.getIssuerDn())
                .digestHex(request.getDigestHex())
                .signatureBase64(request.getSignatureBase64())
                .build();
        return new SignedEventResponse(signatureVerificationService.verifySignedEvent(verification, countryCode));
    }

    /**
     * A {@code ROTATED}, {@code REVOKED} or {@code DECOMMISSIONED} event.
     * Always appends one audit entry; the audit append is not wrapped, so a
     * failure to extend the chain fails the request, as everywhere else.
     *
     * @param countryCode upper-cased jurisdiction from the path
     */
    public KeyStatusChangeResponse changeStatus(String countryCode, KeyLifecycleRequest request) {
        String eventType = request.getEventType();
        RegistryStatus target = targetStatus(eventType);
        String processedAt = Instant.now().toString();

        BigInteger serial;
        X500Principal issuer;
        try {
            serial = SignatureVerificationService.parseSerialHex(request.getCertSerial());
            issuer = new X500Principal(request.getIssuerDn());
        } catch (IllegalArgumentException | NullPointerException e) {
            return audited(countryCode, request, null, KeyStatusChangeResponse.builder()
                    .eventType(eventType)
                    .reason(REASON_MALFORMED_INPUT)
                    .processedAt(processedAt)
                    .build());
        }

        ApprovalRegistry.RegistryEntry entry = approvalRegistry.findByIssuedCertificate(serial, issuer)
                .filter(e -> countryCode != null && countryCode.equals(e.getCountryCode()))
                .filter(this::callerMayChange)
                .orElse(null);
        if (entry == null) {
            return audited(countryCode, request, null, KeyStatusChangeResponse.builder()
                    .eventType(eventType)
                    .reason(REASON_CERT_NOT_FOUND)
                    .processedAt(processedAt)
                    .build());
        }

        String successor = request.getSuccessorVerificationId();
        if (target == RegistryStatus.SUPERSEDED && successor != null) {
            Optional<ApprovalRegistry.RegistryEntry> successorEntry = approvalRegistry.lookup(successor, countryCode);
            if (successorEntry.isEmpty() || successor.equals(entry.getVerificationId())) {
                return audited(countryCode, request, entry, KeyStatusChangeResponse.builder()
                        .eventType(eventType)
                        .verificationId(entry.getVerificationId())
                        .previousStatus(entry.getStatus())
                        .registryStatus(entry.getStatus())
                        .reason(REASON_SUCCESSOR_NOT_FOUND)
                        .processedAt(processedAt)
                        .build());
            }
        }

        ApprovalRegistry.StatusChange change = approvalRegistry.changeStatus(
                entry.getVerificationId(), target, request.getReason(), successor);
        KeyStatusChangeResponse.KeyStatusChangeResponseBuilder response = KeyStatusChangeResponse.builder()
                .eventType(eventType)
                .verificationId(entry.getVerificationId())
                .previousStatus(change.previousStatus())
                .registryStatus(change.currentStatus())
                .processedAt(processedAt);
        switch (change.outcome()) {
            case APPLIED -> response.applied(true)
                    .reason(REASON_OK)
                    .successorVerificationId(target == RegistryStatus.SUPERSEDED ? successor : null);
            case REFUSED -> response.reason(REASON_TRANSITION_NOT_ALLOWED);
            // The entry was found a moment ago and entries are never removed.
            case NOT_FOUND -> response.verificationId(null).reason(REASON_CERT_NOT_FOUND);
        }
        return audited(countryCode, request, entry, response.build());
    }

    /**
     * Whether the caller may change this entry: always without mTLS, always
     * for {@code SUPERVISOR}, otherwise only the principal that performed the
     * Step-3 verification (when one is bound), compared in constant time.
     */
    private boolean callerMayChange(ApprovalRegistry.RegistryEntry entry) {
        if (!mtlsEnabled || callerIsSupervisor()) {
            return true;
        }
        String bound = entry.getVerificationPrincipal();
        if (bound == null || bound.isBlank()) {
            return true;
        }
        String current = principalResolver.currentPrincipal();
        boolean same = current != null && MessageDigest.isEqual(
                bound.getBytes(StandardCharsets.UTF_8), current.getBytes(StandardCharsets.UTF_8));
        if (!same) {
            log.warn("Lifecycle event refused for verificationId={}: calling principal '{}' did not perform "
                    + "the verification. Reported as CERT_NOT_FOUND.", entry.getVerificationId(), current);
        }
        return same;
    }

    private static boolean callerIsSupervisor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getAuthorities() == null) {
            return false;
        }
        for (GrantedAuthority authority : auth.getAuthorities()) {
            if ("ROLE_SUPERVISOR".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Append the audit entry for a status-changing event.
     *
     * <p>Inventory fields (audit entry v2): when the event resolved to a
     * registry entry — exactly when the response names that entry's
     * {@code verificationId}, whether the change was applied or refused —
     * the entry's attested key fingerprint (which joins the audit entry to
     * that key's per-key chain), its issued certificate's serial and issuer
     * DN as stored at confirmation, and the registry status after the event
     * ({@code registryStatus} of the response: the new status when applied,
     * the unchanged one when refused). All {@code null} when the event
     * resolved to no entry ({@code NO-REGISTRY-MATCH}).</p>
     *
     * @param matched the registry entry the event resolved to, or {@code null}
     */
    private KeyStatusChangeResponse audited(String countryCode, KeyLifecycleRequest request,
                                            ApprovalRegistry.RegistryEntry matched,
                                            KeyStatusChangeResponse response) {
        String verificationId = response.getVerificationId() == null
                ? SignatureVerificationService.NO_REGISTRY_MATCH
                : response.getVerificationId();
        AuditAppendRequest req = new AuditAppendRequest(
                principalResolver.currentPrincipal(),
                request.getEventType(),
                verificationId,
                sha256Base64(canonicalRequestBytes(countryCode, request)),
                sha256Base64(canonicalResponseBytes(response)),
                response.isApplied());
        if (matched != null && response.getVerificationId() != null) {
            String fingerprint = matched.getPublicKeyFingerprint();
            req = req.withKeyFingerprintHex(fingerprint == null || fingerprint.isBlank() ? null : fingerprint)
                    .withCertificate(matched.getIssuedCertificateSerial(), matched.getIssuedCertificateIssuerDn())
                    .withRegistryStatus(response.getRegistryStatus() == null
                            ? null : response.getRegistryStatus().name());
        }
        AuditEntry entry = auditLog.append(req);
        response.setAuditEntryHashHex(entry.thisEntryHashHex());
        return response;
    }

    /**
     * {@code v1|lifecycle|eventType|countryCode|certSerial|issuerDn|successorVerificationId|reason},
     * each field with {@code %} → {@code %25} and {@code |} → {@code %7C},
     * {@code null} as empty. Its SHA-256 is the audit entry's
     * {@code requestDigestBase64}.
     */
    static byte[] canonicalRequestBytes(String countryCode, KeyLifecycleRequest r) {
        return String.join("|", "v1", "lifecycle",
                safe(r.getEventType()),
                safe(countryCode),
                safe(r.getCertSerial()),
                safe(r.getIssuerDn()),
                safe(r.getSuccessorVerificationId()),
                safe(r.getReason())).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * {@code v1|lifecycle-response|eventType|verificationId|applied|previousStatus|registryStatus|
     * successorVerificationId|reason|processedAt}, escaped as the request. Its
     * SHA-256 is the audit entry's {@code receiptDigestBase64}.
     */
    static byte[] canonicalResponseBytes(KeyStatusChangeResponse r) {
        return String.join("|", "v1", "lifecycle-response",
                safe(r.getEventType()),
                safe(r.getVerificationId()),
                Boolean.toString(r.isApplied()),
                r.getPreviousStatus() == null ? "" : r.getPreviousStatus().name(),
                r.getRegistryStatus() == null ? "" : r.getRegistryStatus().name(),
                safe(r.getSuccessorVerificationId()),
                safe(r.getReason()),
                safe(r.getProcessedAt())).getBytes(StandardCharsets.UTF_8);
    }

    private static String safe(String s) {
        return s == null ? "" : s.replace("%", "%25").replace("|", "%7C");
    }

    private static String sha256Base64(byte[] in) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(in));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
