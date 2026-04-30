package eu.gillstrom.gatekeeper.audit;

import java.util.Objects;

/**
 * Carrier for the inputs to {@link AuditLog#append(AuditAppendRequest)}.
 *
 * <p>Field semantics:</p>
 * <ul>
 *   <li>{@code mtlsClientPrincipal} — the authenticated identity of the API
 *       caller. In production this is the CN (or full DN) extracted from
 *       the mTLS client certificate. The value {@code "anonymous"} is used
 *       when the open (non-mTLS) reference filter chain is in use.</li>
 *   <li>{@code operation} — one of {@code VERIFY}, {@code CONFIRM},
 *       {@code BATCH_VERIFY}. Used by supervisory tooling to filter the
 *       audit trail by step in the gatekeeper flow.</li>
 *   <li>{@code verificationId} — the gatekeeper-internal UUID that ties this
 *       audit entry to a row in the {@link
 *       eu.gillstrom.gatekeeper.service.ApprovalRegistry}.</li>
 *   <li>{@code requestDigestBase64} — Base64-encoded SHA-256 digest of the
 *       canonical request bytes. Allows a supervisor to prove what was
 *       submitted without storing the full payload (the receipt itself is
 *       authoritative; the digest is a witness).</li>
 *   <li>{@code receiptDigestBase64} — Base64-encoded SHA-256 digest of the
 *       canonical receipt bytes. {@code null} for operations that do not
 *       produce a receipt (e.g. issuance confirmation).</li>
 *   <li>{@code compliant} — the verification outcome.</li>
 * </ul>
 *
 * <p>Legal basis: DORA Article 28(6) (5-year retention of records related
 * to ICT third-party service providers); EBA Regulation Article 35(1)
 * (cooperation with competent authorities — supervisory access to audit
 * trails).</p>
 *
 * <p>{@code null} for {@code mtlsClientPrincipal}, {@code operation}, or
 * {@code verificationId} is a programming error and is rejected on
 * construction. {@code requestDigestBase64} is required (every audited
 * operation has a request); {@code receiptDigestBase64} is optional and
 * may be {@code null} when the operation produces no receipt.</p>
 */
public record AuditAppendRequest(
        String mtlsClientPrincipal,
        String operation,
        String verificationId,
        String requestDigestBase64,
        String receiptDigestBase64,
        boolean compliant) {

    public AuditAppendRequest {
        Objects.requireNonNull(mtlsClientPrincipal, "mtlsClientPrincipal must not be null (use \"anonymous\")");
        Objects.requireNonNull(operation, "operation must not be null");
        Objects.requireNonNull(verificationId, "verificationId must not be null");
        Objects.requireNonNull(requestDigestBase64, "requestDigestBase64 must not be null");
        if (mtlsClientPrincipal.isBlank()) {
            throw new IllegalArgumentException("mtlsClientPrincipal must not be blank");
        }
        if (operation.isBlank()) {
            throw new IllegalArgumentException("operation must not be blank");
        }
        if (verificationId.isBlank()) {
            throw new IllegalArgumentException("verificationId must not be blank");
        }
        if (requestDigestBase64.isBlank()) {
            throw new IllegalArgumentException("requestDigestBase64 must not be blank");
        }
    }
}
