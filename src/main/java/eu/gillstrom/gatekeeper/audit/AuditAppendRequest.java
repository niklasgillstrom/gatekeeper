package eu.gillstrom.gatekeeper.audit;

import java.util.Objects;

/**
 * Carrier for the inputs to {@link AuditLog#append(AuditAppendRequest)}.
 *
 * <p>Field semantics:</p>
 * <ul>
 *   <li>{@code mtlsClientPrincipal} — the authenticated identity of the API
 *       caller. With mTLS this is the value of the subject attribute named by
 *       {@code gatekeeper.security.mtls.principal-attribute} (by default
 *       CN). The open (non-mTLS) reference filter chain records
 *       {@code "reference-anonymous"}; {@code "anonymous"} is recorded only
 *       when no security context exists at all (unit tests).</li>
 *   <li>{@code operation} — one of:
 *       <ul>
 *         <li>{@code VERIFY}, {@code BATCH_VERIFY}, {@code CONFIRM}
 *             (issuance-time, {@code VerificationService});</li>
 *         <li>{@code SETTLEMENT_VERIFY} (settlement-time, {@code POST
 *             /api/v1/verify}) and {@code SIGNED} (a key-lifecycle
 *             {@code SIGNED} event, verified as a settlement), both
 *             {@code SignatureVerificationService};</li>
 *         <li>{@code ROTATED}, {@code REVOKED}, {@code DECOMMISSIONED}
 *             (key-lifecycle status changes, {@code KeyLifecycleService});</li>
 *         <li>{@code TRIANGULATION} (a sealed discrepancy report,
 *             {@code TriangulationService}).</li>
 *       </ul>
 *       Used by supervisory tooling to filter the audit trail by step in the
 *       gatekeeper flow.</li>
 *   <li>{@code verificationId} — the gatekeeper-internal UUID that ties this
 *       audit entry to a row in the {@link
 *       eu.gillstrom.gatekeeper.service.ApprovalRegistry}. For
 *       {@code SETTLEMENT_VERIFY} and {@code SIGNED} the same UUID recurs once
 *       per query against that certificate, and for these and the three
 *       status changes the sentinel {@code NO-REGISTRY-MATCH} is used when
 *       the event resolved to no registry row. For {@code TRIANGULATION} it
 *       is the inquiry id.</li>
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
 *
 * <h2>Inventory fields (audit entry v2)</h2>
 *
 * <p>All optional; {@code null} means "not known for this event". The
 * six-argument constructor leaves them all {@code null}; the
 * {@code with...} methods return a copy with one group set.</p>
 * <ul>
 *   <li>{@code keyFingerprintHex} — fingerprint of the attested public key in
 *       the {@link eu.gillstrom.gatekeeper.util.Fingerprints} format (SHA-256
 *       over SubjectPublicKeyInfo, lower-case hex, colon-separated). It is
 *       also the key of the per-key chain ({@code prevKeyEntryHashHex}), so
 *       it must not be blank.</li>
 *   <li>{@code certSerialHex}, {@code certIssuerDn} — the issued
 *       certificate, in the form {@code ApprovalRegistry.IssuedCertificate}
 *       stores ({@code BigInteger.toString(16)}, RFC 2253 issuer DN).</li>
 *   <li>{@code hsmVendor}, {@code hsmSerial} — as on the signed receipt.</li>
 *   <li>{@code registryStatus} — the approval-registry status name.</li>
 *   <li>{@code hsmFirmwareVersion}, {@code hsmFipsApprovedMode} — as on the
 *       verification response ({@code VerificationResponse}); reported only
 *       for a Yubico attestation whose chain validated.
 *       {@code hsmFipsApprovedMode} is {@code "true"}, {@code "false"} or
 *       {@code null}.</li>
 * </ul>
 *
 * <p>Which operations set which inventory fields:</p>
 * <ul>
 *   <li>{@code VERIFY}, {@code BATCH_VERIFY}: {@code keyFingerprintHex}
 *       (the receipt's {@code publicKeyFingerprint}), {@code hsmVendor} and
 *       {@code hsmSerial} (only when the receipt is compliant),
 *       {@code hsmFirmwareVersion} and {@code hsmFipsApprovedMode}.</li>
 *   <li>{@code CONFIRM}: {@code keyFingerprintHex} of the registry entry,
 *       {@code certSerialHex} and {@code certIssuerDn} of the submitted
 *       certificate once it passed issuer-CA validation, and
 *       {@code registryStatus}.</li>
 *   <li>{@code SETTLEMENT_VERIFY}, {@code SIGNED}: from the matched registry
 *       row, {@code keyFingerprintHex}, {@code certSerialHex},
 *       {@code certIssuerDn} and {@code registryStatus}; none without a
 *       match.</li>
 *   <li>{@code ROTATED}, {@code REVOKED}, {@code DECOMMISSIONED}: from the
 *       registry entry the event resolved to, {@code keyFingerprintHex},
 *       {@code certSerialHex} and {@code certIssuerDn}, and the resulting
 *       {@code registryStatus}; none without an entry.</li>
 *   <li>{@code TRIANGULATION}: none.</li>
 * </ul>
 */
public record AuditAppendRequest(
        String mtlsClientPrincipal,
        String operation,
        String verificationId,
        String requestDigestBase64,
        String receiptDigestBase64,
        boolean compliant,
        String keyFingerprintHex,
        String certSerialHex,
        String certIssuerDn,
        String hsmVendor,
        String hsmSerial,
        String registryStatus,
        String hsmFirmwareVersion,
        String hsmFipsApprovedMode) {

    /**
     * The original six-field request; every inventory field {@code null}.
     */
    public AuditAppendRequest(String mtlsClientPrincipal, String operation, String verificationId,
                              String requestDigestBase64, String receiptDigestBase64, boolean compliant) {
        this(mtlsClientPrincipal, operation, verificationId, requestDigestBase64, receiptDigestBase64, compliant,
                null, null, null, null, null, null, null, null);
    }

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
        if (keyFingerprintHex != null && keyFingerprintHex.isBlank()) {
            throw new IllegalArgumentException("keyFingerprintHex must be null or non-blank");
        }
        if (hsmFipsApprovedMode != null
                && !"true".equals(hsmFipsApprovedMode) && !"false".equals(hsmFipsApprovedMode)) {
            throw new IllegalArgumentException("hsmFipsApprovedMode must be \"true\", \"false\" or null, got '"
                    + hsmFipsApprovedMode + "'");
        }
    }

    /** Copy with the attested key's fingerprint set. */
    public AuditAppendRequest withKeyFingerprintHex(String fingerprintHex) {
        return new AuditAppendRequest(mtlsClientPrincipal, operation, verificationId, requestDigestBase64,
                receiptDigestBase64, compliant, fingerprintHex, certSerialHex, certIssuerDn, hsmVendor, hsmSerial,
                registryStatus, hsmFirmwareVersion, hsmFipsApprovedMode);
    }

    /** Copy with the issued certificate's serial (hex) and issuer DN set. */
    public AuditAppendRequest withCertificate(String serialHex, String issuerDn) {
        return new AuditAppendRequest(mtlsClientPrincipal, operation, verificationId, requestDigestBase64,
                receiptDigestBase64, compliant, keyFingerprintHex, serialHex, issuerDn, hsmVendor, hsmSerial,
                registryStatus, hsmFirmwareVersion, hsmFipsApprovedMode);
    }

    /** Copy with the HSM vendor and serial set. */
    public AuditAppendRequest withHsm(String vendor, String serial) {
        return new AuditAppendRequest(mtlsClientPrincipal, operation, verificationId, requestDigestBase64,
                receiptDigestBase64, compliant, keyFingerprintHex, certSerialHex, certIssuerDn, vendor, serial,
                registryStatus, hsmFirmwareVersion, hsmFipsApprovedMode);
    }

    /** Copy with the approval-registry status set. */
    public AuditAppendRequest withRegistryStatus(String status) {
        return new AuditAppendRequest(mtlsClientPrincipal, operation, verificationId, requestDigestBase64,
                receiptDigestBase64, compliant, keyFingerprintHex, certSerialHex, certIssuerDn, hsmVendor, hsmSerial,
                status, hsmFirmwareVersion, hsmFipsApprovedMode);
    }

    /**
     * Copy with the HSM firmware version and FIPS-approved-mode flag set.
     * {@code fipsApprovedMode} is {@code "true"}, {@code "false"} or
     * {@code null}.
     */
    public AuditAppendRequest withHsmFirmware(String firmwareVersion, String fipsApprovedMode) {
        return new AuditAppendRequest(mtlsClientPrincipal, operation, verificationId, requestDigestBase64,
                receiptDigestBase64, compliant, keyFingerprintHex, certSerialHex, certIssuerDn, hsmVendor, hsmSerial,
                registryStatus, firmwareVersion, fipsApprovedMode);
    }
}
