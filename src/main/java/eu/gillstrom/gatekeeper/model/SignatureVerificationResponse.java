package eu.gillstrom.gatekeeper.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Result of a settlement-time signature verification.
 *
 * <p>{@code signatureValid} reports whether the cryptographic verification
 * succeeded against the certificate's public key. {@code compliant} reports
 * whether the certificate corresponds to a gatekeeper audit entry that
 * passed structural-independence and HSM-attestation checks at issuance.
 *
 * <p>The settlement-rail enforcement layer (railgate) allows settlement
 * if and only if both flags are true. Any false value triggers default-deny.
 *
 * <p>{@code reason} is one of:
 * <ul>
 *   <li>{@code OK} — verification passed</li>
 *   <li>{@code CERT_NOT_FOUND} — no certificate stored at Step 7 for
 *       {@code (certSerial, issuerDn)}, or a supplied certificate that
 *       differs from the stored one</li>
 *   <li>{@code SIGNATURE_INVALID} — cryptographic verification failed</li>
 *   <li>{@code CERT_NON_COMPLIANT} — cert exists but did not pass
 *       structural compliance at issuance</li>
 *   <li>{@code CERT_EXPIRED} — the signature verifies, but the certificate
 *       is outside its validity period</li>
 *   <li>{@code MALFORMED_INPUT} — request fields could not be parsed</li>
 *   <li>{@code ALGORITHM_NOT_SUPPORTED} — algorithm parameter unrecognised</li>
 *   <li>{@code CERT_SUPERSEDED}, {@code CERT_REVOKED},
 *       {@code CERT_DECOMMISSIONED} — the signature verifies, but a key
 *       lifecycle event ({@code ROTATED}, {@code REVOKED},
 *       {@code DECOMMISSIONED}) has moved the certificate's registry entry
 *       out of {@code VERIFIED_AND_ISSUED}</li>
 * </ul>
 *
 * <h2>Signed verdict</h2>
 *
 * <p>{@code verdictSignatureBase64} is the gatekeeper's signature, made with
 * the active {@code ReceiptSigner}, over
 * {@link eu.gillstrom.gatekeeper.signing.SettlementVerdictCanonicalizer}
 * applied to {@code verifiedAt}, the request's {@code certSerial},
 * {@code issuerDn} and {@code digestHex}, and this response's
 * {@code signatureValid}, {@code compliant}, {@code reason},
 * {@code auditEntryId} and {@code auditEntryHashHex}. Every response is
 * signed, denials included, except one whose request {@code certSerial},
 * {@code issuerDn} or {@code digestHex} cannot be normalised: then the four
 * verdict fields are {@code null}.</p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignatureVerificationResponse {

    private boolean signatureValid;

    private boolean compliant;

    private String auditEntryId;

    private String reason;

    private String auditEntryHashHex;

    /**
     * {@link java.time.Instant#toString()} of the verification instant,
     * truncated to milliseconds. Part of the signed verdict.
     */
    private String verifiedAt;

    /** Base64 signature over the canonical verdict (see class javadoc). */
    private String verdictSignatureBase64;

    /** JCA name of the signature algorithm, as {@code ReceiptSigner.getSignatureAlgorithm()}. */
    private String verdictSignatureAlgorithm;

    /**
     * Lower-case hex SHA-256 fingerprint of the signing key, in the form
     * {@code GET /v1/gatekeeper/keys} publishes as
     * {@code publicKeyFingerprintHex} (computed over the DER
     * SubjectPublicKeyInfo of the active signing certificate's public key).
     */
    private String signingKeyFingerprintHex;
}
