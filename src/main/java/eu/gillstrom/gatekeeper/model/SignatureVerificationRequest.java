package eu.gillstrom.gatekeeper.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Settlement-time signature verification request.
 *
 * <p>Submitted by railgate (or any settlement-rail enforcement layer) to
 * verify that a settlement-time signature is valid against a previously
 * issued, gatekeeper-audited certificate. Returns a binary
 * {@link SignatureVerificationResponse} indicating whether the signature
 * verifies and whether the underlying certificate passed the structural
 * compliance checks at issuance.
 *
 * <p>Data minimisation: this request carries only cryptographic artefacts
 * (digest, signature, certificate identifiers) — never transaction payload
 * content. The supervisor never sees transaction content; SHA-512 collision
 * resistance ensures the digest uniquely binds the signature to the exact
 * transaction performed.
 *
 * <p>Two paths are supported for locating the certificate's public key:
 * <ul>
 *   <li>If {@code signingCertificatePem} is supplied, it is used directly
 *       (the supervisor still cross-checks {@code certSerial} against the
 *       audit log to confirm compliance).</li>
 *   <li>If absent, gatekeeper looks up the certificate stored at Step-7
 *       confirmation under {@code (certSerial, issuerDn)}. If no such
 *       certificate exists, the response is {@code CERT_NOT_FOUND} —
 *       a circumvention signal in itself, since a settlement-time
 *       signature for an unknown cert serial cannot have come from a
 *       gatekeeper-audited issuance.</li>
 * </ul>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignatureVerificationRequest {

    @NotBlank
    private String certSerial;

    @NotBlank
    private String issuerDn;

    @NotBlank
    private String digestHex;

    @NotBlank
    private String signatureBase64;

    /**
     * Optional PEM-encoded signing certificate. If supplied, used directly
     * for public-key extraction. If absent, gatekeeper looks up the cert
     * stored at Step-7 confirmation.
     */
    private String signingCertificatePem;

    /**
     * Optional algorithm identifier. Defaults to RSA-PKCS#1 v1.5 with
     * SHA-512 (the algorithm used by the reference Swish utbetalning
     * signing flow). Other supported values:
     * {@code SHA512_WITH_RSA_PSS}, {@code SHA384_WITH_RSA},
     * {@code SHA256_WITH_RSA}.
     */
    private String algorithm;
}
