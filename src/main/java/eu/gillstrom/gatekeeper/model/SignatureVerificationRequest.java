package eu.gillstrom.gatekeeper.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
 *   <li>If {@code signingCertificatePem} is supplied, it must be byte-identical
 *       to the certificate stored for {@code (certSerial, issuerDn)};
 *       otherwise the answer is {@code CERT_NOT_FOUND}. The public key is
 *       always taken from the stored certificate.</li>
 *   <li>If absent, gatekeeper looks up the certificate stored at Step-7
 *       confirmation under {@code (certSerial, issuerDn)}: {@code certSerial}
 *       is hexadecimal, case-insensitive, with an optional {@code 0x}
 *       prefix, and {@code issuerDn} is compared as an
 *       {@link javax.security.auth.x500.X500Principal}. Only confirmations
 *       that ended in {@code VERIFIED_AND_ISSUED} store a certificate. If no
 *       such certificate exists, the response is {@code CERT_NOT_FOUND} —
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

    /**
     * <h2>Field size limits</h2>
     *
     * <p>This endpoint sits in the settlement path and, until an independent
     * review pointed it out, accepted fields of unbounded length: an
     * attacker could make the gatekeeper hex-decode, base64-decode and
     * PEM-parse arbitrarily large strings on the payment-critical thread.
     * The ceilings below are derived from the artefacts themselves:</p>
     *
     * <ul>
     *   <li>A SHA-512 digest is 128 hex characters. 256 leaves room for a
     *       longer digest without letting a caller stream megabytes into
     *       {@code HexFormat.parseHex}.</li>
     *   <li>An RSA-8192 signature is 1024 bytes, or 1368 characters of
     *       base64; 4096 covers that with a wide margin.</li>
     *   <li>An X.509 certificate in PEM is 1–3 KB; 16 KiB is generous.</li>
     *   <li>An X.500 issuer DN is bounded by RFC 5280 practice at a few
     *       hundred characters; a serial number is a big integer in
     *       hexadecimal (at most 20 octets under RFC 5280).</li>
     * </ul>
     */
    public static final int MAX_DIGEST_HEX_LENGTH = 256;

    /** Base64 signature, sized for RSA-8192 with margin. */
    public static final int MAX_SIGNATURE_B64_LENGTH = 4096;

    /** PEM-encoded X.509 signing certificate. */
    public static final int MAX_CERT_PEM_LENGTH = 16 * 1024;

    @NotBlank
    @Size(max = 128, message = "certSerial exceeds the maximum accepted length")
    private String certSerial;

    @NotBlank
    @Size(max = 512, message = "issuerDn exceeds the maximum accepted length")
    private String issuerDn;

    @NotBlank
    @Size(max = MAX_DIGEST_HEX_LENGTH, message = "digestHex exceeds the maximum accepted length")
    private String digestHex;

    @NotBlank
    @Size(max = MAX_SIGNATURE_B64_LENGTH, message = "signatureBase64 exceeds the maximum accepted length")
    private String signatureBase64;

    /**
     * Optional PEM-encoded signing certificate. If supplied, it must equal the
     * certificate stored at Step-7 confirmation for {@code (certSerial,
     * issuerDn)}; the public key is taken from the stored certificate.
     */
    @Size(max = MAX_CERT_PEM_LENGTH, message = "signingCertificatePem exceeds the maximum accepted length")
    private String signingCertificatePem;

    /**
     * Optional algorithm identifier. Defaults to RSA-PKCS#1 v1.5 with
     * SHA-512 (the algorithm used by the reference Swish utbetalning
     * signing flow). Other supported values: {@code SHA384withRSA},
     * {@code SHA256withRSA}, {@code SHA256withECDSA},
     * {@code SHA384withECDSA}, {@code SHA512withECDSA} and
     * {@code RSASSA-PSS}, the last verified with SHA-512, MGF1 with
     * SHA-512, a 64-byte salt and trailer field 1.
     *
     * <p>Bounded independently of the whitelist in
     * {@code SignatureVerificationService}: the whitelist rejects an
     * unrecognised algorithm, but only after the string has been received
     * and logged.</p>
     */
    @Size(max = 64, message = "algorithm exceeds the maximum accepted length")
    private String algorithm;
}
