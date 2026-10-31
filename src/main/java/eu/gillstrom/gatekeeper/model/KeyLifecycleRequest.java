package eu.gillstrom.gatekeeper.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Body of {@code POST /v1/attestation/{countryCode}/lifecycle}: one
 * key-lifecycle event for the certificate identified by {@code certSerial}
 * and {@code issuerDn} (see {@code KeyLifecycleService} for the event types
 * and their mapping to the manuscript's lifecycle).
 *
 * <ul>
 *   <li>{@code SIGNED} — {@code certSerial}, {@code issuerDn},
 *       {@code digestHex}, {@code signatureBase64}. The signature is
 *       verified with {@code SHA512withRSA} over the digest, as
 *       {@code POST /api/v1/verify} does by default.</li>
 *   <li>{@code ROTATED} — {@code certSerial}, {@code issuerDn},
 *       {@code reason}, optionally {@code successorVerificationId}.</li>
 *   <li>{@code REVOKED}, {@code DECOMMISSIONED} — {@code certSerial},
 *       {@code issuerDn}, {@code reason}.</li>
 * </ul>
 *
 * <p>{@code certSerial} and {@code issuerDn} are read as in
 * {@link SignatureVerificationRequest}: hexadecimal serial with an optional
 * {@code 0x}, issuer compared as an X.500 name. Size limits are those of
 * {@link SignatureVerificationRequest}. A field the event does not use is
 * ignored, except {@code successorVerificationId}, which only
 * {@code ROTATED} accepts.</p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyLifecycleRequest {

    public static final String SIGNED = "SIGNED";
    public static final String ROTATED = "ROTATED";
    public static final String REVOKED = "REVOKED";
    public static final String DECOMMISSIONED = "DECOMMISSIONED";

    /** Maximum length of the free-text {@code reason}. */
    public static final int MAX_REASON_LENGTH = 1024;

    @NotBlank
    @Pattern(regexp = "^(SIGNED|ROTATED|REVOKED|DECOMMISSIONED)$",
             message = "eventType must be one of SIGNED, ROTATED, REVOKED, DECOMMISSIONED")
    private String eventType;

    @NotBlank
    @Size(max = 128, message = "certSerial exceeds the maximum accepted length")
    private String certSerial;

    @NotBlank
    @Size(max = 512, message = "issuerDn exceeds the maximum accepted length")
    private String issuerDn;

    /** {@code SIGNED} only: hex digest the key signed. */
    @Size(max = SignatureVerificationRequest.MAX_DIGEST_HEX_LENGTH,
          message = "digestHex exceeds the maximum accepted length")
    private String digestHex;

    /** {@code SIGNED} only: Base64 signature over {@code digestHex}. */
    @Size(max = SignatureVerificationRequest.MAX_SIGNATURE_B64_LENGTH,
          message = "signatureBase64 exceeds the maximum accepted length")
    private String signatureBase64;

    /** {@code ROTATED} only, optional: verificationId of the key that replaces this one. */
    @Size(max = 128, message = "successorVerificationId exceeds the maximum accepted length")
    private String successorVerificationId;

    /** Required for {@code ROTATED}, {@code REVOKED} and {@code DECOMMISSIONED}; free text. */
    @Size(max = MAX_REASON_LENGTH, message = "reason exceeds the maximum accepted length")
    private String reason;

    /** A {@code SIGNED} event carries the digest and the signature. */
    @JsonIgnore
    @AssertTrue(message = "SIGNED requires digestHex and signatureBase64")
    public boolean isSignedEventComplete() {
        return !SIGNED.equals(eventType) || (!isBlank(digestHex) && !isBlank(signatureBase64));
    }

    /** A status-changing event says why. */
    @JsonIgnore
    @AssertTrue(message = "ROTATED, REVOKED and DECOMMISSIONED require a reason")
    public boolean isReasonGivenForStatusChange() {
        return eventType == null || SIGNED.equals(eventType) || !isBlank(reason);
    }

    /** Only a rotation has a successor. */
    @JsonIgnore
    @AssertTrue(message = "successorVerificationId is accepted only with ROTATED")
    public boolean isSuccessorOnlyOnRotation() {
        return successorVerificationId == null || ROTATED.equals(eventType);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
