package eu.gillstrom.gatekeeper.signing;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

/**
 * Result of verifying the HSM attestation of the gatekeeper's active signing
 * key, together with the evidence it was verified from. Published on
 * {@code GET /v1/gatekeeper/keys} (field {@code attestation} of the
 * {@code ACTIVE} entry) when {@code gatekeeper.signing.attestation.vendor} is
 * configured, so that a relying party can re-run the verification against the
 * vendor root itself.
 *
 * @param vendor {@code YUBICO} or {@code SECUROSYS}
 * @param hsmSerial device serial reported by the verifier (Yubico: from the
 *     device certificate or the serial extension; Securosys: from the device
 *     certificate's {@code SN:}), or {@code null}
 * @param valid the verifier's overall verdict ({@code YubicoAttestationResult.isValid()}
 *     or {@code SecurosysAttestationResult.isValid()})
 * @param chainValid the attestation certificate chain validated with PKIX
 *     against {@code verifiedAgainstRootSha256Hex}
 * @param publicKeyMatch the attested public key equals the public key of
 *     the active signing certificate (byte-equal SubjectPublicKeyInfo)
 * @param attestationSignatureValid Securosys only: the signature over the
 *     attestation XML verified under the attestation certificate; {@code null}
 *     for Yubico, whose attestation is the certificate itself
 * @param keyOrigin as the verifier reports it (Yubico: {@code generated},
 *     {@code imported}, {@code imported_wrapped} or {@code unknown};
 *     Securosys: the {@code creation} attribute, e.g. {@code generated})
 * @param exportable Yubico: an export-under-wrap capability is set;
 *     Securosys: {@code extractable=true}
 * @param firmwareVersion Yubico only: firmware from the attestation
 *     extension, or {@code null}
 * @param verifiedAgainstRootSha256Hex lower-case hex SHA-256 of the DER of
 *     the root certificate the chain was validated against
 * @param verifiedAt when the verification ran (gatekeeper start-up)
 * @param errors the verifier's error list; empty when {@code valid}
 * @param evidence the attestation evidence as configured
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record KeyAttestation(
        String vendor,
        String hsmSerial,
        boolean valid,
        boolean chainValid,
        boolean publicKeyMatch,
        Boolean attestationSignatureValid,
        String keyOrigin,
        boolean exportable,
        String firmwareVersion,
        String verifiedAgainstRootSha256Hex,
        Instant verifiedAt,
        List<String> errors,
        Evidence evidence) {

    /**
     * The attestation evidence, in the form the vendor verifier consumes.
     *
     * @param certificateChainPem attestation certificate chain, one PEM
     *     certificate per element, attestation (leaf) certificate first
     * @param attestationXmlBase64 Securosys only: the attestation XML bytes,
     *     Base64 — the signature is over these exact bytes
     * @param attestationSignatureBase64 Securosys only: the SHA256withRSA
     *     signature over the XML bytes, Base64
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Evidence(List<String> certificateChainPem, String attestationXmlBase64,
                           String attestationSignatureBase64) {
    }
}
