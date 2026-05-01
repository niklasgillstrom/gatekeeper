package eu.gillstrom.gatekeeper.controller;

import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.service.SignatureVerificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Settlement-time signature verification endpoint.
 *
 * <p>Companion endpoint to the issuance-time attestation flow. Whereas
 * {@link VerificationController} runs the 7-step verification protocol
 * at certificate issuance, this controller answers a different question
 * at settlement time: <em>given a digest, signature, and certificate, is
 * the signature valid and is the certificate compliant?</em>
 *
 * <p>The intended caller is a settlement-rail enforcement layer such as
 * <strong>railgate</strong>, which receives pacs.008 messages at the
 * central-bank settlement rail (RIX-INST in Sweden, TIPS in the
 * Eurosystem, FedNow in the US) and queries this endpoint to determine
 * whether to allow or default-deny the settlement.
 *
 * <p>Data minimisation: this endpoint never receives or stores transaction
 * payload content. Only cryptographic artefacts (digest, signature,
 * certificate) traverse the boundary. The supervisor never sees
 * transaction amounts, sender/receiver detail, or business message
 * content. SHA-512 collision resistance ensures the digest uniquely
 * binds the signature to the exact transaction performed.
 *
 * <p>Legal basis (Union law):
 * <ul>
 *   <li>DORA Regulation (EU) 2022/2554 — Articles 6.4, 6.6, 6.10, 9, 28.4(e),
 *       32 (oversight forum), 35 (information requests).</li>
 *   <li>GDPR Regulation (EU) 2016/679 — Article 5(1)(c) (data minimisation).</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Tag(
        name = "Settlement-time Signature Verification",
        description = "Settlement-rail enforcement endpoint for railgate or "
                + "equivalent settlement-layer enforcement components. Verifies "
                + "a signature against a previously audited certificate and "
                + "returns binary {signature_valid, compliant} for default-deny "
                + "decisioning. Data-minimised: receives only digest, never "
                + "transaction payload."
)
public class SignatureVerificationController {

    private final SignatureVerificationService verificationService;

    @PostMapping("/verify")
    @Operation(
            summary = "Verify settlement-time signature against gatekeeper audit",
            description = """
                    Receives {certSerial, issuerDn, digestHex, signatureBase64,
                    signingCertificatePem} and returns whether the signature
                    cryptographically verifies and whether the underlying
                    certificate corresponds to a compliant gatekeeper audit
                    entry.

                    The verifier mirrors the production signing flow exactly:
                    Signature.getInstance("SHA512withRSA").initVerify(publicKey).update(digest).verify(signature)
                    — the digest (already computed by the signer) is passed
                    in directly; gatekeeper does not see, store, or transport
                    the original transaction payload.

                    Audit lookup uses the SHA-256 fingerprint of the
                    SubjectPublicKeyInfo (uppercase hex, colon-separated) —
                    the same canonical form used elsewhere in gatekeeper.

                    Default-deny: settlement-rail enforcement should treat
                    any non-positive result (signature_valid=false or
                    compliant=false) as a block. The reason field carries
                    a structured code for observability and operator
                    diagnostics.
                    """,
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Verification result",
                            content = @Content(schema = @Schema(implementation = SignatureVerificationResponse.class))
                    ),
                    @ApiResponse(responseCode = "400", description = "Malformed request body")
            }
    )
    public ResponseEntity<SignatureVerificationResponse> verify(
            @Valid @RequestBody SignatureVerificationRequest request) {
        return ResponseEntity.ok(verificationService.verify(request));
    }
}
