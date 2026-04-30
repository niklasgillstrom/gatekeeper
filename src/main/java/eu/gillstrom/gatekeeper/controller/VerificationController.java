package eu.gillstrom.gatekeeper.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import eu.gillstrom.gatekeeper.model.*;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.VerificationService;

import java.util.List;

/**
 * NCA Gatekeeper API Controller.
 *
 * <p>Implements the 7-step verification flow for HSM attestation verification
 * at certificate issuance, as described in the technical definition.</p>
 *
 * <p>The primary operator is the National Competent Authority (NCA) — in
 * Sweden Finansinspektionen (FI). API base in production is therefore
 * {@code dora-api.fi.se} or the equivalent at other Member States' NCAs.
 * EBA (European Banking Authority) does NOT operate this gatekeeper itself;
 * EBA receives read-only access to the NCA registry under its
 * supervisory-convergence (Regulation (EU) 1093/2010 Article 29) and
 * breach-of-Union-law (Article 17(4)/(6)) powers, and can issue findings
 * or opinions to the NCA on that basis.</p>
 *
 * <p>Steps handled by this controller:</p>
 * <ul>
 *   <li>Steps 2-5: {@code POST /v1/attestation/{countryCode}/verify}
 *       — receive attestation, verify, register, return signed receipt.</li>
 *   <li>Step 7: {@code POST /v1/attestation/{countryCode}/confirm}
 *       — receive issuance confirmation, close the loop.</li>
 *   <li>Batch: {@code POST /v1/attestation/{countryCode}/verify/batch}
 *       — EBA Article 17 investigations read the batch results via the NCA.</li>
 * </ul>
 *
 * <p>Legal basis:</p>
 * <ul>
 *   <li>DORA (EU 2022/2554): Articles 5(2)(b), 6(10), 9(3)(c-d), 9(4)(d), 28(1)(a).</li>
 *   <li>EBA Regulation (EU 1093/2010): Articles 17(4), 17(6), 29 — governing
 *       EBA's read access to and opinions on NCA decisions.</li>
 *   <li>Oversight Framework: DORA Articles 32(2), 35(1)(d)(ii).</li>
 * </ul>
 */
@RestController
@RequestMapping("/v1/attestation")
@Tag(name = "DORA Attestation Gatekeeper",
     description = "HSM attestation verification gatekeeper for DORA compliance — "
         + "operated by the NCA (in Sweden: Finansinspektionen). "
         + "EBA has supervisory access under Regulation (EU) 1093/2010 Art 17 and 29.")
public class VerificationController {

    private final VerificationService verificationService;
    private final ApprovalRegistry approvalRegistry;

    public VerificationController(VerificationService verificationService,
                                      ApprovalRegistry approvalRegistry) {
        this.verificationService = verificationService;
        this.approvalRegistry = approvalRegistry;
    }

    // =========================================================================
    // Steps 2–5: Verify attestation and return signed receipt
    // =========================================================================

    @PostMapping("/{countryCode}/verify")
    @Operation(
        summary = "Verify HSM attestation — Steps 2-5 of the gatekeeper flow",
        description = """
            Receives attestation evidence forwarded by the certificate issuer
            (e.g. GetSwish AB), verifies the attestation certificate chain
            against the HSM manufacturer's root CA, registers the result in
            the approval registry, and returns a cryptographically signed
            verification receipt.
            
            The certificate issuer must NOT issue the signing certificate
            until this endpoint returns a COMPLIANT receipt.
            
            The receipt contains a unique verification ID that must be used
            in the Step 7 confirmation (POST /v1/attestation/{countryCode}/confirm).
            """,
        responses = {
            @ApiResponse(responseCode = "200", description = "Signed verification receipt",
                content = @Content(schema = @Schema(implementation = VerificationResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid request format")
        }
    )
    public ResponseEntity<VerificationResponse> verify(
            @PathVariable String countryCode,
            @Valid @RequestBody VerificationRequest request) {
        request.setCountryCode(countryCode.toUpperCase());
        VerificationResponse response = verificationService.verify(request);
        return ResponseEntity.ok(response);
    }

    // =========================================================================
    // Step 7: Receive issuance confirmation — close the loop
    // =========================================================================

    @PostMapping("/{countryCode}/confirm")
    @Operation(
        summary = "Confirm certificate issuance — Step 7 of the gatekeeper flow",
        description = """
            Receives confirmation from the certificate issuer after the
            issuance decision. If the certificate was issued, the full
            signing certificate must be included so that EBA can independently
            verify that the public key matches the approved attestation evidence.
            
            This closes the verification loop cryptographically: EBA does not
            rely on the issuer's assertion that the correct certificate was
            issued — it extracts the public key and verifies the match itself.
            
            If the certificate was not issued, a non-issuance notice with
            timestamp and reason is required.
            
            Anomalies (e.g. certificate issued despite NON-COMPLIANT status,
            or public key mismatch) are flagged in the response and in the
            approval registry for supervisory review.
            """,
        responses = {
            @ApiResponse(responseCode = "200", description = "Confirmation processed",
                content = @Content(schema = @Schema(implementation = IssuanceConfirmationResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid confirmation format, "
                    + "or submitted confirmationNonce does not match the nonce bound to the "
                    + "verificationId at verify time (Step-7 replay attempt)"),
            @ApiResponse(responseCode = "404", description = "Unknown verification ID")
        }
    )
    public ResponseEntity<IssuanceConfirmationResponse> confirmIssuance(
            @PathVariable String countryCode,
            @Valid @RequestBody IssuanceConfirmation confirmation) {
        try {
            IssuanceConfirmationResponse response = verificationService.confirmIssuance(confirmation);
            return ResponseEntity.ok(response);
        } catch (ApprovalRegistry.NonceMismatchException e) {
            // Step-7 replay attempt — nonce did not match the one bound at
            // verify time. Return 400 with a structured body rather than
            // 500; the FE has supplied a malformed (or replayed) request.
            // The registry has already logged the mismatch at WARN.
            IssuanceConfirmationResponse rejection = new IssuanceConfirmationResponse();
            rejection.setVerificationId(confirmation.getVerificationId());
            rejection.setRegistryStatus(IssuanceConfirmationResponse.RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
            rejection.setAnomalies(java.util.List.of(
                    "Confirmation nonce does not match the nonce bound to verificationId at verify time. "
                  + "Possible Step-7 replay attempt; the gatekeeper has logged this as a security event."));
            return ResponseEntity.badRequest().body(rejection);
        }
    }

    // =========================================================================
    // Batch verification for Article 17 investigations
    // =========================================================================

    @PostMapping("/{countryCode}/verify/batch")
    @Operation(
        summary = "Batch verify multiple technical suppliers",
        description = """
            Verifies HSM attestation for multiple technical suppliers in a
            single request. Returns individual signed receipts plus aggregate
            compliance statistics.
            
            Designed for EBA Article 17(4) investigations to quantify the
            scope of non-compliance across a jurisdiction, and for Article 29
            supervisory convergence assessments.
            
            A compliance rate significantly below 100% indicates a systemic
            supervisory failure by the national competent authority — precisely
            the type of finding that triggers EBA's obligations under
            Article 17 of Regulation 1093/2010.
            """,
        responses = {
            @ApiResponse(responseCode = "200", description = "Batch verification completed",
                content = @Content(schema = @Schema(implementation = BatchVerificationResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid request format")
        }
    )
    public ResponseEntity<BatchVerificationResponse> verifyBatch(
            @PathVariable String countryCode,
            @Valid @RequestBody List<VerificationRequest> requests) {
        requests.forEach(r -> r.setCountryCode(countryCode.toUpperCase()));
        BatchVerificationResponse response = verificationService.verifyBatch(requests);
        return ResponseEntity.ok(response);
    }

    // =========================================================================
    // Registry queries — supervisory tools
    // =========================================================================

    @GetMapping("/{countryCode}/registry/stats")
    @Operation(
        summary = "Compliance statistics for a jurisdiction",
        description = "Returns aggregate compliance statistics from the approval registry.")
    public ResponseEntity<ApprovalRegistry.ComplianceStats> registryStats(
            @PathVariable String countryCode) {
        return ResponseEntity.ok(approvalRegistry.getStats(countryCode.toUpperCase()));
    }

    @GetMapping("/{countryCode}/registry/anomalies")
    @Operation(
        summary = "List all anomalies in the registry",
        description = """
            Returns all registry entries with anomalous status:
            certificates issued despite rejection, public key mismatches,
            or confirmations for unknown verification IDs.
            Each anomaly represents a potential active circumvention of
            the supervisory mechanism.""")
    public ResponseEntity<List<ApprovalRegistry.RegistryEntry>> registryAnomalies(
            @PathVariable String countryCode) {
        return ResponseEntity.ok(approvalRegistry.findAnomalies());
    }

    @GetMapping("/{countryCode}/registry/awaiting")
    @Operation(
        summary = "List verifications awaiting Step 7 confirmation",
        description = """
            Returns all registry entries where the attestation was verified
            but no Step 7 confirmation has been received. Entries that remain
            in this state beyond a reasonable period indicate that the
            certificate issuer has not closed the loop.""")
    public ResponseEntity<List<ApprovalRegistry.RegistryEntry>> registryAwaiting(
            @PathVariable String countryCode) {
        return ResponseEntity.ok(approvalRegistry.findAwaitingConfirmation());
    }

    // =========================================================================
    // Utility endpoints
    // =========================================================================

    @GetMapping("/supported-vendors")
    @Operation(
        summary = "List supported HSM vendors",
        description = "Returns the list of HSM vendors for which attestation verification is supported.")
    public ResponseEntity<List<VendorInfo>> supportedVendors() {
        return ResponseEntity.ok(List.of(
            new VendorInfo("SECUROSYS", "Securosys Primus HSM",
                "Requires: attestationData (XML), attestationSignature, attestationCertChain"),
            new VendorInfo("YUBICO", "Yubico YubiHSM 2",
                "Requires: attestationCertChain"),
            new VendorInfo("AZURE", "Microsoft Azure Managed HSM",
                "Requires: attestationData (JSON from az keyvault key get-attestation)"),
            new VendorInfo("GOOGLE", "Google Cloud HSM",
                "Requires: attestationData (base64), attestationCertChain")
        ));
    }

    @GetMapping("/health")
    @Operation(summary = "Health check")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("DORA Attestation Gatekeeper: OK");
    }

    public record VendorInfo(String vendorId, String productName, String requirements) {}
}
