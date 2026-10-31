package eu.gillstrom.gatekeeper.controller;

import eu.gillstrom.gatekeeper.model.KeyLifecycleRequest;
import eu.gillstrom.gatekeeper.model.KeyStatusChangeResponse;
import eu.gillstrom.gatekeeper.model.SignedEventResponse;
import eu.gillstrom.gatekeeper.service.KeyLifecycleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;

/**
 * Key-lifecycle events: {@code POST /v1/attestation/{countryCode}/lifecycle}.
 * See {@link KeyLifecycleService} for the events, the allowed status
 * changes, the mapping to the manuscript's lifecycle and who may change an
 * entry. Reachable by {@code FE} and {@code SUPERVISOR} under mTLS.
 */
@RestController
@RequestMapping("/v1/attestation")
@Tag(name = "Key Lifecycle",
     description = "Signed, chained key-lifecycle events for issued signing certificates: "
         + "SIGNED, ROTATED, REVOKED, DECOMMISSIONED.")
public class KeyLifecycleController {

    private final KeyLifecycleService lifecycleService;

    public KeyLifecycleController(KeyLifecycleService lifecycleService) {
        this.lifecycleService = lifecycleService;
    }

    @PostMapping("/{countryCode}/lifecycle")
    @Operation(
        summary = "Record a key-lifecycle event for an issued signing certificate",
        description = """
            eventType SIGNED {certSerial, issuerDn, digestHex, signatureBase64}:
            the signature is verified as POST /api/v1/verify verifies a
            settlement (SHA512withRSA over the digest, certificate stored at
            Step 7, registry status, validity), scoped to {countryCode}.
            Always 200; the answer is the settlement answer plus eventType,
            with a signed verdict.

            eventType ROTATED {certSerial, issuerDn, reason,
            successorVerificationId?}, REVOKED {certSerial, issuerDn, reason}
            and DECOMMISSIONED {certSerial, issuerDn, reason} move the
            registry entry to SUPERSEDED, REVOKED or DECOMMISSIONED. Allowed
            only from VERIFIED_AND_ISSUED, or from SUPERSEDED to REVOKED or
            DECOMMISSIONED. Afterwards the certificate no longer settles.

            Every event is appended to the audit log under its own operation
            label.""",
        responses = {
            @ApiResponse(responseCode = "200", description = "SIGNED verdict, or status change applied",
                content = @Content(schema = @Schema(oneOf = {SignedEventResponse.class,
                        KeyStatusChangeResponse.class}))),
            @ApiResponse(responseCode = "400", description = "Invalid body, or certSerial/issuerDn "
                    + "unparseable (MALFORMED_INPUT)"),
            @ApiResponse(responseCode = "404", description = "CERT_NOT_FOUND: no certificate stored at "
                    + "Step 7 for (certSerial, issuerDn) in this jurisdiction that the caller may change"),
            @ApiResponse(responseCode = "409", description = "TRANSITION_NOT_ALLOWED from the current "
                    + "status, or SUCCESSOR_NOT_FOUND")
        }
    )
    public ResponseEntity<?> lifecycle(@PathVariable String countryCode,
                                       @Valid @RequestBody KeyLifecycleRequest request) {
        String jurisdiction = countryCode.toUpperCase(Locale.ROOT);
        if (KeyLifecycleRequest.SIGNED.equals(request.getEventType())) {
            return ResponseEntity.ok(lifecycleService.signed(jurisdiction, request));
        }
        KeyStatusChangeResponse response = lifecycleService.changeStatus(jurisdiction, request);
        return ResponseEntity.status(httpStatus(response.getReason())).body(response);
    }

    static HttpStatus httpStatus(String reason) {
        return switch (reason) {
            case KeyLifecycleService.REASON_OK -> HttpStatus.OK;
            case KeyLifecycleService.REASON_CERT_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case KeyLifecycleService.REASON_MALFORMED_INPUT -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.CONFLICT;
        };
    }
}
