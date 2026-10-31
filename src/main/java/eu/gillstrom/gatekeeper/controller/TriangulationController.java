package eu.gillstrom.gatekeeper.controller;

import eu.gillstrom.gatekeeper.model.TriangulationBankReport;
import eu.gillstrom.gatekeeper.model.TriangulationInquiryResponse;
import eu.gillstrom.gatekeeper.model.TriangulationOperatorReport;
import eu.gillstrom.gatekeeper.model.TriangulationReport;
import eu.gillstrom.gatekeeper.model.TriangulationSubmissionResponse;
import eu.gillstrom.gatekeeper.service.TriangulationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Data triangulation inquiries, {@code SUPERVISOR} only under mTLS. See
 * {@link TriangulationService} for the procedure and
 * {@link TriangulationReport} for the report.
 *
 * <p>A refusal is answered with its HTTP status and a body
 * {@code {"reason": <code>, "message": <text>}}: 404
 * {@code INQUIRY_NOT_FOUND}; 409 {@code INQUIRY_CAP_REACHED},
 * {@code ENTRY_CAP_REACHED}, {@code BANK_PHASE_CLOSED},
 * {@code OPERATOR_MISMATCH}; 400 {@code MALFORMED_INPUT}. A body that fails
 * bean validation is 400 before it reaches the service.</p>
 */
@RestController
@RequestMapping("/v1/triangulation")
@Tag(name = "Data Triangulation",
     description = "Compare bank reports, the operator report and the approval registry; "
         + "the discrepancy report is deterministic, signed and audited.")
public class TriangulationController {

    private final TriangulationService triangulationService;

    public TriangulationController(TriangulationService triangulationService) {
        this.triangulationService = triangulationService;
    }

    @PostMapping("/{countryCode}/inquiries")
    @Operation(summary = "Open a triangulation inquiry",
        description = "Returns 201 with the inquiryId. Inquiries are held in memory, at most "
                + "gatekeeper.triangulation.max-inquiries at a time.")
    public ResponseEntity<TriangulationInquiryResponse> createInquiry(@PathVariable String countryCode) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(triangulationService.createInquiry(upper(countryCode)));
    }

    @PostMapping("/{countryCode}/inquiries/{inquiryId}/bank-reports")
    @Operation(summary = "Submit a bank's report (or a further part of it)",
        description = "Body {bankId, entries:[{organisationNumber, swishNumber, certSerial?, issuerDn?}]}. "
                + "Several banks may report; parts from one bankId accumulate. Refused with 409 "
                + "BANK_PHASE_CLOSED once the operator has reported.")
    public ResponseEntity<TriangulationSubmissionResponse> bankReport(@PathVariable String countryCode,
                                                                      @PathVariable String inquiryId,
                                                                      @Valid @RequestBody TriangulationBankReport report) {
        return ResponseEntity.ok(triangulationService.addBankReport(upper(countryCode), inquiryId, report));
    }

    @PostMapping("/{countryCode}/inquiries/{inquiryId}/operator-report")
    @Operation(summary = "Submit the operator's report (or a further part of it)",
        description = "Body {operatorId, entries:[{swishNumber, organisationNumber?, certSerial, issuerDn}]}. "
                + "One operator per inquiry; parts accumulate.")
    public ResponseEntity<TriangulationSubmissionResponse> operatorReport(@PathVariable String countryCode,
                                                                          @PathVariable String inquiryId,
                                                                          @Valid @RequestBody TriangulationOperatorReport report) {
        return ResponseEntity.ok(triangulationService.addOperatorReport(upper(countryCode), inquiryId, report));
    }

    @GetMapping("/{countryCode}/inquiries/{inquiryId}/discrepancies")
    @Operation(summary = "Signed discrepancy report",
        description = "Compares the reports with the registry as it stands, signs the sorted report and "
                + "appends a TRIANGULATION audit entry (compliant=true iff zero discrepancies).")
    public ResponseEntity<TriangulationReport> discrepancies(@PathVariable String countryCode,
                                                             @PathVariable String inquiryId) {
        return ResponseEntity.ok(triangulationService.discrepancies(upper(countryCode), inquiryId));
    }

    @DeleteMapping("/{countryCode}/inquiries/{inquiryId}")
    @Operation(summary = "Discard an inquiry and the reports it holds",
        description = "Frees a place under the inquiry cap. Reports already generated stay in the audit log.")
    public ResponseEntity<Void> deleteInquiry(@PathVariable String countryCode, @PathVariable String inquiryId) {
        triangulationService.deleteInquiry(upper(countryCode), inquiryId);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(TriangulationService.Rejection.class)
    public ResponseEntity<Map<String, String>> rejected(TriangulationService.Rejection rejection) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("reason", rejection.reason());
        body.put("message", rejection.getMessage());
        return ResponseEntity.status(rejection.status()).body(body);
    }

    private static String upper(String countryCode) {
        return countryCode.toUpperCase(Locale.ROOT);
    }
}
