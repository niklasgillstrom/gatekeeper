package eu.gillstrom.gatekeeper.model;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * The payment-system operator's report to a triangulation inquiry:
 * {@code POST /v1/triangulation/{countryCode}/inquiries/{inquiryId}/operator-report}.
 * Each entry is an active Swish number with a certificate that can sign for
 * it: Swish number, optionally the organisation number, and the
 * certificate's serial and issuer DN.
 *
 * <p>Validated with the patterns of {@link TriangulationBankReport}.</p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TriangulationOperatorReport {

    @NotBlank
    @Size(max = 128, message = "operatorId exceeds the maximum accepted length")
    private String operatorId;

    @NotNull
    @Size(max = TriangulationBankReport.MAX_ENTRIES_PER_SUBMISSION,
          message = "entries exceeds the maximum per submission")
    private List<@NotNull @Valid Entry> entries;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Entry {

        @NotBlank
        @Pattern(regexp = TriangulationBankReport.SWISH_NUMBER_PATTERN,
                 message = "swishNumber must be 123 followed by 7 digits")
        private String swishNumber;

        @Pattern(regexp = TriangulationBankReport.ORGANISATION_NUMBER_PATTERN,
                 message = "organisationNumber must be 10 or 12 digits")
        private String organisationNumber;

        @NotBlank
        @Pattern(regexp = TriangulationBankReport.CERT_SERIAL_PATTERN, message = "certSerial must be hexadecimal")
        private String certSerial;

        @NotBlank
        @Size(max = 512, message = "issuerDn exceeds the maximum accepted length")
        private String issuerDn;
    }
}
