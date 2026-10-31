package eu.gillstrom.gatekeeper.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
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
 * One bank's report to a triangulation inquiry:
 * {@code POST /v1/triangulation/{countryCode}/inquiries/{inquiryId}/bank-reports}.
 * Each entry is an active customer agreement: the customer's organisation
 * number and Swish number, and optionally the signing certificate's serial
 * and issuer DN.
 *
 * <p>Organisation and Swish numbers are validated with the patterns of
 * {@link VerificationRequest}: 10 or 12 digits, and {@code 123} followed by
 * 7 digits. {@code certSerial} is hexadecimal with an optional {@code 0x};
 * {@code certSerial} and {@code issuerDn} are given together or not at
 * all.</p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TriangulationBankReport {

    /** Same pattern as {@link VerificationRequest#getCustomerOrganisationNumber()}. */
    public static final String ORGANISATION_NUMBER_PATTERN = "^\\d{10}(\\d{2})?$";

    /** Same pattern as {@link VerificationRequest#getCustomerSwishNumber()}. */
    public static final String SWISH_NUMBER_PATTERN = "^123\\d{7}$";

    /** Hexadecimal certificate serial, optional {@code 0x}/{@code 0X}. */
    public static final String CERT_SERIAL_PATTERN = "^(0[xX])?[0-9A-Fa-f]{1,128}$";

    /** Entries accepted in one submission; a larger report is sent in several. */
    public static final int MAX_ENTRIES_PER_SUBMISSION = 50_000;

    @NotBlank
    @Size(max = 128, message = "bankId exceeds the maximum accepted length")
    private String bankId;

    @NotNull
    @Size(max = MAX_ENTRIES_PER_SUBMISSION, message = "entries exceeds the maximum per submission")
    private List<@NotNull @Valid Entry> entries;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Entry {

        @NotBlank
        @Pattern(regexp = ORGANISATION_NUMBER_PATTERN, message = "organisationNumber must be 10 or 12 digits")
        private String organisationNumber;

        @NotBlank
        @Pattern(regexp = SWISH_NUMBER_PATTERN, message = "swishNumber must be 123 followed by 7 digits")
        private String swishNumber;

        @Pattern(regexp = CERT_SERIAL_PATTERN, message = "certSerial must be hexadecimal")
        private String certSerial;

        @Size(min = 1, max = 512, message = "issuerDn must be 1 to 512 characters")
        private String issuerDn;

        /** Both certificate fields, or neither. */
        @JsonIgnore
        @AssertTrue(message = "certSerial and issuerDn are given together or not at all")
        public boolean isCertificateFieldsTogether() {
            return (certSerial == null) == (issuerDn == null);
        }
    }
}
