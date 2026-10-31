package eu.gillstrom.gatekeeper.model;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The bank entry's rule that certSerial and issuerDn come together or not at all. */
class TriangulationBankReportTest {

    private static final String ISSUER = "CN=Swish Customer CA1 v2 for Swish,O=Getswish AB,C=SE";

    private static TriangulationBankReport.Entry entry(String certSerial, String issuerDn) {
        return TriangulationBankReport.Entry.builder().organisationNumber("5569743098").swishNumber("1231015932")
                .certSerial(certSerial).issuerDn(issuerDn).build();
    }

    @Test
    void certificateFieldsComeTogetherOrNotAtAll() {
        assertThat(entry(null, null).isCertificateFieldsTogether()).isTrue();
        assertThat(entry("0xab", ISSUER).isCertificateFieldsTogether()).isTrue();
        assertThat(entry("0xab", null).isCertificateFieldsTogether()).isFalse();
        assertThat(entry(null, ISSUER).isCertificateFieldsTogether()).isFalse();
    }

    @Test
    void theRuleIsEnforcedByBeanValidation() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            assertThat(validator.validate(entry("0xab", ISSUER))).isEmpty();
            assertThat(validator.validate(entry("0xab", null)))
                    .extracting(v -> v.getMessage())
                    .containsExactly("certSerial and issuerDn are given together or not at all");
        }
    }
}
