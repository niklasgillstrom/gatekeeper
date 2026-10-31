package eu.gillstrom.gatekeeper.signing;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the {@code sv1} settlement-verdict canonical form. The railgate
 * repository pins the same literal; a change here is a wire-format change
 * that both repositories must make together.
 */
class SettlementVerdictCanonicalizerGoldenTest {

    private static final String DIGEST_UPPER = "AB".repeat(64);
    private static final String HASH = "a".repeat(64);

    @Test
    void theGoldenExampleIsExactlyThePinnedString() {
        String expected = "sv1|2026-10-30T12:00:00Z|c0ffee|CN=Example CA,O=Example Bank,C=SE|"
                + "ab".repeat(64) + "|true|false|A%7CB%25C|id-1|" + "a".repeat(64);

        String actual = SettlementVerdictCanonicalizer.canonicalString(
                "2026-10-30T12:00:00Z", "0x00C0FFEE", "CN=Example CA,O=Example Bank,C=SE", DIGEST_UPPER,
                true, false, "A|B%C", "id-1", HASH);

        assertThat(actual).isEqualTo(expected);
        assertThat(SettlementVerdictCanonicalizer.canonicalize(
                "2026-10-30T12:00:00Z", "0x00C0FFEE", "CN=Example CA,O=Example Bank,C=SE", DIGEST_UPPER,
                true, false, "A|B%C", "id-1", HASH))
                .isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void nullStringsRenderEmptyAndBooleansAsWords() {
        assertThat(SettlementVerdictCanonicalizer.canonicalString(
                null, "1", "CN=X", null, false, true, null, null, null))
                .isEqualTo("sv1||1|CN=X||false|true|||");
    }

    @Test
    void percentIsEscapedBeforeThePipeInEveryEscapedField() {
        assertThat(SettlementVerdictCanonicalizer.canonicalString(
                "t|%", "1", "CN=a|b%c", "", true, true, "%7C", "i|d", "h%"))
                .isEqualTo("sv1|t%7C%25|1|CN=a%7Cb%25c||true|true|%257C|i%7Cd|h%25");
    }

    @Test
    void theSerialLosesAnOptionalPrefixAndLeadingZerosAndIsLowerCase() {
        assertThat(SettlementVerdictCanonicalizer.normaliseSerial("0X00ABC")).isEqualTo("abc");
        assertThat(SettlementVerdictCanonicalizer.normaliseSerial("0001")).isEqualTo("1");
        assertThat(SettlementVerdictCanonicalizer.normaliseSerial("DEADbeef")).isEqualTo("deadbeef");
    }

    @Test
    void theIssuerIsRenderedInRfc2253Form() {
        assertThat(SettlementVerdictCanonicalizer.normaliseIssuerDn("CN=Example CA, O=Example Bank, C=SE"))
                .isEqualTo("CN=Example CA,O=Example Bank,C=SE");
    }

    @Test
    void fieldsThatCannotBeNormalisedAreRefused() {
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.normaliseSerial(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.normaliseSerial("0x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.normaliseSerial("not-hex"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.normaliseSerial(" c0ffee"))
                .as("nothing but the 0x prefix is stripped")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.normaliseIssuerDn(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.normaliseIssuerDn("not a distinguished name"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.normaliseDigestHex("abc"))
                .as("odd length").isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.normaliseDigestHex("ab|c"))
                .as("a digest that is not hex could carry a separator")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SettlementVerdictCanonicalizer.canonicalString(
                "t", "zz", "CN=X", "ab", true, true, "OK", "id", "h"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
