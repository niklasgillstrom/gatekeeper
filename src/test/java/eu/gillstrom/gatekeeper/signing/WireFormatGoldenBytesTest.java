package eu.gillstrom.gatekeeper.signing;

import org.junit.jupiter.api.Test;
import eu.gillstrom.gatekeeper.model.VerificationResponse;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-repo wire-format compatibility test for the supervisory gatekeeper.
 *
 * <p>Locks the canonical byte representation of {@link VerificationResponse}
 * to a hardcoded golden string. The sibling repository
 * {@code hsm} carries a structurally identical test
 * (see {@code eu.gillstrom.hsm.gatekeeper.WireFormatGoldenBytesTest}) that builds
 * an {@code VerifyResponse} from the same fixed values and asserts the
 * same golden bytes.
 *
 * <p>If anyone ever changes field ordering, the separator, the version
 * marker, the escape rules, the boolean rendering, or the timestamp format,
 * the resulting drift between the gatekeeper's signed canonical bytes and
 * the financial entity's locally-computed canonical bytes would silently
 * break signature verification across the wire. This test makes such drift
 * impossible to land: the same hardcoded literal lives on both sides of the
 * wire and the test fails the moment they no longer agree.
 *
 * <p>Three properties are locked:
 * <ol>
 *   <li>The golden-bytes shape — byte-identical to the financial entity
 *       repo's {@code WireFormatGoldenBytesTest} and to the canonical form
 *       described in {@link ReceiptCanonicalizer}'s Javadoc.</li>
 *   <li>The escape rule for {@code |} (percent-encoded as {@code %7C}) and
 *       {@code %} (percent-encoded as {@code %25}) — escaping the percent
 *       sign first keeps the encoding reversible.</li>
 *   <li>The null-field rendering — null string fields render as the empty
 *       string with no NullPointerException; a null
 *       {@code verificationTimestamp} also renders as empty.</li>
 * </ol>
 *
 * <p>Note on key-property semantics: this test deliberately uses
 * {@code exportable=true} alongside the other key-property bits as
 * {@code true}. That combination is non-sensical from a compliance
 * standpoint (a compliant key is non-exportable), but the test exists
 * purely to lock the wire format, not to assert business rules.
 */
class WireFormatGoldenBytesTest {

    /**
     * The exact canonical-bytes form for the locked-down fixed-value receipt
     * below. Any future change to {@link ReceiptCanonicalizer} that breaks
     * byte-identity with the financial entity repo will break this assertion.
     * The financial entity repo's {@code WireFormatGoldenBytesTest} carries
     * an identical literal — keep them in lockstep.
     */
    private static final String EXPECTED_GOLDEN =
            "v3|test-uuid|test-nonce|true|2026-04-27T00:00:00Z|aa:bb|RSA|YUBICO|YubiHSM 2|"
            + "20783176|5569743098|1231015932|5566778899|9871234567|Test|signing|SE|"
            + "true|true|true|true|"
            + "true|true|true|true|true|true";

    private static VerificationResponse fixedReceipt() {
        return VerificationResponse.builder()
                .verificationId("test-uuid")
                // Fixed nonce, not a generated one: the position of this
                // field in the canonical form is exactly what the golden
                // literal has to lock, and a receipt whose nonce is empty
                // would not lock it.
                .confirmationNonce("test-nonce")
                .compliant(true)
                .verificationTimestamp(Instant.parse("2026-04-27T00:00:00Z"))
                .publicKeyFingerprint("aa:bb")
                .publicKeyAlgorithm("RSA")
                .hsmVendor("YUBICO")
                .hsmModel("YubiHSM 2")
                .hsmSerialNumber("20783176")
                .customerOrganisationNumber("5569743098")
                .customerSwishNumber("1231015932")
                .supplierIdentifier("5566778899")
                .supplierNumber("9871234567")
                .supplierName("Test")
                .keyPurpose("signing")
                .countryCode("SE")
                .keyProperties(VerificationResponse.KeyProperties.builder()
                        .generatedOnDevice(true)
                        .exportable(true)
                        .attestationChainValid(true)
                        .publicKeyMatchesAttestation(true)
                        .build())
                .doraCompliance(VerificationResponse.DoraCompliance.builder()
                        .article5_2b(true)
                        .article6_10(true)
                        .article9_3c(true)
                        .article9_3d(true)
                        .article9_4d(true)
                        .article28_1a(true)
                        .summary("test")
                        .build())
                .build();
    }

    @Test
    void canonicalizerGoldenBytesMatchSpec() {
        byte[] actualBytes = ReceiptCanonicalizer.canonicalize(fixedReceipt());

        assertThat(new String(actualBytes, StandardCharsets.UTF_8))
                .as("canonical wire string must equal the cross-repo golden literal; "
                    + "the sibling hsm repo's "
                    + "WireFormatGoldenBytesTest carries the same string and any "
                    + "drift breaks signature verification")
                .isEqualTo(EXPECTED_GOLDEN);

        assertThat(actualBytes)
                .as("canonical bytes must equal the UTF-8 encoding of the golden literal")
                .isEqualTo(EXPECTED_GOLDEN.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void canonicalizerEscapesPipeAndPercent() {
        VerificationResponse r = VerificationResponse.builder()
                .verificationId("test-uuid")
                .compliant(true)
                .verificationTimestamp(Instant.parse("2026-04-27T00:00:00Z"))
                .publicKeyFingerprint("aa:bb")
                .publicKeyAlgorithm("RSA")
                .hsmVendor("YUBICO")
                .hsmModel("YubiHSM 2")
                .hsmSerialNumber("20783176")
                .supplierIdentifier("5569743098")
                .supplierName("100%test")
                .keyPurpose("test|with|pipes")
                .countryCode("SE")
                .keyProperties(VerificationResponse.KeyProperties.builder()
                        .generatedOnDevice(true)
                        .exportable(false)
                        .attestationChainValid(true)
                        .publicKeyMatchesAttestation(true)
                        .build())
                .doraCompliance(VerificationResponse.DoraCompliance.builder()
                        .article5_2b(true)
                        .article6_10(true)
                        .article9_3c(true)
                        .article9_3d(true)
                        .article9_4d(true)
                        .article28_1a(true)
                        .build())
                .build();

        String s = new String(ReceiptCanonicalizer.canonicalize(r), StandardCharsets.UTF_8);

        // | -> %7C — pipes inside a field cannot desynchronise the canonical form.
        assertThat(s)
                .as("literal pipe in keyPurpose must be percent-encoded as %7C")
                .contains("test%7Cwith%7Cpipes");
        // % -> %25 — escaping the percent sign first keeps the encoding reversible.
        assertThat(s)
                .as("literal percent in supplierName must be percent-encoded as %25")
                .contains("100%25test");
        // No raw pipe inside the supplied field survives.
        assertThat(s.indexOf("test|with|pipes")).isEqualTo(-1);
    }

    @Test
    void canonicalizerNullFieldsRenderAsEmpty() {
        VerificationResponse r = VerificationResponse.builder()
                .verificationId("v1-uuid")
                .compliant(false)
                .verificationTimestamp(null)
                // every other field deliberately null — including keyProperties and doraCompliance
                .build();

        String s = new String(ReceiptCanonicalizer.canonicalize(r), StandardCharsets.UTF_8);

        // verificationId set, confirmationNonce null -> empty,
        // compliant=false, verificationTimestamp null -> empty.
        assertThat(s)
                .as("null confirmationNonce and null verificationTimestamp both render as empty")
                .startsWith("v3|v1-uuid||false||");

        // After v3, verificationId, the empty nonce, compliant, and the empty
        // timestamp field, 22 further fields (12 string fields + 4 keyProperty
        // bits + 6 DORA article bits) are all empty. Total 27 canonical cells,
        // 26 separators. We assert the full deterministic output rather than
        // just a prefix so a future change that accidentally inserts a
        // non-empty default is caught.
        String expectedAllNull = "v3|v1-uuid||false" + "|".repeat(23);
        assertThat(s)
                .as("entire canonical form when only verificationId and compliant are set "
                    + "must be the version marker, the verificationId, an empty nonce, the "
                    + "boolean, an empty timestamp, and 22 further empty fields (26 "
                    + "separators total)")
                .isEqualTo(expectedAllNull);
    }

    /** The 1.4.0–1.5.0 literal, byte for byte, for the same receipt without the 1.6.0 fields. */
    private static final String V2_GOLDEN =
            "v2|test-uuid|test-nonce|true|2026-04-27T00:00:00Z|aa:bb|RSA|YUBICO|YubiHSM 2|"
            + "20783176|5566778899|Test|signing|SE|"
            + "true|true|true|true|"
            + "true|true|true|true|true|true";

    @Test
    void thePreviousVersionIsTheFormReleasesBefore160Signed() {
        assertThat(new String(ReceiptCanonicalizer.canonicalize(fixedReceipt(), ReceiptCanonicalizer.PREVIOUS_VERSION),
                StandardCharsets.UTF_8)).isEqualTo(V2_GOLDEN);
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> ReceiptCanonicalizer.canonicalize(fixedReceipt(), "v4"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
