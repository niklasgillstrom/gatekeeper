package eu.gillstrom.gatekeeper.signing;

import org.junit.jupiter.api.Test;
import eu.gillstrom.gatekeeper.model.VerificationResponse;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ReceiptCanonicalizer}. The canonical form is a UTF-8
 * string prefixed with {@code v2|} and any mutation of a decision-relevant
 * field must produce a different byte array.
 */
class ReceiptCanonicalizerTest {

    private VerificationResponse sampleReceipt(boolean compliant) {
        return sampleReceipt(compliant, "nonce-0001");
    }

    private VerificationResponse sampleReceipt(boolean compliant, String confirmationNonce) {
        return VerificationResponse.builder()
                .verificationId("vid-0001")
                .confirmationNonce(confirmationNonce)
                .compliant(compliant)
                .verificationTimestamp(Instant.parse("2026-01-01T00:00:00Z"))
                .publicKeyFingerprint("sha256:abcd")
                .publicKeyAlgorithm("RSA")
                .hsmVendor("SECUROSYS")
                .hsmModel("Primus HSM")
                .hsmSerialNumber("SN12345")
                .supplierIdentifier("supplier-1")
                .supplierName("Supplier AB")
                .keyPurpose("signing")
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
                        .summary("All articles satisfied")
                        .build())
                .build();
    }

    @Test
    void canonicalBytesStartWithVersionPrefix() {
        byte[] canonical = ReceiptCanonicalizer.canonicalize(sampleReceipt(true));

        String asString = new String(canonical, StandardCharsets.UTF_8);
        assertThat(asString).startsWith("v3|");
        assertThat(canonical).isNotEmpty();
    }

    /**
     * The Step-7 confirmation nonce is delivered to the financial entity in
     * the receipt and nowhere else. Leaving it outside the signed bytes (as
     * canonical version {@code v1} did) let an intermediary substitute a
     * nonce of its own choosing on a receipt in transit without breaking
     * the signature.
     */
    @Test
    void mutatingConfirmationNonceChangesCanonicalBytes() {
        byte[] original = ReceiptCanonicalizer.canonicalize(sampleReceipt(true, "nonce-A"));
        byte[] substituted = ReceiptCanonicalizer.canonicalize(sampleReceipt(true, "nonce-B"));

        assertThat(original).isNotEqualTo(substituted);
        assertThat(new String(original, StandardCharsets.UTF_8)).contains("|nonce-A|");
        assertThat(new String(substituted, StandardCharsets.UTF_8)).contains("|nonce-B|");
    }

    @Test
    void mutatingCompliantFieldChangesCanonicalBytes() {
        byte[] compliantBytes = ReceiptCanonicalizer.canonicalize(sampleReceipt(true));
        byte[] nonCompliantBytes = ReceiptCanonicalizer.canonicalize(sampleReceipt(false));

        assertThat(compliantBytes).isNotEqualTo(nonCompliantBytes);
        assertThat(new String(compliantBytes, StandardCharsets.UTF_8))
                .contains("|true|");
        assertThat(new String(nonCompliantBytes, StandardCharsets.UTF_8))
                .contains("|false|");
    }

    @Test
    void nullReceiptThrows() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> ReceiptCanonicalizer.canonicalize(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void pipeCharactersInFieldsAreEscaped() {
        VerificationResponse r = VerificationResponse.builder()
                .verificationId("contains|pipe")
                .compliant(true)
                .verificationTimestamp(Instant.parse("2026-01-01T00:00:00Z"))
                .build();

        String canonical = new String(
                ReceiptCanonicalizer.canonicalize(r), StandardCharsets.UTF_8);

        // The literal pipe inside the verificationId must not appear as a
        // raw separator — it must be %7C-encoded.
        assertThat(canonical).contains("contains%7Cpipe");
    }
}
