package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Locks the canonical bytes of a signed confirmation response. The {@code hsm}
 * repository's {@code ConfirmationCanonicalizerGoldenBytesTest} carries the
 * identical literal; a change on one side must be made on both.
 */
class ConfirmationCanonicalizerGoldenBytesTest {

    static final String EXPECTED_GOLDEN =
            "c1|test-vid|false|false|aa:bb|cc:dd|ANOMALY_PUBLIC_KEY_MISMATCH|2026-10-06T00:00:00Z|"
            + "first%3B anomaly;pipe %7C and %25";

    @Test
    void canonicalBytesMatchTheGoldenLiteral() {
        IssuanceConfirmationResponse r = IssuanceConfirmationResponse.builder()
                .verificationId("test-vid")
                .loopClosed(false)
                .publicKeyMatch(false)
                .expectedPublicKeyFingerprint("aa:bb")
                .actualPublicKeyFingerprint("cc:dd")
                .registryStatus(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH)
                .processedTimestamp("2026-10-06T00:00:00Z")
                .anomalies(List.of("first; anomaly", "pipe | and %"))
                .signature("ignored")
                .signingCertificate("ignored")
                .build();

        assertThat(new String(ConfirmationCanonicalizer.canonicalize(r), StandardCharsets.UTF_8))
                .isEqualTo(EXPECTED_GOLDEN);
    }

    @Test
    void absentPublicKeyMatchAndAnomaliesRenderEmpty() {
        IssuanceConfirmationResponse r = IssuanceConfirmationResponse.builder()
                .verificationId("v").loopClosed(true)
                .registryStatus(RegistryStatus.VERIFIED_NOT_ISSUED)
                .processedTimestamp("t").build();

        assertThat(new String(ConfirmationCanonicalizer.canonicalize(r), StandardCharsets.UTF_8))
                .isEqualTo("c1|v|true||||VERIFIED_NOT_ISSUED|t|");
    }
}
