package eu.gillstrom.gatekeeper.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThat;

class FingerprintsTest {

    @Test
    void theFingerprintIsTheColonSeparatedLowerCaseSha256() {
        // SHA-256("abc"), FIPS 180-2 Appendix B.1.
        assertThat(Fingerprints.ofSubjectPublicKeyInfo("abc".getBytes(StandardCharsets.US_ASCII)))
                .isEqualTo("ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:"
                        + "b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad");
    }

    @Test
    void aPublicKeyIsFingerprintedOverItsSubjectPublicKeyInfo() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        PublicKey key = generator.generateKeyPair().getPublic();

        assertThat(Fingerprints.ofPublicKey(key))
                .isEqualTo(Fingerprints.ofSubjectPublicKeyInfo(key.getEncoded()))
                .hasSize(32 * 3 - 1);
    }
}
