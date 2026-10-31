package eu.gillstrom.gatekeeper.verification;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/** {@code getRootCertificate()} of the two verifiers that validate a PKIX chain: the root they validate against. */
class VerifierRootCertificateTest {

    @Test
    void theRootCertificateIsThePinnedRootOrTheOneTheVerifierWasGiven() throws Exception {
        assertThat(new YubicoVerifier().getRootCertificate()).isEqualTo(YubicoVerifier.pinnedRoot());
        assertThat(new SecurosysVerifier().getRootCertificate()).isEqualTo(SecurosysVerifier.pinnedRoot());

        KeyPair keys = TrustAnchorsTest.rsa();
        X509Certificate other = TrustAnchorsTest.certificate("CN=Other Root", keys.getPublic(), "CN=Other Root",
                keys.getPrivate(), true);
        assertThat(new YubicoVerifier(other).getRootCertificate()).isSameAs(other);
        assertThat(new SecurosysVerifier(other).getRootCertificate()).isSameAs(other);
    }
}
