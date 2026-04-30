package eu.gillstrom.gatekeeper.verification;

import org.junit.jupiter.api.Test;
import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class YubicoVerifierTest {

    @Test
    void chainNotRootedAtPinnedYubicoRootIsRejected() throws Exception {
        YubicoVerifier verifier = new YubicoVerifier();

        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate fakeRoot = TestPki.selfSignedCa(rootKp, "FAKE-YUBICO-ROOT");

        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate deviceCert = TestPki.subordinateCa(
                deviceKp, "YubiHSM Attestation (FAKE1234)", fakeRoot, rootKp.getPrivate());

        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = TestPki.endEntity(
                leafKp, "FAKE-YUBI-ATTEST", deviceCert, deviceKp.getPrivate());

        List<String> chainPem = List.of(
                TestPki.toPem(attestCert),
                TestPki.toPem(deviceCert),
                TestPki.toPem(fakeRoot));

        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(chainPem, leafKp.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("chain"));
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void emptyChainIsRejected() {
        YubicoVerifier verifier = new YubicoVerifier();
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(java.util.Collections.emptyList(), null);

        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("no certificates"));
        assertThat(r.isValid()).isFalse();
    }
}
