package eu.gillstrom.gatekeeper.verification;

import org.junit.jupiter.api.Test;
import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GoogleCloudHsmVerifierTest {

    @Test
    void chainNotRootedAtPinnedTrustAnchorIsRejected() throws Exception {
        GoogleCloudHsmVerifier verifier = new GoogleCloudHsmVerifier();

        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate fakeRoot = TestPki.selfSignedCa(rootKp, "FAKE-MARVELL-ROOT");

        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate deviceCert = TestPki.subordinateCa(
                deviceKp, "FAKE-CAVIUM-DEVICE", fakeRoot, rootKp.getPrivate());

        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = TestPki.endEntity(
                leafKp, "FAKE-GOOGLE-ATTEST", deviceCert, deviceKp.getPrivate());

        List<String> chainPem = List.of(
                TestPki.toPem(attestCert),
                TestPki.toPem(deviceCert),
                TestPki.toPem(fakeRoot));

        byte[] blob = new byte[512];
        String blobB64 = Base64.getEncoder().encodeToString(blob);

        GoogleCloudHsmVerifier.GoogleAttestationResult r =
                verifier.verifyGoogleAttestation(blobB64, chainPem, leafKp.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("chain"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void emptyChainIsRejected() {
        GoogleCloudHsmVerifier verifier = new GoogleCloudHsmVerifier();
        byte[] blob = new byte[16];
        String blobB64 = Base64.getEncoder().encodeToString(blob);

        GoogleCloudHsmVerifier.GoogleAttestationResult r =
                verifier.verifyGoogleAttestation(blobB64, java.util.Collections.emptyList(), null);

        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("no certificates"));
        assertThat(r.isValid()).isFalse();
    }
}
