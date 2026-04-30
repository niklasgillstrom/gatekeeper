package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class AzureHsmVerifierTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void chainNotRootedAtPinnedTrustAnchorIsRejected() throws Exception {
        AzureHsmVerifier verifier = new AzureHsmVerifier();

        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate fakeRoot = TestPki.selfSignedCa(rootKp, "FAKE-MARVELL-ROOT-AZURE");

        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate deviceCert = TestPki.subordinateCa(
                deviceKp, "FAKE-MICROSOFT-BRIDGE", fakeRoot, rootKp.getPrivate());

        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = TestPki.endEntity(
                leafKp, "FAKE-AZURE-ATTEST", deviceCert, deviceKp.getPrivate());

        ObjectNode root = mapper.createObjectNode();
        ArrayNode certs = root.putArray("certificates");
        certs.add(TestPki.toPem(attestCert));
        certs.add(TestPki.toPem(deviceCert));
        certs.add(TestPki.toPem(fakeRoot));

        byte[] blob = new byte[512];
        root.put("attestation", Base64.getEncoder().encodeToString(blob));

        String json = mapper.writeValueAsString(root);

        AzureHsmVerifier.AzureAttestationResult r =
                verifier.verifyAzureAttestation(json, leafKp.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("chain"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void missingCertificatesFieldIsRejected() throws Exception {
        AzureHsmVerifier verifier = new AzureHsmVerifier();
        String json = mapper.writeValueAsString(mapper.createObjectNode()
                .put("attestation", Base64.getEncoder().encodeToString(new byte[16])));

        AzureHsmVerifier.AzureAttestationResult r =
                verifier.verifyAzureAttestation(json, null);

        assertThat(r.getErrors()).isNotEmpty();
        assertThat(r.isValid()).isFalse();
    }
}
