package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AzureHsmVerifier} on synthetic attestations in the
 * {@code az keyvault key get-attestation} shape, under a throwaway Marvell
 * root passed to the test constructor.
 */
class AzureHsmVerifierTest {

    private static final String KEY_ID = "https://pool.managedhsm.azure.net/keys/swish/0123abcd";

    private final ObjectMapper mapper = new ObjectMapper();
    private KeyPair rootKp;
    private X509Certificate root;
    private KeyPair cardKp;
    private X509Certificate card;
    private KeyPair partitionKp;
    private X509Certificate partition;
    private KeyPair hsmKey;

    @BeforeEach
    void pki() throws Exception {
        rootKp = TestPki.newRsaKeyPair(2048);
        root = TestPki.selfSignedCa(rootKp, "TEST-MARVELL-ROOT");
        cardKp = TestPki.newRsaKeyPair(2048);
        card = TestPki.subordinateCa(cardKp, "TEST-CARD", root, rootKp.getPrivate());
        partitionKp = TestPki.newRsaKeyPair(2048);
        partition = TestPki.endEntity(partitionKp, "TEST-PARTITION", card, cardKp.getPrivate());
        hsmKey = TestPki.newRsaKeyPair(2048);
    }

    private RSAPublicKey key() {
        return (RSAPublicKey) hsmKey.getPublic();
    }

    @Test
    @DisplayName("A genuine-shaped attestation of the CSR key verifies once the format gate is open")
    void validAttestationVerifies() throws Exception {
        AzureHsmVerifier.AzureAttestationResult r = new AzureHsmVerifier(List.of(root), true)
                .verifyAzureAttestation(json(MarvellBlobs.privateKey(key(), KEY_ID), MarvellBlobs.publicKey(key(), KEY_ID)),
                        hsmKey.getPublic());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.isExportable()).isFalse();
        assertThat(r.getKeyName()).isEqualTo("swish");
        assertThat(r.getKeyVersion()).isEqualTo("0123abcd");
    }

    @Test
    @DisplayName("While the format is unconfirmed, the same attestation is never valid")
    void unconfirmedFormatIsNeverValid() throws Exception {
        AzureHsmVerifier.AzureAttestationResult r = new AzureHsmVerifier(List.of(root), false)
                .verifyAzureAttestation(json(MarvellBlobs.privateKey(key(), KEY_ID), MarvellBlobs.publicKey(key(), KEY_ID)),
                        hsmKey.getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_FORMAT_UNCONFIRMED"));
        assertThat(MarvellAttestation.FORMAT_CONFIRMED_BY_REAL_SAMPLE).isFalse();
    }

    @Test
    @DisplayName("The unsigned JWK in the JSON does not bind the attestation to the CSR key")
    void jwkNamingTheCsrKeyIsNotABinding() throws Exception {
        KeyPair csr = TestPki.newRsaKeyPair(2048);
        ObjectNode root = (ObjectNode) mapper.readTree(json(
                MarvellBlobs.privateKey(key(), KEY_ID), MarvellBlobs.publicKey(key(), KEY_ID)));
        RSAPublicKey k = (RSAPublicKey) csr.getPublic();
        ObjectNode jwk = root.putObject("key");
        jwk.put("kty", "RSA");
        jwk.put("n", Base64.getUrlEncoder().withoutPadding().encodeToString(k.getModulus().toByteArray()));
        jwk.put("e", Base64.getUrlEncoder().withoutPadding().encodeToString(k.getPublicExponent().toByteArray()));

        AzureHsmVerifier.AzureAttestationResult r = new AzureHsmVerifier(List.of(root()), true)
                .verifyAzureAttestation(mapper.writeValueAsString(root), csr.getPublic());

        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_PUBLIC_KEY_MISMATCH"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    @DisplayName("A bundle under another root fails against the pinned Marvell roots")
    void chainNotUnderPinnedRootIsRejected() throws Exception {
        AzureHsmVerifier.AzureAttestationResult r = new AzureHsmVerifier()
                .verifyAzureAttestation(json(MarvellBlobs.privateKey(key(), KEY_ID), null), hsmKey.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_CHAIN_INVALID"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    @DisplayName("An attestation signed by a key other than the partition's is refused")
    void otherSignerIsRefused() throws Exception {
        KeyPair stranger = TestPki.newRsaKeyPair(2048);
        String json = json(MarvellBlobs.signed(MarvellBlobs.privateKey(key(), KEY_ID).fw3Data(), stranger.getPrivate()), null);

        AzureHsmVerifier.AzureAttestationResult r = new AzureHsmVerifier(List.of(root), true)
                .verifyAzureAttestation(json, hsmKey.getPublic());

        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_SIGNATURE_INVALID"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    @DisplayName("Missing fields and unknown versions are refused")
    void incompleteOrUnknownVersionIsRefused() throws Exception {
        AzureHsmVerifier v = new AzureHsmVerifier(List.of(root), true);
        assertThat(v.verifyAzureAttestation("{}", hsmKey.getPublic()).getErrors())
                .anyMatch(e -> e.startsWith("AZURE_ATTESTATION_INCOMPLETE"));

        ObjectNode n = (ObjectNode) mapper.readTree(json(MarvellBlobs.privateKey(key(), KEY_ID), null));
        ((ObjectNode) n.get("attributes").get("attestation")).put("version", "MRVL-2");
        AzureHsmVerifier.AzureAttestationResult r = v.verifyAzureAttestation(mapper.writeValueAsString(n), hsmKey.getPublic());
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("AZURE_ATTESTATION_VERSION_UNSUPPORTED"));
        assertThat(r.isValid()).isFalse();
    }

    private X509Certificate root() {
        return root;
    }

    private String json(MarvellBlobs priv, MarvellBlobs pub) throws Exception {
        return json(MarvellBlobs.signed(priv.fw3Data(), partitionKp.getPrivate()),
                pub == null ? null : MarvellBlobs.signed(pub.fw3Data(), partitionKp.getPrivate()));
    }

    private String json(byte[] priv, byte[] pub) throws Exception {
        Base64.Encoder url = Base64.getUrlEncoder().withoutPadding();
        String pem = TestPki.toPem(partition) + TestPki.toPem(card) + TestPki.toPem(root);
        ObjectNode out = mapper.createObjectNode();
        ObjectNode att = out.putObject("attributes").putObject("attestation");
        att.put("version", "MRVL-1");
        att.put("certificatePemFile", url.encodeToString(pem.getBytes(StandardCharsets.US_ASCII)));
        att.put("privateKeyAttestation", url.encodeToString(priv));
        if (pub == null) {
            att.putNull("publicKeyAttestation");
        } else {
            att.put("publicKeyAttestation", url.encodeToString(pub));
        }
        return mapper.writeValueAsString(out);
    }
}
