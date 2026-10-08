package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeAll;
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
 * The remaining branches of {@link AzureHsmVerifier}: the interface methods,
 * {@code verifyChain}, private-key-only attestations, the key identifier and
 * malformed input, on synthetic attestations under a throwaway Marvell root.
 * The production format gate stays closed; tests that need a valid result use
 * the test constructor with the gate opened.
 */
class AzureHsmVerifierMutationTest {

    private static final String KEY_ID = "https://pool.managedhsm.azure.net/keys/swish/0123abcd";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static KeyPair rootKp;
    private static X509Certificate root;
    private static KeyPair cardKp;
    private static X509Certificate card;
    private static KeyPair partitionKp;
    private static X509Certificate partition;
    private static KeyPair hsmKey;

    @BeforeAll
    static void pki() throws Exception {
        rootKp = TestPki.newRsaKeyPair(2048);
        root = TestPki.selfSignedCa(rootKp, "TEST-MARVELL-ROOT");
        cardKp = TestPki.newRsaKeyPair(2048);
        card = TestPki.subordinateCa(cardKp, "TEST-CARD", root, rootKp.getPrivate());
        partitionKp = TestPki.newRsaKeyPair(2048);
        partition = TestPki.endEntity(partitionKp, "TEST-PARTITION", card, cardKp.getPrivate());
        hsmKey = TestPki.newRsaKeyPair(2048);
    }

    private static RSAPublicKey key() {
        return (RSAPublicKey) hsmKey.getPublic();
    }

    private static AzureHsmVerifier gateOpen() {
        return new AzureHsmVerifier(List.of(root), true);
    }

    @Test
    @DisplayName("Vendor is AZURE; the generic certificate path refuses; model and serial are reported")
    void interfaceMethods() {
        AzureHsmVerifier v = new AzureHsmVerifier();
        assertThat(v.getVendor()).isEqualTo(HsmVendor.AZURE);
        assertThat(v.verifyAttestation(partition, hsmKey.getPublic())).isFalse();
        assertThat(v.extractModel(partition)).isEqualTo("Azure Managed HSM");
        assertThat(v.extractSerialNumber(partition)).isEqualTo(partition.getSerialNumber().toString(16));
    }

    @Test
    @DisplayName("verifyChain accepts the partition certificate under a pinned root, and nothing else")
    void verifyChainRequiresThePartitionUnderAPinnedRoot() {
        AzureHsmVerifier v = new AzureHsmVerifier(List.of(root), false);
        assertThat(v.verifyChain(partition, new X509Certificate[] {card, root})).isTrue();
        assertThat(v.verifyChain(partition, null)).isFalse();
        assertThat(v.verifyChain(partition, new X509Certificate[0])).isFalse();
        assertThat(v.verifyChain(card, new X509Certificate[] {partition, root})).as("card as the leaf").isFalse();
        assertThat(new AzureHsmVerifier().verifyChain(partition, new X509Certificate[] {card, root}))
                .as("not under a pinned Marvell root").isFalse();
    }

    @Test
    @DisplayName("A private-key attestation alone is accepted, as Microsoft issues for asymmetric keys")
    void privateKeyAttestationAloneVerifies() throws Exception {
        AzureHsmVerifier.AzureAttestationResult r = gateOpen().verifyAzureAttestation(
                json(MarvellBlobs.privateKey(key(), KEY_ID), null), hsmKey.getPublic());
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.getHsmPool()).isEqualTo(KEY_ID);
        assertThat(r.getKeyName()).isEqualTo("swish");
        assertThat(r.getKeyVersion()).isEqualTo("0123abcd");

        AzureHsmVerifier.AzureAttestationResult gated = new AzureHsmVerifier(List.of(root), false)
                .verifyAzureAttestation(json(MarvellBlobs.privateKey(key(), KEY_ID), null), hsmKey.getPublic());
        assertThat(gated.isValid()).isFalse();
        assertThat(gated.getErrors()).containsExactly(MarvellAttestation.FORMAT_UNCONFIRMED_ERROR);
    }

    @Test
    @DisplayName("A public-key attestation not signed by the partition is refused even if the private one is")
    void publicKeyAttestationMustBeSignedToo() throws Exception {
        byte[] priv = MarvellBlobs.signed(MarvellBlobs.privateKey(key(), KEY_ID).fw3Data(), partitionKp.getPrivate());
        byte[] pub = MarvellBlobs.signed(MarvellBlobs.publicKey(key(), KEY_ID).fw3Data(),
                TestPki.newRsaKeyPair(2048).getPrivate());
        AzureHsmVerifier.AzureAttestationResult r = gateOpen().verifyAzureAttestation(json(priv, pub), hsmKey.getPublic());
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).containsExactly("MARVELL_SIGNATURE_INVALID: an attestation is not signed by the "
                + "Marvell-issued partition certificate");
    }

    @Test
    @DisplayName("Key name and version are the last two segments of the key identifier")
    void keyNameAndVersionFromTheIdentifier() throws Exception {
        AzureHsmVerifier.AzureAttestationResult two = gateOpen().verifyAzureAttestation(
                json(MarvellBlobs.privateKey(key(), "swish/v1"), null), hsmKey.getPublic());
        assertThat(two.getHsmPool()).isEqualTo("swish/v1");
        assertThat(two.getKeyName()).isEqualTo("swish");
        assertThat(two.getKeyVersion()).isEqualTo("v1");

        AzureHsmVerifier.AzureAttestationResult one = gateOpen().verifyAzureAttestation(
                json(MarvellBlobs.privateKey(key(), "swish"), null), hsmKey.getPublic());
        assertThat(one.getHsmPool()).isEqualTo("swish");
        assertThat(one.getKeyName()).isNull();
        assertThat(one.getKeyVersion()).isNull();
    }

    @Test
    @DisplayName("An extractable key is reported exportable and refused")
    void extractableKeyIsExportable() throws Exception {
        MarvellBlobs extractable = MarvellBlobs.privateKey(key(), KEY_ID)
                .put(MarvellAttestation.ATTR_EXTRACTABLE, new byte[] {1});
        AzureHsmVerifier.AzureAttestationResult r = gateOpen().verifyAzureAttestation(
                json(extractable, null), hsmKey.getPublic());
        assertThat(r.isExportable()).isTrue();
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_KEY_EXTRACTABLE"));
    }

    @Test
    @DisplayName("Input that is not JSON is refused as malformed without an exception")
    void malformedJsonIsRefused() {
        AzureHsmVerifier.AzureAttestationResult r = gateOpen().verifyAzureAttestation("{not json", hsmKey.getPublic());
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).singleElement()
                .satisfies(e -> assertThat(e).startsWith("MARVELL_ATTESTATION_MALFORMED: "));
    }

    private static String json(MarvellBlobs priv, MarvellBlobs pub) throws Exception {
        return json(MarvellBlobs.signed(priv.fw3Data(), partitionKp.getPrivate()),
                pub == null ? null : MarvellBlobs.signed(pub.fw3Data(), partitionKp.getPrivate()));
    }

    private static String json(byte[] priv, byte[] pub) throws Exception {
        Base64.Encoder url = Base64.getUrlEncoder().withoutPadding();
        String pem = TestPki.toPem(partition) + TestPki.toPem(card) + TestPki.toPem(root);
        ObjectNode out = MAPPER.createObjectNode();
        ObjectNode att = out.putObject("attributes").putObject("attestation");
        att.put("version", AzureHsmVerifier.SUPPORTED_VERSION);
        att.put("certificatePemFile", url.encodeToString(pem.getBytes(StandardCharsets.US_ASCII)));
        att.put("privateKeyAttestation", url.encodeToString(priv));
        if (pub != null) {
            att.put("publicKeyAttestation", url.encodeToString(pub));
        }
        return MAPPER.writeValueAsString(out);
    }
}
