package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link MarvellHsmVerifier}: the {@link HsmAttestationVerifier} methods,
 * an empty or forged chain, an unreadable attestation, and every field of
 * the result, under a throwaway Marvell root passed to the test constructor.
 */
class MarvellHsmVerifierMutationTest {

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

    private MarvellHsmVerifier verifier() {
        return new MarvellHsmVerifier(List.of(root), true);
    }

    private List<String> chainPem() throws Exception {
        return List.of(TestPki.toPem(partition), TestPki.toPem(card));
    }

    private String attestation(MarvellBlobs priv) throws Exception {
        MarvellBlobs pub = MarvellBlobs.publicKey((RSAPublicKey) hsmKey.getPublic(), "k");
        return Base64.getEncoder().encodeToString(
                MarvellBlobs.signed(MarvellBlobs.fw3Data(pub, priv), partitionKp.getPrivate()));
    }

    private MarvellBlobs priv() throws Exception {
        return MarvellBlobs.privateKey((RSAPublicKey) hsmKey.getPublic(), "keys/k/1");
    }

    @Test
    @DisplayName("Vendor, model and serial; the X.509-only attestation check never passes")
    void verifierIdentity() {
        MarvellHsmVerifier v = verifier();
        assertThat(v.getVendor()).isEqualTo(HsmVendor.MARVELL);
        assertThat(v.extractModel(partition)).isEqualTo("Marvell LiquidSecurity");
        assertThat(v.extractSerialNumber(partition)).isEqualTo(partition.getSerialNumber().toString(16));
        assertThat(v.verifyAttestation(partition, hsmKey.getPublic())).isFalse();
    }

    @Test
    @DisplayName("verifyChain: the partition certificate under a pinned root through its card, and nothing else")
    void verifyChain() throws Exception {
        MarvellHsmVerifier v = verifier();
        assertThat(v.verifyChain(partition, new X509Certificate[] {card})).isTrue();
        assertThat(v.verifyChain(partition, new X509Certificate[] {card, root})).isTrue();

        assertThat(v.verifyChain(partition, null)).isFalse();
        assertThat(v.verifyChain(partition, new X509Certificate[0])).isFalse();
        // The chain is found, but its partition is not the certificate asked about.
        assertThat(v.verifyChain(card, new X509Certificate[] {partition})).isFalse();
        // Not under a pinned root.
        assertThat(new MarvellHsmVerifier().verifyChain(partition, new X509Certificate[] {card, root})).isFalse();
    }

    @Test
    @DisplayName("No certificate in the chain: refused before the attestation is read")
    void emptyChain() throws Exception {
        for (List<String> chain : Arrays.asList(null, List.<String>of(), Arrays.asList(null, " ", ""))) {
            MarvellHsmVerifier.MarvellAttestationResult r = verifier()
                    .verifyMarvellAttestation(attestation(priv()), chain, hsmKey.getPublic());
            assertThat(r.getErrors()).containsExactly("No certificates in chain");
            assertThat(r.isChainValid()).isFalse();
            assertThat(r.isValid()).isFalse();
            assertThat(r.isExtractable()).isTrue();
            assertThat(r.getKeyOrigin()).isEqualTo("unverified");
        }
    }

    @Test
    @DisplayName("A card that names the pinned root but is signed by another key does not make a chain")
    void forgedCard() throws Exception {
        KeyPair impostorKp = TestPki.newRsaKeyPair(2048);
        X509Certificate impostor = TestPki.selfSignedCa(impostorKp, "TEST-MARVELL-ROOT");
        X509Certificate forgedCard = TestPki.subordinateCa(cardKp, "TEST-CARD", impostor, impostorKp.getPrivate());
        X509Certificate forgedPartition = TestPki.endEntity(partitionKp, "TEST-PARTITION", forgedCard,
                cardKp.getPrivate());

        MarvellHsmVerifier.MarvellAttestationResult r = verifier().verifyMarvellAttestation(attestation(priv()),
                List.of(TestPki.toPem(forgedPartition), TestPki.toPem(forgedCard)), hsmKey.getPublic());
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_CHAIN_INVALID"));
        assertThat(verifier().verifyChain(forgedPartition, new X509Certificate[] {forgedCard})).isFalse();
    }

    @Test
    @DisplayName("An attestation that is not base64 or not a Marvell blob is reported as malformed")
    void malformedAttestation() throws Exception {
        for (String data : List.of("%%%", Base64.getEncoder().encodeToString(new byte[300]))) {
            MarvellHsmVerifier.MarvellAttestationResult r = verifier()
                    .verifyMarvellAttestation(data, chainPem(), hsmKey.getPublic());
            assertThat(r.isChainValid()).isTrue();
            assertThat(r.isSignatureValid()).isFalse();
            assertThat(r.isValid()).isFalse();
            assertThat(r.getErrors()).hasSize(1);
            assertThat(r.getErrors().get(0)).startsWith("MARVELL_ATTESTATION_MALFORMED: ");
        }
    }

    @Test
    @DisplayName("A valid attestation reports the key's identifier, size and flags")
    void validResultFields() throws Exception {
        MarvellHsmVerifier.MarvellAttestationResult r = verifier()
                .verifyMarvellAttestation(attestation(priv()), chainPem(), hsmKey.getPublic());
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isExtractable()).isFalse();
        assertThat(r.getKeyId()).isEqualTo("keys/k/1");
        assertThat(r.getKeySize()).isEqualTo(2048);
    }

    @Test
    @DisplayName("Another CSR key: no match, no key size, not valid")
    void otherCsrKey() throws Exception {
        MarvellHsmVerifier.MarvellAttestationResult r = verifier().verifyMarvellAttestation(
                attestation(priv()), chainPem(), TestPki.newRsaKeyPair(2048).getPublic());
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.getKeySize()).isZero();
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("An extractable key is reported as extractable and refused")
    void extractableKey() throws Exception {
        MarvellHsmVerifier.MarvellAttestationResult r = verifier().verifyMarvellAttestation(
                attestation(priv().put(MarvellAttestation.ATTR_EXTRACTABLE, new byte[] {1})), chainPem(),
                hsmKey.getPublic());
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isExtractable()).isTrue();
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_KEY_EXTRACTABLE"));
    }
}
