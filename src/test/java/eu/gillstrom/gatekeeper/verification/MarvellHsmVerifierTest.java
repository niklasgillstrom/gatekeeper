package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link MarvellHsmVerifier} on synthetic key-pair
 * attestations under a throwaway Marvell root passed to the test constructor.
 */
class MarvellHsmVerifierTest {

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

    private String keyPairAttestation(MarvellBlobs priv) throws Exception {
        MarvellBlobs pub = MarvellBlobs.publicKey((RSAPublicKey) hsmKey.getPublic(), "k");
        return Base64.getEncoder().encodeToString(
                MarvellBlobs.signed(MarvellBlobs.fw3Data(pub, priv), partitionKp.getPrivate()));
    }

    private MarvellBlobs priv() throws Exception {
        return MarvellBlobs.privateKey((RSAPublicKey) hsmKey.getPublic(), "k");
    }

    @Test
    @DisplayName("A key-pair attestation of the CSR key verifies once the format gate is open")
    void validAttestationVerifies() throws Exception {
        MarvellHsmVerifier.MarvellAttestationResult r = new MarvellHsmVerifier(List.of(root), true)
                .verifyMarvellAttestation(keyPairAttestation(priv()),
                        List.of(TestPki.toPem(partition), TestPki.toPem(card)), hsmKey.getPublic());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.getPartitionSerial()).isEqualTo(partition.getSerialNumber().toString(16));
    }

    @Test
    @DisplayName("While the format is unconfirmed, the same attestation is never valid")
    void unconfirmedFormatIsNeverValid() throws Exception {
        MarvellHsmVerifier.MarvellAttestationResult r = new MarvellHsmVerifier(List.of(root), false)
                .verifyMarvellAttestation(keyPairAttestation(priv()),
                        List.of(TestPki.toPem(partition), TestPki.toPem(card)), hsmKey.getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_FORMAT_UNCONFIRMED"));
    }

    @Test
    @DisplayName("An imported key (LOCAL false) is refused")
    void importedKeyIsRefused() throws Exception {
        MarvellHsmVerifier.MarvellAttestationResult r = new MarvellHsmVerifier(List.of(root), true)
                .verifyMarvellAttestation(keyPairAttestation(priv().put(MarvellAttestation.ATTR_LOCAL, new byte[] {0})),
                        List.of(TestPki.toPem(partition), TestPki.toPem(card)), hsmKey.getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_KEY_NOT_GENERATED"));
    }

    @Test
    @DisplayName("The attestation must be signed by the partition certificate in the chain")
    void otherSignerIsRefused() throws Exception {
        KeyPair stranger = TestPki.newRsaKeyPair(2048);
        String blob = Base64.getEncoder().encodeToString(MarvellBlobs.signed(
                MarvellBlobs.fw3Data(MarvellBlobs.publicKey((RSAPublicKey) hsmKey.getPublic(), "k"), priv()),
                stranger.getPrivate()));

        MarvellHsmVerifier.MarvellAttestationResult r = new MarvellHsmVerifier(List.of(root), true)
                .verifyMarvellAttestation(blob, List.of(TestPki.toPem(partition), TestPki.toPem(card)),
                        hsmKey.getPublic());

        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_SIGNATURE_INVALID"));
    }

    @Test
    @DisplayName("A chain under another root fails against the pinned Marvell roots")
    void pinnedRootsRejectTestChain() throws Exception {
        MarvellHsmVerifier.MarvellAttestationResult r = new MarvellHsmVerifier()
                .verifyMarvellAttestation(keyPairAttestation(priv()),
                        List.of(TestPki.toPem(partition), TestPki.toPem(card), TestPki.toPem(root)),
                        hsmKey.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_CHAIN_INVALID"));
        assertThat(r.isValid()).isFalse();
    }
}
