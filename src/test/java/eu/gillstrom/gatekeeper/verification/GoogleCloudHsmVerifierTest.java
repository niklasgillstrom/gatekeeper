package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link GoogleCloudHsmVerifier} on synthetic attestations
 * and dual chains, under throwaway Marvell and owner roots passed to the
 * test constructor.
 */
class GoogleCloudHsmVerifierTest {

    private KeyPair mfrRootKp;
    private X509Certificate mfrRoot;
    private KeyPair ownerRootKp;
    private X509Certificate ownerRoot;
    private KeyPair cardKp;
    private X509Certificate mfrCard;
    private KeyPair partitionKp;
    private X509Certificate mfrPartition;
    private X509Certificate ownerCard;
    private X509Certificate ownerPartition;
    private KeyPair hsmKey;

    @BeforeEach
    void pki() throws Exception {
        mfrRootKp = TestPki.newRsaKeyPair(2048);
        mfrRoot = TestPki.selfSignedCa(mfrRootKp, "TEST-MARVELL-ROOT");
        ownerRootKp = TestPki.newRsaKeyPair(2048);
        ownerRoot = TestPki.selfSignedCa(ownerRootKp, "TEST-HAWKSBILL-ROOT");
        cardKp = TestPki.newRsaKeyPair(2048);
        mfrCard = TestPki.subordinateCa(cardKp, "MFR-CARD", mfrRoot, mfrRootKp.getPrivate());
        partitionKp = TestPki.newRsaKeyPair(2048);
        mfrPartition = TestPki.endEntity(partitionKp, "MFR-PARTITION", mfrCard, cardKp.getPrivate());
        ownerCard = TestPki.subordinateCa(cardKp, "OWNER-CARD", ownerRoot, ownerRootKp.getPrivate());
        ownerPartition = TestPki.endEntity(partitionKp, "OWNER-PARTITION", ownerRoot, ownerRootKp.getPrivate());
        hsmKey = TestPki.newRsaKeyPair(2048);
    }

    private GoogleCloudHsmVerifier verifier(boolean formatConfirmed) {
        return new GoogleCloudHsmVerifier(List.of(mfrRoot), ownerRoot, formatConfirmed);
    }

    private String attestation() throws Exception {
        byte[] blob = MarvellBlobs.signed(
                MarvellBlobs.privateKey((RSAPublicKey) hsmKey.getPublic(), "kms-key-1").fw2Data(),
                partitionKp.getPrivate());
        ByteArrayOutputStream gz = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(gz)) {
            out.write(blob);
        }
        return Base64.getEncoder().encodeToString(gz.toByteArray());
    }

    private List<String> bundle(X509Certificate... certs) throws Exception {
        List<String> out = new ArrayList<>();
        for (X509Certificate c : certs) {
            out.add(TestPki.toPem(c));
        }
        return out;
    }

    @Test
    @DisplayName("The pinned owner root is the certificate in Google's sample")
    void pinnedOwnerRootIsGooglesCertificate() {
        assertThat(MarvellAttestationTest.sha256(MarvellAttestation.certificate(GoogleCloudHsmVerifier.HAWKSBILL_ROOT_PEM)))
                .isEqualTo("46b5fd351d56a0721ca0afcd1731c0f7b74e3941eb818bfd0ec36e29df0de095");
    }

    @Test
    @DisplayName("Both chains, a gzip attestation and the CSR key verify once the format gate is open")
    void validAttestationVerifies() throws Exception {
        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                attestation(), bundle(mfrCard, mfrPartition, ownerCard, ownerPartition), hsmKey.getPublic());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.getKeySize()).isEqualTo(2048);
    }

    @Test
    @DisplayName("While the format is unconfirmed, the same attestation is never valid")
    void unconfirmedFormatIsNeverValid() throws Exception {
        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(false).verifyGoogleAttestation(
                attestation(), bundle(mfrCard, mfrPartition, ownerCard, ownerPartition), hsmKey.getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_FORMAT_UNCONFIRMED"));
    }

    @Test
    @DisplayName("Without the owner chain the attestation is refused")
    void ownerChainIsRequired() throws Exception {
        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                attestation(), bundle(mfrCard, mfrPartition), hsmKey.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_CHAIN_INVALID"));
    }

    @Test
    @DisplayName("An owner partition certificate for another key is refused")
    void ownerPartitionMustCarryTheManufacturerPartitionKey() throws Exception {
        X509Certificate otherPartition = TestPki.endEntity(
                TestPki.newRsaKeyPair(2048), "OWNER-PARTITION", ownerRoot, ownerRootKp.getPrivate());

        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                attestation(), bundle(mfrCard, mfrPartition, ownerCard, otherPartition), hsmKey.getPublic());

        assertThat(r.isChainValid()).isFalse();
    }

    @Test
    @DisplayName("An extra certificate in the bundle is refused, as in Google's tool")
    void extraCertificateIsRefused() throws Exception {
        X509Certificate extra = TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), "EXTRA");

        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                attestation(), bundle(mfrCard, mfrPartition, ownerCard, ownerPartition, extra), hsmKey.getPublic());

        assertThat(r.isChainValid()).isFalse();
    }

    @Test
    @DisplayName("A chain under another root fails against the pinned roots")
    void pinnedRootsRejectTestChain() throws Exception {
        GoogleCloudHsmVerifier.GoogleAttestationResult r = new GoogleCloudHsmVerifier().verifyGoogleAttestation(
                attestation(), bundle(mfrCard, mfrPartition, ownerCard, ownerPartition), hsmKey.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    @DisplayName("An empty chain is refused")
    void emptyChainIsRejected() {
        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                Base64.getEncoder().encodeToString(new byte[512]), List.of(), hsmKey.getPublic());

        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("no certificates"));
        assertThat(r.isValid()).isFalse();
    }
}
