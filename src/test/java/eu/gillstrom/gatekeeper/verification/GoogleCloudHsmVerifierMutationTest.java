package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link GoogleCloudHsmVerifier}: the {@link HsmAttestationVerifier} entry
 * points, the dual-chain check through {@code verifyChain}, the signature
 * refusal, malformed attestation data, and the key evidence the result
 * reports, on synthetic chains under throwaway Marvell and owner roots.
 */
class GoogleCloudHsmVerifierMutationTest {

    private static KeyPair mfrRootKp;
    private static X509Certificate mfrRoot;
    private static KeyPair ownerRootKp;
    private static X509Certificate ownerRoot;
    private static KeyPair cardKp;
    private static X509Certificate mfrCard;
    private static KeyPair partitionKp;
    private static X509Certificate mfrPartition;
    private static X509Certificate ownerCard;
    private static X509Certificate ownerPartition;
    private static KeyPair hsmKey;

    @BeforeAll
    static void pki() throws Exception {
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

    private static GoogleCloudHsmVerifier verifier(boolean formatConfirmed) {
        return new GoogleCloudHsmVerifier(List.of(mfrRoot), ownerRoot, formatConfirmed);
    }

    private static String attestation(MarvellBlobs key, PrivateKey signer) throws Exception {
        return Base64.getEncoder().encodeToString(MarvellBlobs.signed(key.fw2Data(), signer));
    }

    private static MarvellBlobs nonExtractableKey() throws Exception {
        return MarvellBlobs.privateKey((RSAPublicKey) hsmKey.getPublic(), "kms-key-1");
    }

    private static List<String> bundle(X509Certificate... certs) throws Exception {
        List<String> out = new ArrayList<>();
        for (X509Certificate c : certs) {
            out.add(TestPki.toPem(c));
        }
        return out;
    }

    private static List<String> fullBundle() throws Exception {
        return bundle(mfrCard, mfrPartition, ownerCard, ownerPartition);
    }

    @Test
    @DisplayName("Vendor is GOOGLE; the certificate-only entry point never accepts; serial and model are reported")
    void entryPoints() {
        GoogleCloudHsmVerifier v = verifier(true);
        assertThat(v.getVendor()).isEqualTo(HsmVendor.GOOGLE);
        assertThat(v.verifyAttestation(mfrPartition, hsmKey.getPublic())).isFalse();
        assertThat(v.extractSerialNumber(mfrPartition)).isEqualTo(mfrPartition.getSerialNumber().toString(16));
        assertThat(v.extractModel(mfrPartition)).isEqualTo("Google Cloud HSM");
    }

    @Test
    @DisplayName("verifyChain accepts the manufacturer partition certificate with both chains, and nothing else")
    void verifyChain() {
        GoogleCloudHsmVerifier v = verifier(true);
        assertThat(v.verifyChain(mfrPartition, new X509Certificate[] {mfrCard, ownerCard, ownerPartition})).isTrue();

        assertThat(v.verifyChain(mfrPartition, null)).as("no chain").isFalse();
        assertThat(v.verifyChain(mfrPartition, new X509Certificate[0])).as("empty chain").isFalse();
        assertThat(v.verifyChain(mfrPartition, new X509Certificate[] {mfrCard}))
                .as("owner chain missing").isFalse();
        assertThat(v.verifyChain(ownerPartition, new X509Certificate[] {mfrCard, mfrPartition, ownerCard}))
                .as("owner partition is not the attestation certificate").isFalse();
    }

    @Test
    @DisplayName("The result reports the attested key id, type and size")
    void reportsKeyFields() throws Exception {
        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                attestation(nonExtractableKey(), partitionKp.getPrivate()), fullBundle(), hsmKey.getPublic());

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isExtractable()).isFalse();
        assertThat(r.getKeyId()).isEqualTo("kms-key-1");
        assertThat(r.getKeyType()).isEqualTo("RSA");
        assertThat(r.getKeySize()).isEqualTo(2048);
    }

    @Test
    @DisplayName("An attestation not signed by the partition key is refused before its contents are read")
    void signatureIsRequired() throws Exception {
        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                attestation(nonExtractableKey(), TestPki.newRsaKeyPair(2048).getPrivate()), fullBundle(),
                hsmKey.getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.isExtractable()).as("unverified counts as extractable").isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("unverified");
        assertThat(r.getErrors()).containsExactly(
                "MARVELL_SIGNATURE_INVALID: the attestation is not signed by both partition certificates");
    }

    @Test
    @DisplayName("The key evidence's findings are reported: another CSR key is a mismatch")
    void evidenceErrorsAreReported() throws Exception {
        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                attestation(nonExtractableKey(), partitionKp.getPrivate()), fullBundle(),
                TestPki.newRsaKeyPair(2048).getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("An extractable key is reported extractable and refused")
    void extractableKeyIsRefused() throws Exception {
        MarvellBlobs extractable = nonExtractableKey().put(MarvellAttestation.ATTR_EXTRACTABLE, new byte[] {1});
        GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                attestation(extractable, partitionKp.getPrivate()), fullBundle(), hsmKey.getPublic());

        assertThat(r.isValid()).isFalse();
        assertThat(r.isExtractable()).isTrue();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("MARVELL_KEY_EXTRACTABLE"));
    }

    @Test
    @DisplayName("Attestation data that is not base64, or absent, is refused as malformed")
    void malformedAttestationData() throws Exception {
        for (String data : new String[] {"*** not base64 ***", null}) {
            GoogleCloudHsmVerifier.GoogleAttestationResult r = verifier(true).verifyGoogleAttestation(
                    data, fullBundle(), hsmKey.getPublic());
            assertThat(r.isValid()).isFalse();
            assertThat(r.isSignatureValid()).isFalse();
            assertThat(r.getErrors()).singleElement()
                    .satisfies(e -> assertThat(e).startsWith("MARVELL_ATTESTATION_MALFORMED: "));
        }
    }
}
