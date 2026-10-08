package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MarvellAttestationTest {

    private static KeyPair hsmKey;
    private static KeyPair partitionKp;
    private static X509Certificate partition;

    @BeforeAll
    static void keys() throws Exception {
        hsmKey = TestPki.newRsaKeyPair(2048);
        partitionKp = TestPki.newRsaKeyPair(2048);
        partition = TestPki.selfSignedCa(partitionKp, "TEST-PARTITION");
    }

    private static RSAPublicKey key() {
        return (RSAPublicKey) hsmKey.getPublic();
    }

    @Test
    @DisplayName("The pinned Marvell roots are the certificates in Microsoft's validator")
    void pinnedRootsAreTheVendorsCertificates() throws Exception {
        assertThat(MarvellAttestation.marvellRoots()).extracting(MarvellAttestationTest::sha256).containsExactly(
                "230143df00e0b452743e068a5b3fc08df8f06cefc4854ea627aeb7ebd70ee2f4",
                "17644de0d33bc73b2f4ef4c20a11f6c8cc1f723a4cd83ee600361cbb24d8d2e5");
    }

    @Test
    @DisplayName("Firmware 2.x and 3.x layouts parse to the same attributes")
    void bothLayoutsParse() throws Exception {
        MarvellBlobs b = MarvellBlobs.privateKey(key(), "keys/k/1");

        MarvellAttestation.Parsed fw2 = MarvellAttestation.parse(MarvellBlobs.signed(b.fw2Data(), partitionKp.getPrivate()));
        MarvellAttestation.Parsed fw3 = MarvellAttestation.parse(MarvellBlobs.signed(b.fw3Data(), partitionKp.getPrivate()));

        assertThat(fw2.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_2X);
        assertThat(fw3.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_3X);
        assertThat(fw2.objects().get(0).attributes().keySet()).isEqualTo(fw3.objects().get(0).attributes().keySet());
        assertThat(fw3.objects().get(0).id()).isEqualTo("keys/k/1");
        assertThat(fw3.objects().get(0).number(MarvellAttestation.ATTR_MODULUS)).isEqualTo(key().getModulus());

        MarvellAttestation.Parsed pair = MarvellAttestation.parse(MarvellBlobs.signed(
                MarvellBlobs.fw3Data(MarvellBlobs.publicKey(key(), "k"), b), partitionKp.getPrivate()));
        assertThat(pair.objects()).hasSize(2);
        assertThat(pair.objects().get(0).number(MarvellAttestation.ATTR_CLASS)).isEqualTo(2);
        assertThat(pair.objects().get(1).number(MarvellAttestation.ATTR_CLASS)).isEqualTo(3);
        assertThat(MarvellAttestation.signedBy(fw2, partition)).isTrue();
        assertThat(MarvellAttestation.signedBy(fw3, partition)).isTrue();
    }

    @Test
    @DisplayName("A record that runs into the signature, a huge count or a repeated attribute is rejected")
    void malformedListsAreRejected() throws Exception {
        byte[] overrun = MarvellBlobs.signed(MarvellBlobs.privateKey(key(), "k").fw2Data(), partitionKp.getPrivate());
        // Last record's length now reaches into the signature.
        int lastLen = overrun.length - MarvellAttestation.SIGNATURE_SIZE - 1 - 4;
        ByteBuffer.wrap(overrun).putInt(lastLen, 2);
        assertThatThrownBy(() -> MarvellAttestation.parse(overrun)).isInstanceOf(IllegalArgumentException.class);

        byte[] huge = MarvellBlobs.signed(MarvellBlobs.privateKey(key(), "k").fw2Data(), partitionKp.getPrivate());
        ByteBuffer.wrap(huge).putInt(MarvellAttestation.FW2_ATTRIBUTE_OFFSET + 4, 0x7FFFFFFF);
        assertThatThrownBy(() -> MarvellAttestation.parse(huge)).isInstanceOf(IllegalArgumentException.class);

        ByteArrayOutputStream dup = new ByteArrayOutputStream();
        dup.writeBytes(new byte[MarvellAttestation.FW2_ATTRIBUTE_OFFSET]);
        dup.writeBytes(ByteBuffer.allocate(12).putInt(0).putInt(2).putInt(0).array());
        for (int i = 0; i < 2; i++) {
            dup.writeBytes(ByteBuffer.allocate(9).putInt(MarvellAttestation.ATTR_EXTRACTABLE).putInt(1).put((byte) i).array());
        }
        byte[] twice = MarvellBlobs.signed(dup.toByteArray(), partitionKp.getPrivate());
        assertThatThrownBy(() -> MarvellAttestation.parse(twice)).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> MarvellAttestation.parse(new byte[256])).isInstanceOf(IllegalArgumentException.class);

        // ulTotalSize must be the length of the response, as Marvell documents it.
        byte[] wrongTotal = MarvellBlobs.signed(MarvellBlobs.privateKey(key(), "k").fw3Data(), partitionKp.getPrivate());
        // Total and buffer both grow by 4, so the buffer start is unchanged and
        // only the total-size check can catch it.
        ByteBuffer w = ByteBuffer.wrap(wrongTotal);
        w.putInt(8, wrongTotal.length + 4).putInt(12, w.getInt(12) + 4);
        assertThatThrownBy(() -> MarvellAttestation.parse(wrongTotal)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Firmware 2.x raw check: a cube-root forgery under e = 3 is refused")
    void smallExponentForgeryIsRefused() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F0));
        KeyPair e3 = g.generateKeyPair();
        X509Certificate e3Partition = TestPki.selfSignedCa(e3, "E3-PARTITION");

        byte[] data = MarvellBlobs.privateKey(key(), "k").fw2Data();
        byte[] hash;
        do {
            data[0]++;
            hash = MessageDigest.getInstance("SHA-256").digest(data);
        } while ((hash[hash.length - 1] & 1) == 0);
        BigInteger mod256 = BigInteger.ONE.shiftLeft(256);
        BigInteger h = new BigInteger(1, hash);
        BigInteger s = BigInteger.ONE;
        for (int k = 1; k < 256; k++) {
            if (!s.pow(3).subtract(h).mod(BigInteger.ONE.shiftLeft(k + 1)).equals(BigInteger.ZERO)) {
                s = s.setBit(k);
            }
        }
        // The forgery satisfies Microsoft's trailing-hash comparison without the private key.
        RSAPublicKey pub = (RSAPublicKey) e3.getPublic();
        BigInteger raised = s.modPow(pub.getPublicExponent(), pub.getModulus());
        assertThat(raised.mod(mod256)).isEqualTo(h);

        byte[] sig = new byte[MarvellAttestation.SIGNATURE_SIZE];
        byte[] sb = s.toByteArray();
        System.arraycopy(sb, 0, sig, sig.length - sb.length, sb.length);
        byte[] blob = Arrays.copyOf(data, data.length + sig.length);
        System.arraycopy(sig, 0, blob, data.length, sig.length);

        MarvellAttestation.Parsed parsed = MarvellAttestation.parse(blob);
        assertThat(parsed.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_2X);
        assertThat(MarvellAttestation.signedBy(parsed, e3Partition)).isFalse();
    }

    @Test
    @DisplayName("Generated, never-extractable RSA key that is the CSR key gives clean evidence")
    void cleanEvidence() throws Exception {
        MarvellAttestation.KeyEvidence e = evaluate(MarvellBlobs.privateKey(key(), "keys/k/1"), null);

        assertThat(e.errors()).isEmpty();
        assertThat(e.publicKeyMatch()).isTrue();
        assertThat(e.extractable()).isFalse();
        assertThat(e.keyOrigin()).isEqualTo("generated");
        assertThat(e.keyBits()).isEqualTo(2048);
    }

    @Test
    @DisplayName("Extractable, imported or unflagged keys are refused")
    void attributesCountAgainstTheKey() throws Exception {
        assertThat(evaluate(MarvellBlobs.privateKey(key(), "k")
                .put(MarvellAttestation.ATTR_EXTRACTABLE, new byte[] {1}), null).errors())
                .anyMatch(s -> s.startsWith("MARVELL_KEY_EXTRACTABLE"));
        assertThat(evaluate(MarvellBlobs.privateKey(key(), "k")
                .put(MarvellAttestation.ATTR_LOCAL, new byte[] {0}), null).errors())
                .anyMatch(s -> s.startsWith("MARVELL_KEY_NOT_GENERATED"));
        MarvellAttestation.KeyEvidence missing = evaluate(MarvellBlobs.privateKey(key(), "k")
                .remove(MarvellAttestation.ATTR_NEVER_EXTRACTABLE), null);
        assertThat(missing.extractable()).isTrue();
        assertThat(missing.keyOrigin()).isEqualTo("unverified");
        assertThat(evaluate(MarvellBlobs.privateKey(key(), "k")
                .put(MarvellAttestation.ATTR_CLASS, new byte[] {4}), null).errors())
                .anyMatch(s -> s.startsWith("MARVELL_UNEXPECTED_OBJECT"));
    }

    @Test
    @DisplayName("Without an attested modulus, or with another key's, nothing binds to the CSR")
    void keyBinding() throws Exception {
        assertThat(evaluate(MarvellBlobs.privateKey(key(), "k").remove(MarvellAttestation.ATTR_MODULUS)
                .remove(MarvellAttestation.ATTR_EKCV), null).errors())
                .anyMatch(s -> s.startsWith("MARVELL_KEY_NOT_BOUND"));

        RSAPublicKey other = (RSAPublicKey) TestPki.newRsaKeyPair(2048).getPublic();
        MarvellAttestation.KeyEvidence e = evaluate(MarvellBlobs.privateKey(other, "k"), null);
        assertThat(e.publicKeyMatch()).isFalse();
        assertThat(e.errors()).anyMatch(s -> s.startsWith("MARVELL_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("Marvell's published example: KCV and EKCV are SHA-1 and SHA-256 of the DER public key")
    void marvellPublishedExampleBindsItsKey() throws Exception {
        // Public-key object values from Marvell's "LiquidSecurity HSM - Software
        // Key Attestation" page, parsed RSA key-pair example.
        BigInteger n = new BigInteger(MARVELL_EXAMPLE_MODULUS, 16);
        RSAPublicKey exampleKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(n, BigInteger.valueOf(65537)));
        MarvellBlobs pub = new MarvellBlobs()
                .put(MarvellAttestation.ATTR_CLASS, new byte[] {2})
                .put(MarvellAttestation.ATTR_KEY_TYPE, new byte[] {0})
                .put(MarvellAttestation.ATTR_MODULUS, HexFormat.of().parseHex(MARVELL_EXAMPLE_MODULUS))
                .put(0x0121, HexFormat.of().parseHex("00000800"))
                .put(MarvellAttestation.ATTR_PUBLIC_EXPONENT, HexFormat.of().parseHex("010001"))
                .put(MarvellAttestation.ATTR_KCV, HexFormat.of().parseHex("ebf8c2"))
                .put(MarvellAttestation.ATTR_EKCV, HexFormat.of().parseHex(
                        "baf99b5bbb885149e191c1b107f10638cb34c1390f050e2abb9ed23692c7510b"));
        MarvellBlobs priv = new MarvellBlobs()
                .put(MarvellAttestation.ATTR_CLASS, new byte[] {3})
                .put(MarvellAttestation.ATTR_KEY_TYPE, new byte[] {0})
                .put(MarvellAttestation.ATTR_EXTRACTABLE, new byte[] {0})
                .put(MarvellAttestation.ATTR_NEVER_EXTRACTABLE, new byte[] {1})
                .put(MarvellAttestation.ATTR_LOCAL, new byte[] {1})
                .put(MarvellAttestation.ATTR_KCV, HexFormat.of().parseHex("ebf8c2"))
                .put(MarvellAttestation.ATTR_EKCV, HexFormat.of().parseHex(
                        "baf99b5bbb885149e191c1b107f10638cb34c1390f050e2abb9ed23692c7510b"));

        MarvellAttestation.KeyEvidence ok = MarvellAttestation.evaluate(List.of(MarvellAttestation.parse(
                MarvellBlobs.signed(MarvellBlobs.fw3Data(pub, priv), partitionKp.getPrivate()))), exampleKey);
        assertThat(ok.errors()).isEmpty();
        assertThat(ok.publicKeyMatch()).isTrue();

        priv.put(MarvellAttestation.ATTR_EKCV, HexFormat.of().parseHex(
                "baf99b5bbb885149e191c1b107f10638cb34c1390f050e2abb9ed23692c7510c"));
        MarvellAttestation.KeyEvidence flipped = MarvellAttestation.evaluate(List.of(MarvellAttestation.parse(
                MarvellBlobs.signed(MarvellBlobs.fw3Data(pub, priv), partitionKp.getPrivate()))), exampleKey);
        assertThat(flipped.publicKeyMatch()).isFalse();
        assertThat(flipped.errors()).anyMatch(s -> s.startsWith("MARVELL_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("A public key in the same signed blob ties the private key; one in another blob does not")
    void bindingThroughThePairedPublicKey() throws Exception {
        MarvellBlobs bare = MarvellBlobs.privateKey(key(), "k")
                .remove(MarvellAttestation.ATTR_MODULUS)
                .remove(MarvellAttestation.ATTR_EKCV)
                .remove(MarvellAttestation.ATTR_KCV);

        MarvellAttestation.Parsed pair = MarvellAttestation.parse(MarvellBlobs.signed(
                MarvellBlobs.fw3Data(MarvellBlobs.publicKey(key(), "k"), bare), partitionKp.getPrivate()));
        assertThat(MarvellAttestation.evaluate(List.of(pair), hsmKey.getPublic()).errors()).isEmpty();

        MarvellAttestation.Parsed alone = MarvellAttestation.parse(MarvellBlobs.signed(bare.fw3Data(), partitionKp.getPrivate()));
        MarvellAttestation.Parsed separate = MarvellAttestation.parse(MarvellBlobs.signed(
                MarvellBlobs.publicKey(key(), "k").fw3Data(), partitionKp.getPrivate()));
        assertThat(MarvellAttestation.evaluate(List.of(alone, separate), hsmKey.getPublic()).errors())
                .anyMatch(s -> s.startsWith("MARVELL_KEY_NOT_BOUND"));
    }

    @Test
    @DisplayName("A KCV alone (3 bytes) does not bind, and a paired public key of another key is refused")
    void weakOrForeignKeyMaterialIsRefused() throws Exception {
        MarvellBlobs kcvOnly = MarvellBlobs.privateKey(key(), "k")
                .remove(MarvellAttestation.ATTR_MODULUS)
                .remove(MarvellAttestation.ATTR_EKCV);
        assertThat(evaluate(kcvOnly, null).errors()).anyMatch(s -> s.startsWith("MARVELL_KEY_NOT_BOUND"));

        RSAPublicKey other = (RSAPublicKey) TestPki.newRsaKeyPair(2048).getPublic();
        MarvellAttestation.Parsed pair = MarvellAttestation.parse(MarvellBlobs.signed(
                MarvellBlobs.fw3Data(MarvellBlobs.publicKey(other, "k"), MarvellBlobs.privateKey(key(), "k")),
                partitionKp.getPrivate()));
        assertThat(MarvellAttestation.evaluate(List.of(pair), hsmKey.getPublic()).errors())
                .anyMatch(s -> s.startsWith("MARVELL_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("Two private-key objects, or none, are refused")
    void exactlyOnePrivateKey() throws Exception {
        MarvellAttestation.Parsed two = MarvellAttestation.parse(MarvellBlobs.signed(
                MarvellBlobs.fw3Data(MarvellBlobs.privateKey(key(), "a"), MarvellBlobs.privateKey(key(), "b")),
                partitionKp.getPrivate()));
        assertThat(MarvellAttestation.evaluate(List.of(two), hsmKey.getPublic()).errors())
                .anyMatch(s -> s.startsWith("MARVELL_NO_SINGLE_PRIVATE_KEY"));

        MarvellAttestation.Parsed none = MarvellAttestation.parse(MarvellBlobs.signed(
                MarvellBlobs.publicKey(key(), "k").fw3Data(), partitionKp.getPrivate()));
        assertThat(MarvellAttestation.evaluate(List.of(none), hsmKey.getPublic()).errors())
                .anyMatch(s -> s.startsWith("MARVELL_NO_SINGLE_PRIVATE_KEY"));
    }

    @Test
    @DisplayName("gzip input is decompressed with a size bound")
    void gzipIsBounded() throws Exception {
        ByteArrayOutputStream bomb = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bomb)) {
            gz.write(new byte[MarvellAttestation.MAX_DECOMPRESSED_SIZE + 1]);
        }
        assertThatThrownBy(() -> MarvellAttestation.gunzipIfCompressed(bomb.toByteArray()))
                .hasMessageContaining("exceeds");
    }

    private static MarvellAttestation.KeyEvidence evaluate(MarvellBlobs priv, MarvellBlobs pub) throws Exception {
        MarvellAttestation.Parsed p = MarvellAttestation.parse(MarvellBlobs.signed(
                pub == null ? priv.fw3Data() : MarvellBlobs.fw3Data(pub, priv), partitionKp.getPrivate()));
        return MarvellAttestation.evaluate(List.of(p), hsmKey.getPublic());
    }

    private static final String MARVELL_EXAMPLE_MODULUS =
            "a20e7c2db60828fb705a35e8377a535c498c1981e967bccc4e3bfb0377316dc19fd251b9656c39df295dee7e4bc5c85f"
            + "f47e8a0adaeff866cf8dc8b18a9588df08689a524fc891782462e8b55568c41e6efeebdce53645fbd1a74a200cc74638"
            + "8fce21d159102ee2193b1df981d134e925ade65bf2bf74bf87afe99944f03cf6c1701ae58b58fa80473c5801db9e0d8e"
            + "6c568391dfedc1ca8e24543fb8223d0d3b6fa0565b668a9eb68e8bbca286e84c91591e85480f3d2dc542e31455de358c"
            + "78704b689abb01bd7575dc1346e4b75fdd708f5af4988aae260387faed9c7521fb419f40d3c0799436e0d81af17967bd"
            + "3802a73cb5f001f056f1533067cd6047";

    static String sha256(X509Certificate c) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
