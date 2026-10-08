package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Edge cases of {@link MarvellAttestation}: the bounds of the binary
 * {@code attest.dat} layouts, the two signature schemes and which one each
 * layout uses, the partition certificate's digest, and the key evidence for
 * absent, malformed or foreign attributes.
 */
class MarvellAttestationMutationTest {

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

    // ------------------------------------------------------------ layouts

    @Test
    @DisplayName("A blob no longer than the 256-byte signature is refused as too short")
    void blobMustBeLongerThanTheSignature() {
        for (byte[] blob : new byte[][] {null, new byte[0], new byte[MarvellAttestation.SIGNATURE_SIZE]}) {
            assertThatThrownBy(() -> MarvellAttestation.parse(blob))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Attestation is shorter than its 256-byte signature");
        }
    }

    @Test
    @DisplayName("An object may carry up to 512 attributes; 513 and 0 are refused")
    void attributeCountBound() throws Exception {
        MarvellAttestation.Parsed max = MarvellAttestation.parse(signed(fw2(emptyRecords(512))));
        assertThat(max.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_2X);
        assertThat(max.objects().get(0).attributes()).hasSize(512);

        assertNeither(signed(fw2(emptyRecords(513))));
        assertNeither(signed(fw2(emptyRecords(0))));
    }

    @Test
    @DisplayName("Attribute types up to 0x7FFFFFFF are read; a type with the top bit set is refused")
    void attributeTypeBound() throws Exception {
        MarvellAttestation.Parsed top = MarvellAttestation.parse(signed(fw2(record(0x7FFFFFFF, new byte[] {9}))));
        assertThat(top.objects().get(0).attribute(Integer.MAX_VALUE)).containsExactly(9);

        assertNeither(signed(fw2(record(0x80000000L, new byte[] {9}))));
    }

    @Test
    @DisplayName("A last record of length zero that ends exactly at the signature is read as an empty value")
    void zeroLengthRecordAtTheEnd() throws Exception {
        MarvellAttestation.Parsed p = MarvellAttestation.parse(signed(fw2(
                record(MarvellAttestation.ATTR_CLASS, new byte[] {3}), record(MarvellAttestation.ATTR_LOCAL, new byte[0]))));
        MarvellAttestation.KeyObject o = p.objects().get(0);
        assertThat(o.attribute(MarvellAttestation.ATTR_LOCAL)).isEmpty();
        assertThat(o.number(MarvellAttestation.ATTR_LOCAL)).isNull();
        assertThat(o.flag(MarvellAttestation.ATTR_LOCAL)).isNull();
    }

    @Test
    @DisplayName("Firmware 3.x: an attribute buffer straight after the 16-byte response header is read")
    void fw3BufferRightAfterTheResponseHeader() throws Exception {
        byte[] object = MarvellBlobs.privateKey(key(), "k").object();
        int buffer = 8 + object.length;
        ByteBuffer b = ByteBuffer.allocate(16 + buffer);
        b.putInt(0).putInt(0).putInt(16 + buffer + MarvellAttestation.SIGNATURE_SIZE).putInt(buffer);
        b.putShort((short) 1).putShort((short) 0).putShort((short) 8).putShort((short) 0);
        b.put(object);

        MarvellAttestation.Parsed p = MarvellAttestation.parse(signed(b.array()));
        assertThat(p.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_3X);
        assertThat(p.objects()).hasSize(1);
        assertThat(p.objects().get(0).id()).isEqualTo("k");

        // One byte more of buffer would start it inside the response header.
        ByteBuffer.wrap(b.array()).putInt(12, buffer + 1);
        assertNeither(signed(b.array()));
    }

    // --------------------------------------------------------------- gzip

    @Test
    @DisplayName("gzip: exactly the size bound decompresses; the bare gzip magic is a truncated stream")
    void gzipEdges() throws Exception {
        ByteArrayOutputStream exact = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(exact)) {
            gz.write(new byte[MarvellAttestation.MAX_DECOMPRESSED_SIZE]);
        }
        assertThat(MarvellAttestation.gunzipIfCompressed(exact.toByteArray()))
                .hasSize(MarvellAttestation.MAX_DECOMPRESSED_SIZE);

        assertThatThrownBy(() -> MarvellAttestation.gunzipIfCompressed(new byte[] {0x1F, (byte) 0x8B}))
                .isInstanceOf(IOException.class);

        byte[] one = {0x1F};
        assertThat(MarvellAttestation.gunzipIfCompressed(one)).isSameAs(one);
        byte[] plain = {0x1F, 0x00, 0x01};
        assertThat(MarvellAttestation.gunzipIfCompressed(plain)).isSameAs(plain);
    }

    // ---------------------------------------------------------- signatures

    @Test
    @DisplayName("Firmware 2.x: an unpadded raw signature over the SHA-256 is accepted; another key's is not")
    void fw2RawSignature() throws Exception {
        byte[] data = hashWithTopBitClear(MarvellBlobs.privateKey(key(), "k").fw2Data());
        MarvellAttestation.Parsed raw = MarvellAttestation.parse(concat(data, rawSignature(data, partitionKp)));
        assertThat(raw.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_2X);
        assertThat(MarvellAttestation.signedBy(raw, partition)).isTrue();

        // The same signature over other data: in range for the key, but the trailing hash differs.
        byte[] tampered = data.clone();
        tampered[1] ^= 1;
        byte[] genuine = Arrays.copyOfRange(raw.signature(), 0, MarvellAttestation.SIGNATURE_SIZE);
        assertThat(MarvellAttestation.signedBy(MarvellAttestation.parse(concat(tampered, genuine)), partition)).isFalse();

        KeyPair stranger = TestPki.newRsaKeyPair(2048);
        MarvellAttestation.Parsed other = MarvellAttestation.parse(concat(data, rawSignature(data, stranger)));
        assertThat(MarvellAttestation.signedBy(other, partition)).isFalse();
        MarvellAttestation.Parsed otherPkcs1 = MarvellAttestation.parse(MarvellBlobs.signed(data, stranger.getPrivate()));
        assertThat(MarvellAttestation.signedBy(otherPkcs1, partition)).isFalse();
    }

    @Test
    @DisplayName("Firmware 3.x needs PKCS#1 v1.5: an unpadded raw signature over the hash is refused")
    void fw3RefusesRawSignature() throws Exception {
        byte[] data = hashWithTopBitClear(MarvellBlobs.privateKey(key(), "k").fw3Data());
        MarvellAttestation.Parsed p = MarvellAttestation.parse(concat(data, rawSignature(data, partitionKp)));
        assertThat(p.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_3X);
        assertThat(MarvellAttestation.signedBy(p, partition)).isFalse();
    }

    @Test
    @DisplayName("Firmware 2.x: a signature of zero or not below the modulus is refused")
    void fw2SignatureOutOfRange() throws Exception {
        byte[] data = MarvellBlobs.privateKey(key(), "k").fw2Data();
        byte[] ones = new byte[MarvellAttestation.SIGNATURE_SIZE];
        Arrays.fill(ones, (byte) 0xFF);
        assertThat(MarvellAttestation.signedBy(MarvellAttestation.parse(concat(data, ones)), partition)).isFalse();
        byte[] modulus = MarvellBlobs.unsigned(((RSAPublicKey) partitionKp.getPublic()).getModulus());
        assertThat(MarvellAttestation.signedBy(MarvellAttestation.parse(concat(data, modulus)), partition)).isFalse();
        byte[] zero = new byte[MarvellAttestation.SIGNATURE_SIZE];
        assertThat(MarvellAttestation.signedBy(MarvellAttestation.parse(concat(data, zero)), partition)).isFalse();
    }

    @Test
    @DisplayName("A partition certificate without an RSA key verifies nothing")
    void nonRsaPartition() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ec = g.generateKeyPair();
        X509Certificate ecPartition = selfSigned(ec, "EC-PARTITION", "SHA256withECDSA");
        for (byte[] data : List.of(MarvellBlobs.privateKey(key(), "k").fw2Data(),
                MarvellBlobs.privateKey(key(), "k").fw3Data())) {
            MarvellAttestation.Parsed p = MarvellAttestation.parse(MarvellBlobs.signed(data, partitionKp.getPrivate()));
            assertThat(MarvellAttestation.signedBy(p, ecPartition)).isFalse();
            assertThat(MarvellAttestation.signedPkcs1Sha256(p, ecPartition)).isFalse();
        }
    }

    @Test
    @DisplayName("Google's check: SHA-256 PKCS#1 v1.5 by the given certificate's key, and no other")
    void pkcs1Sha256() throws Exception {
        MarvellAttestation.Parsed p = MarvellAttestation.parse(
                MarvellBlobs.signed(MarvellBlobs.privateKey(key(), "k").fw3Data(), partitionKp.getPrivate()));
        assertThat(MarvellAttestation.signedPkcs1Sha256(p, partition)).isTrue();
        X509Certificate other = TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), "OTHER");
        assertThat(MarvellAttestation.signedPkcs1Sha256(p, other)).isFalse();
    }

    @Test
    @DisplayName("Firmware 3.x uses the hash of the partition certificate's own signature algorithm")
    void fw3DigestFollowsThePartitionCertificate() throws Exception {
        byte[] data = MarvellBlobs.privateKey(key(), "k").fw3Data();
        for (String alg : List.of("SHA384withRSA", "SHA512withRSA")) {
            X509Certificate cert = selfSigned(partitionKp, "PARTITION-" + alg, alg);
            MarvellAttestation.Parsed matching = MarvellAttestation.parse(signed(data, partitionKp.getPrivate(), alg));
            MarvellAttestation.Parsed sha256 = MarvellAttestation.parse(MarvellBlobs.signed(data, partitionKp.getPrivate()));
            assertThat(MarvellAttestation.signedBy(matching, cert)).as(alg).isTrue();
            assertThat(MarvellAttestation.signedBy(sha256, cert)).as(alg).isFalse();
            assertThat(MarvellAttestation.signedBy(matching, partition)).as(alg).isFalse();
        }
    }

    @Test
    @DisplayName("A partition key that is not RSA-2048 cannot have made the 256-byte signature")
    void partitionKeyOfAnotherSize() throws Exception {
        KeyPair big = TestPki.newRsaKeyPair(3072);
        X509Certificate bigPartition = TestPki.selfSignedCa(big, "RSA-3072-PARTITION");
        MarvellAttestation.Parsed p = MarvellAttestation.parse(
                MarvellBlobs.signed(MarvellBlobs.privateKey(key(), "k").fw3Data(), partitionKp.getPrivate()));
        assertThat(MarvellAttestation.signedBy(p, bigPartition)).isFalse();
        assertThat(MarvellAttestation.signedPkcs1Sha256(p, bigPartition)).isFalse();
    }

    @Test
    @DisplayName("A hand-built Parsed without signed data is refused under both layouts rather than thrown")
    void parsedWithoutSignedDataIsRefused() throws Exception {
        byte[] data = MarvellBlobs.privateKey(key(), "k").fw2Data();
        byte[] sig = Arrays.copyOfRange(MarvellBlobs.signed(data, partitionKp.getPrivate()), data.length,
                data.length + MarvellAttestation.SIGNATURE_SIZE);
        for (MarvellAttestation.Layout layout : MarvellAttestation.Layout.values()) {
            MarvellAttestation.Parsed p = new MarvellAttestation.Parsed(layout, List.of(), null, sig);
            assertThat(MarvellAttestation.signedBy(p, partition)).as(layout.name()).isFalse();
        }
    }

    // ------------------------------------------------------------- evidence

    @Test
    @DisplayName("A CSR key that is not RSA is a mismatch; the attributes are still reported")
    void nonRsaCsrKey() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        var ecKey = g.generateKeyPair().getPublic();

        MarvellAttestation.KeyEvidence generated = MarvellAttestation.evaluate(
                List.of(parsedFw3(MarvellBlobs.privateKey(key(), "keys/k/1"))), ecKey);
        assertThat(generated.errors()).containsExactly("MARVELL_PUBLIC_KEY_MISMATCH: the CSR key is not an RSA key");
        assertThat(generated.publicKeyMatch()).isFalse();
        assertThat(generated.keyOrigin()).isEqualTo("generated");
        assertThat(generated.extractable()).isFalse();
        assertThat(generated.keyId()).isEqualTo("keys/k/1");
        assertThat(generated.keyBits()).isZero();

        MarvellAttestation.KeyEvidence imported = MarvellAttestation.evaluate(List.of(parsedFw3(
                MarvellBlobs.privateKey(key(), "k").put(MarvellAttestation.ATTR_LOCAL, new byte[] {0}))), ecKey);
        assertThat(imported.keyOrigin()).isEqualTo("unverified");
        assertThat(imported.errors()).contains("MARVELL_PUBLIC_KEY_MISMATCH: the CSR key is not an RSA key");
    }

    @Test
    @DisplayName("The CSR's modulus with another public exponent is a mismatch; an absent exponent is not")
    void publicExponent() throws Exception {
        MarvellAttestation.KeyEvidence e3 = evaluate(MarvellBlobs.privateKey(key(), "k")
                .put(MarvellAttestation.ATTR_PUBLIC_EXPONENT, new byte[] {3}));
        assertThat(e3.publicKeyMatch()).isFalse();
        assertThat(e3.keyBits()).isZero();
        assertThat(e3.errors()).contains(
                "MARVELL_PUBLIC_KEY_MISMATCH: an attested modulus, exponent, KCV or EKCV is not the CSR key's");

        MarvellAttestation.KeyEvidence noExponent = evaluate(MarvellBlobs.privateKey(key(), "k")
                .remove(MarvellAttestation.ATTR_PUBLIC_EXPONENT));
        assertThat(noExponent.errors()).isEmpty();
        assertThat(noExponent.publicKeyMatch()).isTrue();
    }

    @Test
    @DisplayName("A KCV that is not the CSR key's is a mismatch even when the modulus and EKCV match")
    void wrongKcv() throws Exception {
        byte[] kcv = Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(key().getEncoded()), 3);
        kcv[2] ^= 1;
        MarvellAttestation.KeyEvidence e = evaluate(MarvellBlobs.privateKey(key(), "k")
                .put(MarvellAttestation.ATTR_KCV, kcv));
        assertThat(e.publicKeyMatch()).isFalse();
        assertThat(e.errors()).contains(
                "MARVELL_PUBLIC_KEY_MISMATCH: an attested modulus, exponent, KCV or EKCV is not the CSR key's");
    }

    @Test
    @DisplayName("OBJ_ATTR_CLASS is read up to 63 bits; a wider value is reported as absent")
    void objectClassWidth() throws Exception {
        byte[] bits63 = new byte[8];
        bits63[0] = 0x40;
        byte[] bits64 = new byte[8];
        bits64[0] = (byte) 0x80;
        for (byte[] cls : List.of(bits63, bits64)) {
            MarvellBlobs odd = MarvellBlobs.publicKey(key(), "k").put(MarvellAttestation.ATTR_CLASS, cls);
            MarvellAttestation.Parsed p = MarvellAttestation.parse(MarvellBlobs.signed(
                    MarvellBlobs.fw3Data(odd, MarvellBlobs.privateKey(key(), "k")), partitionKp.getPrivate()));
            String expected = cls == bits63 ? "4611686018427387904" : "null";
            assertThat(MarvellAttestation.evaluate(List.of(p), hsmKey.getPublic()).errors()).containsExactly(
                    "MARVELL_UNEXPECTED_OBJECT: OBJ_ATTR_CLASS " + expected + " is neither a public nor a private key");
        }
    }

    @Test
    @DisplayName("An absent or malformed EXTRACTABLE flag counts as extractable")
    void extractableFlagMustBeWellFormed() throws Exception {
        MarvellAttestation.KeyEvidence absent = evaluate(MarvellBlobs.privateKey(key(), "k")
                .remove(MarvellAttestation.ATTR_EXTRACTABLE));
        assertThat(absent.extractable()).isTrue();
        assertThat(absent.errors()).containsExactly("MARVELL_KEY_EXTRACTABLE: OBJ_ATTR_EXTRACTABLE=null, "
                + "OBJ_ATTR_NEVER_EXTRACTABLE=true (required: false and true; null means absent or malformed)");

        for (byte[] malformed : List.of(new byte[] {0, 0}, new byte[] {2}, new byte[0])) {
            MarvellAttestation.KeyEvidence e = evaluate(MarvellBlobs.privateKey(key(), "k")
                    .put(MarvellAttestation.ATTR_EXTRACTABLE, malformed));
            assertThat(e.extractable()).isTrue();
            assertThat(e.errors()).anyMatch(s -> s.startsWith("MARVELL_KEY_EXTRACTABLE: OBJ_ATTR_EXTRACTABLE=null,"));
        }
    }

    @Test
    @DisplayName("KeyObject: flags are TRUE, FALSE or null; attribute() returns a copy, or null when absent")
    void keyObjectAccessors() throws Exception {
        MarvellAttestation.KeyObject o = parsedFw3(MarvellBlobs.privateKey(key(), "k")
                .put(0x0170, new byte[] {0, 1})
                .put(0x0171, new byte[] {2})).objects().get(0);
        assertThat(o.flag(MarvellAttestation.ATTR_EXTRACTABLE)).isFalse();
        assertThat(o.flag(MarvellAttestation.ATTR_LOCAL)).isTrue();
        assertThat(o.flag(0x0170)).isNull();
        assertThat(o.flag(0x0171)).isNull();
        assertThat(o.flag(0x0172)).isNull();

        byte[] modulus = o.attribute(MarvellAttestation.ATTR_MODULUS);
        assertThat(new BigInteger(1, modulus)).isEqualTo(key().getModulus());
        modulus[0] ^= 1;
        assertThat(o.number(MarvellAttestation.ATTR_MODULUS)).isEqualTo(key().getModulus());
        assertThat(o.attribute(0x0172)).isNull();
    }

    // ---------------------------------------------------------------- chain

    @Test
    @DisplayName("A card certificate that names the root but is not signed by its key is not in the chain")
    void issuedByChecksTheSignature() throws Exception {
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKp, "TEST-MARVELL-ROOT");
        KeyPair impostorKp = TestPki.newRsaKeyPair(2048);
        X509Certificate impostor = TestPki.selfSignedCa(impostorKp, "TEST-MARVELL-ROOT");
        KeyPair cardKp = TestPki.newRsaKeyPair(2048);
        X509Certificate forgedCard = TestPki.subordinateCa(cardKp, "TEST-CARD", impostor, impostorKp.getPrivate());
        X509Certificate forgedPartition = TestPki.endEntity(partitionKp, "TEST-PARTITION", forgedCard, cardKp.getPrivate());

        assertThat(forgedCard.getIssuerX500Principal()).isEqualTo(root.getSubjectX500Principal());
        assertThat(MarvellAttestation.issuedBy(root, List.of(forgedCard, forgedPartition))).isEmpty();
        assertThat(MarvellAttestation.manufacturerChain(List.of(forgedCard, forgedPartition), List.of(root))).isNull();

        X509Certificate card = TestPki.subordinateCa(cardKp, "TEST-CARD", root, rootKp.getPrivate());
        assertThat(MarvellAttestation.issuedBy(root, List.of(forgedCard, card))).containsExactly(card);
    }

    // -------------------------------------------------------------- helpers

    private static void assertNeither(byte[] blob) {
        assertThatThrownBy(() -> MarvellAttestation.parse(blob))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Attestation parses as neither firmware 2.x nor 3.x");
    }

    private static MarvellAttestation.Parsed parsedFw3(MarvellBlobs priv) throws Exception {
        return MarvellAttestation.parse(MarvellBlobs.signed(priv.fw3Data(), partitionKp.getPrivate()));
    }

    private static MarvellAttestation.KeyEvidence evaluate(MarvellBlobs priv) throws Exception {
        return MarvellAttestation.evaluate(List.of(parsedFw3(priv)), hsmKey.getPublic());
    }

    private static byte[] record(long type, byte[] value) {
        return ByteBuffer.allocate(8 + value.length).putInt((int) type).putInt(value.length).put(value).array();
    }

    private static byte[][] emptyRecords(int n) {
        byte[][] records = new byte[n][];
        for (int i = 0; i < n; i++) {
            records[i] = record(0x2000 + i, new byte[0]);
        }
        return records;
    }

    /** Firmware 2.x: 20 zero bytes, then one {@code >III} header and the records. */
    private static byte[] fw2(byte[]... records) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[MarvellAttestation.FW2_ATTRIBUTE_OFFSET]);
        out.writeBytes(ByteBuffer.allocate(12).putInt(0).putInt(records.length).putInt(0).array());
        for (byte[] r : records) {
            out.writeBytes(r);
        }
        return out.toByteArray();
    }

    private static byte[] signed(byte[] data) throws Exception {
        return MarvellBlobs.signed(data, partitionKp.getPrivate());
    }

    private static byte[] signed(byte[] data, PrivateKey key, String alg) throws Exception {
        Signature s = Signature.getInstance(alg);
        s.initSign(key);
        s.update(data);
        return concat(data, s.sign());
    }

    /**
     * Varies the first data byte (zero padding in both layouts' headers is
     * not read) until SHA-256 of the data is a 32-byte positive integer, so
     * that the raw value H itself is a 32-byte big-endian number.
     */
    private static byte[] hashWithTopBitClear(byte[] data) throws Exception {
        byte[] d = data.clone();
        while (true) {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(d);
            if (h[0] > 0) {
                return d;
            }
            d[0]++;
        }
    }

    /** Textbook RSA over the bare SHA-256: s = H^d mod n, no padding. */
    private static byte[] rawSignature(byte[] data, KeyPair kp) throws Exception {
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
        BigInteger h = new BigInteger(1, MessageDigest.getInstance("SHA-256").digest(data));
        byte[] s = MarvellBlobs.unsigned(h.modPow(priv.getPrivateExponent(), priv.getModulus()));
        byte[] sig = new byte[MarvellAttestation.SIGNATURE_SIZE];
        System.arraycopy(s, 0, sig, sig.length - s.length, s.length);
        return sig;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static X509Certificate selfSigned(KeyPair kp, String cn, String alg) throws Exception {
        X500Name name = new X500Name("CN=" + cn);
        long now = System.currentTimeMillis();
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), new Date(now - 60_000L),
                new Date(now + 3_600_000L), name, kp.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder(alg).build(kp.getPrivate())));
    }
}
