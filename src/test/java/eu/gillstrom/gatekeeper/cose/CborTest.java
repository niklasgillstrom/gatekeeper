package eu.gillstrom.gatekeeper.cose;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link Cbor} against RFC 8949 Appendix A examples and the §4.2.1 deterministic rules. */
class CborTest {

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    @Test
    void integersUseTheShortestHead() {
        assertThat(hex(Cbor.integer(0))).isEqualTo("00");
        assertThat(hex(Cbor.integer(23))).isEqualTo("17");
        assertThat(hex(Cbor.integer(24))).isEqualTo("1818");
        assertThat(hex(Cbor.integer(255))).isEqualTo("18ff");
        assertThat(hex(Cbor.integer(256))).isEqualTo("190100");
        assertThat(hex(Cbor.integer(65535))).isEqualTo("19ffff");
        assertThat(hex(Cbor.integer(65536))).isEqualTo("1a00010000");
        assertThat(hex(Cbor.integer(0xffffffffL))).as("the largest four-byte argument").isEqualTo("1affffffff");
        assertThat(hex(Cbor.integer(0x100000000L))).isEqualTo("1b0000000100000000");
        assertThat(hex(Cbor.integer(1_000_000_000_000L))).isEqualTo("1b000000e8d4a51000");
        assertThat(hex(Cbor.integer(-1))).isEqualTo("20");
        assertThat(hex(Cbor.integer(-7))).isEqualTo("26");
        assertThat(hex(Cbor.integer(-35))).isEqualTo("3822");
        assertThat(hex(Cbor.integer(-257))).isEqualTo("390100");
        assertThat(hex(Cbor.integer(Long.MIN_VALUE))).isEqualTo("3b7fffffffffffffff");
    }

    @Test
    void stringsArraysTagsAndSimpleValues() {
        assertThat(hex(Cbor.text(""))).isEqualTo("60");
        assertThat(hex(Cbor.text("IETF"))).isEqualTo("6449455446");
        assertThat(hex(Cbor.text("ü"))).isEqualTo("62c3bc");
        assertThat(hex(Cbor.bytes(new byte[] {1, 2, 3, 4}))).isEqualTo("4401020304");
        assertThat(hex(Cbor.bytes(new byte[0]))).isEqualTo("40");
        assertThat(hex(Cbor.array(Cbor.integer(1), Cbor.integer(2), Cbor.integer(3)))).isEqualTo("83010203");
        assertThat(hex(Cbor.tag(18, Cbor.array()))).isEqualTo("d280");
        assertThat(hex(Cbor.bool(false))).isEqualTo("f4");
        assertThat(hex(Cbor.bool(true))).isEqualTo("f5");
        assertThat(hex(Cbor.nul())).isEqualTo("f6");
        assertThat(hex(Cbor.text("a".repeat(24)))).startsWith("7818");
    }

    @Test
    void mapKeysAreSortedByTheirEncodingAndDuplicatesRefused() {
        byte[] m = Cbor.map()
                .put("b", Cbor.integer(1))
                .put("aa", Cbor.integer(2))
                .put(10, Cbor.integer(3))
                .put(-1, Cbor.integer(4))
                .put("a", Cbor.integer(5))
                .build();
        // 0a < 20 < 6161 ("a") < 6162 ("b") < 626161 ("aa"): shorter text first.
        assertThat(hex(m)).isEqualTo("a5" + "0a03" + "2004" + "616105" + "616201" + "62616102");

        assertThatThrownBy(() -> Cbor.map().put("k", Cbor.integer(1)).put("k", Cbor.integer(2)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(hex(Cbor.map().build())).isEqualTo("a0");
    }

    @Test
    void theDecoderReadsBackWhatTheEncoderWrites() {
        byte[] encoded = Cbor.tag(18, Cbor.array(Cbor.bytes(new byte[] {9}),
                Cbor.map().put(1, Cbor.integer(-257)).put("x", Cbor.text("y")).build(),
                Cbor.bool(true), Cbor.nul(), Cbor.integer(1L << 40)));
        CborDecoder d = new CborDecoder(encoded);
        Object item = d.next();

        assertThat(d.atEnd()).isTrue();
        assertThat(d.allShortest()).isTrue();
        CborDecoder.Tagged tagged = (CborDecoder.Tagged) item;
        assertThat(tagged.tag()).isEqualTo(18);
        List<?> array = (List<?>) tagged.value();
        assertThat((byte[]) array.get(0)).containsExactly(9);
        @SuppressWarnings("unchecked")
        Map<Object, Object> map = (Map<Object, Object>) array.get(1);
        assertThat(map).containsEntry(1L, -257L).containsEntry("x", "y");
        assertThat(array.get(2)).isEqualTo(true);
        assertThat(array.get(3)).isNull();
        assertThat(array.get(4)).isEqualTo(1L << 40);
    }

    @Test
    void anEcdsaDerSignatureBecomesFixedLengthRAndS() throws Exception {
        // r has a leading zero byte in DER (high bit set), s is short.
        BigInteger r = new BigInteger(1, HexFormat.of().parseHex("ff" + "00".repeat(31)));
        BigInteger s = BigInteger.valueOf(5);
        byte[] der = new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                new org.bouncycastle.asn1.ASN1Integer(r), new org.bouncycastle.asn1.ASN1Integer(s)}).getEncoded();

        byte[] raw = CoseSign1.derToRaw(der, 32);

        assertThat(raw).hasSize(64);
        assertThat(hex(raw)).isEqualTo("ff" + "00".repeat(31) + "00".repeat(31) + "05");
        assertThatThrownBy(() -> CoseSign1.derToRaw(der, 16)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theAlgorithmMapping() {
        assertThat(CoseSign1.algorithmId("SHA256withRSA")).isEqualTo(-257);
        assertThat(CoseSign1.algorithmId("SHA384withRSA")).isEqualTo(-258);
        assertThat(CoseSign1.algorithmId("SHA512withRSA")).isEqualTo(-259);
        assertThat(CoseSign1.algorithmId("SHA256withECDSA")).isEqualTo(-7);
        assertThat(CoseSign1.algorithmId("SHA384withECDSA")).isEqualTo(-35);
        assertThat(CoseSign1.algorithmId("SHA512withECDSA")).isEqualTo(-36);
        assertThatThrownBy(() -> CoseSign1.algorithmId("SHA1withRSA"))
                .isInstanceOf(CoseSign1.UnsupportedAlgorithmException.class);
    }
}
