package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.verification.NShieldVerifierTest.Nc;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Edge cases of {@link NShieldVerifier}: the {@link HsmAttestationVerifier}
 * methods, an out-of-range nCore signature, the DDDS tag ranges and nesting
 * bound, and NUL in an nCore string.
 */
class NShieldVerifierMutationTest {

    @Test
    @DisplayName("Vendor, model and serial; the X.509 attestation and chain checks never pass")
    void verifierIdentity() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = TestPki.selfSignedCa(kp, "NSHIELD");
        NShieldVerifier v = new NShieldVerifier();
        assertThat(v.getVendor()).isEqualTo(HsmVendor.ENTRUST);
        assertThat(v.extractModel(cert)).isEqualTo("Entrust nShield");
        assertThat(v.extractSerialNumber(cert)).isEqualTo(cert.getSerialNumber().toString(16));
        assertThat(v.verifyAttestation(cert, kp.getPublic())).isFalse();
        assertThat(v.verifyChain(cert, new X509Certificate[] {cert})).isFalse();
    }

    @Test
    @DisplayName("A DSA signature whose r or s is out of range does not verify")
    void outOfRangeDsaSignature() throws Exception {
        KeyPair dsa = NShieldVerifierTest.dsa();
        NShieldVerifier.KeyData key = NShieldVerifier.keyData(new NShieldVerifier.In(Nc.key(dsa.getPublic())), true);
        byte[] message = "module state".getBytes(StandardCharsets.US_ASCII);
        assertThat(NShieldVerifier.verify(key, Nc.sign(dsa.getPrivate(), message), message)).isTrue();

        BigInteger q = ((DSAPublicKey) dsa.getPublic()).getParams().getQ();
        for (BigInteger[] rs : List.of(new BigInteger[] {BigInteger.ZERO, BigInteger.ONE},
                new BigInteger[] {BigInteger.ONE, BigInteger.ZERO},
                new BigInteger[] {q, BigInteger.ONE})) {
            byte[] sig = Nc.cat(Nc.w(NShieldVerifier.MECH_DSA_SHA256), Nc.bn(rs[0]), Nc.bn(rs[1]));
            assertThat(NShieldVerifier.verify(key, sig, message)).isFalse();
        }
    }

    @Test
    @DisplayName("DDDS: the first tag of each range opens it, the first after it is outside")
    void dddsTagRanges() throws Exception {
        assertThat(NShieldVerifier.Ddds.decode(new byte[] {0x20})).isEqualTo("");
        assertThat(NShieldVerifier.Ddds.decode(new byte[] {0x30})).isEqualTo(new NShieldVerifier.Ddds.Sym(""));
        assertThat(NShieldVerifier.Ddds.decode(new byte[] {(byte) 0x90})).isEqualTo(List.of());
        assertThat(NShieldVerifier.Ddds.decode(new byte[] {(byte) 0xb0})).isEqualTo(Map.of());
        assertThat(NShieldVerifier.Ddds.decode(new byte[] {0x2f, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                'k', 'l', 'm', 'n', 'o'})).isEqualTo("abcdefghijklmno");
        assertThat(NShieldVerifier.Ddds.decode(new byte[] {(byte) 0x9f, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                14})).isInstanceOf(List.class).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.LIST).hasSize(15);
        for (int tag : List.of(0x40, 0xa0)) {
            assertThatThrownBy(() -> NShieldVerifier.Ddds.decode(new byte[] {(byte) tag}))
                    .isInstanceOf(NShieldVerifier.Refusal.class)
                    .hasMessage("unsupported DDDS tag 0x" + Integer.toHexString(tag));
        }
    }

    @Test
    @DisplayName("DDDS: map keys, map values and integers each count towards the nesting bound of 8")
    void dddsNestingThroughMapsAndIntegers() throws Exception {
        // Nine maps, each the key of the one before.
        byte[] keys = new byte[9];
        Arrays.fill(keys, (byte) 0xb1);
        assertTooDeep(keys);

        // Nine maps, each the value of the one before under the key 1.
        byte[] values = new byte[18];
        for (int i = 0; i < 9; i++) {
            values[2 * i] = (byte) 0xb1;
            values[2 * i + 1] = 0x01;
        }
        assertTooDeep(values);
        // Eight levels of maps are within the bound.
        byte[] eight = new byte[17];
        System.arraycopy(values, 0, eight, 0, 16);
        eight[16] = 0x05;
        assertThat(NShieldVerifier.Ddds.decode(eight)).isInstanceOf(Map.class);

        // An integer inside eight lists: its byte block would be the ninth level.
        byte[] integer = {(byte) 0x91, (byte) 0x91, (byte) 0x91, (byte) 0x91, (byte) 0x91, (byte) 0x91, (byte) 0x91,
                (byte) 0x91, (byte) 0xf4, (byte) 0xc5, 0x01, 0x05};
        assertTooDeep(integer);
        byte[] shallower = Arrays.copyOfRange(integer, 1, integer.length);
        assertThat(NShieldVerifier.Ddds.decode(shallower)).isInstanceOf(List.class);
    }

    private static void assertTooDeep(byte[] b) {
        assertThatThrownBy(() -> NShieldVerifier.Ddds.decode(b))
                .isInstanceOf(NShieldVerifier.Refusal.class).hasMessage("DDDS nesting too deep");
    }

    @Test
    @DisplayName("An nCore string that starts with NUL is refused")
    void leadingNulInString() {
        var in = new NShieldVerifier.In(Nc.cat(Nc.w(3), new byte[] {0, 'a', 0}, new byte[1]));
        assertThatThrownBy(in::string).isInstanceOf(NShieldVerifier.Refusal.class).hasMessage("string contains NUL");
    }
}
