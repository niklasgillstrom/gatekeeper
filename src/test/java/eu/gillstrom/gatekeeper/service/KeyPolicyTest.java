package eu.gillstrom.gatekeeper.service;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyPolicyTest {

    private static PublicKey rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair().getPublic();
    }

    private static PublicKey ec(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curve));
        return g.generateKeyPair().getPublic();
    }

    @Test
    void defaultAllowsRsa4096Only() throws Exception {
        KeyPolicy policy = KeyPolicy.defaults();
        assertThat(policy.violation(rsa(4096))).isEmpty();
        assertThat(policy.violation(rsa(2048))).contains("key RSA-2048 is not in the allowed keys [rsa-4096]");
        assertThat(policy.violation(rsa(3072))).contains("key RSA-3072 is not in the allowed keys [rsa-4096]");
        assertThat(policy.violation(ec("secp384r1"))).contains("key EC-secp384r1 is not in the allowed keys [rsa-4096]");
    }

    @Test
    void listIsCaseInsensitiveAndTrimmed() throws Exception {
        KeyPolicy policy = new KeyPolicy(" rsa-4096 , EC-SECP256R1 ,");
        assertThat(policy.violation(rsa(4096))).isEmpty();
        assertThat(policy.violation(ec("secp256r1"))).isEmpty();
        assertThat(policy.violation(ec("secp384r1"))).isPresent();
    }

    @Test
    void anEmptyListIsRefused() {
        assertThatThrownBy(() -> new KeyPolicy(" , ")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new KeyPolicy(null)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void fipsApprovedModeIsNotRequiredByDefaultAndThenOnlyYubicoCanMeetIt() {
        for (KeyPolicy off : new KeyPolicy[] {KeyPolicy.defaults(), new KeyPolicy("RSA-4096"),
                new KeyPolicy("RSA-4096", false)}) {
            assertThat(off.requiresFipsApprovedMode()).isFalse();
            for (eu.gillstrom.gatekeeper.model.HsmVendor v : eu.gillstrom.gatekeeper.model.HsmVendor.values()) {
                assertThat(off.fipsModeViolation(v, null)).as(v.name()).isEmpty();
                assertThat(off.fipsModeViolation(v, Boolean.FALSE)).as(v.name()).isEmpty();
            }
        }
        KeyPolicy on = new KeyPolicy("RSA-4096", true);
        assertThat(on.requiresFipsApprovedMode()).isTrue();
        for (eu.gillstrom.gatekeeper.model.HsmVendor v : eu.gillstrom.gatekeeper.model.HsmVendor.values()) {
            if (v == eu.gillstrom.gatekeeper.model.HsmVendor.YUBICO) {
                assertThat(on.fipsModeViolation(v, Boolean.TRUE)).isEmpty();
                assertThat(on.fipsModeViolation(v, Boolean.FALSE)).get().asString()
                        .startsWith(KeyPolicy.FIPS_APPROVED_MODE_NOT_ATTESTED + ": ");
                assertThat(on.fipsModeViolation(v, null)).get().asString()
                        .startsWith(KeyPolicy.FIPS_APPROVED_MODE_NOT_ATTESTED + ": ");
            } else {
                // A statement passed for another vendor does not count: its format has none this verifier reads.
                assertThat(on.fipsModeViolation(v, Boolean.TRUE)).as(v.name()).get().asString()
                        .startsWith(KeyPolicy.FIPS_MODE_NOT_IN_ATTESTATION_FORMAT + ": ");
            }
        }
    }
}
