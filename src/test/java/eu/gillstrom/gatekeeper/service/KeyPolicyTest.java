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
}
