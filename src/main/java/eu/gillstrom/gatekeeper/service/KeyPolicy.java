package eu.gillstrom.gatekeeper.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Which keys a verification may find compliant.
 *
 * <p>Keys are named {@code RSA-<modulus bits>} or {@code EC-<curve name>}
 * (e.g. {@code RSA-4096}, {@code EC-secp384r1}), as in the hsm service's key
 * policy; comparison ignores case. The list is an exact allow-list: a key not
 * named is NON-COMPLIANT whatever its attestation shows.</p>
 *
 * <p>The default admits RSA-4096 only, the key that Swish signing
 * certificates use. A deployment for another scheme names its keys in
 * {@code gatekeeper.key-policy.allowed-keys}.</p>
 */
@Component
public class KeyPolicy {

    public static final String DEFAULT_ALLOWED_KEYS = "RSA-4096";

    private final Set<String> allowedKeys;

    public KeyPolicy(@Value("${gatekeeper.key-policy.allowed-keys:" + DEFAULT_ALLOWED_KEYS + "}") String allowedKeys) {
        this.allowedKeys = Arrays.stream(allowedKeys == null ? new String[0] : allowedKeys.split(","))
                .map(s -> s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
        if (this.allowedKeys.isEmpty()) {
            throw new IllegalStateException("gatekeeper.key-policy.allowed-keys must name at least one key");
        }
    }

    /** The default policy: RSA-4096. */
    public static KeyPolicy defaults() {
        return new KeyPolicy(DEFAULT_ALLOWED_KEYS);
    }

    /** @return a description of the violation, or empty if the key is allowed */
    public Optional<String> violation(PublicKey publicKey) {
        String key = describeKey(publicKey);
        if (!allowedKeys.contains(key.toLowerCase(Locale.ROOT))) {
            return Optional.of("key " + key + " is not in the allowed keys " + allowedKeys);
        }
        return Optional.empty();
    }

    static String describeKey(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsa) {
            return "RSA-" + rsa.getModulus().bitLength();
        }
        AlgorithmIdentifier alg = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm();
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(alg.getAlgorithm())
                && alg.getParameters() instanceof ASN1ObjectIdentifier curve) {
            // Prefer the SEC name (secp256r1) over the X9.62 one (prime256v1).
            String name = SECNamedCurves.getName(curve);
            if (name == null) {
                name = ECNamedCurveTable.getName(curve);
            }
            return "EC-" + (name != null ? name : curve.getId());
        }
        return alg.getAlgorithm().getId();
    }
}
