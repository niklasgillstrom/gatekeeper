package eu.gillstrom.gatekeeper.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

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
 *
 * <p>{@code gatekeeper.key-policy.require-fips-approved-mode} (default false)
 * additionally requires that the HSM attestation itself states that the HSM
 * operates in FIPS-approved mode; see {@link #fipsModeViolation}.</p>
 */
@Component
public class KeyPolicy {

    public static final String DEFAULT_ALLOWED_KEYS = "RSA-4096";

    public static final String REQUIRE_FIPS_APPROVED_MODE_PROPERTY = "gatekeeper.key-policy.require-fips-approved-mode";
    /** Error code: the vendor format can state FIPS-approved mode, but this attestation does not state it as true. */
    public static final String FIPS_APPROVED_MODE_NOT_ATTESTED = "FIPS_APPROVED_MODE_NOT_ATTESTED";
    /** Error code: this verifier reads no FIPS-approved-mode statement from the vendor's attestation format. */
    public static final String FIPS_MODE_NOT_IN_ATTESTATION_FORMAT = "FIPS_MODE_NOT_IN_ATTESTATION_FORMAT";

    private final Set<String> allowedKeys;
    private final boolean requireFipsApprovedMode;

    /** A policy that does not require FIPS-approved mode. */
    public KeyPolicy(String allowedKeys) {
        this(allowedKeys, false);
    }

    @Autowired
    public KeyPolicy(@Value("${gatekeeper.key-policy.allowed-keys:" + DEFAULT_ALLOWED_KEYS + "}") String allowedKeys,
            @Value("${" + REQUIRE_FIPS_APPROVED_MODE_PROPERTY + ":false}") boolean requireFipsApprovedMode) {
        this.requireFipsApprovedMode = requireFipsApprovedMode;
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

    /** Whether an attestation must state that the HSM operates in FIPS-approved mode. */
    public boolean requiresFipsApprovedMode() {
        return requireFipsApprovedMode;
    }

    /**
     * The FIPS-approved-mode requirement, applied to one attestation.
     *
     * <p>Of the supported formats, only Yubico's carries a statement this
     * verifier reads: extension {@code 1.3.6.1.4.1.41482.4.12} (BOOLEAN,
     * "FIPS-approved"). For every other vendor the requirement cannot be met
     * from the attestation.</p>
     *
     * @param vendor           the attestation's vendor
     * @param fipsApprovedMode the statement as attested by a chain that
     *                         validated to the pinned root, or null when there
     *                         is none
     * @return a description of the violation, or empty when the requirement is
     *         off or met
     */
    public Optional<String> fipsModeViolation(HsmVendor vendor, Boolean fipsApprovedMode) {
        if (!requireFipsApprovedMode) {
            return Optional.empty();
        }
        if (vendor != HsmVendor.YUBICO) {
            return Optional.of(FIPS_MODE_NOT_IN_ATTESTATION_FORMAT + ": the " + vendor.getVendorName()
                    + " attestation, as this verifier reads it, carries no statement that the HSM operates in "
                    + "FIPS-approved mode, which " + REQUIRE_FIPS_APPROVED_MODE_PROPERTY + "=true requires");
        }
        if (Boolean.TRUE.equals(fipsApprovedMode)) {
            return Optional.empty();
        }
        return Optional.of(FIPS_APPROVED_MODE_NOT_ATTESTED + ": the Yubico attestation "
                + (fipsApprovedMode == null
                        ? "carries no attested FIPS-approved flag (1.3.6.1.4.1.41482.4.12)"
                        : "states FIPS-approved mode false (1.3.6.1.4.1.41482.4.12)")
                + ", and " + REQUIRE_FIPS_APPROVED_MODE_PROPERTY + "=true requires it to be true");
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
