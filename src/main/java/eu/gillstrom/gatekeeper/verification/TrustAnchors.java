package eu.gillstrom.gatekeeper.verification;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The trust anchors the vendor verifiers start from, and where each one came
 * from.
 *
 * <p>Every anchor is pinned in its verifier's source (the "Pinned trust
 * anchor" comment blocks, checked by {@code TrustAnchorPinningTest}). An
 * operator that must obtain the manufacturers' roots from the manufacturers
 * themselves can replace any of them, without a code change, by naming a PEM
 * file for its key: {@link #YUBICO}, {@link #SECUROSYS}, {@link #MARVELL},
 * {@link #GOOGLE_OWNER}, {@link #THALES}, {@link #CRYPTO4A}, {@link #FORTANIX}
 * or {@link #ENTRUST}. The application binds these keys under its own
 * property prefix and calls {@link #load}; the verifiers then start from the
 * file instead of the constant. A key that is not named, or named with an
 * empty value, keeps the pinned constant, parsed by the same code as the
 * verifiers' no-argument constructors, so verification is unchanged.</p>
 *
 * <p>What a file must hold:</p>
 * <ul>
 * <li>{@code marvell}: one or more PEM certificates; they replace both pinned
 * Marvell roots, for the Azure, Google and Marvell verifiers.</li>
 * <li>{@code entrust}: one PEM {@code PUBLIC KEY} (DER SubjectPublicKeyInfo)
 * on NIST P-521, in the named-curve, uncompressed-point encoding the pinned
 * KWARN-1 key has.</li>
 * <li>every other key: exactly one PEM certificate.</li>
 * </ul>
 *
 * <p>{@link #load} fails closed, with {@link IllegalStateException}, so the
 * application does not start, when a named file is missing, unreadable or
 * larger than {@value #MAX_FILE_SIZE} bytes; holds no PEM block, a block of
 * another type, a block that does not parse, or the wrong number of blocks;
 * holds a key of another type than the pinned anchor's (RSA, or EC on the
 * pinned anchor's curve) or an EC point that is not on that curve; or holds a
 * certificate that is not self-issued and self-signed (every pinned anchor
 * that is a certificate is a self-signed one). An unknown key is refused too,
 * so that a misspelt key cannot leave the pinned anchor in place unnoticed.</p>
 *
 * <p>For each file, {@link #load} logs its SHA-256 with the definition the
 * comment blocks use (of the DER certificate; for {@code entrust}, of the DER
 * SubjectPublicKeyInfo), and a WARN naming both values when it is not the
 * pinned anchor. {@link #forVendor} and {@link #all} report the active anchors
 * with their origin.</p>
 */
public final class TrustAnchors {

    private static final Logger log = LoggerFactory.getLogger(TrustAnchors.class);

    public static final String YUBICO = "yubico";
    public static final String SECUROSYS = "securosys";
    public static final String MARVELL = "marvell";
    public static final String GOOGLE_OWNER = "google-owner";
    public static final String THALES = "thales";
    public static final String CRYPTO4A = "crypto4a";
    public static final String FORTANIX = "fortanix";
    public static final String ENTRUST = "entrust";

    /** Every key, in the order the anchors are reported. */
    public static final List<String> KEYS = List.of(
            YUBICO, SECUROSYS, MARVELL, GOOGLE_OWNER, THALES, CRYPTO4A, FORTANIX, ENTRUST);

    /** {@link ActiveAnchor#origin()} of a constant from the verifier source. */
    public static final String ORIGIN_PINNED = "pinned";
    /** {@link ActiveAnchor#origin()} of an operator's file. */
    public static final String ORIGIN_OVERRIDE = "override";

    /** {@link ActiveAnchor#sha256Of()}: SHA-256 of the DER certificate. */
    public static final String SHA256_OF_CERTIFICATE = "DER certificate";
    /** {@link ActiveAnchor#sha256Of()}: SHA-256 of the DER SubjectPublicKeyInfo (a bare key). */
    public static final String SHA256_OF_PUBLIC_KEY = "DER SubjectPublicKeyInfo";

    /** Upper bound on an override file; a root certificate is a few kilobytes. */
    static final int MAX_FILE_SIZE = 1 << 20;

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----([^-]*)-----END ([A-Z0-9 ]+)-----");

    /**
     * One active anchor.
     *
     * @param anchor          the key: yubico, securosys, marvell, google-owner, thales, crypto4a,
     *                        fortanix or entrust
     * @param origin          {@value #ORIGIN_PINNED} or {@value #ORIGIN_OVERRIDE}
     * @param path            the override file, absolute and normalised; null when pinned
     * @param sha256Of        what {@code sha256} is computed over: {@value #SHA256_OF_CERTIFICATE}
     *                        or {@value #SHA256_OF_PUBLIC_KEY}, as in the comment blocks
     * @param sha256          one SHA-256 per certificate (one for a bare key), colon-separated
     *                        upper-case hex, in file order
     * @param publicKeySha256 SHA-256 of each certificate's (or the bare key's) DER
     *                        SubjectPublicKeyInfo, in the same form and order
     * @param subjects        RFC 2253 subject of each certificate; empty for a bare key
     * @param matchesPinned   whether {@code sha256} holds exactly the pinned anchor's values
     */
    public record ActiveAnchor(String anchor, String origin, String path, String sha256Of,
                               List<String> sha256, List<String> publicKeySha256, List<String> subjects,
                               boolean matchesPinned) {
    }

    /** An anchor: its certificates (none for a bare key), one key per certificate (or the bare key). */
    private record Anchor(List<X509Certificate> certificates, List<PublicKey> keys, ActiveAnchor active) {
    }

    /** The form of a key's anchor; {@code curve} is the EC curve, or null for RSA. */
    private enum Form {
        CERTIFICATE, CERTIFICATES, PUBLIC_KEY
    }

    private record Spec(Form form, String curve) {
    }

    private static Spec spec(String key) {
        return switch (key) {
            case YUBICO, SECUROSYS, GOOGLE_OWNER, THALES, FORTANIX -> new Spec(Form.CERTIFICATE, null);
            case MARVELL -> new Spec(Form.CERTIFICATES, null);
            case CRYPTO4A -> new Spec(Form.CERTIFICATE, "secp384r1");
            case ENTRUST -> new Spec(Form.PUBLIC_KEY, "secp521r1");
            default -> throw new IllegalArgumentException("unknown trust anchor " + key);
        };
    }

    private final Map<String, Anchor> anchors;

    private TrustAnchors(Map<String, Anchor> anchors) {
        this.anchors = anchors;
    }

    /** Every anchor pinned, as the verifiers' no-argument constructors have them. Logs nothing. */
    public static TrustAnchors pinned() {
        Map<String, Anchor> out = new LinkedHashMap<>();
        for (String key : KEYS) {
            out.put(key, pinnedAnchor(key));
        }
        return new TrustAnchors(out);
    }

    /**
     * The pinned anchors, with those {@code paths} names replaced by the
     * operator's files.
     *
     * @param paths          key to PEM file path; a null or blank value keeps the pinned anchor
     * @param propertyPrefix the application's property prefix for these keys, used in messages
     * @throws IllegalStateException when a key is unknown or a named file is refused
     */
    public static TrustAnchors load(Map<String, String> paths, String propertyPrefix) {
        Map<String, String> named = new LinkedHashMap<>();
        if (paths != null) {
            for (Map.Entry<String, String> e : paths.entrySet()) {
                String key = e.getKey() == null ? "" : e.getKey().trim().toLowerCase(Locale.ROOT);
                if (!KEYS.contains(key)) {
                    throw new IllegalStateException("Unknown trust anchor " + propertyPrefix + "." + e.getKey()
                            + "; the keys are " + String.join(", ", KEYS));
                }
                if (e.getValue() != null && !e.getValue().isBlank()) {
                    if (named.put(key, e.getValue().trim()) != null) {
                        throw new IllegalStateException("Trust anchor " + propertyPrefix + "." + key
                                + " is named more than once");
                    }
                }
            }
        }
        Map<String, Anchor> out = new LinkedHashMap<>();
        for (String key : KEYS) {
            Anchor pinned = pinnedAnchor(key);
            out.put(key, named.containsKey(key)
                    ? override(key, named.get(key), propertyPrefix + "." + key, pinned)
                    : pinned);
        }
        if (named.isEmpty()) {
            log.debug("Trust anchors: every anchor is the pinned one");
        }
        return new TrustAnchors(out);
    }

    // ------------------------------------------------------------- accessors

    X509Certificate yubicoRoot() {
        return anchors.get(YUBICO).certificates().get(0);
    }

    X509Certificate securosysRoot() {
        return anchors.get(SECUROSYS).certificates().get(0);
    }

    List<X509Certificate> marvellRoots() {
        return anchors.get(MARVELL).certificates();
    }

    X509Certificate googleOwnerRoot() {
        return anchors.get(GOOGLE_OWNER).certificates().get(0);
    }

    PublicKey thalesRootKey() {
        return anchors.get(THALES).keys().get(0);
    }

    PublicKey crypto4aRootKey() {
        return anchors.get(CRYPTO4A).keys().get(0);
    }

    X509Certificate fortanixRoot() {
        return anchors.get(FORTANIX).certificates().get(0);
    }

    PublicKey entrustRootKey() {
        return anchors.get(ENTRUST).keys().get(0);
    }

    /** The active anchor for {@code key}. */
    public ActiveAnchor active(String key) {
        Anchor a = anchors.get(key);
        if (a == null) {
            throw new IllegalArgumentException("unknown trust anchor " + key);
        }
        return a.active();
    }

    /** Every active anchor, in {@link #KEYS} order. */
    public List<ActiveAnchor> all() {
        return anchors.values().stream().map(Anchor::active).toList();
    }

    /** The anchors {@code vendor}'s verifier starts from. */
    public List<ActiveAnchor> forVendor(HsmVendor vendor) {
        return switch (vendor) {
            case YUBICO -> List.of(active(YUBICO));
            case SECUROSYS -> List.of(active(SECUROSYS));
            case AZURE, MARVELL -> List.of(active(MARVELL));
            case GOOGLE -> List.of(active(MARVELL), active(GOOGLE_OWNER));
            case THALES -> List.of(active(THALES));
            case CRYPTO4A -> List.of(active(CRYPTO4A));
            case FORTANIX -> List.of(active(FORTANIX));
            case ENTRUST -> List.of(active(ENTRUST));
        };
    }

    // ---------------------------------------------------------------- pinned

    /** The pinned anchor, parsed and checked as the verifier's no-argument constructor does. */
    private static Anchor pinnedAnchor(String key) {
        List<X509Certificate> certificates = switch (key) {
            case YUBICO -> List.of(YubicoVerifier.pinnedRoot());
            case SECUROSYS -> List.of(SecurosysVerifier.pinnedRoot());
            case MARVELL -> MarvellAttestation.marvellRoots();
            case GOOGLE_OWNER -> List.of(MarvellAttestation.certificate(GoogleCloudHsmVerifier.HAWKSBILL_ROOT_PEM));
            case THALES -> List.of(pinnedByKey(ThalesLunaVerifier.CHRYSALIS_ROOT_PEM,
                    ThalesLunaVerifier.CHRYSALIS_ROOT_KEY_SHA256, "Pinned Chrysalis-ITS Root key"));
            case CRYPTO4A -> List.of(pinnedByKey(Crypto4AVerifier.C4A_ROOT_PEM,
                    Crypto4AVerifier.C4A_ROOT_KEY_SHA256, "Pinned C4A_RCA key"));
            case FORTANIX -> List.of(pinnedByKey(FortanixVerifier.FORTANIX_ROOT_PEM,
                    FortanixVerifier.FORTANIX_ROOT_KEY_SHA256, "Pinned Fortanix root key"));
            case ENTRUST -> List.of();
            default -> throw new IllegalArgumentException("unknown trust anchor " + key);
        };
        List<PublicKey> keys = ENTRUST.equals(key)
                ? List.of(NShieldVerifier.ecKey("secp521r1", NShieldVerifier.KWARN_1_X, NShieldVerifier.KWARN_1_Y))
                : certificates.stream().map(X509Certificate::getPublicKey).toList();
        return new Anchor(certificates, keys, describe(key, ORIGIN_PINNED, null, certificates, keys, null));
    }

    private static X509Certificate pinnedByKey(String pem, String keySha256, String what) {
        X509Certificate c = MarvellAttestation.certificate(pem);
        if (!keySha256.equals(ThalesLunaVerifier.sha256(c.getPublicKey().getEncoded()))) {
            throw new IllegalStateException(what + " does not match its fingerprint");
        }
        return c;
    }

    // -------------------------------------------------------------- override

    private static Anchor override(String key, String configured, String property, Anchor pinned) {
        Path path;
        try {
            path = Path.of(configured).toAbsolutePath().normalize();
        } catch (java.nio.file.InvalidPathException e) {
            throw new IllegalStateException("Trust anchor " + property + ": " + configured + " is not a path", e);
        }
        String where = "Trust anchor " + property + " (" + path + ")";
        Spec spec = spec(key);
        List<String[]> blocks = pemBlocks(read(path, where), where);
        String expectedType = spec.form() == Form.PUBLIC_KEY ? "PUBLIC KEY" : "CERTIFICATE";
        for (String[] b : blocks) {
            if (!expectedType.equals(b[0])) {
                throw new IllegalStateException(where + ": holds a PEM " + b[0] + " block; expected "
                        + (spec.form() == Form.CERTIFICATES ? "one or more" : "exactly one") + " PEM "
                        + expectedType + " block" + (spec.form() == Form.CERTIFICATES ? "s" : ""));
            }
        }
        if (spec.form() != Form.CERTIFICATES && blocks.size() != 1) {
            throw new IllegalStateException(where + ": holds " + blocks.size() + " PEM " + expectedType
                    + " blocks; expected exactly one");
        }

        List<X509Certificate> certificates = new ArrayList<>();
        List<PublicKey> keys = new ArrayList<>();
        if (spec.form() == Form.PUBLIC_KEY) {
            keys.add(publicKey(decode(blocks.get(0)[1], where), spec.curve(), where));
        } else {
            Set<String> seen = new HashSet<>();
            for (String[] b : blocks) {
                X509Certificate c = certificate(decode(b[1], where), where);
                String subject = c.getSubjectX500Principal().getName();
                PublicKey checked = requireKeyType(c.getPublicKey(), spec.curve(), where + ", certificate " + subject);
                requireSelfSigned(c, where + ", certificate " + subject);
                if (!seen.add(fingerprint(der(c)))) {
                    throw new IllegalStateException(where + ": certificate " + subject + " appears twice");
                }
                certificates.add(c);
                keys.add(checked);
            }
        }
        ActiveAnchor active = describe(key, ORIGIN_OVERRIDE, path.toString(), certificates, keys, pinned.active());
        logOverride(property, active, pinned.active(), certificates);
        return new Anchor(List.copyOf(certificates), List.copyOf(keys), active);
    }

    private static byte[] read(Path path, String where) {
        try {
            if (!Files.exists(path)) {
                throw new IllegalStateException(where + ": no such file");
            }
            if (!Files.isRegularFile(path)) {
                throw new IllegalStateException(where + ": not a regular file");
            }
            if (Files.size(path) > MAX_FILE_SIZE) {
                throw new IllegalStateException(where + ": larger than " + MAX_FILE_SIZE + " bytes");
            }
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new IllegalStateException(where + ": cannot be read: " + e.getMessage(), e);
        }
    }

    /** Each PEM block as {type, base64 body}; text outside the blocks is ignored. */
    private static List<String[]> pemBlocks(byte[] file, String where) {
        String text = new String(file, StandardCharsets.ISO_8859_1);
        List<String[]> out = new ArrayList<>();
        Matcher m = PEM_BLOCK.matcher(text);
        while (m.find()) {
            if (!m.group(1).equals(m.group(3))) {
                throw new IllegalStateException(where + ": PEM block BEGIN " + m.group(1) + " ends with END "
                        + m.group(3));
            }
            out.add(new String[] {m.group(1), m.group(2)});
        }
        int begins = text.split("-----BEGIN ", -1).length - 1;
        if (out.isEmpty()) {
            throw new IllegalStateException(where + ": holds no PEM block"
                    + (begins == 0 ? " (a DER file must first be converted to PEM)" : " that parses"));
        }
        if (begins != out.size()) {
            throw new IllegalStateException(where + ": holds a PEM block that does not parse");
        }
        return out;
    }

    private static byte[] decode(String body, String where) {
        try {
            return Base64.getDecoder().decode(body.replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(where + ": a PEM block is not valid base64", e);
        }
    }

    private static X509Certificate certificate(byte[] der, String where) {
        X509Certificate c;
        try {
            c = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException(where + ": a certificate does not parse: " + e.getMessage(), e);
        }
        if (!Arrays.equals(der(c), der)) {
            throw new IllegalStateException(where + ": a certificate block carries bytes beyond the certificate");
        }
        return c;
    }

    private static byte[] der(X509Certificate c) {
        try {
            return c.getEncoded();
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException("certificate " + c.getSubjectX500Principal() + " does not encode", e);
        }
    }

    /** A bare key: an EC SubjectPublicKeyInfo on {@code curve}, encoded as the JDK encodes such a key. */
    private static PublicKey publicKey(byte[] der, String curve, String where) {
        SubjectPublicKeyInfo spki;
        try {
            spki = SubjectPublicKeyInfo.getInstance(der);
        } catch (Exception e) {
            throw new IllegalStateException(where + ": the PUBLIC KEY block does not parse: " + e.getMessage(), e);
        }
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(spki.getAlgorithm().getAlgorithm())) {
            throw new IllegalStateException(where + ": the key is of type " + spki.getAlgorithm().getAlgorithm()
                    + ", not an EC key (id-ecPublicKey) on " + curve);
        }
        PublicKey parsed;
        try {
            parsed = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException(where + ": the PUBLIC KEY block does not parse: " + e.getMessage(), e);
        }
        PublicKey key = requireKeyType(parsed, curve, where);
        if (!Arrays.equals(key.getEncoded(), der)) {
            throw new IllegalStateException(where + ": the PUBLIC KEY block is not the named-curve, "
                    + "uncompressed-point SubjectPublicKeyInfo of its key");
        }
        return key;
    }

    /**
     * Refuses a key whose type is not the pinned anchor's: RSA when
     * {@code curve} is null, else EC on {@code curve} with its point on the
     * curve. Returns the key, rebuilt from its point for an EC key.
     */
    private static PublicKey requireKeyType(PublicKey key, String curve, String where) {
        if (curve == null) {
            if (!(key instanceof RSAPublicKey)) {
                throw new IllegalStateException(where + ": the key is " + key.getAlgorithm()
                        + "; the pinned anchor's key is RSA");
            }
            return key;
        }
        if (!(key instanceof ECPublicKey ec)) {
            throw new IllegalStateException(where + ": the key is " + key.getAlgorithm()
                    + "; the pinned anchor's key is EC on " + curve);
        }
        if (!onNamedCurve(ec.getParams(), curve)) {
            throw new IllegalStateException(where + ": the EC key is not on " + curve
                    + ", the pinned anchor's curve");
        }
        try {
            return NShieldVerifier.ecKey(curve, ec.getW().getAffineX(), ec.getW().getAffineY());
        } catch (RuntimeException e) {
            throw new IllegalStateException(where + ": the EC point is not on " + curve, e);
        }
    }

    private static boolean onNamedCurve(ECParameterSpec params, String curve) {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec(curve));
            ECParameterSpec named = ap.getParameterSpec(ECParameterSpec.class);
            return named.getCurve().equals(params.getCurve())
                    && named.getGenerator().equals(params.getGenerator())
                    && named.getOrder().equals(params.getOrder())
                    && named.getCofactor() == params.getCofactor();
        } catch (Exception e) {
            throw new IllegalStateException("curve " + curve + " is not available", e);
        }
    }

    private static void requireSelfSigned(X509Certificate c, String where) {
        if (!c.getIssuerX500Principal().equals(c.getSubjectX500Principal())) {
            throw new IllegalStateException(where + ": not self-signed: issued by "
                    + c.getIssuerX500Principal().getName() + "; the pinned anchor is a self-signed certificate");
        }
        try {
            c.verify(c.getPublicKey());
        } catch (Exception e) {
            throw new IllegalStateException(where + ": not self-signed: its signature does not verify under its "
                    + "own key (" + e.getMessage() + "); the pinned anchor is a self-signed certificate", e);
        }
    }

    // ------------------------------------------------------------- reporting

    /** SHA-256 as the comment blocks write it: colon-separated upper-case hex. */
    static String fingerprint(byte[] der) {
        try {
            return HexFormat.ofDelimiter(":").withUpperCase()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ActiveAnchor describe(String key, String origin, String path, List<X509Certificate> certificates,
            List<PublicKey> keys, ActiveAnchor pinned) {
        List<String> sha256 = new ArrayList<>();
        List<String> subjects = new ArrayList<>();
        for (X509Certificate c : certificates) {
            sha256.add(fingerprint(der(c)));
            subjects.add(c.getSubjectX500Principal().getName());
        }
        List<String> keySha256 = keys.stream().map(k -> fingerprint(k.getEncoded())).toList();
        if (certificates.isEmpty()) {
            sha256.addAll(keySha256);
        }
        boolean matches = pinned == null
                || (sha256.size() == pinned.sha256().size() && Set.copyOf(sha256).equals(Set.copyOf(pinned.sha256())));
        return new ActiveAnchor(key, origin, path,
                certificates.isEmpty() ? SHA256_OF_PUBLIC_KEY : SHA256_OF_CERTIFICATE,
                List.copyOf(sha256), keySha256, List.copyOf(subjects), matches);
    }

    /** Logs an override: INFO with its SHA-256, and a WARN with both values when it is not the pinned anchor. */
    static void logOverride(String property, ActiveAnchor override, ActiveAnchor pinned,
            List<X509Certificate> certificates) {
        for (int i = 0; i < override.sha256().size(); i++) {
            String detail = certificates.isEmpty() ? "" : " (subject " + override.subjects().get(i)
                    + ", valid " + certificates.get(i).getNotBefore().toInstant()
                    + " to " + certificates.get(i).getNotAfter().toInstant() + ")";
            log.info("Trust anchor {}: override {}; SHA-256 of the {}: {}{}", property, override.path(),
                    override.sha256Of(), override.sha256().get(i), detail);
        }
        if (override.matchesPinned()) {
            log.info("Trust anchor {}: the override {} is the pinned anchor (SHA-256 {})", property,
                    override.path(), String.join(", ", pinned.sha256()));
            return;
        }
        String keys = "";
        if (!certificates.isEmpty()) {
            boolean sameKeys = override.publicKeySha256().size() == pinned.publicKeySha256().size()
                    && Set.copyOf(override.publicKeySha256()).equals(Set.copyOf(pinned.publicKeySha256()));
            keys = "; SHA-256 of the DER SubjectPublicKeyInfo: override " + String.join(", ", override.publicKeySha256())
                    + ", pinned " + String.join(", ", pinned.publicKeySha256())
                    + (sameKeys ? " (the same key" + (override.publicKeySha256().size() == 1 ? "" : "s") + ")"
                            : " (different)");
        }
        log.warn("Trust anchor {}: the override {} is NOT the pinned anchor. SHA-256 of the {}: override {}, "
                        + "pinned {}{}", property, override.path(), override.sha256Of(),
                String.join(", ", override.sha256()), String.join(", ", pinned.sha256()), keys);
    }
}
