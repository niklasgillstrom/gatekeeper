package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Entrust nShield key attestation bundle verifier.
 *
 * <p>Follows Entrust's "Verifying an attestation bundle" (nShield key
 * attestation application note). The input is the JSON bundle that
 * {@code nfkmattest} writes: base64url fields {@code warrant},
 * {@code modstatemsg}/{@code modstatesig}, {@code knsopub}, the world
 * binding certificates, {@code kcmsg}/{@code kcsig} and {@code pubkeydata}.</p>
 *
 * <ol>
 * <li>WV1: the warrant, a DDDS list, must chain from the pinned KWARN-1 key
 * (ECDSA P-521, SHA-512, {@code r || s}) through Delegation certificates to a
 * module information certificate, which yields the module's KLF2 key and
 * electronic serial number (ESN).</li>
 * <li>MSCV1-5: the module state certificate must be signed by KLF2 and name
 * the warrant's ESN, the module's KML key, the hash of its security officer's
 * key (HKNSO) and its module key list; {@code knsopub} must hash to HKNSO and
 * {@code hkm} must be in the list.</li>
 * <li>WBCV1-5: the world binding certificate (CertKMaKMCbKNSO or its FIPS
 * variant) must verify under {@code knsopub}; only then is {@code hkm}
 * trusted. CertKREaKRAbKNSO is verified when present.</li>
 * <li>KGCV1-2: the key generation certificate {@code kcmsg} must be signed by
 * KML, and its key hash must be the hash of {@code pubkeydata}.</li>
 * <li>ACL: the generation-time ACL is read in full and refused on anything
 * this verifier does not recognise. A permission group certified by the
 * security officer's key ("trump ops") or a MakeArchiveBlob action makes the
 * key recoverable: the holders of the Administrator Card Set can then load
 * and use it without the key's own protection, which is a human factor, so a
 * recoverable key is refused. ExportAsPlain, SetAppData, ExpandACL,
 * UseAsBlobKey, UseAsKM and UseAsLoaderKey are refused, as Entrust lists them
 * as forbidden. Working blobs must be under the trusted module key.</li>
 * <li>CSRL1: {@code pubkeydata} must be the CSR key.</li>
 * </ol>
 *
 * <p>Key hashes are computed as in Entrust's "Construction of nCore key
 * hashes" for RSA (public exponent of at most 32 bits), DSA and ECDSA on
 * NIST P-256; other key types are refused. Only {@code ModuleInformation}
 * warrants are accepted: Entrust states that
 * {@code FieldUpgradeModuleInformation} certificates "depend on signatures
 * made using legacy DSA-1024 keys, limiting their security", and NIST SP
 * 800-131A no longer allows signatures to be made with DSA-1024.</p>
 */
@Component
public class NShieldVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(NShieldVerifier.class);

    /** Name of the nShield warrant root key. */
    static final String KWARN_1 = "KWARN-1";
    /** KWARN-1, ECDSA NIST P-521, as published by Entrust ("nShield root key"). */
    static final BigInteger KWARN_1_X = new BigInteger(
            "1d21dfde6d7e001c5a4f78ae8d2f799e0caf79c60d673d0da88b206a3ba52f20dce0956ce02f01af32736767c8b9feff398c29e0208527371856aa2f40fcae61d96", 16);
    static final BigInteger KWARN_1_Y = new BigInteger(
            "1641ca5472f06257de815ae06b33e1b868c149645f55fb7c91738014d3d235e7b247649cc2f7d1075e9b4d4388661e754a7fc386913c33ddd60208bded5301a1b77", 16);

    static final int MAX_JSON_SIZE = 64 * 1024;

    static final int MECH_SHA1_HASH = 44;
    static final int MECH_DSA_SHA256 = 170;
    static final int MECH_ECDSA_SHA512 = 187;
    static final int KEY_RSA_PUBLIC = 1;
    static final int KEY_DSA_PUBLIC = 3;
    static final int KEY_ECDSA_PUBLIC = 46;
    static final int CURVE_P256 = 4;
    static final int CURVE_P521 = 6;

    static final long PERM_EXPORT_AS_PLAIN = 0x4;
    static final long PERM_SET_APP_DATA = 0x10;
    static final long PERM_EXPAND_ACL = 0x40;
    static final long PERM_USE_AS_BLOB_KEY = 0x400;
    static final long PERM_USE_AS_KM = 0x800;
    static final long PERM_USE_AS_LOADER_KEY = 0x4000;
    static final long FORBIDDEN_PERMS = PERM_EXPORT_AS_PLAIN | PERM_SET_APP_DATA | PERM_EXPAND_ACL
            | PERM_USE_AS_BLOB_KEY | PERM_USE_AS_KM | PERM_USE_AS_LOADER_KEY;
    static final long KNOWN_PERMS = 0xffff;

    static final String[] PROTECTION_ORDER = {"module", "softcard", "cardset"};

    private final ObjectMapper objectMapper = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private final PublicKey root;

    public NShieldVerifier() {
        this(ecKey("secp521r1", KWARN_1_X, KWARN_1_Y));
    }

    /** For tests: another root key. */
    NShieldVerifier(PublicKey root) {
        this.root = root;
    }

    PublicKey rootKey() {
        return root;
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.ENTRUST;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        return false; // Use verifyNShieldAttestation instead
    }

    /**
     * @param json         the attestation bundle JSON, or its base64
     * @param csrPublicKey the CSR's public key
     */
    public NShieldResult verifyNShieldAttestation(String json, PublicKey csrPublicKey) {
        NShieldResult result = new NShieldResult();
        try {
            String text = json.trim().startsWith("{")
                    ? json : new String(Base64.getMimeDecoder().decode(json.trim()), StandardCharsets.UTF_8);
            if (text.length() > MAX_JSON_SIZE) {
                result.addError("NSHIELD_BUNDLE_MALFORMED: JSON exceeds " + MAX_JSON_SIZE + " bytes");
                return result;
            }
            JsonNode bundle = objectMapper.readTree(text);
            if (bundle == null || !bundle.isObject()) {
                result.addError("NSHIELD_BUNDLE_MALFORMED: not a JSON object");
                return result;
            }

            // WV1
            if (!KWARN_1.equals(bundle.path("root").asText())) {
                result.addError("NSHIELD_WARRANT_INVALID: root is not " + KWARN_1);
                return result;
            }
            Warrant warrant;
            try {
                warrant = verifyWarrant(field(bundle, "warrant"), root);
            } catch (Refusal e) {
                result.addError("NSHIELD_WARRANT_INVALID: " + e.getMessage());
                return result;
            }
            result.setWarrantType(warrant.type());
            result.setEsn(warrant.esn());

            // MSCV1-5
            ModuleState state;
            KeyData knso;
            byte[] hknso;
            byte[] hkm = keyHashEx(field(bundle, "hkm"));
            try {
                if (!verify(warrant.klf2(), field(bundle, "modstatesig"), field(bundle, "modstatemsg"))) {
                    throw new Refusal("modstatesig does not verify under the warrant's KLF2");
                }
                state = moduleState(field(bundle, "modstatemsg"));
                if (!state.esn().equals(warrant.esn())) {
                    throw new Refusal("ESN " + state.esn() + " is not the warrant's " + warrant.esn());
                }
                knso = keyData(new In(field(bundle, "knsopub")), true);
                hknso = keyHash(knso);
                if (!Arrays.equals(hknso, state.hknso())) {
                    throw new Refusal("knsopub does not hash to the module's HKNSO");
                }
                if (state.moduleKeys().stream().noneMatch(k -> Arrays.equals(k, hkm))) {
                    throw new Refusal("hkm is not in the module key list");
                }
            } catch (Refusal e) {
                result.addError("NSHIELD_MODULE_STATE_INVALID: " + e.getMessage());
                return result;
            }

            // WBCV1-5
            try {
                worldBinding(bundle, knso, hknso, hkm);
            } catch (Refusal e) {
                result.addError("NSHIELD_WORLD_BINDING_INVALID: " + e.getMessage());
                return result;
            }

            // KGCV1-2
            byte[] kcmsg = field(bundle, "kcmsg");
            KeyData attested;
            try {
                if (!verify(state.kml(), field(bundle, "kcsig"), kcmsg)) {
                    throw new Refusal("kcsig does not verify under the module's KML");
                }
                attested = keyData(new In(field(bundle, "pubkeydata")), true);
                byte[] hash = keyHash(attested);
                KeyGen keyGen = keyGen(kcmsg, attested);
                if (!Arrays.equals(hash, keyGen.hka())) {
                    throw new Refusal("the key hash in kcmsg is not the hash of pubkeydata");
                }
                result.setChainValid(true);
                result.setKeyOrigin("generated");

                Acl acl = evaluateAcl(keyGen.acl(), hkm, hknso);
                result.setRecoverable(acl.recoverable());
                result.setProtection(acl.protection());
                result.setExportable(acl.recoverable() || !acl.refusals().isEmpty());
                acl.refusals().forEach(r -> result.addError("NSHIELD_ACL_REFUSED: " + r));
                if (acl.recoverable()) {
                    result.addError("NSHIELD_KEY_RECOVERABLE: the Administrator Card Set can recover the key");
                }
            } catch (Refusal e) {
                result.addError("NSHIELD_KEYGEN_INVALID: " + e.getMessage());
                return result;
            }

            // CSRL1
            if (csrPublicKey != null && Arrays.equals(attested.publicKey().getEncoded(), csrPublicKey.getEncoded())) {
                result.setPublicKeyMatch(true);
            } else {
                result.addError("NSHIELD_PUBLIC_KEY_MISMATCH: the bundle attests another key");
            }
            result.setValid(result.isChainValid() && result.isPublicKeyMatch()
                    && !result.isExportable() && result.getErrors().isEmpty());
        } catch (Exception e) {
            result.addError("NSHIELD_BUNDLE_MALFORMED: " + e.getMessage());
            log.warn("nShield attestation bundle verification failed: {}", e.getMessage());
        }
        return result;
    }

    /** A verification step's refusal, reported under the step's error code. */
    static final class Refusal extends Exception {
        Refusal(String message) {
            super(message);
        }
    }

    private static byte[] field(JsonNode bundle, String name) throws Refusal {
        JsonNode node = bundle.get(name);
        if (node == null || !node.isTextual()) {
            throw new Refusal(name + " is missing");
        }
        try {
            return Base64.getUrlDecoder().decode(node.asText());
        } catch (IllegalArgumentException e) {
            throw new Refusal(name + " is not base64url");
        }
    }

    // ------------------------------------------------------------------ WV1

    record Warrant(KeyData klf2, String esn, String type) {
    }

    /** Verifies a warrant under {@code root} and returns the module's KLF2 and ESN. */
    static Warrant verifyWarrant(byte[] encoded, PublicKey root) throws Refusal {
        if (!(Ddds.decode(encoded) instanceof List<?> list) || list.size() < 2
                || !(list.get(0) instanceof Ddds.Sym name) || !KWARN_1.equals(name.name())) {
            throw new Refusal("not a warrant list rooted at " + KWARN_1);
        }
        PublicKey current = root;
        // No loop condition: every certificate before the last continues to the
        // next one, and the last one returns or throws.
        for (int i = 1; ; i++) {
            if (!(list.get(i) instanceof Map<?, ?> cert) || cert.size() != 2
                    || !(cert.get(new Ddds.Sym("Signature")) instanceof byte[] sig)
                    || !(cert.get(new Ddds.Sym("Payload")) instanceof byte[] payload)) {
                throw new Refusal("certificate " + i + " is not {Signature, Payload}");
            }
            if (sig.length != 132 || !verifySignature("SHA512withECDSA", current,
                    new BigInteger(1, Arrays.copyOfRange(sig, 0, 66)),
                    new BigInteger(1, Arrays.copyOfRange(sig, 66, 132)), payload)) {
                throw new Refusal("certificate " + i + " does not verify");
            }
            if (!(Ddds.decode(payload) instanceof Map<?, ?> body)
                    || !(body.get(new Ddds.Sym("WarrantCertificateType")) instanceof Ddds.Sym type)) {
                throw new Refusal("certificate " + i + " has no WarrantCertificateType");
            }
            boolean last = i == list.size() - 1;
            if (!last) {
                if (!"Delegation".equals(type.name())) {
                    throw new Refusal("certificate " + i + " is " + type.name() + ", not Delegation");
                }
                checkMech(body.get(new Ddds.Sym("SigMech")));
                current = warrantKey(body.get(new Ddds.Sym("DelegateKey"))).publicKey();
            } else {
                if ("FieldUpgradeModuleInformation".equals(type.name())) {
                    throw new Refusal("FieldUpgradeModuleInformation warrants depend on legacy DSA-1024 signatures"
                            + " (Entrust) and are not accepted");
                }
                if (!"ModuleInformation".equals(type.name())) {
                    throw new Refusal("the last certificate is " + type.name() + ", not module information");
                }
                checkMech(body.get(new Ddds.Sym("KLF2mech")));
                if (!(body.get(new Ddds.Sym("ElectronicSerialNumber")) instanceof String esn)) {
                    throw new Refusal("module information has no ElectronicSerialNumber");
                }
                return new Warrant(warrantKey(body.get(new Ddds.Sym("KLF2pub"))), esn, type.name());
            }
        }
    }

    private static void checkMech(Object mech) throws Refusal {
        if (!(mech instanceof List<?> m) || m.size() != 2 || !new Ddds.Sym("ECDSA").equals(m.get(0))
                || !List.of(new Ddds.Sym("EMSA1"), new Ddds.Sym("SHA512")).equals(m.get(1))) {
            throw new Refusal("signature mechanism is not ECDSA EMSA1 SHA512");
        }
    }

    /** {@code ['ECDSA', 'Public', 'NISTP521', [x, y]]}. */
    private static KeyData warrantKey(Object key) throws Refusal {
        if (!(key instanceof List<?> k) || k.size() != 4 || !new Ddds.Sym("ECDSA").equals(k.get(0))
                || !new Ddds.Sym("Public").equals(k.get(1)) || !new Ddds.Sym("NISTP521").equals(k.get(2))
                || !(k.get(3) instanceof List<?> q) || q.size() != 2
                || !(q.get(0) instanceof BigInteger x) || !(q.get(1) instanceof BigInteger y)) {
            throw new Refusal("warrant key is not an ECDSA NISTP521 public key");
        }
        return new KeyData(KEY_ECDSA_PUBLIC, CURVE_P521, List.of(x, y));
    }

    // ---------------------------------------------------------------- MSCV

    record ModuleState(String esn, KeyData kml, byte[] hknso, List<byte[]> moduleKeys) {
    }

    /** Reads a module state certificate (M_ModCertMsg, type StateCert). */
    static ModuleState moduleState(byte[] msg) throws Refusal {
        In in = new In(msg);
        if (in.u32() != 4 || in.u32() != 0) {
            throw new Refusal("modstatemsg is not a StateCert without flags");
        }
        Map<Long, Object> attributes = new LinkedHashMap<>();
        long n = in.count(4);
        for (long i = 0; i < n; i++) {
            long tag = in.u32();
            Object value = switch ((int) tag) {
                case 2 -> in.string(); // ESN
                case 3, 13 -> { // KML, KLF2: hash, key, mech
                    in.hash();
                    KeyData key = keyData(in, false);
                    in.u32();
                    yield key;
                }
                case 5 -> { // KNSO: hash, NSO permissions
                    byte[] hash = in.hash();
                    in.u32();
                    yield hash;
                }
                case 6 -> { // KMList: hash, mech_i, mech_c
                    List<byte[]> keys = new ArrayList<>();
                    long count = in.count(28);
                    for (long k = 0; k < count; k++) {
                        keys.add(in.hash());
                        in.u32();
                        in.u32();
                    }
                    yield keys;
                }
                default -> throw new Refusal("unsupported module attribute " + tag);
            };
            if (attributes.put(tag, value) != null) {
                throw new Refusal("module attribute " + tag + " repeated");
            }
        }
        in.end("modstatemsg");
        if (!(attributes.get(2L) instanceof String esn) || !(attributes.get(3L) instanceof KeyData kml)
                || !(attributes.get(5L) instanceof byte[] hknso) || !(attributes.get(6L) instanceof List<?> keys)) {
            throw new Refusal("modstatemsg lacks ESN, KML, KNSO or KMList");
        }
        @SuppressWarnings("unchecked")
        List<byte[]> moduleKeys = (List<byte[]>) keys;
        return new ModuleState(esn, kml, hknso, moduleKeys);
    }

    // ---------------------------------------------------------------- WBCV

    private static void worldBinding(JsonNode bundle, KeyData knso, byte[] hknso, byte[] hkm) throws Refusal {
        String suite = bundle.path("ciphersuite").asText();
        if (!suite.matches("[A-Za-z0-9]+")) {
            throw new Refusal("ciphersuite is missing");
        }
        if (suite.equals("DLf1024s160mDES3") || suite.equals("DLf1024s160mRijndael")) {
            throw new Refusal("legacy ciphersuite " + suite + " is not supported");
        }
        boolean plain = bundle.has("CertKMaKMCbKNSO");
        boolean fips = bundle.has("CertKMaKMCaKFIPSbKNSO");
        if (plain == fips) {
            throw new Refusal("exactly one of CertKMaKMCbKNSO and CertKMaKMCaKFIPSbKNSO is required");
        }
        byte[] hkmc = keyHashEx(field(bundle, "hkmc"));
        byte[] body = fips
                ? concat(("Module setup, FIPS3; suite = " + suite + "\0").getBytes(StandardCharsets.US_ASCII),
                        hknso, hkm, hkmc, keyHashEx(field(bundle, "hkfips")))
                : concat(("Module keys: suite = " + suite + "\0").getBytes(StandardCharsets.US_ASCII),
                        hknso, hkm, hkmc);
        String name = fips ? "CertKMaKMCaKFIPSbKNSO" : "CertKMaKMCbKNSO";
        if (!verify(knso, field(bundle, name), body)) {
            throw new Refusal(name + " does not verify under knsopub");
        }
        if (bundle.has("CertKREaKRAbKNSO")) {
            byte[] recovery = concat("Card Recovery\0".getBytes(StandardCharsets.US_ASCII), hknso,
                    keyHashEx(field(bundle, "hkre")), keyHashEx(field(bundle, "hkra")));
            if (!verify(knso, field(bundle, "CertKREaKRAbKNSO"), recovery)) {
                throw new Refusal("CertKREaKRAbKNSO does not verify under knsopub");
            }
        }
    }

    // ---------------------------------------------------------------- KGCV

    record KeyGen(byte[] acl, byte[] hka) {
    }

    /**
     * Reads a key generation certificate (M_ModCertMsg, type KeyGen): its
     * generation parameters must fit {@code key}; returns the raw ACL and the
     * key hash.
     */
    static KeyGen keyGen(byte[] msg, KeyData key) throws Refusal {
        In in = new In(msg);
        if (in.u32() != 2) {
            throw new Refusal("kcmsg is not a KeyGen certificate");
        }
        if (in.u32() != 0) {
            throw new Refusal("unsupported KeyGen flags");
        }
        long type = in.u32();
        if (type == 2 && key.type() == KEY_RSA_PUBLIC) { // RSAPrivate
            long flags = in.u32();
            if ((flags & ~7L) != 0) {
                throw new Refusal("unsupported RSA generation flags");
            }
            in.u32(); // lenbits
            if ((flags & 1) != 0) {
                in.bignum(); // given_e
            }
            if ((flags & 2) != 0) {
                in.u32(); // nchecks
            }
        } else if ((type == 45 || type == 47) && key.type() == KEY_ECDSA_PUBLIC) {
            if (in.u32() != key.curve()) {
                throw new Refusal("generation curve is not the key's curve");
            }
        } else {
            throw new Refusal("generation parameters " + type + " do not fit key type " + key.type());
        }
        int aclStart = in.pos;
        skipAcl(in);
        byte[] acl = Arrays.copyOfRange(msg, aclStart, in.pos);
        byte[] hka = in.hash();
        in.end("kcmsg");
        return new KeyGen(acl, hka);
    }

    private static void skipAcl(In in) throws Refusal {
        // Parsed for its length; evaluateAcl reads it again with the policy.
        evaluateAcl(in, null, null, false);
    }

    // ----------------------------------------------------------------- ACL

    /** The ACL's recoverability, weakest working blob protection, and what the policy refuses. */
    record Acl(boolean recoverable, String protection, List<String> refusals) {
    }

    /**
     * Evaluates a generation-time ACL (M_ACL) against Entrust's ACL validation
     * steps. Anything that cannot be read is thrown; what can be read but is
     * refused is collected, so that a recoverable key also reports its other
     * refusals.
     *
     * @param hkm   the trusted module key hash
     * @param hknso the security officer's key hash
     */
    static Acl evaluateAcl(byte[] acl, byte[] hkm, byte[] hknso) throws Refusal {
        In in = new In(acl);
        Acl result = evaluateAcl(in, hkm, hknso, true);
        in.end("ACL");
        return result;
    }

    private static Acl evaluateAcl(In in, byte[] hkm, byte[] hknso, boolean apply) throws Refusal {
        boolean recoverable = false;
        int weakest = Integer.MAX_VALUE;
        List<String> refusals = new ArrayList<>();
        long groups = in.count(12);
        for (long g = 0; g < groups; g++) {
            long flags = in.u32();
            if ((flags & ~(0x1L | 0x2 | 0x4 | 0x8 | 0x20 | 0x40)) != 0) {
                throw new Refusal("unsupported permission group flags 0x" + Long.toHexString(flags));
            }
            long limits = in.count(8);
            for (long l = 0; l < limits; l++) {
                long type = in.u32();
                switch ((int) type) {
                    case 1, 6 -> { // Global, Auth: hash, max
                        in.hash();
                        in.u32();
                    }
                    case 3 -> in.u32(); // Time: seconds
                    default -> throw new Refusal("unsupported use limit " + type);
                }
            }
            List<Object[]> actions = new ArrayList<>();
            long n = in.count(8);
            for (long a = 0; a < n; a++) {
                actions.add(action(in));
            }
            List<byte[]> certifiers = new ArrayList<>();
            if ((flags & 0x1) != 0) {
                certifiers.add(in.hash());
            }
            if ((flags & 0x4) != 0) {
                certifiers.add(in.hash());
                in.u32();
            }
            if ((flags & 0x8) != 0) {
                in.string(); // moduleserial
            }
            if ((flags & 0x40) != 0) {
                certifiers.add(keyHashEx(in));
                in.u32();
            }
            if (!apply) {
                continue;
            }
            if (!certifiers.isEmpty()) {
                // ACLV1
                if (certifiers.stream().allMatch(c -> Arrays.equals(c, hknso))) {
                    recoverable = true;
                } else {
                    refusals.add("a permission group needs certification by another key");
                }
                continue;
            }
            for (Object[] action : actions) {
                switch ((String) action[0]) {
                    case "OpPermissions" -> { // ACLV3
                        long perms = (Long) action[1];
                        if ((perms & ~KNOWN_PERMS) != 0) {
                            refusals.add("unknown operation permissions 0x" + Long.toHexString(perms & ~KNOWN_PERMS));
                        }
                        if ((perms & FORBIDDEN_PERMS) != 0) {
                            refusals.add("forbidden operation permissions 0x"
                                    + Long.toHexString(perms & FORBIDDEN_PERMS));
                        }
                    }
                    case "MakeBlob" -> {
                        String refusal = makeBlobRefusal(action, hkm);
                        if (refusal != null) {
                            refusals.add(refusal);
                        } else {
                            weakest = Math.min(weakest, protection(action));
                        }
                    }
                    case "MakeArchiveBlob" -> recoverable = true; // RB5
                    case "DeriveKey" -> {
                        if ((Long) action[1] != 29) { // DeriveMech_PublicFromPrivate
                            refusals.add("unsupported key derivation mechanism " + action[1]);
                        }
                    }
                    default -> throw new IllegalStateException(String.valueOf(action[0]));
                }
            }
        }
        return new Acl(recoverable, weakest == Integer.MAX_VALUE ? "non-persistent" : PROTECTION_ORDER[weakest],
                refusals);
    }

    /** Reads one M_Action; unknown actions are refused (ACLV4). */
    private static Object[] action(In in) throws Refusal {
        long type = in.u32();
        switch ((int) type) {
            case 1 -> {
                return new Object[]{"OpPermissions", in.u32()};
            }
            case 2 -> {
                long flags = in.u32();
                if ((flags & ~0x7fL) != 0) {
                    throw new Refusal("unsupported MakeBlob flags 0x" + Long.toHexString(flags));
                }
                byte[] kmhash = (flags & 0x4) != 0 ? in.hash() : null;
                if ((flags & 0x8) != 0) {
                    in.hash(); // kthash
                }
                Long tokenFlags = null;
                if ((flags & 0x10) != 0) {
                    tokenFlags = in.u32();
                    in.u32(); // sharesneeded
                    in.u32(); // sharestotal
                    in.u32(); // timelimit
                }
                if ((flags & 0x40) != 0) {
                    blobFile(in);
                }
                return new Object[]{"MakeBlob", flags, kmhash, tokenFlags};
            }
            case 3 -> {
                long flags = in.u32();
                if ((flags & ~0x3L) != 0) {
                    throw new Refusal("unsupported MakeArchiveBlob flags 0x" + Long.toHexString(flags));
                }
                in.u32(); // mech
                if ((flags & 0x1) != 0) {
                    in.hash(); // kahash
                }
                if ((flags & 0x2) != 0) {
                    blobFile(in);
                }
                return new Object[]{"MakeArchiveBlob"};
            }
            case 5, 47 -> {
                long flags = in.u32();
                in.u32(); // role
                long mech = in.u32();
                if (flags != 0 || in.u32() != 0) {
                    throw new Refusal("key derivation with parameters or other keys is not supported");
                }
                return new Object[]{"DeriveKey", mech};
            }
            default -> throw new Refusal("unsupported ACL action " + type);
        }
    }

    private static void blobFile(In in) throws Refusal {
        long flags = in.u32();
        if ((flags & ~0x3L) != 0) {
            throw new Refusal("unsupported blob file flags 0x" + Long.toHexString(flags));
        }
        if ((flags & 0x1) != 0) {
            in.u32(); // devs
        }
        if ((flags & 0x2) != 0) {
            in.hash(); // aclhash
        }
    }

    /** WB1-WB3, WB6: null when the working blob is acceptable. */
    private static String makeBlobRefusal(Object[] action, byte[] hkm) {
        long flags = (Long) action[1];
        byte[] kmhash = (byte[]) action[2];
        if ((flags & 0x1) == 0 && (flags & 0x8) == 0) {
            return "a working blob is neither module- nor token-protected";
        }
        if (kmhash == null || !Arrays.equals(kmhash, hkm)) {
            return "a working blob is not under the trusted module key";
        }
        if ((flags & 0x20) != 0) {
            return "a working blob allows a null module key token";
        }
        if ((flags & 0x8) != 0 && action[3] == null) {
            return "a token-protected working blob lacks token parameters";
        }
        return null;
    }

    /** WB5, WB7: the protection's index in {@link #PROTECTION_ORDER}. */
    private static int protection(Object[] action) {
        if (((Long) action[1] & 0x1) != 0) {
            return 0;
        }
        return ((Long) action[3] & 0x4) != 0 ? 1 : 2;
    }

    // ------------------------------------------------------- keys and hashes

    /** An nCore public key (M_KeyData): RSA (e, n), DSA (p, q, g, y) or ECDSA (x, y). */
    record KeyData(int type, int curve, List<BigInteger> values) {

        PublicKey publicKey() throws Refusal {
            try {
                return switch (type) {
                    case KEY_RSA_PUBLIC -> KeyFactory.getInstance("RSA")
                            .generatePublic(new RSAPublicKeySpec(values.get(1), values.get(0)));
                    case KEY_DSA_PUBLIC -> KeyFactory.getInstance("DSA").generatePublic(
                            new DSAPublicKeySpec(values.get(3), values.get(0), values.get(1), values.get(2)));
                    default -> ecKey(curve == CURVE_P256 ? "secp256r1" : "secp521r1", values.get(0), values.get(1));
                };
            } catch (Exception e) {
                throw new Refusal("invalid public key: " + e.getMessage());
            }
        }
    }

    /** Reads an M_KeyData; with {@code end}, nothing may follow it. */
    static KeyData keyData(In in, boolean end) throws Refusal {
        long type = in.u32();
        KeyData key;
        if (type == KEY_RSA_PUBLIC) {
            key = new KeyData(KEY_RSA_PUBLIC, 0, List.of(in.bignum(), in.bignum()));
        } else if (type == KEY_DSA_PUBLIC) {
            key = new KeyData(KEY_DSA_PUBLIC, 0, List.of(in.bignum(), in.bignum(), in.bignum(), in.bignum()));
        } else if (type == KEY_ECDSA_PUBLIC) {
            long curve = in.u32();
            if (curve != CURVE_P256 && curve != CURVE_P521) {
                throw new Refusal("unsupported curve " + curve);
            }
            if (in.u32() != 0) {
                throw new Refusal("unsupported ECDSA key flags");
            }
            key = new KeyData(KEY_ECDSA_PUBLIC, (int) curve, List.of(in.bignum(), in.bignum()));
        } else {
            throw new Refusal("unsupported key type " + type);
        }
        if (end) {
            in.end("key data");
        }
        return key;
    }

    private static final BigInteger[] P256 = {
            BigInteger.valueOf(256),
            new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
            new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
            new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
            new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
            BigInteger.ONE};

    /** The nCore key hash (SHA-1) of an RSA, DSA or ECDSA P-256 public key. */
    static byte[] keyHash(KeyData key) throws Refusal {
        List<BigInteger> v = key.values();
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        String prefix;
        switch (key.type()) {
            case KEY_RSA_PUBLIC -> {
                if (v.get(0).bitLength() > 32) {
                    throw new Refusal("RSA public exponents above 32 bits are not supported");
                }
                prefix = "RSA00";
                data.writeBytes(padded(v.get(0)));
                data.writeBytes(padded(v.get(1)));
            }
            case KEY_DSA_PUBLIC -> {
                prefix = "DSA00";
                v.forEach(x -> data.writeBytes(padded(x)));
            }
            default -> {
                if (key.curve() != CURVE_P256) {
                    throw new Refusal("key hashes are supported for ECDSA on NIST P-256 only");
                }
                prefix = "ECDSA00";
                data.writeBytes(new byte[8]);
                data.writeBytes(littleEndian(P256[0], 4));
                for (int i = 1; i < P256.length; i++) {
                    data.writeBytes(padded(P256[i]));
                }
                data.writeBytes(padded(v.get(0)));
                data.writeBytes(padded(v.get(1)));
            }
        }
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(("nFast KeyHash\0" + prefix + "\0").getBytes(StandardCharsets.US_ASCII));
            sha1.update(data.toByteArray());
            sha1.update("invented by nCipher 1997\0".getBytes(StandardCharsets.US_ASCII));
            return sha1.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Little-endian, zero-padded to a multiple of 64 bytes. */
    static byte[] padded(BigInteger x) {
        int bytes = (x.bitLength() + 7) / 8;
        return littleEndian(x, (bytes + 63) / 64 * 64);
    }

    private static byte[] littleEndian(BigInteger x, int length) {
        byte[] out = new byte[length];
        byte[] be = x.toByteArray();
        for (int i = 0; i < length && i < be.length; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    /** An M_KeyHashEx with SHA-1: the 20-byte hash. */
    private static byte[] keyHashEx(byte[] encoded) throws Refusal {
        In in = new In(encoded);
        byte[] hash = keyHashEx(in);
        in.end("key hash");
        return hash;
    }

    private static byte[] keyHashEx(In in) throws Refusal {
        if (in.u32() != MECH_SHA1_HASH) {
            throw new Refusal("unsupported key hash mechanism");
        }
        return in.hash();
    }

    /** Verifies an M_CipherText signature (DSA SHA-256 or ECDSA SHA-512) under {@code key}. */
    static boolean verify(KeyData key, byte[] cipherText, byte[] message) throws Refusal {
        In in = new In(cipherText);
        long mech = in.u32();
        BigInteger r = in.bignum();
        BigInteger s = in.bignum();
        in.end("signature");
        if (mech == MECH_DSA_SHA256 && key.type() == KEY_DSA_PUBLIC) {
            return verifySignature("SHA256withDSA", key.publicKey(), r, s, message);
        }
        if (mech == MECH_ECDSA_SHA512 && key.type() == KEY_ECDSA_PUBLIC) {
            return verifySignature("SHA512withECDSA", key.publicKey(), r, s, message);
        }
        throw new Refusal("unsupported signature mechanism " + mech + " for key type " + key.type());
    }

    private static boolean verifySignature(String algorithm, PublicKey key, BigInteger r, BigInteger s,
            byte[] message) {
        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                    new ASN1Integer(r), new ASN1Integer(s)}).getEncoded());
        } catch (Exception e) {
            return false;
        }
    }

    static PublicKey ecKey(String curve, BigInteger x, BigInteger y) {
        // The JDK does not check that the point is on the curve.
        org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(curve).getCurve().validatePoint(x, y);
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curve));
            return KeyFactory.getInstance("EC").generatePublic(
                    new ECPublicKeySpec(new ECPoint(x, y), parameters.getParameterSpec(ECParameterSpec.class)));
        } catch (Exception e) {
            throw new IllegalStateException("invalid " + curve + " key", e);
        }
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------- readers

    /** nCore marshalling: little-endian 32-bit words, length-prefixed bignums and strings. */
    static final class In {
        private final byte[] b;
        int pos;

        In(byte[] b) {
            this.b = b;
        }

        private byte[] raw(long n) throws Refusal {
            if (n < 0 || n > b.length - pos) {
                throw new Refusal("truncated nCore data");
            }
            byte[] out = Arrays.copyOfRange(b, pos, pos + (int) n);
            pos += (int) n;
            return out;
        }

        long u32() throws Refusal {
            byte[] w = raw(4);
            return (w[0] & 0xffL) | (w[1] & 0xffL) << 8 | (w[2] & 0xffL) << 16 | (w[3] & 0xffL) << 24;
        }

        /** A count of items of at least {@code size} bytes each. */
        long count(int size) throws Refusal {
            long n = u32();
            if (n > (b.length - pos) / size) {
                throw new Refusal("count exceeds the data");
            }
            return n;
        }

        BigInteger bignum() throws Refusal {
            byte[] le = raw(u32());
            byte[] be = new byte[le.length];
            for (int i = 0; i < le.length; i++) {
                be[i] = le[le.length - 1 - i];
            }
            return new BigInteger(1, be);
        }

        byte[] hash() throws Refusal {
            return raw(20);
        }

        /** An M_ASCIIString, whose length counts a terminating NUL, padded to a word. */
        String string() throws Refusal {
            long n = u32();
            byte[] bytes = raw(n);
            raw((4 - n % 4) % 4);
            int length = bytes.length > 0 && bytes[bytes.length - 1] == 0 ? bytes.length - 1 : bytes.length;
            String s = new String(bytes, 0, length, StandardCharsets.US_ASCII);
            if (s.indexOf('\0') >= 0) {
                throw new Refusal("string contains NUL");
            }
            return s;
        }

        void end(String what) throws Refusal {
            if (pos != b.length) {
                throw new Refusal(what + " has " + (b.length - pos) + " trailing bytes");
            }
        }
    }

    /**
     * DDDS, the encoding of nShield warrants, as far as warrants use it: small
     * integers, short strings and symbols, lists, maps, byte blocks and
     * big-endian integers. Anything else is refused.
     */
    static final class Ddds {

        record Sym(String name) {
        }

        static Object decode(byte[] b) throws Refusal {
            int[] pos = {0};
            Object value = value(b, pos, 0);
            if (pos[0] != b.length) {
                throw new Refusal("DDDS data has trailing bytes");
            }
            return value;
        }

        private static Object value(byte[] b, int[] pos, int depth) throws Refusal {
            if (depth > 8) {
                throw new Refusal("DDDS nesting too deep");
            }
            int tag = take(b, pos, 1)[0] & 0xff;
            int low = tag & 0x0f;
            if (tag < 0x20) {
                return BigInteger.valueOf(tag);
            }
            if (tag < 0x30) {
                return new String(take(b, pos, low), StandardCharsets.US_ASCII);
            }
            if (tag < 0x40) {
                return new Sym(new String(take(b, pos, low), StandardCharsets.US_ASCII));
            }
            if (tag >= 0x90 && tag < 0xa0) {
                List<Object> list = new ArrayList<>();
                for (int i = 0; i < low; i++) {
                    list.add(value(b, pos, depth + 1));
                }
                return list;
            }
            if (tag >= 0xb0 && tag < 0xc0) {
                Map<Object, Object> map = new LinkedHashMap<>();
                for (int i = 0; i < low; i++) {
                    Object key = value(b, pos, depth + 1);
                    if (map.put(key, value(b, pos, depth + 1)) != null) {
                        throw new Refusal("DDDS map key repeated");
                    }
                }
                return map;
            }
            switch (tag) {
                case 0xc4 -> {
                    return new Sym(new String(take(b, pos, take(b, pos, 1)[0] & 0xff), StandardCharsets.US_ASCII));
                }
                case 0xc5 -> {
                    return take(b, pos, take(b, pos, 1)[0] & 0xff);
                }
                case 0xd5 -> {
                    byte[] n = take(b, pos, 2);
                    return take(b, pos, (n[0] & 0xff) << 8 | (n[1] & 0xff));
                }
                case 0xf4 -> {
                    if (!(value(b, pos, depth + 1) instanceof byte[] be)) {
                        throw new Refusal("DDDS integer is not a byte block");
                    }
                    return new BigInteger(1, be);
                }
                default -> throw new Refusal("unsupported DDDS tag 0x" + Integer.toHexString(tag));
            }
        }

        private static byte[] take(byte[] b, int[] pos, int n) throws Refusal {
            if (n > b.length - pos[0]) {
                throw new Refusal("truncated DDDS data");
            }
            byte[] out = Arrays.copyOfRange(b, pos[0], pos[0] + n);
            pos[0] += n;
            return out;
        }
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        return false; // nShield attestations are not X.509; use verifyNShieldAttestation
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return attestationCert.getSerialNumber().toString(16);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        return "Entrust nShield";
    }

    public static class NShieldResult {
        private boolean valid;
        private boolean chainValid;
        private boolean publicKeyMatch;
        private boolean exportable = true;
        private boolean recoverable;
        private String protection;
        private String keyOrigin = "unverified";
        private String esn;
        private String warrantType;
        private List<String> errors = new ArrayList<>();

        public void addError(String error) {
            errors.add(error);
        }

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public boolean isChainValid() {
            return chainValid;
        }

        public void setChainValid(boolean chainValid) {
            this.chainValid = chainValid;
        }

        public boolean isPublicKeyMatch() {
            return publicKeyMatch;
        }

        public void setPublicKeyMatch(boolean publicKeyMatch) {
            this.publicKeyMatch = publicKeyMatch;
        }

        public boolean isExportable() {
            return exportable;
        }

        public void setExportable(boolean exportable) {
            this.exportable = exportable;
        }

        public boolean isRecoverable() {
            return recoverable;
        }

        public void setRecoverable(boolean recoverable) {
            this.recoverable = recoverable;
        }

        public String getProtection() {
            return protection;
        }

        public void setProtection(String protection) {
            this.protection = protection;
        }

        public String getKeyOrigin() {
            return keyOrigin;
        }

        public void setKeyOrigin(String keyOrigin) {
            this.keyOrigin = keyOrigin;
        }

        public String getEsn() {
            return esn;
        }

        public void setEsn(String esn) {
            this.esn = esn;
        }

        public String getWarrantType() {
            return warrantType;
        }

        public void setWarrantType(String warrantType) {
            this.warrantType = warrantType;
        }

        public List<String> getErrors() {
            return errors;
        }
    }
}
