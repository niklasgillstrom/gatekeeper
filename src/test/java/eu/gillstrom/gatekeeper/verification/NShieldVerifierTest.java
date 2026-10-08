package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link NShieldVerifier} against Entrust's two example bundles (see
 * {@code src/test/resources/vendor-fixtures/nshield/NOTICE.md}) and against
 * synthetic bundles and ACLs that isolate each check.
 */
class NShieldVerifierTest {

    private static final Path DIR = Path.of("src/test/resources/vendor-fixtures/nshield");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    /** The EC P-256 key of key_pkcs11_test2.att. */
    private static final PublicKey SOFTCARD_KEY = NShieldVerifier.ecKey("secp256r1",
            new BigInteger("df62d0efed4c48300897c4dab40d26574e129cd39cd946c877494ed31bcfd0dd", 16),
            new BigInteger("9d8e0277ea5489bae9c38769545ae65161cb3d8a02f924a62a80b5d0e683cc20", 16));
    /** The RSA-2048 key of key_simple_test1.att. */
    private static PublicKey recoverableKey;

    private static final byte[] HKM = random(20);
    private static final byte[] HKNSO = random(20);

    @BeforeAll
    static void keys() throws Exception {
        recoverableKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(
                "ad3ee904799b1c0a7376b751edb09f2ade867bafcf726703fa92713b2190e4094b58ec7c88223b2aacc008143d5348c9"
                        + "16ceeba995305c40152546b89b0dc36b95d336c2cb0cc8d885b37afd6ac8567ce77ac47912f28fe8d721d9355b2d"
                        + "26ce7ee6ef6242ea610601a541b9bb0334d5dd45fc48108a486cbe976d717f1e6762c11baff96971dd8ef39f6c8e"
                        + "3ee091b7b833f68ddd45d8f0a99feaf9c0e675bde0574b0224c1cc1bded2969b6c819cdc623303087481f1d38abc"
                        + "9f97c3e8ed96cfdbc83673cb638c4314c2fdf37b0eac38599f27cdaead8ece3f59eb81c556353577fe8be6500504"
                        + "8ae1df5f60ed52ed0bb518a2b39b18f82b7bbd7d2615234b", 16), BigInteger.valueOf(65537)));
    }

    /** A test root for warrants reissued as ModuleInformation. */
    private static final KeyPair TEST_ROOT = p521();

    /**
     * Entrust's bundles carry FieldUpgradeModuleInformation warrants, which
     * are refused. To verify everything below the warrant against Entrust's
     * real data, the warrant is reissued as ModuleInformation under a test
     * root, with the real warrant's KLF2 and ESN; the module state, world
     * binding and key generation certificates stay Entrust's.
     */
    private static NShieldVerifier.NShieldResult run(ObjectNode bundle, PublicKey key) {
        return new NShieldVerifier(TEST_ROOT.getPublic()).verifyNShieldAttestation(reissued(bundle).toString(), key);
    }

    /** As Entrust published it, under the pinned KWARN-1. */
    private static NShieldVerifier.NShieldResult runReal(ObjectNode bundle, PublicKey key) {
        return new NShieldVerifier().verifyNShieldAttestation(bundle.toString(), key);
    }

    private static ObjectNode reissued(ObjectNode bundle) {
        try {
            ObjectNode copy = bundle.deepCopy();
            if (copy.get("warrant") != null && copy.get("warrant").isTextual()
                    && copy.get("warrant").asText().equals(softcard().get("warrant").asText())) {
                put(copy, "warrant", Ddds.warrant("KWARN-1", Ddds.cert(TEST_ROOT,
                        Ddds.moduleInfo("ModuleInformation", "8938-1075-88BB", realKlf2()))));
            }
            return copy;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** KLF2 from Entrust's warrant, read without accepting the warrant. */
    private static PublicKey realKlf2() throws Exception {
        List<?> warrant = (List<?>) NShieldVerifier.Ddds.decode(field(softcard(), "warrant"));
        Map<?, ?> last = (Map<?, ?>) warrant.get(warrant.size() - 1);
        Map<?, ?> payload = (Map<?, ?>) NShieldVerifier.Ddds.decode((byte[]) last.get(Ddds.sym("Payload")));
        List<?> q = (List<?>) ((List<?>) payload.get(Ddds.sym("KLF2pub"))).get(3);
        return NShieldVerifier.ecKey("secp521r1", (BigInteger) q.get(0), (BigInteger) q.get(1));
    }

    private static ObjectNode fixture(String name) throws Exception {
        return (ObjectNode) MAPPER.readTree(Files.readString(DIR.resolve(name)));
    }

    private static ObjectNode softcard() throws Exception {
        return fixture("key_pkcs11_test2.att");
    }

    private static ObjectNode recoverable() throws Exception {
        return fixture("key_simple_test1.att");
    }

    private static byte[] field(ObjectNode bundle, String name) {
        return Base64.getUrlDecoder().decode(bundle.get(name).asText());
    }

    private static void put(ObjectNode bundle, String name, byte[] value) {
        bundle.put(name, Base64.getUrlEncoder().encodeToString(value));
    }

    private static ObjectNode flip(ObjectNode bundle, String name, int index) {
        byte[] b = field(bundle, name);
        b[index] ^= 1;
        put(bundle, name, b);
        return bundle;
    }

    private static boolean hasError(NShieldVerifier.NShieldResult r, String prefix) {
        return r.getErrors().stream().anyMatch(e -> e.startsWith(prefix));
    }

    // ------------------------------------------------------- Entrust's bundles

    @Test
    @DisplayName("Entrust's softcard bundle below the warrant: key bound, not recoverable")
    void softcardBundleIsAccepted() throws Exception {
        var r = run(softcard(), SOFTCARD_KEY);
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isExportable()).isFalse();
        assertThat(r.isRecoverable()).isFalse();
        assertThat(r.getProtection()).isEqualTo("softcard");
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.getEsn()).isEqualTo("8938-1075-88BB");
        assertThat(r.getWarrantType()).isEqualTo("ModuleInformation");
    }

    @Test
    @DisplayName("Entrust's warrants verify under KWARN-1 but are FieldUpgradeModuleInformation: refused")
    void entrustsFieldUpgradeWarrantsAreRefused() throws Exception {
        for (ObjectNode b : List.of(softcard(), recoverable())) {
            var r = runReal(b, SOFTCARD_KEY);
            assertThat(r.getErrors()).containsExactly("NSHIELD_WARRANT_INVALID: FieldUpgradeModuleInformation "
                    + "warrants depend on legacy DSA-1024 signatures (Entrust) and are not accepted");
            assertThat(r.isChainValid()).isFalse();
            assertThat(r.isValid()).isFalse();
        }
        // The type is read only after every certificate verified under KWARN-1.
        byte[] tampered = field(softcard(), "warrant");
        tampered[700] ^= 1;
        assertThatThrownBy(() -> NShieldVerifier.verifyWarrant(tampered, new NShieldVerifier().rootKey()))
                .hasMessage("certificate 2 does not verify");
    }

    @Test
    @DisplayName("Entrust's module-protected bundle is recoverable and allows UseAsBlobKey: refused")
    void recoverableBundleIsRefused() throws Exception {
        var r = run(recoverable(), recoverableKey);
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.getWarrantType()).isEqualTo("ModuleInformation");
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isRecoverable()).isTrue();
        assertThat(r.getProtection()).isEqualTo("module");
        assertThat(r.isExportable()).isTrue();
        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).contains(
                "NSHIELD_ACL_REFUSED: forbidden operation permissions 0x400",
                "NSHIELD_KEY_RECOVERABLE: the Administrator Card Set can recover the key");
    }

    @Test
    void anotherCsrKeyIsAMismatch() throws Exception {
        var r = run(softcard(), recoverableKey);
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.isValid()).isFalse();
        assertThat(hasError(r, "NSHIELD_PUBLIC_KEY_MISMATCH")).isTrue();
        assertThat(hasError(run(softcard(), null), "NSHIELD_PUBLIC_KEY_MISMATCH")).isTrue();
    }

    @Test
    void base64OfTheBundleIsAccepted() throws Exception {
        String b64 = Base64.getEncoder().encodeToString(reissued(softcard()).toString().getBytes(StandardCharsets.UTF_8));
        assertThat(new NShieldVerifier(TEST_ROOT.getPublic()).verifyNShieldAttestation(b64, SOFTCARD_KEY).isValid())
                .isTrue();
    }

    @Test
    void malformedInputIsRefused() throws Exception {
        var v = new NShieldVerifier();
        assertThat(hasError(v.verifyNShieldAttestation("{", SOFTCARD_KEY), "NSHIELD_BUNDLE_MALFORMED")).isTrue();
        assertThat(hasError(v.verifyNShieldAttestation(Base64.getEncoder().encodeToString("[1]".getBytes()),
                SOFTCARD_KEY), "NSHIELD_BUNDLE_MALFORMED")).isTrue();
        String big = "{\"x\":\"" + "a".repeat(NShieldVerifier.MAX_JSON_SIZE) + "\"}";
        assertThat(v.verifyNShieldAttestation(big, SOFTCARD_KEY).getErrors())
                .containsExactly("NSHIELD_BUNDLE_MALFORMED: JSON exceeds 65536 bytes");
        String fits = "{\"x\":\"" + "a".repeat(NShieldVerifier.MAX_JSON_SIZE - 8) + "\"}";
        assertThat(v.verifyNShieldAttestation(fits, SOFTCARD_KEY).getErrors())
                .containsExactly("NSHIELD_WARRANT_INVALID: root is not KWARN-1");
        String text = softcard().toString();
        String duplicate = text.replaceFirst("\\{", "{\"root\":\"KWARN-1\",");
        assertThat(hasError(v.verifyNShieldAttestation(duplicate, SOFTCARD_KEY), "NSHIELD_BUNDLE_MALFORMED")).isTrue();
        ObjectNode notBase64 = softcard();
        notBase64.put("hkm", "!!");
        assertThat(run(notBase64, SOFTCARD_KEY).getErrors()).containsExactly("NSHIELD_BUNDLE_MALFORMED: hkm is not base64url");
        ObjectNode numeric = softcard();
        numeric.put("kcsig", 1);
        assertThat(run(numeric, SOFTCARD_KEY).getErrors()).containsExactly("NSHIELD_KEYGEN_INVALID: kcsig is missing");
    }

    // --------------------------------------------------------------- warrant

    @Test
    void anotherRootOrRootNameIsRefused() throws Exception {
        var other = new NShieldVerifier(p521().getPublic()).verifyNShieldAttestation(softcard().toString(), SOFTCARD_KEY);
        assertThat(other.getErrors()).containsExactly("NSHIELD_WARRANT_INVALID: certificate 1 does not verify");
        ObjectNode renamed = softcard();
        renamed.put("root", "KWARN-2");
        assertThat(run(renamed, SOFTCARD_KEY).getErrors()).containsExactly("NSHIELD_WARRANT_INVALID: root is not KWARN-1");
        assertThat(runReal(flip(softcard(), "warrant", 700), SOFTCARD_KEY).getErrors())
                .containsExactly("NSHIELD_WARRANT_INVALID: certificate 2 does not verify");
    }


    @Test
    void warrantStructureIsEnforced() throws Exception {
        KeyPair root = p521();
        KeyPair delegate = p521();
        KeyPair klf2 = p521();
        // root -> module information
        var direct = NShieldVerifier.verifyWarrant(Ddds.warrant("KWARN-1",
                Ddds.cert(root, Ddds.moduleInfo("ModuleInformation", "ESN-1", klf2.getPublic()))), root.getPublic());
        assertThat(direct.esn()).isEqualTo("ESN-1");
        assertThat(direct.type()).isEqualTo("ModuleInformation");
        assertThat(direct.klf2().publicKey()).isEqualTo(klf2.getPublic());
        // root -> delegation -> module information
        var delegated = NShieldVerifier.verifyWarrant(Ddds.warrant("KWARN-1",
                Ddds.cert(root, Ddds.delegation(delegate.getPublic(), Ddds.MECH)),
                Ddds.cert(delegate, Ddds.moduleInfo("ModuleInformation", "ESN-2", klf2.getPublic()))), root.getPublic());
        assertThat(delegated.esn()).isEqualTo("ESN-2");

        assertRefused(Ddds.warrant("KWARN-1",
                Ddds.cert(root, Ddds.delegation(delegate.getPublic(), Ddds.MECH)),
                Ddds.cert(root, Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic()))), root,
                "certificate 2 does not verify");
        assertRefused(Ddds.warrant("KWARN-1", Ddds.cert(root, Ddds.delegation(delegate.getPublic(), Ddds.MECH))),
                root, "the last certificate is Delegation, not module information");
        assertRefused(Ddds.warrant("KWARN-1",
                Ddds.cert(root, Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic())),
                Ddds.cert(klf2, Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic()))), root,
                "certificate 1 is ModuleInformation, not Delegation");
        assertRefused(Ddds.warrant("KWARN-1",
                Ddds.cert(root, Ddds.moduleInfo("SmartcardInformation", "ESN", klf2.getPublic()))), root,
                "the last certificate is SmartcardInformation, not module information");
        assertRefused(Ddds.warrant("KWARN-1",
                Ddds.cert(root, Ddds.delegation(delegate.getPublic(), Ddds.MECH)),
                Ddds.cert(delegate, Ddds.moduleInfo("FieldUpgradeModuleInformation", "ESN", klf2.getPublic()))), root,
                "FieldUpgradeModuleInformation warrants depend on legacy DSA-1024 signatures (Entrust) and are not accepted");
        assertRefused(Ddds.warrant("KWARN-1",
                Ddds.cert(root, Ddds.delegation(delegate.getPublic(), List.of(Ddds.sym("ECDSA"),
                        List.of(Ddds.sym("EMSA1"), Ddds.sym("SHA256"))))),
                Ddds.cert(delegate, Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic()))), root,
                "signature mechanism is not ECDSA EMSA1 SHA512");
        Map<Object, Object> noMech = Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic());
        noMech.put(Ddds.sym("KLF2mech"), List.of(Ddds.sym("DSA"), List.of(Ddds.sym("EMSA1"), Ddds.sym("SHA512"))));
        assertRefused(Ddds.warrant("KWARN-1", Ddds.cert(root, noMech)), root,
                "signature mechanism is not ECDSA EMSA1 SHA512");
        Map<Object, Object> shortMech = Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic());
        shortMech.put(Ddds.sym("KLF2mech"), List.of(Ddds.sym("ECDSA")));
        assertRefused(Ddds.warrant("KWARN-1", Ddds.cert(root, shortMech)), root,
                "signature mechanism is not ECDSA EMSA1 SHA512");
        Map<Object, Object> noEsn = Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic());
        noEsn.remove(Ddds.sym("ElectronicSerialNumber"));
        assertRefused(Ddds.warrant("KWARN-1", Ddds.cert(root, noEsn)), root,
                "module information has no ElectronicSerialNumber");
        Map<Object, Object> noType = Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic());
        noType.put(Ddds.sym("WarrantCertificateType"), "Module");
        assertRefused(Ddds.warrant("KWARN-1", Ddds.cert(root, noType)), root,
                "certificate 1 has no WarrantCertificateType");
        for (int part = 0; part < 4; part++) {
            Map<Object, Object> badKey = Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic());
            List<Object> key = new ArrayList<>((List<?>) badKey.get(Ddds.sym("KLF2pub")));
            key.set(part, part == 3 ? List.of(BigInteger.ONE) : Ddds.sym("NISTP256"));
            badKey.put(Ddds.sym("KLF2pub"), key);
            assertRefused(Ddds.warrant("KWARN-1", Ddds.cert(root, badKey)), root,
                    "warrant key is not an ECDSA NISTP521 public key");
        }
        assertRefused(Ddds.warrant("KWARN-2",
                Ddds.cert(root, Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic()))), root,
                "not a warrant list rooted at KWARN-1");
        assertRefused(Ddds.encode(List.of(Ddds.sym("KWARN-1"))), root, "not a warrant list rooted at KWARN-1");
        assertRefused(Ddds.encode(List.of("KWARN-1", "x")), root, "not a warrant list rooted at KWARN-1");
        assertRefused(Ddds.encode(Map.of(Ddds.sym("KWARN-1"), "x")), root, "not a warrant list rooted at KWARN-1");

        Map<Object, Object> cert = Ddds.cert(root, Ddds.moduleInfo("ModuleInformation", "ESN", klf2.getPublic()));
        Map<Object, Object> extra = new LinkedHashMap<>(cert);
        extra.put(Ddds.sym("Extra"), "x");
        assertRefused(Ddds.warrant("KWARN-1", extra), root, "certificate 1 is not {Signature, Payload}");
        Map<Object, Object> shortSig = new LinkedHashMap<>(cert);
        shortSig.put(Ddds.sym("Signature"), Arrays.copyOf((byte[]) cert.get(Ddds.sym("Signature")), 131));
        assertRefused(Ddds.warrant("KWARN-1", shortSig), root, "certificate 1 does not verify");
        Map<Object, Object> stringPayload = new LinkedHashMap<>(cert);
        stringPayload.put(Ddds.sym("Payload"), "x");
        assertRefused(Ddds.warrant("KWARN-1", stringPayload), root, "certificate 1 is not {Signature, Payload}");
        Map<Object, Object> stringSig = new LinkedHashMap<>(cert);
        stringSig.put(Ddds.sym("Signature"), "x");
        assertRefused(Ddds.warrant("KWARN-1", stringSig), root, "certificate 1 is not {Signature, Payload}");
        assertRefused(Ddds.warrant("KWARN-1", "x"), root, "certificate 1 is not {Signature, Payload}");
        byte[] listPayload = Ddds.encode(List.of(Ddds.sym("WarrantCertificateType")));
        assertRefused(Ddds.warrant("KWARN-1", Ddds.signed(root, listPayload)), root,
                "certificate 1 has no WarrantCertificateType");
    }

    private static void assertRefused(byte[] warrant, KeyPair root, String message) {
        assertThatThrownBy(() -> NShieldVerifier.verifyWarrant(warrant, root.getPublic()))
                .isInstanceOf(NShieldVerifier.Refusal.class).hasMessage(message);
    }

    // ---------------------------------------------------------- module state

    @Test
    void tamperedModuleStateIsRefused() throws Exception {
        assertThat(run(flip(softcard(), "modstatesig", 20), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_MODULE_STATE_INVALID: modstatesig does not verify under the warrant's KLF2");
        assertThat(run(flip(softcard(), "modstatemsg", 30), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_MODULE_STATE_INVALID: modstatesig does not verify under the warrant's KLF2");
        assertThat(run(flip(softcard(), "knsopub", 100), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_MODULE_STATE_INVALID: knsopub does not hash to the module's HKNSO");
        assertThat(run(flip(softcard(), "hkm", 10), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_MODULE_STATE_INVALID: hkm is not in the module key list");
    }

    @Test
    @DisplayName("A warrant for another ESN does not cover Entrust's module state")
    void esnMustMatchTheWarrant() throws Exception {
        KeyPair root = p521();
        PublicKey klf2 = realKlf2();
        for (String esn : List.of("8938-1075-88BB", "8938-1075-88BC")) {
            ObjectNode bundle = softcard();
            put(bundle, "warrant", Ddds.warrant("KWARN-1", Ddds.cert(root, Ddds.moduleInfo("ModuleInformation", esn, klf2))));
            var r = new NShieldVerifier(root.getPublic()).verifyNShieldAttestation(bundle.toString(), SOFTCARD_KEY);
            if (esn.endsWith("BB")) {
                assertThat(r.getErrors()).isEmpty();
                assertThat(r.getWarrantType()).isEqualTo("ModuleInformation");
            } else {
                assertThat(r.getErrors()).containsExactly(
                        "NSHIELD_MODULE_STATE_INVALID: ESN 8938-1075-88BB is not the warrant's 8938-1075-88BC");
            }
        }
    }

    @Test
    void moduleStateIsReadStrictly() throws Exception {
        var state = NShieldVerifier.moduleState(field(softcard(), "modstatemsg"));
        assertThat(state.esn()).isEqualTo("8938-1075-88BB");
        assertThat(state.kml().type()).isEqualTo(NShieldVerifier.KEY_DSA_PUBLIC);
        byte[] hkm = Arrays.copyOfRange(field(softcard(), "hkm"), 4, 24);
        assertThat(state.moduleKeys()).anySatisfy(k -> assertThat(k).isEqualTo(hkm));

        byte[] dsa = Nc.dsa(dsaKey());
        byte[] esn = Nc.cat(Nc.w(2), Nc.string("E"));
        byte[] kml = Nc.cat(Nc.w(3), new byte[20], dsa, Nc.w(0));
        byte[] knso = Nc.cat(Nc.w(5), HKNSO, Nc.w(0));
        byte[] kms = Nc.cat(Nc.w(6), Nc.w(1), HKM, Nc.w(0), Nc.w(0));
        var ok = NShieldVerifier.moduleState(Nc.state(0, esn, kml, knso, kms));
        assertThat(ok.esn()).isEqualTo("E");
        assertThat(ok.hknso()).isEqualTo(HKNSO);
        assertThat(ok.moduleKeys().get(0)).isEqualTo(HKM);
        assertStateRefused(Nc.state(1, esn, kml, knso, kms), "modstatemsg is not a StateCert without flags");
        assertStateRefused(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(0)), "modstatemsg is not a StateCert without flags");
        assertStateRefused(Nc.state(0, esn, kml, knso), "modstatemsg lacks ESN, KML, KNSO or KMList");
        assertStateRefused(Nc.state(0, esn, kml, kms), "modstatemsg lacks ESN, KML, KNSO or KMList");
        assertStateRefused(Nc.state(0, esn, knso, kms), "modstatemsg lacks ESN, KML, KNSO or KMList");
        assertStateRefused(Nc.state(0, kml, knso, kms), "modstatemsg lacks ESN, KML, KNSO or KMList");
        assertStateRefused(Nc.state(0, esn, esn, kml, knso, kms), "module attribute 2 repeated");
        assertStateRefused(Nc.state(0, esn, kml, knso, kms, Nc.cat(Nc.w(19), Nc.w(0))), "unsupported module attribute 19");
        assertStateRefused(Nc.cat(Nc.state(0, esn, kml, knso, kms), Nc.w(0)), "modstatemsg has 4 trailing bytes");
        assertStateRefused(Nc.cat(Nc.w(4), Nc.w(0), Nc.w(1000)), "count exceeds the data");
        assertStateRefused(Nc.state(0, esn, Nc.cat(Nc.w(6), Nc.w(2), HKM, Nc.w(0), Nc.w(0))), "count exceeds the data");
        // KLF2 (13) is read like KML
        var withKlf2 = NShieldVerifier.moduleState(Nc.state(0, esn, kml, knso, kms, Nc.cat(Nc.w(13), new byte[20], dsa, Nc.w(0))));
        assertThat(withKlf2.esn()).isEqualTo("E");
    }

    private static void assertStateRefused(byte[] msg, String message) {
        assertThatThrownBy(() -> NShieldVerifier.moduleState(msg))
                .isInstanceOf(NShieldVerifier.Refusal.class).hasMessage(message);
    }

    // --------------------------------------------------------- world binding

    @Test
    void worldBindingIsVerified() throws Exception {
        assertThat(run(flip(softcard(), "CertKMaKMCbKNSO", 10), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKMaKMCbKNSO does not verify under knsopub");
        assertThat(run(flip(softcard(), "hkmc", 10), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKMaKMCbKNSO does not verify under knsopub");
        assertThat(run(flip(softcard(), "CertKREaKRAbKNSO", 10), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKREaKRAbKNSO does not verify under knsopub");
        assertThat(run(flip(softcard(), "hkre", 10), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKREaKRAbKNSO does not verify under knsopub");
        assertThat(run(flip(softcard(), "hkra", 10), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKREaKRAbKNSO does not verify under knsopub");
        ObjectNode noRecovery = softcard();
        noRecovery.remove("CertKREaKRAbKNSO");
        assertThat(run(noRecovery, SOFTCARD_KEY).isValid()).isTrue();
        ObjectNode suite = softcard();
        suite.put("ciphersuite", "DLf3072s256mRijndael");
        assertThat(run(suite, SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKMaKMCbKNSO does not verify under knsopub");
        for (String legacy : List.of("DLf1024s160mDES3", "DLf1024s160mRijndael")) {
            ObjectNode b = softcard();
            b.put("ciphersuite", legacy);
            assertThat(run(b, SOFTCARD_KEY).getErrors()).containsExactly(
                    "NSHIELD_WORLD_BINDING_INVALID: legacy ciphersuite " + legacy + " is not supported");
        }
        for (String bad : List.of("", "DLf3072s256mAEScSP800131Ar1\u0000x")) {
            ObjectNode b = softcard();
            b.put("ciphersuite", bad);
            assertThat(run(b, SOFTCARD_KEY).getErrors()).containsExactly(
                    "NSHIELD_WORLD_BINDING_INVALID: ciphersuite is missing");
        }
        ObjectNode none = softcard();
        none.remove("CertKMaKMCbKNSO");
        assertThat(run(none, SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: exactly one of CertKMaKMCbKNSO and CertKMaKMCaKFIPSbKNSO is required");
        ObjectNode both = softcard();
        both.put("CertKMaKMCaKFIPSbKNSO", both.get("CertKMaKMCbKNSO").asText());
        assertThat(run(both, SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: exactly one of CertKMaKMCbKNSO and CertKMaKMCaKFIPSbKNSO is required");
        ObjectNode sha256Hash = softcard();
        byte[] hkmc = field(sha256Hash, "hkmc");
        hkmc[0] = 45;
        put(sha256Hash, "hkmc", hkmc);
        assertThat(run(sha256Hash, SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: unsupported key hash mechanism");
        ObjectNode longHash = softcard();
        put(longHash, "hkmc", Nc.cat(field(longHash, "hkmc"), new byte[1]));
        assertThat(run(longHash, SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: key hash has 1 trailing bytes");
    }

    // ---------------------------------------------------- key generation

    @Test
    void keyGenerationCertificateIsVerified() throws Exception {
        assertThat(run(flip(softcard(), "kcsig", 12), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_KEYGEN_INVALID: kcsig does not verify under the module's KML");
        // pubkeydata x changed: another key hash
        assertThat(run(flip(softcard(), "pubkeydata", 20), SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_KEYGEN_INVALID: the key hash in kcmsg is not the hash of pubkeydata");
        ObjectNode swapped = softcard();
        swapped.put("pubkeydata", recoverable().get("pubkeydata").asText());
        assertThat(run(swapped, recoverableKey).getErrors()).containsExactly(
                "NSHIELD_KEYGEN_INVALID: generation parameters 47 do not fit key type 1");
        ObjectNode kcsigMech = softcard();
        byte[] sig = field(kcsigMech, "kcsig");
        sig[0] = (byte) 187;
        put(kcsigMech, "kcsig", sig);
        assertThat(run(kcsigMech, SOFTCARD_KEY).getErrors()).containsExactly(
                "NSHIELD_KEYGEN_INVALID: unsupported signature mechanism 187 for key type 3");
    }

    @Test
    void keyHashesMatchEntrustsBundles() throws Exception {
        for (ObjectNode b : List.of(softcard(), recoverable())) {
            byte[] kcmsg = field(b, "kcmsg");
            var key = NShieldVerifier.keyData(new NShieldVerifier.In(field(b, "pubkeydata")), true);
            assertThat(NShieldVerifier.keyHash(key)).isEqualTo(Arrays.copyOfRange(kcmsg, kcmsg.length - 20, kcmsg.length));
        }
        var rsaBigExponent = new NShieldVerifier.KeyData(NShieldVerifier.KEY_RSA_PUBLIC, 0,
                List.of(BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE), BigInteger.TEN));
        assertThatThrownBy(() -> NShieldVerifier.keyHash(rsaBigExponent)).hasMessage(
                "RSA public exponents above 32 bits are not supported");
        var rsa32 = new NShieldVerifier.KeyData(NShieldVerifier.KEY_RSA_PUBLIC, 0,
                List.of(BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE), BigInteger.TEN));
        assertThat(NShieldVerifier.keyHash(rsa32)).hasSize(20);
        var p521 = new NShieldVerifier.KeyData(NShieldVerifier.KEY_ECDSA_PUBLIC, NShieldVerifier.CURVE_P521,
                List.of(BigInteger.ONE, BigInteger.ONE));
        assertThatThrownBy(() -> NShieldVerifier.keyHash(p521)).hasMessage(
                "key hashes are supported for ECDSA on NIST P-256 only");
        assertThat(NShieldVerifier.padded(BigInteger.ZERO)).isEmpty();
        assertThat(NShieldVerifier.padded(BigInteger.ONE.shiftLeft(511))).hasSize(64);
        assertThat(NShieldVerifier.padded(BigInteger.ONE.shiftLeft(512))).hasSize(128).startsWith(new byte[64]);
    }

    @Test
    void keyDataIsReadStrictly() throws Exception {
        assertKeyRefused(Nc.cat(Nc.w(2), Nc.w(0)), "unsupported key type 2");
        assertKeyRefused(Nc.cat(Nc.w(46), Nc.w(5), Nc.w(0)), "unsupported curve 5");
        assertKeyRefused(Nc.cat(Nc.w(46), Nc.w(4), Nc.w(1)), "unsupported ECDSA key flags");
        assertKeyRefused(Nc.cat(Nc.w(1), Nc.bn(BigInteger.TEN), Nc.bn(BigInteger.TEN), Nc.w(0)), "key data has 4 trailing bytes");
        assertKeyRefused(Nc.cat(Nc.w(1), Nc.w(8), Nc.w(0)), "truncated nCore data");
        assertKeyRefused(Nc.cat(Nc.w(1), Nc.w(0xffffffffL)), "truncated nCore data");
        var p521 = NShieldVerifier.keyData(new NShieldVerifier.In(
                Nc.cat(Nc.w(46), Nc.w(6), Nc.w(0), Nc.bn(BigInteger.ONE), Nc.bn(BigInteger.TWO))), true);
        assertThat(p521.curve()).isEqualTo(NShieldVerifier.CURVE_P521);
        assertThat(p521.values()).containsExactly(BigInteger.ONE, BigInteger.TWO);
        assertThatThrownBy(p521::publicKey).isInstanceOf(NShieldVerifier.Refusal.class)
                .hasMessageStartingWith("invalid public key");
        var onCurve = p521().getPublic();
        var good = NShieldVerifier.keyData(new NShieldVerifier.In(Nc.key(onCurve)), true);
        assertThat(good.publicKey()).isEqualTo(onCurve);
    }

    private static void assertKeyRefused(byte[] data, String message) {
        assertThatThrownBy(() -> NShieldVerifier.keyData(new NShieldVerifier.In(data), true))
                .isInstanceOf(NShieldVerifier.Refusal.class).hasMessage(message);
    }

    @Test
    void keyGenIsReadStrictly() throws Exception {
        var ec = NShieldVerifier.keyData(new NShieldVerifier.In(field(softcard(), "pubkeydata")), true);
        var rsa = new NShieldVerifier.KeyData(NShieldVerifier.KEY_RSA_PUBLIC, 0, List.of(BigInteger.TEN, BigInteger.TEN));
        byte[] acl = Nc.w(0);
        byte[] hka = random(20);
        assertThat(NShieldVerifier.keyGen(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(45), Nc.w(4), acl, hka), ec).hka()).isEqualTo(hka);
        assertThat(NShieldVerifier.keyGen(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(47), Nc.w(4), acl, hka), ec).acl()).isEqualTo(acl);
        assertThat(NShieldVerifier.keyGen(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(2), Nc.w(7), Nc.w(4096),
                Nc.bn(BigInteger.valueOf(65537)), Nc.w(30), acl, hka), rsa).hka()).isEqualTo(hka);
        assertThat(NShieldVerifier.keyGen(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(2), Nc.w(1), Nc.w(4096),
                Nc.bn(BigInteger.valueOf(65537)), acl, hka), rsa).hka()).isEqualTo(hka);
        assertThat(NShieldVerifier.keyGen(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(2), Nc.w(2), Nc.w(4096),
                Nc.w(30), acl, hka), rsa).hka()).isEqualTo(hka);
        assertKeyGenRefused(Nc.cat(Nc.w(4), Nc.w(0)), ec, "kcmsg is not a KeyGen certificate");
        assertKeyGenRefused(Nc.cat(Nc.w(2), Nc.w(2)), ec, "unsupported KeyGen flags");
        assertKeyGenRefused(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(2), Nc.w(8)), rsa, "unsupported RSA generation flags");
        assertKeyGenRefused(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(47), Nc.w(6)), ec, "generation curve is not the key's curve");
        assertKeyGenRefused(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(2)), ec, "generation parameters 2 do not fit key type 46");
        assertKeyGenRefused(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(46)), ec, "generation parameters 46 do not fit key type 46");
        assertKeyGenRefused(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(45), Nc.w(4), acl, hka, Nc.w(0)), ec, "kcmsg has 4 trailing bytes");
        assertKeyGenRefused(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(45), Nc.w(4), Nc.w(1), Nc.w(0x80), Nc.w(0), Nc.w(0)), ec,
                "unsupported permission group flags 0x80");
    }

    private static void assertKeyGenRefused(byte[] msg, NShieldVerifier.KeyData key, String message) {
        assertThatThrownBy(() -> NShieldVerifier.keyGen(msg, key))
                .isInstanceOf(NShieldVerifier.Refusal.class).hasMessage(message);
    }

    @Test
    void signaturesNeedAKnownMechanismForTheKeyType() throws Exception {
        var dsa = new NShieldVerifier.KeyData(NShieldVerifier.KEY_DSA_PUBLIC, 0,
                List.of(BigInteger.TEN, BigInteger.TEN, BigInteger.TEN, BigInteger.TEN));
        var ec = new NShieldVerifier.KeyData(NShieldVerifier.KEY_ECDSA_PUBLIC, 4, List.of(BigInteger.ONE, BigInteger.ONE));
        byte[] rs = Nc.cat(Nc.bn(BigInteger.ONE), Nc.bn(BigInteger.ONE));
        assertThatThrownBy(() -> NShieldVerifier.verify(dsa, Nc.cat(Nc.w(187), rs), new byte[0]))
                .hasMessage("unsupported signature mechanism 187 for key type 3");
        assertThatThrownBy(() -> NShieldVerifier.verify(ec, Nc.cat(Nc.w(170), rs), new byte[0]))
                .hasMessage("unsupported signature mechanism 170 for key type 46");
        assertThatThrownBy(() -> NShieldVerifier.verify(dsa, Nc.cat(Nc.w(169), rs), new byte[0]))
                .hasMessage("unsupported signature mechanism 169 for key type 3");
        assertThatThrownBy(() -> NShieldVerifier.verify(dsa, Nc.cat(Nc.w(170), rs, Nc.w(0)), new byte[0]))
                .hasMessage("signature has 4 trailing bytes");
    }

    // --------------------------------------------------------- synthetic bundles

    @Test
    @DisplayName("Synthetic bundles: a DSA or ECDSA KML, the FIPS world binding, and an RSA-4096 key")
    void syntheticBundlesVerify() throws Exception {
        Synth plain = new Synth();
        var r = plain.verify();
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.getProtection()).isEqualTo("module");
        assertThat(r.getWarrantType()).isEqualTo("ModuleInformation");

        Synth fips = new Synth();
        fips.fips = true;
        assertThat(fips.verify().getErrors()).isEmpty();
        ObjectNode fipsBundle = fips.bundle();
        flip(fipsBundle, "hkfips", 10);
        assertThat(fips.verify(fipsBundle).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKMaKMCaKFIPSbKNSO does not verify under knsopub");
        Synth plainHeader = new Synth();
        plainHeader.fips = true;
        plainHeader.fipsHeader = "Module keys: suite = ";
        assertThat(plainHeader.verify().getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKMaKMCaKFIPSbKNSO does not verify under knsopub");

        Synth ecKml = new Synth();
        ecKml.kml = p521();
        assertThat(ecKml.verify().getErrors()).isEmpty();

        Synth rsa4096 = new Synth();
        rsa4096.app = rsa(4096);
        var big = rsa4096.verify();
        assertThat(big.getErrors()).isEmpty();
        assertThat(big.isValid()).isTrue();
        assertThat(((RSAPublicKey) rsa4096.app.getPublic()).getModulus().bitLength()).isEqualTo(4096);

        Synth exportable = new Synth();
        exportable.ops = 0x1000 | 0x4;
        var plainExport = exportable.verify();
        assertThat(plainExport.getErrors()).containsExactly("NSHIELD_ACL_REFUSED: forbidden operation permissions 0x4");
        assertThat(plainExport.isExportable()).isTrue();
        assertThat(plainExport.isRecoverable()).isFalse();
        assertThat(plainExport.isChainValid()).isTrue();
        assertThat(plainExport.isPublicKeyMatch()).isTrue();
        assertThat(plainExport.isValid()).isFalse();

        Synth recoveryBound = new Synth();
        recoveryBound.recovery = true;
        assertThat(recoveryBound.verify().getErrors()).isEmpty();
        ObjectNode badRecovery = recoveryBound.bundle();
        flip(badRecovery, "CertKREaKRAbKNSO", 12);
        assertThat(recoveryBound.verify(badRecovery).getErrors()).containsExactly(
                "NSHIELD_WORLD_BINDING_INVALID: CertKREaKRAbKNSO does not verify under knsopub");
    }

    /** Builds a complete bundle from test keys, under a test root. */
    private static final class Synth {
        KeyPair root = p521();
        KeyPair klf2 = p521();
        KeyPair kml = dsa();
        KeyPair knso = dsa();
        KeyPair app = p256();
        String esn = "TEST-0001";
        String suite = "DLf3072s256mAEScSP800131Ar1";
        boolean fips;
        String fipsHeader = "Module setup, FIPS3; suite = ";
        boolean recovery;
        byte[] hkm = random(20);
        long ops = 0x1000 | 0x200;

        ObjectNode bundle() throws Exception {
            ObjectNode b = MAPPER.createObjectNode();
            b.put("root", "KWARN-1");
            put(b, "warrant", Ddds.warrant("KWARN-1", Ddds.cert(root, Ddds.moduleInfo("ModuleInformation", esn, klf2.getPublic()))));
            byte[] hknso = NShieldVerifier.keyHash(keyData(knso.getPublic()));
            byte[] state = Nc.state(0, Nc.cat(Nc.w(2), Nc.string(esn)),
                    Nc.cat(Nc.w(3), new byte[20], Nc.key(kml.getPublic()), Nc.w(0)),
                    Nc.cat(Nc.w(5), hknso, Nc.w(0)),
                    Nc.cat(Nc.w(6), Nc.w(1), hkm, Nc.w(0), Nc.w(0)));
            put(b, "modstatemsg", state);
            put(b, "modstatesig", Nc.sign(klf2.getPrivate(), state));
            put(b, "knsopub", Nc.key(knso.getPublic()));
            byte[] hkmc = random(20);
            put(b, "hkm", Nc.cat(Nc.w(44), hkm));
            put(b, "hkmc", Nc.cat(Nc.w(44), hkmc));
            b.put("ciphersuite", suite);
            if (fips) {
                byte[] hkfips = random(20);
                put(b, "hkfips", Nc.cat(Nc.w(44), hkfips));
                put(b, "CertKMaKMCaKFIPSbKNSO", Nc.sign(knso.getPrivate(), Nc.cat(
                        (fipsHeader + suite + "\0").getBytes(StandardCharsets.US_ASCII), hknso, hkm, hkmc, hkfips)));
            } else {
                put(b, "CertKMaKMCbKNSO", Nc.sign(knso.getPrivate(), Nc.cat(
                        ("Module keys: suite = " + suite + "\0").getBytes(StandardCharsets.US_ASCII), hknso, hkm, hkmc)));
            }
            if (recovery) {
                byte[] hkre = random(20);
                byte[] hkra = random(20);
                put(b, "hkre", Nc.cat(Nc.w(44), hkre));
                put(b, "hkra", Nc.cat(Nc.w(44), hkra));
                put(b, "CertKREaKRAbKNSO", Nc.sign(knso.getPrivate(), Nc.cat(
                        "Card Recovery\0".getBytes(StandardCharsets.US_ASCII), hknso, hkre, hkra)));
            }
            var pub = keyData(app.getPublic());
            byte[] params = pub.type() == NShieldVerifier.KEY_RSA_PUBLIC
                    ? Nc.cat(Nc.w(2), Nc.w(4), Nc.w(4096)) : Nc.cat(Nc.w(47), Nc.w(4));
            byte[] acl = Acl.acl(Acl.group(0, Acl.ops(ops), Acl.blob(0x5, hkm)));
            byte[] kcmsg = Nc.cat(Nc.w(2), Nc.w(0), params, acl, NShieldVerifier.keyHash(pub));
            put(b, "kcmsg", kcmsg);
            put(b, "kcsig", Nc.sign(kml.getPrivate(), kcmsg));
            put(b, "pubkeydata", Nc.key(app.getPublic()));
            return b;
        }

        NShieldVerifier.NShieldResult verify() throws Exception {
            return verify(bundle());
        }

        NShieldVerifier.NShieldResult verify(ObjectNode bundle) {
            return new NShieldVerifier(root.getPublic()).verifyNShieldAttestation(bundle.toString(), app.getPublic());
        }
    }

    private static NShieldVerifier.KeyData keyData(PublicKey key) throws Exception {
        return NShieldVerifier.keyData(new NShieldVerifier.In(Nc.key(key)), true);
    }

    // ------------------------------------------------------------------ ACL

    @Test
    void entrustAclsAreEvaluatedAsEntrustDoes() throws Exception {
        for (ObjectNode b : List.of(softcard(), recoverable())) {
            var key = NShieldVerifier.keyData(new NShieldVerifier.In(field(b, "pubkeydata")), true);
            byte[] acl = NShieldVerifier.keyGen(field(b, "kcmsg"), key).acl();
            byte[] hkm = Arrays.copyOfRange(field(b, "hkm"), 4, 24);
            byte[] hknso = NShieldVerifier.keyHash(NShieldVerifier.keyData(new NShieldVerifier.In(field(b, "knsopub")), true));
            var result = NShieldVerifier.evaluateAcl(acl, hkm, hknso);
            if (b.equals(softcard())) {
                assertThat(result).isEqualTo(new NShieldVerifier.Acl(false, "softcard", List.of()));
            } else {
                assertThat(result).isEqualTo(new NShieldVerifier.Acl(true, "module",
                        List.of("forbidden operation permissions 0x400")));
            }
        }
    }

    @Test
    void operationPermissions() throws Exception {
        assertThat(eval(Acl.group(0, Acl.ops(0xb02b))).refusals()).isEmpty();
        for (long bit : List.of(0x4L, 0x10L, 0x40L, 0x400L, 0x800L, 0x4000L)) {
            assertThat(eval(Acl.group(0, Acl.ops(0x1000 | bit))).refusals())
                    .containsExactly("forbidden operation permissions 0x" + Long.toHexString(bit));
        }
        assertThat(eval(Acl.group(0, Acl.ops(0x10000 | 0x1000))).refusals())
                .containsExactly("unknown operation permissions 0x10000");
        assertThat(eval(Acl.group(0, Acl.ops(0xffffffffL))).refusals()).containsExactly(
                "unknown operation permissions 0xffff0000", "forbidden operation permissions 0x4c54");
        assertThat(eval().protection()).isEqualTo("non-persistent");
        assertThat(eval(Acl.group(0, Acl.ops(0x1000))).protection()).isEqualTo("non-persistent");
    }

    @Test
    void workingBlobs() throws Exception {
        byte[] token = Acl.tokenParams(0x4);
        assertThat(eval(Acl.group(0, Acl.blob(0x5, HKM))).protection()).isEqualTo("module");
        assertThat(eval(Acl.group(0, Acl.blob(0x1e, HKM, random(20), token)))).isEqualTo(
                new NShieldVerifier.Acl(false, "softcard", List.of()));
        assertThat(eval(Acl.group(0, Acl.blob(0x1c, HKM, random(20), Acl.tokenParams(0x3)))).protection())
                .isEqualTo("cardset");
        assertThat(eval(Acl.group(0, Acl.blob(0x1c, HKM, random(20), Acl.tokenParams(0x3)),
                Acl.blob(0x1c, HKM, random(20), token))).protection()).isEqualTo("softcard");
        assertThat(eval(Acl.group(0, Acl.blob(0x1c, HKM, random(20), token)),
                Acl.group(0, Acl.blob(0x5, HKM))).protection()).isEqualTo("module");
        assertThat(eval(Acl.group(0, Acl.blob(0x5, HKM)),
                Acl.group(0, Acl.blob(0x1c, HKM, random(20), token))).protection()).isEqualTo("module");
        // module-only with a token as well is module-protected
        assertThat(eval(Acl.group(0, Acl.blob(0x1d, HKM, random(20), token))).protection()).isEqualTo("module");

        assertThat(eval(Acl.group(0, Acl.blob(0x6, HKM))).refusals())
                .containsExactly("a working blob is neither module- nor token-protected");
        assertThat(eval(Acl.group(0, Acl.blob(0x1))).refusals())
                .containsExactly("a working blob is not under the trusted module key");
        assertThat(eval(Acl.group(0, Acl.blob(0x5, random(20)))).refusals())
                .containsExactly("a working blob is not under the trusted module key");
        assertThat(NShieldVerifier.evaluateAcl(Acl.acl(Acl.group(0, Acl.blob(0x5, HKM))), null, HKNSO).refusals())
                .containsExactly("a working blob is not under the trusted module key");
        assertThat(eval(Acl.group(0, Acl.blob(0x25, HKM))).refusals())
                .containsExactly("a working blob allows a null module key token");
        assertThat(eval(Acl.group(0, Acl.blob(0xc, HKM, random(20)))).refusals())
                .containsExactly("a token-protected working blob lacks token parameters");
        var refused = eval(Acl.group(0, Acl.blob(0x6, HKM)));
        assertThat(refused.protection()).isEqualTo("non-persistent");

        assertThat(eval(Acl.group(0, Acl.blob(0x45, HKM, Acl.blobFile(0x3, Nc.w(7), random(20))))).refusals()).isEmpty();
        assertThat(eval(Acl.group(0, Acl.blob(0x45, HKM, Acl.blobFile(0x1, Nc.w(7))))).refusals()).isEmpty();
        assertThat(eval(Acl.group(0, Acl.blob(0x45, HKM, Acl.blobFile(0x2, random(20))))).refusals()).isEmpty();
        assertAclRefused(Acl.acl(Acl.group(0, Acl.blob(0x45, HKM, Acl.blobFile(0x4)))), "unsupported blob file flags 0x4");
        assertAclRefused(Acl.acl(Acl.group(0, Acl.blob(0x85, HKM))), "unsupported MakeBlob flags 0x85");
    }

    @Test
    void recoverability() throws Exception {
        assertThat(eval(Acl.group(0, Acl.ops(0x1000)), Acl.group(0, Acl.archive(0x0, 225)))).isEqualTo(
                new NShieldVerifier.Acl(true, "non-persistent", List.of()));
        assertThat(eval(Acl.group(0, Acl.archive(0x3, 225, random(20), Acl.blobFile(0)))).recoverable()).isTrue();
        assertAclRefused(Acl.acl(Acl.group(0, Acl.archive(0x4, 225))), "unsupported MakeArchiveBlob flags 0x4");

        // trump ops: certified by KNSO; its actions are disregarded
        byte[] ops = Acl.ops(0xffff);
        byte[] blob = Acl.blob(0x0);
        assertThat(eval(Acl.certified(0x3, HKNSO, ops, blob))).isEqualTo(
                new NShieldVerifier.Acl(true, "non-persistent", List.of()));
        assertThat(eval(Acl.certified(0x4, Nc.cat(HKNSO, Nc.w(1)), ops, blob))).isEqualTo(
                new NShieldVerifier.Acl(true, "non-persistent", List.of()));
        assertThat(eval(Acl.certified(0x40, Nc.cat(Nc.w(44), HKNSO, Nc.w(1)), ops, blob))).isEqualTo(
                new NShieldVerifier.Acl(true, "non-persistent", List.of()));
        assertThat(eval(Acl.certified(0x1, random(20), ops, blob))).isEqualTo(new NShieldVerifier.Acl(false,
                "non-persistent", List.of("a permission group needs certification by another key")));
        assertThat(eval(Acl.certified(0x5, Nc.cat(HKNSO, random(20), Nc.w(1)), ops, blob)).refusals())
                .containsExactly("a permission group needs certification by another key");
        assertAclRefused(Acl.acl(Acl.certified(0x40, Nc.cat(Nc.w(45), HKNSO, Nc.w(1)), Acl.ops(0))),
                "unsupported key hash mechanism");
        // a later group is still evaluated after a trump ops group
        assertThat(eval(Acl.certified(0x1, HKNSO, ops, blob), Acl.group(0, Acl.ops(0x4))).refusals())
                .containsExactly("forbidden operation permissions 0x4");
    }

    @Test
    void groupFlagsLimitsAndOtherActions() throws Exception {
        assertThat(eval(Acl.certified(0x2a, Nc.string("1234-5678-9ABC"), Acl.ops(0x1000))).refusals()).isEmpty();
        assertAclRefused(Acl.acl(Acl.group(0x10, Acl.ops(0x1000))), "unsupported permission group flags 0x10");
        assertAclRefused(Acl.acl(Acl.group(0x80, Acl.ops(0x1000))), "unsupported permission group flags 0x80");
        byte[] limits = Nc.cat(Nc.w(3), Nc.w(1), HKM, Nc.w(5), Nc.w(3), Nc.w(60), Nc.w(6), HKM, Nc.w(2));
        assertThat(NShieldVerifier.evaluateAcl(Nc.cat(Nc.w(1), Nc.w(0), limits, Nc.w(1), Acl.ops(0x1000)), HKM, HKNSO)
                .refusals()).isEmpty();
        assertAclRefused(Nc.cat(Nc.w(1), Nc.w(0), Nc.w(1), Nc.w(4), Nc.w(0), Nc.w(0)), "unsupported use limit 4");

        assertThat(eval(Acl.group(0, Acl.derive(5, 29), Acl.derive(47, 29))).refusals()).isEmpty();
        assertThat(eval(Acl.group(0, Acl.derive(5, 30))).refusals()).containsExactly("unsupported key derivation mechanism 30");
        assertAclRefused(Acl.acl(Acl.group(0, Nc.cat(Nc.w(5), Nc.w(1), Nc.w(0), Nc.w(29), Nc.w(0)))),
                "key derivation with parameters or other keys is not supported");
        assertAclRefused(Acl.acl(Acl.group(0, Nc.cat(Nc.w(5), Nc.w(0), Nc.w(0), Nc.w(29), Nc.w(1)))),
                "key derivation with parameters or other keys is not supported");
        assertAclRefused(Acl.acl(Acl.group(0, Nc.cat(Nc.w(4), Nc.w(0)))), "unsupported ACL action 4");
        assertAclRefused(Nc.cat(Acl.acl(Acl.group(0, Acl.ops(0x1000))), Nc.w(0)), "ACL has 4 trailing bytes");
        assertAclRefused(Nc.cat(Nc.w(2), Nc.w(0), Nc.w(0), Nc.w(0)), "count exceeds the data");
        // an empty group is 12 bytes
        assertThat(NShieldVerifier.evaluateAcl(Nc.cat(Nc.w(1), Nc.w(0), Nc.w(0), Nc.w(0)), HKM, HKNSO).refusals()).isEmpty();
    }

    private static NShieldVerifier.Acl eval(byte[]... groups) throws Exception {
        return NShieldVerifier.evaluateAcl(Acl.acl(groups), HKM, HKNSO);
    }

    private static void assertAclRefused(byte[] acl, String message) {
        assertThatThrownBy(() -> NShieldVerifier.evaluateAcl(acl, HKM, HKNSO))
                .isInstanceOf(NShieldVerifier.Refusal.class).hasMessage(message);
    }

    // ----------------------------------------------------------------- DDDS

    @Test
    void dddsIsDecodedStrictly() throws Exception {
        assertThat(NShieldVerifier.Ddds.decode(new byte[]{0x1f})).isEqualTo(BigInteger.valueOf(31));
        assertThat(NShieldVerifier.Ddds.decode(new byte[]{(byte) 0xc4, 2, 'a', 'b'}))
                .isEqualTo(new NShieldVerifier.Ddds.Sym("ab"));
        byte[] long300 = new byte[303];
        long300[0] = (byte) 0xd5;
        long300[1] = 1;
        long300[2] = 44;
        assertThat((byte[]) NShieldVerifier.Ddds.decode(long300)).hasSize(300);
        assertThat(NShieldVerifier.Ddds.decode(new byte[]{(byte) 0xf4, (byte) 0xc5, 2, 1, 0}))
                .isEqualTo(BigInteger.valueOf(256));
        assertDddsRefused(new byte[]{(byte) 0xf4, 0x21, 'a'}, "DDDS integer is not a byte block");
        assertDddsRefused(new byte[]{(byte) 0x80}, "unsupported DDDS tag 0x80");
        assertDddsRefused(new byte[]{(byte) 0xc0}, "unsupported DDDS tag 0xc0");
        assertDddsRefused(new byte[]{1, 1}, "DDDS data has trailing bytes");
        assertDddsRefused(new byte[]{0x22, 'a'}, "truncated DDDS data");
        assertDddsRefused(new byte[]{}, "truncated DDDS data");
        assertDddsRefused(new byte[]{(byte) 0xb2, 1, 2, 1, 3}, "DDDS map key repeated");
        byte[] deep = new byte[10];
        Arrays.fill(deep, 0, 9, (byte) 0x91);
        assertDddsRefused(deep, "DDDS nesting too deep");
        byte[] eight = new byte[9];
        Arrays.fill(eight, 0, 8, (byte) 0x91);
        assertThat(NShieldVerifier.Ddds.decode(eight)).isInstanceOf(List.class);
    }

    private static void assertDddsRefused(byte[] b, String message) {
        assertThatThrownBy(() -> NShieldVerifier.Ddds.decode(b))
                .isInstanceOf(NShieldVerifier.Refusal.class).hasMessage(message);
    }

    @Test
    void nCoreStringsArePaddedToWords() throws Exception {
        var in = new NShieldVerifier.In(Nc.cat(Nc.string("abcde"), Nc.w(9)));
        assertThat(in.string()).isEqualTo("abcde");
        assertThat(in.u32()).isEqualTo(9);
        in.end("x");
        var four = new NShieldVerifier.In(Nc.cat(Nc.string("abcd"), Nc.w(9)));
        assertThat(four.string()).isEqualTo("abcd");
        assertThat(four.u32()).isEqualTo(9);
        var unterminated = new NShieldVerifier.In(Nc.cat(Nc.w(3), "abc".getBytes(StandardCharsets.US_ASCII), new byte[1]));
        assertThat(unterminated.string()).isEqualTo("abc");
        unterminated.end("x");
        var empty = new NShieldVerifier.In(Nc.w(0));
        assertThat(empty.string()).isEmpty();
        assertThatThrownBy(() -> new NShieldVerifier.In(Nc.cat(Nc.w(3), new byte[]{'a', 0, 0}, new byte[1])).string())
                .hasMessage("string contains NUL");
        assertThat(new NShieldVerifier.In(new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}).u32())
                .isEqualTo(0xffffffffL);
    }

    // ------------------------------------------------------------- helpers

    static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    static KeyPair p521() {
        return ec("secp521r1");
    }

    static KeyPair p256() {
        return ec("secp256r1");
    }

    private static KeyPair ec(String curve) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec(curve));
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair dsaKeys;

    static KeyPair dsa() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("DSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static PublicKey dsaKey() {
        if (dsaKeys == null) {
            dsaKeys = dsa();
        }
        return dsaKeys.getPublic();
    }

    static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    /** nCore marshalling for test data. */
    static final class Nc {
        static byte[] w(long v) {
            return new byte[]{(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)};
        }

        static byte[] bn(BigInteger x) {
            byte[] be = x.toByteArray();
            int start = be.length > 1 && be[0] == 0 ? 1 : 0;
            int n = be.length - start;
            int padded = (n + 3) / 4 * 4;
            byte[] le = new byte[padded];
            for (int i = 0; i < n; i++) {
                le[i] = be[be.length - 1 - i];
            }
            return cat(w(padded), le);
        }

        static byte[] string(String s) {
            byte[] b = (s + "\0").getBytes(StandardCharsets.US_ASCII);
            return cat(w(b.length), b, new byte[(4 - b.length % 4) % 4]);
        }

        static byte[] cat(byte[]... parts) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (byte[] p : parts) {
                out.writeBytes(p);
            }
            return out.toByteArray();
        }

        static byte[] state(long flags, byte[]... attributes) {
            return cat(w(4), w(flags), w(attributes.length), cat(attributes));
        }

        static byte[] dsa(PublicKey key) {
            DSAPublicKey k = (DSAPublicKey) key;
            return cat(w(3), bn(k.getParams().getP()), bn(k.getParams().getQ()), bn(k.getParams().getG()), bn(k.getY()));
        }

        static byte[] key(PublicKey key) {
            if (key instanceof DSAPublicKey) {
                return dsa(key);
            }
            if (key instanceof RSAPublicKey k) {
                return cat(w(1), bn(k.getPublicExponent()), bn(k.getModulus()));
            }
            ECPublicKey k = (ECPublicKey) key;
            int curve = k.getParams().getCurve().getField().getFieldSize() == 521 ? 6 : 4;
            return cat(w(46), w(curve), w(0), bn(k.getW().getAffineX()), bn(k.getW().getAffineY()));
        }

        /** An M_CipherText: DSA SHA-256 (170) or ECDSA SHA-512 (187). */
        static byte[] sign(PrivateKey key, byte[] message) throws Exception {
            boolean dsa = key.getAlgorithm().equals("DSA");
            Signature s = Signature.getInstance(dsa ? "SHA256withDSA" : "SHA512withECDSA");
            s.initSign(key);
            s.update(message);
            ASN1Sequence rs = ASN1Sequence.getInstance(s.sign());
            return cat(w(dsa ? 170 : 187), bn(ASN1Integer.getInstance(rs.getObjectAt(0)).getValue()),
                    bn(ASN1Integer.getInstance(rs.getObjectAt(1)).getValue()));
        }
    }

    /** ACL encoding for test data. */
    static final class Acl {
        static byte[] acl(byte[]... groups) {
            return Nc.cat(Nc.w(groups.length), Nc.cat(groups));
        }

        /** A group without limits or optional fields. */
        static byte[] group(long flags, byte[]... actions) {
            return certified(flags, new byte[0], actions);
        }

        /** A group without limits, with {@code tail} as its optional fields (certifier, moduleserial, ...). */
        static byte[] certified(long flags, byte[] tail, byte[]... actions) {
            return Nc.cat(Nc.w(flags), Nc.w(0), Nc.w(actions.length), Nc.cat(actions), tail);
        }

        static byte[] ops(long perms) {
            return Nc.cat(Nc.w(1), Nc.w(perms));
        }

        static byte[] blob(long flags, byte[]... fields) {
            return Nc.cat(Nc.w(2), Nc.w(flags), Nc.cat(fields));
        }

        static byte[] tokenParams(long flags) {
            return Nc.cat(Nc.w(flags), Nc.w(1), Nc.w(1), Nc.w(0));
        }

        static byte[] blobFile(long flags, byte[]... fields) {
            return Nc.cat(Nc.w(flags), Nc.cat(fields));
        }

        static byte[] archive(long flags, long mech, byte[]... fields) {
            return Nc.cat(Nc.w(3), Nc.w(flags), Nc.w(mech), Nc.cat(fields));
        }

        static byte[] derive(long type, long mech) {
            return Nc.cat(Nc.w(type), Nc.w(0), Nc.w(0), Nc.w(mech), Nc.w(0));
        }
    }

    /** DDDS encoding for test warrants. */
    static final class Ddds {
        static final List<Object> MECH = List.of(sym("ECDSA"), List.of(sym("EMSA1"), sym("SHA512")));

        static NShieldVerifier.Ddds.Sym sym(String s) {
            return new NShieldVerifier.Ddds.Sym(s);
        }

        static byte[] encode(Object v) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            write(out, v);
            return out.toByteArray();
        }

        private static void write(ByteArrayOutputStream out, Object v) {
            if (v instanceof NShieldVerifier.Ddds.Sym s) {
                if (s.name().length() < 16) {
                    out.write(0x30 | s.name().length());
                } else {
                    out.write(0xc4);
                    out.write(s.name().length());
                }
                out.writeBytes(s.name().getBytes(StandardCharsets.US_ASCII));
            } else if (v instanceof String s) {
                out.write(0x20 | s.length());
                out.writeBytes(s.getBytes(StandardCharsets.US_ASCII));
            } else if (v instanceof byte[] b) {
                if (b.length < 256) {
                    out.write(0xc5);
                    out.write(b.length);
                } else {
                    out.write(0xd5);
                    out.write(b.length >> 8);
                    out.write(b.length & 0xff);
                }
                out.writeBytes(b);
            } else if (v instanceof BigInteger x) {
                out.write(0xf4);
                byte[] be = x.toByteArray();
                byte[] fixed = new byte[66];
                int n = Math.min(be.length, 66);
                System.arraycopy(be, be.length - n, fixed, 66 - n, n);
                write(out, fixed);
            } else if (v instanceof List<?> l) {
                out.write(0x90 | l.size());
                l.forEach(x -> write(out, x));
            } else if (v instanceof Map<?, ?> m) {
                out.write(0xb0 | m.size());
                m.forEach((k, x) -> {
                    write(out, k);
                    write(out, x);
                });
            } else {
                throw new IllegalArgumentException(String.valueOf(v));
            }
        }

        static List<Object> p521Key(PublicKey key) {
            ECPoint w = ((ECPublicKey) key).getW();
            return List.of(sym("ECDSA"), sym("Public"), sym("NISTP521"), List.of(w.getAffineX(), w.getAffineY()));
        }

        static Map<Object, Object> delegation(PublicKey key, List<Object> mech) {
            Map<Object, Object> m = new LinkedHashMap<>();
            m.put(sym("WarrantCertificateType"), sym("Delegation"));
            m.put(sym("DelegateKey"), p521Key(key));
            m.put(sym("SigMech"), mech);
            return m;
        }

        static Map<Object, Object> moduleInfo(String type, String esn, PublicKey klf2) {
            Map<Object, Object> m = new LinkedHashMap<>();
            m.put(sym("WarrantCertificateType"), sym(type));
            m.put(sym("ElectronicSerialNumber"), esn);
            m.put(sym("KLF2pub"), p521Key(klf2));
            m.put(sym("KLF2mech"), MECH);
            return m;
        }

        static Map<Object, Object> cert(KeyPair signer, Map<Object, Object> payload) throws Exception {
            return signed(signer, encode(payload));
        }

        static Map<Object, Object> signed(KeyPair signer, byte[] payload) throws Exception {
            Signature s = Signature.getInstance("SHA512withECDSA");
            s.initSign(signer.getPrivate());
            s.update(payload);
            ASN1Sequence rs = ASN1Sequence.getInstance(s.sign());
            byte[] sig = new byte[132];
            for (int i = 0; i < 2; i++) {
                byte[] be = ASN1Integer.getInstance(rs.getObjectAt(i)).getValue().toByteArray();
                int n = Math.min(be.length, 66);
                System.arraycopy(be, be.length - n, sig, 66 * i + 66 - n, n);
            }
            Map<Object, Object> m = new LinkedHashMap<>();
            m.put(sym("Signature"), sig);
            m.put(sym("Payload"), payload);
            return m;
        }

        static byte[] warrant(String root, Object... certs) {
            List<Object> l = new ArrayList<>();
            l.add(sym(root));
            l.addAll(List.of(certs));
            return encode(l);
        }
    }
}
