package eu.gillstrom.gatekeeper.verification;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.model.HsmVendor;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link TrustAnchors}: without configuration every verifier keeps exactly
 * its pinned anchor; an operator's file replaces it, is refused at load when
 * it is not a usable anchor, and is logged and reported with its SHA-256.
 */
class TrustAnchorsTest {

    private static final String PREFIX = "test.trust-anchors";
    private static final String YUBICO_OID = "1.3.6.1.4.1.41482.4";
    private static final byte[] NON_EXPORTABLE_CAPABILITIES = {0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x06, 0x60};
    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    /** The values in the "Pinned trust anchor" comment blocks, as TrustAnchorPinningTest pins them. */
    private static final Map<String, List<String>> PINNED_SHA256 = Map.of(
            TrustAnchors.YUBICO, List.of(
                    "09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24"),
            TrustAnchors.SECUROSYS, List.of(
                    "D2:C9:3D:8F:69:BC:8D:62:4E:37:F2:5B:9E:6E:7B:EC:41:76:1A:AB:86:4C:94:F3:79:36:1B:9B:78:A9:DB:97"),
            TrustAnchors.MARVELL, List.of(
                    "23:01:43:DF:00:E0:B4:52:74:3E:06:8A:5B:3F:C0:8D:F8:F0:6C:EF:C4:85:4E:A6:27:AE:B7:EB:D7:0E:E2:F4",
                    "17:64:4D:E0:D3:3B:C7:3B:2F:4E:F4:C2:0A:11:F6:C8:CC:1F:72:3A:4C:D8:3E:E6:00:36:1C:BB:24:D8:D2:E5"),
            TrustAnchors.GOOGLE_OWNER, List.of(
                    "46:B5:FD:35:1D:56:A0:72:1C:A0:AF:CD:17:31:C0:F7:B7:4E:39:41:EB:81:8B:FD:0E:C3:6E:29:DF:0D:E0:95"),
            TrustAnchors.THALES, List.of(
                    "69:6A:7E:E6:7B:C4:FA:CF:F6:09:11:BC:0B:24:A3:A6:BC:E7:5A:2E:F4:C4:23:18:44:8A:DD:45:01:B6:99:69"),
            TrustAnchors.CRYPTO4A, List.of(
                    "63:7E:6A:7E:95:DE:D7:27:2F:5B:3E:5A:0D:94:41:4D:23:E1:B5:4F:9E:2E:65:93:B6:41:75:62:BB:B5:43:3C"),
            TrustAnchors.FORTANIX, List.of(
                    "D7:1A:15:B3:4E:78:1E:9E:F9:13:54:FA:BA:E8:B1:15:E0:62:B8:97:95:FE:C3:AE:C0:E0:45:FE:D2:66:C2:C2"),
            TrustAnchors.ENTRUST, List.of(
                    "DF:8F:05:A3:95:96:BB:9C:4A:8C:C4:D3:B6:DE:10:60:7F:36:2D:71:82:E8:81:EA:82:A5:ED:C7:CD:CD:F8:4F"));

    private static KeyPair rootKeys;
    private static X509Certificate testRoot;

    @TempDir
    Path dir;

    private ListAppender<ILoggingEvent> logs;

    @BeforeAll
    static void testRoot() throws Exception {
        rootKeys = rsa();
        testRoot = certificate("CN=Operator Test Root", rootKeys.getPublic(), "CN=Operator Test Root",
                rootKeys.getPrivate(), true);
    }

    @BeforeEach
    void captureLogs() {
        logs = new ListAppender<>();
        logs.start();
        ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(TrustAnchors.class)).addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(TrustAnchors.class)).detachAppender(logs);
    }

    // ------------------------------------------------------- no configuration

    @Test
    void withoutConfigurationEveryVerifierKeepsItsPinnedAnchor() throws Exception {
        Map<String, String> blank = new HashMap<>();
        for (String key : TrustAnchors.KEYS) {
            blank.put(key, key.equals(TrustAnchors.MARVELL) ? "  " : "");
        }
        for (TrustAnchors anchors : List.of(TrustAnchors.pinned(), TrustAnchors.load(Map.of(), PREFIX),
                TrustAnchors.load(null, PREFIX), TrustAnchors.load(blank, PREFIX))) {
            assertSameAnchorsAsTheNoArgumentConstructors(anchors);
            for (TrustAnchors.ActiveAnchor a : anchors.all()) {
                assertThat(a.origin()).as(a.anchor()).isEqualTo(TrustAnchors.ORIGIN_PINNED);
                assertThat(a.path()).as(a.anchor()).isNull();
                assertThat(a.matchesPinned()).as(a.anchor()).isTrue();
                assertThat(a.sha256()).as(a.anchor()).isEqualTo(PINNED_SHA256.get(a.anchor()));
            }
        }
        assertThat(TrustAnchors.pinned().all()).extracting(TrustAnchors.ActiveAnchor::anchor)
                .containsExactlyElementsOf(TrustAnchors.KEYS);
        assertThat(logs.list).noneMatch(e -> e.getLevel().isGreaterOrEqual(Level.INFO));
    }

    @Test
    void pinnedReportShowsWhatEachAnchorIsHashedOver() {
        TrustAnchors anchors = TrustAnchors.pinned();
        assertThat(anchors.active(TrustAnchors.ENTRUST).sha256Of()).isEqualTo(TrustAnchors.SHA256_OF_PUBLIC_KEY);
        assertThat(anchors.active(TrustAnchors.ENTRUST).subjects()).isEmpty();
        assertThat(anchors.active(TrustAnchors.ENTRUST).publicKeySha256())
                .isEqualTo(anchors.active(TrustAnchors.ENTRUST).sha256());
        assertThat(anchors.active(TrustAnchors.THALES).sha256Of()).isEqualTo(TrustAnchors.SHA256_OF_CERTIFICATE);
        assertThat(anchors.active(TrustAnchors.THALES).subjects())
                .containsExactly("CN=Chrysalis-ITS Root,O=Chrysalis-ITS Inc.,L=Ottawa,ST=Ontario,C=CA");
        assertThat(anchors.active(TrustAnchors.THALES).publicKeySha256()).containsExactly(
                "5D:31:FC:46:2A:E8:A1:A5:32:7B:14:9F:F4:3A:A6:D8:67:A2:8D:7E:17:CA:1C:CA:7E:7D:51:4C:F8:CD:C1:32");
        assertThat(anchors.forVendor(HsmVendor.GOOGLE)).extracting(TrustAnchors.ActiveAnchor::anchor)
                .containsExactly(TrustAnchors.MARVELL, TrustAnchors.GOOGLE_OWNER);
        assertThat(anchors.forVendor(HsmVendor.AZURE)).extracting(TrustAnchors.ActiveAnchor::anchor)
                .containsExactly(TrustAnchors.MARVELL);
        for (HsmVendor v : HsmVendor.values()) {
            assertThat(anchors.forVendor(v)).as(v.name()).isNotEmpty();
        }
    }

    // ----------------------------------------------------------- overrides

    @Test
    void yubicoOverrideVerifiesATestPkiAttestationAndRejectsTheRealOne() throws Exception {
        TrustAnchors anchors = TrustAnchors.load(Map.of(TrustAnchors.YUBICO,
                write("root.pem", pem("CERTIFICATE", testRoot.getEncoded())).toString()), PREFIX);
        YubicoVerifier overridden = new YubicoVerifier(anchors);
        assertThat(overridden.rootCa()).isEqualTo(testRoot);

        KeyPair attested = rsa();
        List<String> chain = yubicoChain(attested.getPublic());
        YubicoVerifier.YubicoAttestationResult test = overridden.verifyYubicoAttestation(chain, attested.getPublic());
        assertThat(test.getErrors()).isEmpty();
        assertThat(test.isValid()).isTrue();
        assertThat(new YubicoVerifier().verifyYubicoAttestation(chain, attested.getPublic()).isValid())
                .as("the pinned root does not accept the test PKI").isFalse();

        JsonNode fixture = fixture("/fixtures/yubico/request.json");
        List<String> realChain = texts(fixture.get("attestationCertChain"));
        PublicKey realKey = csrKey(fixture.get("csr").asText());
        YubicoVerifier.YubicoAttestationResult real = overridden.verifyYubicoAttestation(realChain, realKey);
        assertThat(real.isChainValid()).isFalse();
        assertThat(real.isValid()).isFalse();
        assertThat(new YubicoVerifier().verifyYubicoAttestation(realChain, realKey).isValid())
                .as("the pinned root accepts the real fixture").isTrue();

        // The other anchors are untouched.
        assertThat(new SecurosysVerifier(anchors).rootCa()).isEqualTo(new SecurosysVerifier().rootCa());
    }

    @Test
    void securosysOverrideVerifiesATestPkiAttestationAndRejectsTheRealOne() throws Exception {
        TrustAnchors anchors = TrustAnchors.load(Map.of(TrustAnchors.SECUROSYS,
                write("root.pem", pem("CERTIFICATE", testRoot.getEncoded())).toString()), PREFIX);
        SecurosysVerifier overridden = new SecurosysVerifier(anchors);

        KeyPair device = rsa();
        X509Certificate deviceCert = certificate("CN=PRIMUS HSM KEY (SN: 1234567)", device.getPublic(),
                "CN=Operator Test Root", rootKeys.getPrivate(), true);
        KeyPair attestationKey = rsa();
        X509Certificate attestationCert = certificate("CN=attestation-key", attestationKey.getPublic(),
                "CN=PRIMUS HSM KEY (SN: 1234567)", device.getPrivate(), false);
        KeyPair attested = rsa();
        byte[] xml = ("<private_key creation=\"generated\"><public_key>"
                + Base64.getEncoder().encodeToString(attested.getPublic().getEncoded()) + "</public_key>"
                + "<label>k</label><algorithm>RSA</algorithm><key_size>2048</key_size><attributes>"
                + "<extractable>false</extractable><never_extractable>true</never_extractable>"
                + "<sensitive>true</sensitive><always_sensitive>true</always_sensitive></attributes></private_key>")
                .getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(attestationKey.getPrivate());
        s.update(xml);
        List<String> chain = List.of(pem("CERTIFICATE", attestationCert.getEncoded()),
                pem("CERTIFICATE", deviceCert.getEncoded()));

        SecurosysVerifier.SecurosysAttestationResult test = overridden.verifySecurosysAttestation(
                Base64.getEncoder().encodeToString(xml), Base64.getEncoder().encodeToString(s.sign()), chain,
                attested.getPublic());
        assertThat(test.getErrors()).isEmpty();
        assertThat(test.isValid()).isTrue();

        JsonNode fixture = fixture("/fixtures/securosys/request.json");
        SecurosysVerifier.SecurosysAttestationResult real = overridden.verifySecurosysAttestation(
                fixture.get("attestationData").asText(), fixture.get("attestationSignature").asText(),
                texts(fixture.get("attestationCertChain")), csrKey(fixture.get("csr").asText()));
        assertThat(real.isChainValid()).isFalse();
        assertThat(real.isValid()).isFalse();
    }

    @Test
    void overrideThatIsNotThePinnedAnchorIsReportedAndWarnedWithBothValues() throws Exception {
        Path file = write("root.pem", "operator copy\n" + pem("CERTIFICATE", testRoot.getEncoded()));
        TrustAnchors anchors = TrustAnchors.load(Map.of(TrustAnchors.YUBICO, file.toString()), PREFIX);

        String overrideSha256 = TrustAnchors.fingerprint(testRoot.getEncoded());
        String pinnedSha256 = PINNED_SHA256.get(TrustAnchors.YUBICO).get(0);
        TrustAnchors.ActiveAnchor a = anchors.active(TrustAnchors.YUBICO);
        assertThat(a.origin()).isEqualTo(TrustAnchors.ORIGIN_OVERRIDE);
        assertThat(a.path()).isEqualTo(file.toAbsolutePath().normalize().toString());
        assertThat(a.sha256()).containsExactly(overrideSha256);
        assertThat(a.subjects()).containsExactly("CN=Operator Test Root");
        assertThat(a.matchesPinned()).isFalse();
        assertThat(anchors.forVendor(HsmVendor.YUBICO)).containsExactly(a);
        assertThat(anchors.active(TrustAnchors.SECUROSYS).origin()).isEqualTo(TrustAnchors.ORIGIN_PINNED);

        List<ILoggingEvent> warnings = logs.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
        assertThat(warnings).hasSize(1);
        assertThat(warnings.get(0).getFormattedMessage())
                .contains(PREFIX + ".yubico", a.path(), overrideSha256, pinnedSha256);
        assertThat(logs.list).anyMatch(e -> e.getLevel() == Level.INFO
                && e.getFormattedMessage().contains(overrideSha256));
    }

    @Test
    void everyPinnedAnchorWrittenToAFileIsAcceptedAsItselfWithoutAWarning() throws Exception {
        TrustAnchors pinned = TrustAnchors.pinned();
        Map<String, String> files = new LinkedHashMap<>();
        files.put(TrustAnchors.YUBICO, write("y.pem", pem("CERTIFICATE", pinned.yubicoRoot().getEncoded())).toString());
        files.put(TrustAnchors.SECUROSYS,
                write("s.pem", pem("CERTIFICATE", pinned.securosysRoot().getEncoded())).toString());
        StringBuilder marvell = new StringBuilder();
        for (X509Certificate c : pinned.marvellRoots()) {
            marvell.append(pem("CERTIFICATE", c.getEncoded()));
        }
        files.put(TrustAnchors.MARVELL, write("m.pem", marvell.toString()).toString());
        files.put(TrustAnchors.GOOGLE_OWNER,
                write("g.pem", pem("CERTIFICATE", pinned.googleOwnerRoot().getEncoded())).toString());
        files.put(TrustAnchors.THALES, write("t.pem", ThalesLunaVerifier.CHRYSALIS_ROOT_PEM).toString());
        files.put(TrustAnchors.CRYPTO4A, write("c.pem", Crypto4AVerifier.C4A_ROOT_PEM).toString());
        files.put(TrustAnchors.FORTANIX, write("f.pem", pem("CERTIFICATE", pinned.fortanixRoot().getEncoded())).toString());
        files.put(TrustAnchors.ENTRUST, write("e.pem", pem("PUBLIC KEY", pinned.entrustRootKey().getEncoded())).toString());

        TrustAnchors anchors = TrustAnchors.load(files, PREFIX);

        assertSameAnchorsAsTheNoArgumentConstructors(anchors);
        for (TrustAnchors.ActiveAnchor a : anchors.all()) {
            assertThat(a.origin()).as(a.anchor()).isEqualTo(TrustAnchors.ORIGIN_OVERRIDE);
            assertThat(a.path()).as(a.anchor()).isEqualTo(Path.of(files.get(a.anchor())).toString());
            assertThat(a.sha256()).as(a.anchor()).isEqualTo(PINNED_SHA256.get(a.anchor()));
            assertThat(a.matchesPinned()).as(a.anchor()).isTrue();
        }
        assertThat(logs.list).noneMatch(e -> e.getLevel() == Level.WARN);
        assertThat(logs.list).anyMatch(e -> e.getFormattedMessage().contains("is the pinned anchor"));
    }

    @Test
    void marvellOverrideMayHoldSeveralCertificatesAndReplacesBothPinnedRoots() throws Exception {
        KeyPair second = rsa();
        X509Certificate secondRoot = certificate("CN=Operator Test Root 2", second.getPublic(),
                "CN=Operator Test Root 2", second.getPrivate(), true);
        TrustAnchors anchors = TrustAnchors.load(Map.of(TrustAnchors.MARVELL, write("m.pem",
                pem("CERTIFICATE", testRoot.getEncoded()) + pem("CERTIFICATE", secondRoot.getEncoded())).toString()),
                PREFIX);

        assertThat(anchors.marvellRoots()).containsExactly(testRoot, secondRoot);
        assertThat(new AzureHsmVerifier(anchors).marvellRoots()).containsExactly(testRoot, secondRoot);
        assertThat(new MarvellHsmVerifier(anchors).marvellRoots()).containsExactly(testRoot, secondRoot);
        GoogleCloudHsmVerifier google = new GoogleCloudHsmVerifier(anchors);
        assertThat(google.marvellRoots()).containsExactly(testRoot, secondRoot);
        assertThat(google.ownerRoot()).isEqualTo(new GoogleCloudHsmVerifier().ownerRoot());
        assertThat(anchors.active(TrustAnchors.MARVELL).sha256()).hasSize(2);
        assertThat(anchors.active(TrustAnchors.MARVELL).matchesPinned()).isFalse();
    }

    @Test
    void keyOverridesReplaceTheKeyTheVerifierChecksAgainst() throws Exception {
        KeyPair p384 = ec("secp384r1");
        X509Certificate c4a = certificate("CN=Operator C4A", p384.getPublic(), "CN=Operator C4A",
                p384.getPrivate(), true);
        KeyPair p521 = ec("secp521r1");
        TrustAnchors anchors = TrustAnchors.load(Map.of(
                TrustAnchors.THALES, write("t.pem", pem("CERTIFICATE", testRoot.getEncoded())).toString(),
                TrustAnchors.CRYPTO4A, write("c.pem", pem("CERTIFICATE", c4a.getEncoded())).toString(),
                TrustAnchors.FORTANIX, write("f.pem", pem("CERTIFICATE", testRoot.getEncoded())).toString(),
                TrustAnchors.ENTRUST, write("e.pem", pem("PUBLIC KEY", p521.getPublic().getEncoded())).toString(),
                TrustAnchors.GOOGLE_OWNER, write("g.pem", pem("CERTIFICATE", testRoot.getEncoded())).toString()),
                PREFIX);

        assertThat(new ThalesLunaVerifier(anchors).rootKey()).isEqualTo(testRoot.getPublicKey());
        assertThat(new Crypto4AVerifier(anchors).rootKey().getEncoded()).isEqualTo(p384.getPublic().getEncoded());
        assertThat(new FortanixVerifier(anchors).root()).isEqualTo(testRoot);
        assertThat(new NShieldVerifier(anchors).rootKey().getEncoded()).isEqualTo(p521.getPublic().getEncoded());
        assertThat(new GoogleCloudHsmVerifier(anchors).ownerRoot()).isEqualTo(testRoot);
        assertThat(anchors.active(TrustAnchors.ENTRUST).sha256())
                .containsExactly(TrustAnchors.fingerprint(p521.getPublic().getEncoded()));
        assertThat(logs.list.stream().filter(e -> e.getLevel() == Level.WARN)).hasSize(5);
    }

    // --------------------------------------------------------- fail closed

    @Test
    void missingFileIsRefused() {
        refused(TrustAnchors.YUBICO, dir.resolve("absent.pem").toString(), "no such file");
        refused(TrustAnchors.YUBICO, dir.toString(), "not a regular file");
    }

    @Test
    void unparseableFilesAreRefused() throws Exception {
        refused(TrustAnchors.SECUROSYS, write("text.pem", "not a certificate\n").toString(), "no PEM block");
        refused(TrustAnchors.SECUROSYS, write("root.der", testRoot.getEncoded()).toString(), "converted to PEM");
        refused(TrustAnchors.SECUROSYS, write("b64.pem",
                "-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n").toString(), "base64");
        refused(TrustAnchors.SECUROSYS, write("der.pem", pem("CERTIFICATE", new byte[] {0x30, 0x03, 1, 2, 3}))
                .toString(), "does not parse");
        refused(TrustAnchors.SECUROSYS, write("open.pem", pem("CERTIFICATE", testRoot.getEncoded())
                + "-----BEGIN CERTIFICATE-----\nMIIB\n").toString(), "does not parse");
        byte[] trailing = java.util.Arrays.copyOf(testRoot.getEncoded(), testRoot.getEncoded().length + 2);
        refused(TrustAnchors.SECUROSYS, write("trailing.pem", pem("CERTIFICATE", trailing)).toString(),
                "beyond the certificate");
        refused(TrustAnchors.ENTRUST, write("key.pem", pem("PUBLIC KEY", new byte[] {0x30, 0x00})).toString(),
                "does not parse");
    }

    @Test
    void wrongBlockTypeOrCountIsRefused() throws Exception {
        String root = pem("CERTIFICATE", testRoot.getEncoded());
        refused(TrustAnchors.YUBICO, write("two.pem", root + root).toString(), "expected exactly one");
        refused(TrustAnchors.YUBICO, write("key.pem", pem("PUBLIC KEY", testRoot.getPublicKey().getEncoded()))
                .toString(), "PUBLIC KEY block");
        refused(TrustAnchors.ENTRUST, write("cert.pem", root).toString(), "CERTIFICATE block");
        refused(TrustAnchors.MARVELL, write("dup.pem", root + root).toString(), "appears twice");
    }

    @Test
    void wrongKeyTypeOrCurveIsRefused() throws Exception {
        KeyPair p256 = ec("secp256r1");
        X509Certificate ecRoot = certificate("CN=EC Root", p256.getPublic(), "CN=EC Root", p256.getPrivate(), true);
        String ecPem = pem("CERTIFICATE", ecRoot.getEncoded());
        for (String rsaAnchor : List.of(TrustAnchors.YUBICO, TrustAnchors.SECUROSYS, TrustAnchors.MARVELL,
                TrustAnchors.GOOGLE_OWNER, TrustAnchors.THALES, TrustAnchors.FORTANIX)) {
            refused(rsaAnchor, write(rsaAnchor + ".pem", ecPem).toString(), "the pinned anchor's key is RSA");
        }
        refused(TrustAnchors.CRYPTO4A, write("c4a-p256.pem", ecPem).toString(), "not on secp384r1");
        refused(TrustAnchors.CRYPTO4A, write("c4a-rsa.pem", pem("CERTIFICATE", testRoot.getEncoded())).toString(),
                "is EC on secp384r1");
        refused(TrustAnchors.ENTRUST, write("e-p256.pem", pem("PUBLIC KEY", p256.getPublic().getEncoded())).toString(),
                "not on secp521r1");
        refused(TrustAnchors.ENTRUST, write("e-p384.pem", pem("PUBLIC KEY", ec("secp384r1").getPublic().getEncoded()))
                .toString(), "not on secp521r1");
        refused(TrustAnchors.ENTRUST, write("e-rsa.pem", pem("PUBLIC KEY", testRoot.getPublicKey().getEncoded()))
                .toString(), "not an EC key");
    }

    @Test
    void certificateThatIsNotSelfSignedIsRefused() throws Exception {
        KeyPair leaf = rsa();
        X509Certificate issued = certificate("CN=Issued By Test Root", leaf.getPublic(), "CN=Operator Test Root",
                rootKeys.getPrivate(), true);
        refused(TrustAnchors.YUBICO, write("issued.pem", pem("CERTIFICATE", issued.getEncoded())).toString(),
                "not self-signed: issued by CN=Operator Test Root");
        // Self-issued, but signed with another key.
        X509Certificate forged = certificate("CN=Operator Test Root", leaf.getPublic(), "CN=Operator Test Root",
                rootKeys.getPrivate(), true);
        refused(TrustAnchors.FORTANIX, write("forged.pem", pem("CERTIFICATE", forged.getEncoded())).toString(),
                "does not verify under its own key");
        refused(TrustAnchors.MARVELL, write("mixed.pem", pem("CERTIFICATE", testRoot.getEncoded())
                + pem("CERTIFICATE", issued.getEncoded())).toString(), "not self-signed");
    }

    @Test
    void unknownOrRepeatedKeyIsRefused() throws Exception {
        String root = write("root.pem", pem("CERTIFICATE", testRoot.getEncoded())).toString();
        assertThatThrownBy(() -> TrustAnchors.load(Map.of("yubikey", root), PREFIX))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(PREFIX + ".yubikey").hasMessageContaining("google-owner");
        Map<String, String> twice = new LinkedHashMap<>();
        twice.put("yubico", root);
        twice.put("YUBICO", root);
        assertThatThrownBy(() -> TrustAnchors.load(twice, PREFIX))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("more than once");
    }

    // ---------------------------------------------------- messages and logs

    @Test
    void theDebugLineThatEveryAnchorIsPinnedIsWrittenOnlyWithoutOverrides() throws Exception {
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(TrustAnchors.class);
        Level before = logger.getLevel();
        logger.setLevel(Level.DEBUG);
        try {
            TrustAnchors.load(Map.of(), PREFIX);
            assertThat(logs.list).anyMatch(e -> e.getLevel() == Level.DEBUG
                    && e.getFormattedMessage().equals("Trust anchors: every anchor is the pinned one"));
            logs.list.clear();
            TrustAnchors.load(Map.of(TrustAnchors.YUBICO,
                    write("root.pem", pem("CERTIFICATE", testRoot.getEncoded())).toString()), PREFIX);
            assertThat(logs.list).noneMatch(e -> e.getFormattedMessage().contains("every anchor is the pinned one"));
        } finally {
            logger.setLevel(before);
        }
    }

    @Test
    void aBlockOfTheWrongTypeIsRefusedNamingTheFormTheAnchorTakes() throws Exception {
        String certificate = pem("CERTIFICATE", testRoot.getEncoded());
        String key = pem("PUBLIC KEY", testRoot.getPublicKey().getEncoded());
        assertThatThrownBy(() -> TrustAnchors.load(Map.of(TrustAnchors.YUBICO, write("y.pem", key).toString()), PREFIX))
                .hasMessageEndingWith(": holds a PEM PUBLIC KEY block; expected exactly one PEM CERTIFICATE block");
        assertThatThrownBy(() -> TrustAnchors.load(Map.of(TrustAnchors.MARVELL, write("m.pem", key).toString()), PREFIX))
                .hasMessageEndingWith(": holds a PEM PUBLIC KEY block; expected one or more PEM CERTIFICATE blocks");
        assertThatThrownBy(() -> TrustAnchors.load(Map.of(TrustAnchors.ENTRUST, write("e.pem", certificate).toString()),
                PREFIX))
                .hasMessageEndingWith(": holds a PEM CERTIFICATE block; expected exactly one PEM PUBLIC KEY block");
    }

    @Test
    void aFileOfExactlyTheSizeLimitIsReadAndOneByteMoreIsRefused() throws Exception {
        byte[] atLimit = new byte[TrustAnchors.MAX_FILE_SIZE];
        java.util.Arrays.fill(atLimit, (byte) 'x');
        assertThatThrownBy(() -> TrustAnchors.load(Map.of(TrustAnchors.YUBICO,
                write("limit.pem", atLimit).toString()), PREFIX))
                .hasMessageContaining("no PEM block").hasMessageNotContaining("larger than");
        refused(TrustAnchors.YUBICO, write("over.pem", java.util.Arrays.copyOf(atLimit, atLimit.length + 1)).toString(),
                "larger than " + TrustAnchors.MAX_FILE_SIZE + " bytes");
    }

    @Test
    void anEcKeyOnAnotherCurveIsRefusedBeforeItsPointIsChecked() throws Exception {
        KeyPair p256 = ec("secp256r1");
        X509Certificate ecRoot = certificate("CN=EC Root", p256.getPublic(), "CN=EC Root", p256.getPrivate(), true);
        refused(TrustAnchors.CRYPTO4A, write("c4a-p256.pem", pem("CERTIFICATE", ecRoot.getEncoded())).toString(),
                "the EC key is not on secp384r1, the pinned anchor's curve");
        refused(TrustAnchors.ENTRUST, write("e-p384.pem", pem("PUBLIC KEY", ec("secp384r1").getPublic().getEncoded()))
                .toString(), "the EC key is not on secp521r1, the pinned anchor's curve");
    }

    @Test
    void theWarningComparesTheKeysOfACertificateOverrideWithThePinnedKeys() {
        TrustAnchors.ActiveAnchor onePinned = anchor(TrustAnchors.ORIGIN_PINNED, List.of("P1"), List.of("K1"), true);
        TrustAnchors.ActiveAnchor twoPinned = anchor(TrustAnchors.ORIGIN_PINNED, List.of("P1", "P2"),
                List.of("K1", "K2"), true);

        // A re-issued root: another certificate, the same key.
        TrustAnchors.logOverride("p.k", anchor(TrustAnchors.ORIGIN_OVERRIDE, List.of("O1"), List.of("K1"), false),
                onePinned, List.of(testRoot));
        assertThat(lastWarning()).endsWith("; SHA-256 of the DER SubjectPublicKeyInfo: override K1, pinned K1 (the same key)");

        TrustAnchors.logOverride("p.k", anchor(TrustAnchors.ORIGIN_OVERRIDE, List.of("O1", "O2"), List.of("K2", "K1"),
                false), twoPinned, List.of(testRoot, testRoot));
        assertThat(lastWarning()).endsWith("override K2, K1, pinned K1, K2 (the same keys)");

        // As many keys, not the same ones.
        TrustAnchors.logOverride("p.k", anchor(TrustAnchors.ORIGIN_OVERRIDE, List.of("O1", "O2"), List.of("K1", "K3"),
                false), twoPinned, List.of(testRoot, testRoot));
        assertThat(lastWarning()).endsWith("override K1, K3, pinned K1, K2 (different)");

        // The same set of keys, but not as many: two certificates for one key.
        TrustAnchors.logOverride("p.k", anchor(TrustAnchors.ORIGIN_OVERRIDE, List.of("O1", "O2"), List.of("K1", "K1"),
                false), onePinned, List.of(testRoot, testRoot));
        assertThat(lastWarning()).endsWith("override K1, K1, pinned K1 (different)");

        // A bare key has nothing to compare beyond its own SHA-256.
        TrustAnchors.logOverride("p.k", anchor(TrustAnchors.ORIGIN_OVERRIDE, List.of("O1"), List.of("O1"), false),
                onePinned, List.of());
        assertThat(lastWarning()).endsWith("override O1, pinned P1").doesNotContain("SubjectPublicKeyInfo");
    }

    private static TrustAnchors.ActiveAnchor anchor(String origin, List<String> sha256, List<String> keys,
            boolean matchesPinned) {
        List<String> subjects = sha256.stream().map(s -> "CN=" + s).toList();
        return new TrustAnchors.ActiveAnchor("k", origin, "/o.pem", TrustAnchors.SHA256_OF_CERTIFICATE, sha256, keys,
                subjects, matchesPinned);
    }

    private String lastWarning() {
        List<ILoggingEvent> warnings = logs.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
        assertThat(warnings).isNotEmpty();
        return warnings.get(warnings.size() - 1).getFormattedMessage();
    }

    // ------------------------------------------------------------- helpers

    private static void assertSameAnchorsAsTheNoArgumentConstructors(TrustAnchors anchors) {
        assertThat(new YubicoVerifier(anchors).rootCa()).isEqualTo(new YubicoVerifier().rootCa());
        assertThat(new SecurosysVerifier(anchors).rootCa()).isEqualTo(new SecurosysVerifier().rootCa());
        assertThat(new AzureHsmVerifier(anchors).marvellRoots())
                .containsExactlyElementsOf(new AzureHsmVerifier().marvellRoots());
        assertThat(new MarvellHsmVerifier(anchors).marvellRoots())
                .containsExactlyElementsOf(new MarvellHsmVerifier().marvellRoots());
        assertThat(new GoogleCloudHsmVerifier(anchors).marvellRoots())
                .containsExactlyElementsOf(new GoogleCloudHsmVerifier().marvellRoots());
        assertThat(new GoogleCloudHsmVerifier(anchors).ownerRoot()).isEqualTo(new GoogleCloudHsmVerifier().ownerRoot());
        assertThat(new ThalesLunaVerifier(anchors).rootKey()).isEqualTo(new ThalesLunaVerifier().rootKey());
        assertThat(new Crypto4AVerifier(anchors).rootKey()).isEqualTo(new Crypto4AVerifier().rootKey());
        assertThat(new FortanixVerifier(anchors).root()).isEqualTo(new FortanixVerifier().root());
        assertThat(new NShieldVerifier(anchors).rootKey().getEncoded())
                .isEqualTo(new NShieldVerifier().rootKey().getEncoded());
    }

    private void refused(String key, String path, String reason) {
        assertThatThrownBy(() -> TrustAnchors.load(Map.of(key, path), PREFIX))
                .as(key + " " + path)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(PREFIX + "." + key)
                .hasMessageContaining(reason);
    }

    private Path write(String name, String text) throws Exception {
        return write(name, text.getBytes(StandardCharsets.US_ASCII));
    }

    private Path write(String name, byte[] bytes) throws Exception {
        Path p = dir.resolve(name);
        Files.write(p, bytes);
        return p;
    }

    static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curve));
        return g.generateKeyPair();
    }

    static X509Certificate certificate(String subject, PublicKey key, String issuer, PrivateKey signer, boolean ca)
            throws Exception {
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(SERIAL.incrementAndGet()), new Date(now - 60_000L), new Date(now + 3_600_000L),
                new X500Name(subject), key);
        if (ca) {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        String algorithm = signer instanceof RSAPrivateKey ? "SHA256withRSA" : "SHA384withECDSA";
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder(algorithm).build(signer)));
    }

    private static List<String> yubicoChain(PublicKey attested) throws Exception {
        return yubicoChain(rootKeys.getPrivate(), testRoot, attested);
    }

    /**
     * Yubico-shaped [attestation, device] chain for {@code attested} under
     * {@code root}: generated on the device, no export capability.
     */
    static List<String> yubicoChain(PrivateKey rootKey, X509Certificate root, PublicKey attested) throws Exception {
        KeyPair device = rsa();
        String deviceName = "CN=YubiHSM Attestation (12345678)";
        X509Certificate deviceCert = certificate(deviceName, device.getPublic(),
                root.getSubjectX500Principal().getName(), rootKey, true);
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(deviceName),
                BigInteger.valueOf(SERIAL.incrementAndGet()), new Date(now - 60_000L), new Date(now + 3_600_000L),
                new X500Name("CN=YubiHSM Attestation id:0x0024"), attested);
        b.addExtension(new ASN1ObjectIdentifier(YUBICO_OID + ".1"), false, new DEROctetString(new byte[] {2, 4, 0}));
        b.addExtension(new ASN1ObjectIdentifier(YUBICO_OID + ".3"), false, new DERBitString(new byte[] {0x01}));
        b.addExtension(new ASN1ObjectIdentifier(YUBICO_OID + ".5"), false,
                new DERBitString(NON_EXPORTABLE_CAPABILITIES));
        b.addExtension(new ASN1ObjectIdentifier(YUBICO_OID + ".6"), false, new ASN1Integer(0x24));
        X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(device.getPrivate())));
        return List.of(pem("CERTIFICATE", leaf.getEncoded()), pem("CERTIFICATE", deviceCert.getEncoded()));
    }

    static JsonNode fixture(String resource) throws Exception {
        try (InputStream in = TrustAnchorsTest.class.getResourceAsStream(resource)) {
            return new ObjectMapper().readTree(in);
        }
    }

    static List<String> texts(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asText()));
        return out;
    }

    static PublicKey csrKey(String csrPem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(csr.getSubjectPublicKeyInfo().getEncoded()));
        }
    }
}
