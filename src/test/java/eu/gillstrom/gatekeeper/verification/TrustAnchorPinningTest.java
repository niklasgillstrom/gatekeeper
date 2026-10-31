package eu.gillstrom.gatekeeper.verification;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every trust anchor the vendor verifiers pin, recomputed from the constant in
 * the verifier source and compared with the values stated in the constant's
 * "Pinned trust anchor" comment block: subject, SHA-256 of the DER
 * certificate (or, for a bare public key, of its DER SubjectPublicKeyInfo) and
 * validity. Each test also checks that the verifier built by its public
 * constructor holds exactly that anchor. Changing a pinned anchor without
 * changing this test fails the build.
 */
class TrustAnchorPinningTest {

    private static String sha256(byte[] der) throws Exception {
        return HexFormat.ofDelimiter(":").withUpperCase()
                .formatHex(MessageDigest.getInstance("SHA-256").digest(der));
    }

    /** The colon-separated upper-case form as the lower-case hex the *_KEY_SHA256 constants use. */
    private static String plainHex(String colonHex) {
        return colonHex.replace(":", "").toLowerCase(java.util.Locale.ROOT);
    }

    private static X509Certificate certificate(String pem, String subject, String derSha256,
            String notBefore, String notAfter) throws Exception {
        X509Certificate c = MarvellAttestation.certificate(pem);
        assertThat(c.getSubjectX500Principal().getName()).as("subject (RFC 2253)").isEqualTo(subject);
        assertThat(c.getIssuerX500Principal()).as("self-issued").isEqualTo(c.getSubjectX500Principal());
        c.verify(c.getPublicKey());
        assertThat(sha256(c.getEncoded())).as("SHA-256 of the DER certificate").isEqualTo(derSha256);
        assertThat(c.getNotBefore().toInstant()).as("notBefore").isEqualTo(Instant.parse(notBefore));
        assertThat(c.getNotAfter().toInstant()).as("notAfter").isEqualTo(Instant.parse(notAfter));
        return c;
    }

    @Test
    void yubicoRoot() throws Exception {
        X509Certificate root = certificate(YubicoVerifier.YUBICO_ROOT_CA,
                "CN=Yubico YubiHSM Root CA",
                "09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24",
                "2017-01-01T00:00:00Z", "2071-10-05T00:00:00Z");
        assertThat(new YubicoVerifier().rootCa()).isEqualTo(root);
    }

    @Test
    void securosysRoot() throws Exception {
        X509Certificate root = certificate(SecurosysVerifier.SECUROSYS_ROOT_CA,
                "ST=ZH,O=Securosys,L=Zurich,C=CH,CN=PRIMUS_HSM_ROOTKEY",
                "D2:C9:3D:8F:69:BC:8D:62:4E:37:F2:5B:9E:6E:7B:EC:41:76:1A:AB:86:4C:94:F3:79:36:1B:9B:78:A9:DB:97",
                "2024-08-21T12:33:45Z", "2054-08-14T12:33:45Z");
        assertThat(new SecurosysVerifier().rootCa()).isEqualTo(root);
    }

    @Test
    void marvellRoots() throws Exception {
        X509Certificate ls = certificate(MarvellAttestation.MARVELL_ROOT_PEM,
                "CN=localca.liquidsecurity.cavium.com,OU=LiquidSecurity,O=Cavium\\, Inc.,L=San Jose,"
                        + "ST=California,C=US",
                "23:01:43:DF:00:E0:B4:52:74:3E:06:8A:5B:3F:C0:8D:F8:F0:6C:EF:C4:85:4E:A6:27:AE:B7:EB:D7:0E:E2:F4",
                "2024-07-25T20:29:20Z", "2034-07-23T20:29:20Z");
        X509Certificate ls2 = certificate(MarvellAttestation.MARVELL_LS2_ROOT_PEM,
                "CN=cavium-liquidsecurity-ls2,C=US+ST=CA+OU=SSBU+L=SanJose+O=Marvell",
                "17:64:4D:E0:D3:3B:C7:3B:2F:4E:F4:C2:0A:11:F6:C8:CC:1F:72:3A:4C:D8:3E:E6:00:36:1C:BB:24:D8:D2:E5",
                "2024-07-22T20:34:23Z", "2034-07-20T20:34:23Z");

        List<X509Certificate> pinned = List.of(ls, ls2);
        assertThat(MarvellAttestation.marvellRoots()).containsExactlyElementsOf(pinned);
        assertThat(new AzureHsmVerifier().marvellRoots()).containsExactlyElementsOf(pinned);
        assertThat(new GoogleCloudHsmVerifier().marvellRoots()).containsExactlyElementsOf(pinned);
        assertThat(new MarvellHsmVerifier().marvellRoots()).containsExactlyElementsOf(pinned);
    }

    @Test
    void googleOwnerRoot() throws Exception {
        X509Certificate root = certificate(GoogleCloudHsmVerifier.HAWKSBILL_ROOT_PEM,
                "CN=Hawksbill Root v1 prod,O=Google Inc,L=Mountain View,ST=CA,C=US",
                "46:B5:FD:35:1D:56:A0:72:1C:A0:AF:CD:17:31:C0:F7:B7:4E:39:41:EB:81:8B:FD:0E:C3:6E:29:DF:0D:E0:95",
                "2017-07-01T00:00:00Z", "2030-01-01T00:00:00Z");
        assertThat(new GoogleCloudHsmVerifier().ownerRoot()).isEqualTo(root);
    }

    @Test
    void thalesChrysalisItsRoot() throws Exception {
        X509Certificate root = certificate(ThalesLunaVerifier.CHRYSALIS_ROOT_PEM,
                "CN=Chrysalis-ITS Root,O=Chrysalis-ITS Inc.,L=Ottawa,ST=Ontario,C=CA",
                "69:6A:7E:E6:7B:C4:FA:CF:F6:09:11:BC:0B:24:A3:A6:BC:E7:5A:2E:F4:C4:23:18:44:8A:DD:45:01:B6:99:69",
                "2002-01-01T00:00:00Z", "2032-01-01T00:00:00Z");
        assertThat(root.getSerialNumber().toString(16)).isEqualTo("80450000000d");
        String key = "5D:31:FC:46:2A:E8:A1:A5:32:7B:14:9F:F4:3A:A6:D8:67:A2:8D:7E:17:CA:1C:CA:7E:7D:51:4C:F8:CD:C1:32";
        assertThat(sha256(root.getPublicKey().getEncoded())).isEqualTo(key);
        assertThat(ThalesLunaVerifier.CHRYSALIS_ROOT_KEY_SHA256).isEqualTo(plainHex(key));
        assertThat(new ThalesLunaVerifier().rootKey()).isEqualTo(root.getPublicKey());
    }

    @Test
    void crypto4aRoot() throws Exception {
        X509Certificate root = certificate(Crypto4AVerifier.C4A_ROOT_PEM,
                "CN=C4A_RCA,O=Crypto4A,L=Ottawa,ST=Ontario,C=Canada",
                "63:7E:6A:7E:95:DE:D7:27:2F:5B:3E:5A:0D:94:41:4D:23:E1:B5:4F:9E:2E:65:93:B6:41:75:62:BB:B5:43:3C",
                "2020-07-13T13:06:33Z", "2045-07-13T13:06:33Z");
        String key = "40:14:6C:BF:79:12:E0:A2:9C:A6:01:F9:A1:63:5E:37:BA:8D:69:A4:CD:B8:8A:9A:F1:63:16:33:E7:34:9B:F0";
        assertThat(sha256(root.getPublicKey().getEncoded())).isEqualTo(key);
        assertThat(Crypto4AVerifier.C4A_ROOT_KEY_SHA256).isEqualTo(plainHex(key));
        assertThat(new Crypto4AVerifier().rootKey()).isEqualTo(root.getPublicKey());
    }

    @Test
    void fortanixRoot() throws Exception {
        X509Certificate root = certificate(FortanixVerifier.FORTANIX_ROOT_PEM,
                "CN=Fortanix Attestation and Provisioning Root CA,O=Fortanix\\, Inc.,L=Santa Clara,"
                        + "ST=California,C=US",
                "D7:1A:15:B3:4E:78:1E:9E:F9:13:54:FA:BA:E8:B1:15:E0:62:B8:97:95:FE:C3:AE:C0:E0:45:FE:D2:66:C2:C2",
                "2023-09-01T16:38:12Z", "2033-08-29T16:38:12Z");
        String key = "D0:12:75:CC:16:BD:C2:DA:D8:CD:51:53:2B:CF:C9:E6:9E:DB:99:63:A4:32:4A:A5:E1:29:45:37:2A:FB:5E:15";
        assertThat(sha256(root.getPublicKey().getEncoded())).isEqualTo(key);
        assertThat(FortanixVerifier.FORTANIX_ROOT_KEY_SHA256).isEqualTo(plainHex(key));
        assertThat(new FortanixVerifier().root()).isEqualTo(root);
    }

    @Test
    void entrustNShieldKwarn1Key() throws Exception {
        PublicKey kwarn1 = NShieldVerifier.ecKey("secp521r1", NShieldVerifier.KWARN_1_X, NShieldVerifier.KWARN_1_Y);
        assertThat(NShieldVerifier.KWARN_1).isEqualTo("KWARN-1");
        assertThat(((ECPublicKey) kwarn1).getParams().getCurve().getField().getFieldSize()).isEqualTo(521);
        assertThat(sha256(kwarn1.getEncoded())).as("SHA-256 of the DER SubjectPublicKeyInfo")
                .isEqualTo("DF:8F:05:A3:95:96:BB:9C:4A:8C:C4:D3:B6:DE:10:60:"
                        + "7F:36:2D:71:82:E8:81:EA:82:A5:ED:C7:CD:CD:F8:4F");
        assertThat(new NShieldVerifier().rootKey().getEncoded()).isEqualTo(kwarn1.getEncoded());
    }
}
