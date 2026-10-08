package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.model.HsmVendor;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behaviour of {@link YubicoVerifier} that the main test leaves open: the
 * attributes read from a real YubiHSM 2 attestation, where the device serial
 * comes from, the generic {@link HsmAttestationVerifier} entry points, and the
 * refusals for a mismatched key, a root-only chain and unparseable input.
 */
class YubicoVerifierMutationTest {

    private static final String YUBICO_OID = "1.3.6.1.4.1.41482.4";
    private static final String SERIAL_OID = YUBICO_OID + ".2";
    private static final String ORIGIN_OID = YUBICO_OID + ".3";
    private static final String CAPABILITIES_OID = YUBICO_OID + ".5";

    /** Capabilities of the reference device's signing key: no export bit set. */
    private static final byte[] NON_EXPORTABLE_CAPABILITIES = {0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x06, 0x60};

    /**
     * The Yubico YubiHSM Root CA as published at
     * https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem
     * (the root the verifier pins).
     */
    private static final String YUBICO_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            """;

    /** Chain of the real reference-device attestation: attestation cert, device cert, Yubico sub-CA. */
    private static List<String> realChainPem;
    private static X509Certificate[] realChain;
    private static PublicKey realCsrKey;
    private static X509Certificate yubicoRoot;

    private final YubicoVerifier verifier = new YubicoVerifier();

    @BeforeAll
    static void loadRealAttestation() throws Exception {
        JsonNode fixture;
        try (InputStream in = YubicoVerifierMutationTest.class.getResourceAsStream("/fixtures/yubico/request.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        realChainPem = new ArrayList<>();
        for (JsonNode pem : fixture.get("attestationCertChain")) {
            realChainPem.add(pem.asText());
        }
        realChain = new X509Certificate[realChainPem.size()];
        for (int i = 0; i < realChain.length; i++) {
            realChain[i] = parse(realChainPem.get(i));
        }
        try (PEMParser parser = new PEMParser(new StringReader(fixture.get("csr").asText()))) {
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
            realCsrKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(csr.getSubjectPublicKeyInfo().getEncoded()));
        }
        yubicoRoot = parse(YUBICO_ROOT_PEM);
    }

    // ---- attributes of the real attestation -------------------------------------------------

    @Test
    void theRealAttestationReportsFirmwareLabelAndObjectId() {
        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(realChainPem, realCsrKey);

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.getFirmware()).isEqualTo("2.2.0");
        assertThat(r.getKeyLabel()).isEqualTo("Swish Sign RSA4096");
        assertThat(r.getKeyId()).isEqualTo(0x24);
        assertThat(r.isGenerated()).isTrue();
        assertThat(r.isImported()).isFalse();
        assertThat(r.isImportedWrapped()).isFalse();
    }

    @Test
    void aCsrKeyOtherThanTheAttestedKeyIsRefused() throws Exception {
        PublicKey otherKey = TestPki.newRsaKeyPair(2048).getPublic();

        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(realChainPem, otherKey);

        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isFalse();
        assertThat(r.getErrors()).containsExactly("Public key mismatch: CSR key does not match attested key");
        assertThat(r.isValid()).isFalse();
    }

    // ---- chain refusals ----------------------------------------------------------------------

    @Test
    void aChainOfOnlyThePinnedRootIsRefused() {
        // The root is publicly downloadable; on its own it attests nothing.
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(List.of(YUBICO_ROOT_PEM), yubicoRoot.getPublicKey());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).contains("Certificate chain verification failed");
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void anUnparseableCertificateIsReportedAsAVerificationError() {
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(List.of("this is not a certificate"), realCsrKey);

        assertThat(r.getErrors()).singleElement().asString().startsWith("Verification error: ");
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void aMalformedAttestationExtensionIsReportedAndRefused() throws Exception {
        // The origin extension must be a BIT STRING; a UTF8String in its place
        // cannot be parsed and the attestation must not pass.
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        Map<String, ASN1Encodable> ext = new LinkedHashMap<>();
        ext.put(ORIGIN_OID, new DERUTF8String("generated"));
        ext.put(CAPABILITIES_OID, new DERBitString(NON_EXPORTABLE_CAPABILITIES));
        X509Certificate cert = attestationCert(kp, "CN=YubiHSM Attestation id:0x0001", ext, null, kp.getPrivate());

        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(List.of(TestPki.toPem(cert)), kp.getPublic());

        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("Failed to parse attestation extensions: "));
        assertThat(r.isValid()).isFalse();
    }

    // ---- device serial -----------------------------------------------------------------------

    @Test
    void theDeviceSerialIsReadFromTheSerialExtensionOfALoneAttestationCertificate() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        Map<String, ASN1Encodable> ext = generatedNonExportable();
        ext.put(SERIAL_OID, new ASN1Integer(20783176L));
        X509Certificate cert = attestationCert(kp, "CN=YubiHSM Attestation id:0x0001", ext, null, kp.getPrivate());

        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(List.of(TestPki.toPem(cert)), kp.getPublic());

        assertThat(r.getDeviceSerial()).isEqualTo("20783176");
        // Self-signed, so not rooted at Yubico; nothing else is wrong with it.
        assertThat(r.getErrors()).containsExactly("Certificate chain verification failed");
    }

    @Test
    void theDeviceSerialIsReadFromTheDeviceCertificateName() throws Exception {
        List<String> chain = chainWithDeviceCert("YubiHSM Attestation (12345678)");

        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(chain, leafKp.getPublic());

        assertThat(r.getDeviceSerial()).isEqualTo("12345678");
    }

    @Test
    void aDeviceCertificateThatIsNotAYubiHsmAttestationCertGivesNoSerial() throws Exception {
        List<String> chain = chainWithDeviceCert("Some Other CA (12345678)");

        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(chain, leafKp.getPublic());

        assertThat(r.getDeviceSerial()).isNull();
    }

    private KeyPair leafKp;

    /** Attestation cert without a serial extension, issued by a device cert with the given CN. */
    private List<String> chainWithDeviceCert(String deviceCn) throws Exception {
        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate device = TestPki.selfSignedCa(deviceKp, deviceCn);
        leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate leaf = attestationCert(leafKp, "CN=YubiHSM Attestation id:0x0001",
                generatedNonExportable(), device, deviceKp.getPrivate());
        return List.of(TestPki.toPem(leaf), TestPki.toPem(device));
    }

    // ---- key origin --------------------------------------------------------------------------

    @Test
    void anImportedKeyIsReportedAsImportedAndRefused() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyOrigin(new byte[] {0x02}, r);
        YubicoVerifier.applyCapabilities(NON_EXPORTABLE_CAPABILITIES, r);
        YubicoVerifier.validateKeyAttributes(r);

        assertThat(r.isGenerated()).isFalse();
        assertThat(r.isImported()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("imported");
        assertThat(r.getErrors()).containsExactly(
                "Key was not generated on this HSM without import (origin: imported)");
    }

    @Test
    void anOriginWithNoBitSetIsUnknownAndRefused() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyOrigin(new byte[] {0x00}, r);
        YubicoVerifier.validateKeyAttributes(r);

        assertThat(r.isGenerated()).isFalse();
        assertThat(r.getKeyOrigin()).isEqualTo("unknown");
        assertThat(r.getErrors()).containsExactly(
                "Key was not generated on this HSM without import (origin: unknown)");
    }

    @Test
    void anEmptyOriginBitStringSetsNothingAndIsRefused() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyOrigin(new byte[0], r);
        YubicoVerifier.validateKeyAttributes(r);

        assertThat(r.isGenerated()).isFalse();
        assertThat(r.getKeyOrigin()).isEqualTo("unknown");
        assertThat(r.getErrors()).containsExactly(
                "Key was not generated on this HSM without import (origin: unknown)");
    }

    // ---- HsmAttestationVerifier entry points -------------------------------------------------

    @Test
    void vendorModelAndSerial() {
        assertThat(verifier.getVendor()).isEqualTo(HsmVendor.YUBICO);
        assertThat(verifier.extractModel(realChain[0])).isEqualTo("YubiHSM 2");
        assertThat(verifier.extractSerialNumber(realChain[0])).isEqualTo("f64af76d1846e85ec41ad5624b82c4d4");
    }

    @Test
    void verifyAttestationComparesTheAttestedKeyWithTheCsrKey() throws Exception {
        assertThat(verifier.verifyAttestation(realChain[0], realCsrKey)).isTrue();
        assertThat(verifier.verifyAttestation(realChain[0], TestPki.newRsaKeyPair(2048).getPublic())).isFalse();
        assertThat(verifier.verifyAttestation(realChain[0], null)).as("no CSR key").isFalse();
    }

    @Test
    void verifyChainAcceptsTheRealChainAndRefusesIncompleteOnes() {
        X509Certificate leaf = realChain[0];
        X509Certificate[] rest = {realChain[1], realChain[2]};
        X509Certificate subCa = realChain[2];

        assertThat(verifier.verifyChain(leaf, rest)).isTrue();
        assertThat(verifier.verifyChain(leaf, null)).isFalse();
        assertThat(verifier.verifyChain(leaf, new X509Certificate[0])).isFalse();
        assertThat(verifier.verifyChain(leaf, new X509Certificate[] {realChain[1]}))
                .as("device cert without the Yubico sub-CA").isFalse();
        assertThat(verifier.verifyChain(subCa, new X509Certificate[0]))
                .as("a certificate issued by the root, with no chain").isFalse();
        assertThat(verifier.verifyChain(yubicoRoot, new X509Certificate[] {yubicoRoot}))
                .as("the pinned root alone").isFalse();
    }

    // ---- helpers -----------------------------------------------------------------------------

    private static Map<String, ASN1Encodable> generatedNonExportable() {
        Map<String, ASN1Encodable> ext = new LinkedHashMap<>();
        ext.put(ORIGIN_OID, new DERBitString(new byte[] {0x01}));
        ext.put(CAPABILITIES_OID, new DERBitString(NON_EXPORTABLE_CAPABILITIES));
        return ext;
    }

    /** Attestation certificate with the given Yubico extensions; self-signed when {@code issuer} is null. */
    private static X509Certificate attestationCert(KeyPair kp, String subjectDn, Map<String, ASN1Encodable> ext,
            X509Certificate issuer, PrivateKey signer) throws Exception {
        X500Name subject = new X500Name(subjectDn);
        X500Name issuerName = issuer == null ? subject : new X500Name(issuer.getSubjectX500Principal().getName());
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerName, BigInteger.valueOf(now), new Date(now - 60_000L), new Date(now + 3600_000L),
                subject, kp.getPublic());
        for (Map.Entry<String, ASN1Encodable> e : ext.entrySet()) {
            b.addExtension(new ASN1ObjectIdentifier(e.getKey()), false, e.getValue());
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer)));
    }

    private static X509Certificate parse(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    }
}
