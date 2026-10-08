package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class YubicoVerifierTest {

    @Test
    void chainNotRootedAtPinnedYubicoRootIsRejected() throws Exception {
        YubicoVerifier verifier = new YubicoVerifier();

        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate fakeRoot = TestPki.selfSignedCa(rootKp, "FAKE-YUBICO-ROOT");

        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate deviceCert = TestPki.subordinateCa(
                deviceKp, "YubiHSM Attestation (FAKE1234)", fakeRoot, rootKp.getPrivate());

        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = TestPki.endEntity(
                leafKp, "FAKE-YUBI-ATTEST", deviceCert, deviceKp.getPrivate());

        List<String> chainPem = List.of(
                TestPki.toPem(attestCert),
                TestPki.toPem(deviceCert),
                TestPki.toPem(fakeRoot));

        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(chainPem, leafKp.getPublic());

        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("chain"));
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void emptyChainIsRejected() {
        YubicoVerifier verifier = new YubicoVerifier();
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(java.util.Collections.emptyList(), null);

        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("no certificates"));
        assertThat(r.isValid()).isFalse();
    }

    private static final String ORIGIN_OID = "1.3.6.1.4.1.41482.4.3";
    private static final String CAPABILITIES_OID = "1.3.6.1.4.1.41482.4.5";

    private static final byte[] REFERENCE_DEVICE_CAPABILITIES = {0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x06, 0x60};
    private static final byte[] EXPORTABLE_UNDER_WRAP_CAPABILITY = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
    private static final byte[] EXPORT_WRAPPED_CAPABILITY = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00};

    @Test
    void capabilitiesByteOrderReferenceDeviceBytesCarryNoExportFlag() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyCapabilities(REFERENCE_DEVICE_CAPABILITIES, r);

        assertThat(YubicoVerifier.parseCapabilities(REFERENCE_DEVICE_CAPABILITIES))
                .isEqualTo(0x0000000400000660L);
        assertThat(r.isExportableUnderWrap()).isFalse();
        assertThat(r.isCanExportWrapped()).isFalse();
        assertThat(r.isKeyExportable()).isFalse();
    }

    @Test
    void capabilitiesByteOrderBit16IsExportableUnderWrap() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyCapabilities(EXPORTABLE_UNDER_WRAP_CAPABILITY, r);

        assertThat(YubicoVerifier.parseCapabilities(EXPORTABLE_UNDER_WRAP_CAPABILITY)).isEqualTo(1L << 16);
        assertThat(r.isExportableUnderWrap()).isTrue();
        assertThat(r.isCanExportWrapped()).isFalse();
    }

    @Test
    void capabilitiesByteOrderBit12IsExportWrapped() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyCapabilities(EXPORT_WRAPPED_CAPABILITY, r);

        assertThat(YubicoVerifier.parseCapabilities(EXPORT_WRAPPED_CAPABILITY)).isEqualTo(1L << 12);
        assertThat(r.isCanExportWrapped()).isTrue();
        assertThat(r.isExportableUnderWrap()).isFalse();
    }

    @Test
    void capabilitiesByteOrderExportableUnderWrapInAnAttestationCertificateIsRejected() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = attestationCertificate(kp, new byte[] {0x01}, EXPORTABLE_UNDER_WRAP_CAPABILITY);

        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier()
                .verifyYubicoAttestation(List.of(TestPki.toPem(cert)), kp.getPublic());

        assertThat(r.isExportableUnderWrap()).isTrue();
        assertThat(r.isKeyExportable()).isTrue();
        assertThat(r.getErrors()).anyMatch(e -> e.contains("export capabilities"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void capabilitiesByteOrderExportWrappedInAnAttestationCertificateIsRejected() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = attestationCertificate(kp, new byte[] {0x01}, EXPORT_WRAPPED_CAPABILITY);

        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier()
                .verifyYubicoAttestation(List.of(TestPki.toPem(cert)), kp.getPublic());

        assertThat(r.isCanExportWrapped()).isTrue();
        assertThat(r.getErrors()).anyMatch(e -> e.contains("export capabilities"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void originGeneratedIsAccepted() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyOrigin(new byte[] {0x01}, r);
        YubicoVerifier.applyCapabilities(REFERENCE_DEVICE_CAPABILITIES, r);
        YubicoVerifier.validateKeyAttributes(r);

        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.getErrors()).isEmpty();
    }

    @Test
    void originGeneratedAndImportedWrappedIsRejected() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyOrigin(new byte[] {0x11}, r);
        YubicoVerifier.applyCapabilities(REFERENCE_DEVICE_CAPABILITIES, r);
        YubicoVerifier.validateKeyAttributes(r);

        assertThat(r.isGenerated()).isTrue();
        assertThat(r.isImportedWrapped()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("imported_wrapped");
        assertThat(r.getErrors()).anyMatch(e -> e.contains("origin: imported_wrapped"));
    }

    @Test
    void originGeneratedAndImportedWrappedInAnAttestationCertificateIsRejected() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = attestationCertificate(kp, new byte[] {0x11}, REFERENCE_DEVICE_CAPABILITIES);

        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier()
                .verifyYubicoAttestation(List.of(TestPki.toPem(cert)), kp.getPublic());

        assertThat(r.getKeyOrigin()).isEqualTo("imported_wrapped");
        assertThat(r.getErrors()).anyMatch(e -> e.contains("origin: imported_wrapped"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void realYubiHsm2AttestationIsValidGeneratedAndNotExportable() throws Exception {
        JsonNode fixture;
        try (InputStream in = YubicoVerifierTest.class.getResourceAsStream("/fixtures/yubico/request.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        List<String> chain = new ArrayList<>();
        for (JsonNode pem : fixture.get("attestationCertChain")) {
            chain.add(pem.asText());
        }

        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier()
                .verifyYubicoAttestation(chain, csrPublicKey(fixture.get("csr").asText()));

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.isKeyExportable()).isFalse();
        assertThat(r.getDeviceSerial()).isEqualTo("20783176");
        assertThat(r.isValid()).isTrue();
    }

    @Test
    void missingCapabilitiesExtensionIsRejected() throws Exception {
        // Origin present, capabilities extension absent. The exportability
        // flags default to false, which reads as "not exportable"; an absent
        // attribute must not count as a satisfied one.
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = attestationCertificate(kp, new byte[] {0x01}, null);

        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier()
                .verifyYubicoAttestation(List.of(TestPki.toPem(cert)), kp.getPublic());

        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("YUBICO_CAPABILITIES_MISSING"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void attestationExtensionsMarkedCriticalAreRead() throws Exception {
        // Yubico marks the extensions non-critical, but a certificate that
        // marks them critical must not have them skipped.
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = attestationCertificate(kp, new byte[] {0x01}, EXPORTABLE_UNDER_WRAP_CAPABILITY, true);

        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier()
                .verifyYubicoAttestation(List.of(TestPki.toPem(cert)), kp.getPublic());

        assertThat(r.isExportableUnderWrap()).isTrue();
        assertThat(r.getErrors()).anyMatch(e -> e.contains("export capabilities"));
    }

    private static X509Certificate attestationCertificate(KeyPair kp, byte[] origin, byte[] capabilities)
            throws Exception {
        return attestationCertificate(kp, origin, capabilities, false);
    }

    /** {@code capabilities == null} leaves the capabilities extension out. */
    private static X509Certificate attestationCertificate(KeyPair kp, byte[] origin, byte[] capabilities,
            boolean critical) throws Exception {
        X500Name subject = new X500Name("CN=YubiHSM Attestation id:0x0001");
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(now), new Date(now - 60_000L), new Date(now + 3600_000L),
                subject, kp.getPublic());
        b.addExtension(new ASN1ObjectIdentifier(ORIGIN_OID), critical, new DERBitString(origin));
        if (capabilities != null) {
            b.addExtension(new ASN1ObjectIdentifier(CAPABILITIES_OID), critical, new DERBitString(capabilities));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    private static PublicKey csrPublicKey(String csrPem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(csr.getSubjectPublicKeyInfo().getEncoded()));
        }
    }
}
