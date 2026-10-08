package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.model.VerificationResponse;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class SigningBehaviourTest {

    @TempDir
    Path tempDir;

    private static X509Certificate parse(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void theEphemeralKeyHasTheConfiguredSizeAndADayOfValidity() throws Exception {
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
        X509Certificate cert = parse(signer.getSigningCertificatePem());

        assertThat(((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength()).isEqualTo(2048);
        assertThat(Duration.between(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant()))
                .isEqualTo(Duration.ofHours(24));
        assertThat(cert.getSerialNumber().signum()).isPositive();
        assertThat(signer.getSignerIdentifier())
                .isEqualTo("REFERENCE-EPHEMERAL/serial=" + cert.getSerialNumber().toString(16));
    }

    @Test
    void theConfiguredSignerIsIdentifiedByItsCertificate() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = TestPki.selfSignedCa(kp, "NCA Seal");
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("seal", kp.getPrivate(), "pw".toCharArray(), new Certificate[] {cert});
        Path keystore = tempDir.resolve("seal.p12");
        try (OutputStream out = Files.newOutputStream(keystore)) {
            store.store(out, "pw".toCharArray());
        }

        ConfiguredReceiptSigner signer = new ConfiguredReceiptSigner(keystore.toString(), "pw", "seal", "pw",
                "SHA256withRSA");

        assertThat(signer.getSignerIdentifier())
                .startsWith(cert.getSubjectX500Principal().getName())
                .contains(cert.getSerialNumber().toString(16));
    }

    @Test
    void onlyTheCustomerAndSupplierNumbersMakeAReceiptCurrentOnly() {
        assertThat(ReceiptCanonicalizer.hasCurrentOnlyFields(VerificationResponse.builder().build())).isFalse();
        assertThat(ReceiptCanonicalizer.hasCurrentOnlyFields(VerificationResponse.builder()
                .supplierIdentifier("5569743098").supplierName("Supplier AB").build())).isFalse();
        assertThat(ReceiptCanonicalizer.hasCurrentOnlyFields(VerificationResponse.builder()
                .customerOrganisationNumber("5569743098").build())).isTrue();
        assertThat(ReceiptCanonicalizer.hasCurrentOnlyFields(VerificationResponse.builder()
                .customerSwishNumber("1231015932").build())).isTrue();
        assertThat(ReceiptCanonicalizer.hasCurrentOnlyFields(VerificationResponse.builder()
                .supplierNumber("9871234567").build())).isTrue();
    }
}
