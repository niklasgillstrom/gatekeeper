package eu.gillstrom.gatekeeper.signing;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link EphemeralReceiptSigner}. The signer generates a fresh
 * RSA key pair on construction and signs with SHA256withRSA; these tests round-
 * trip a signature through the public key extracted from the exposed PEM and
 * also assert the REFERENCE-EPHEMERAL marker is present.
 */
class EphemeralReceiptSignerTest {

    @Test
    void signAndVerifyRoundTripsAgainstExposedCertificate() throws Exception {
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

        byte[] canonical = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] sigBytes = signer.sign(canonical);

        String pem = signer.getSigningCertificatePem();
        assertThat(pem).contains("-----BEGIN CERTIFICATE-----");

        // Re-parse the PEM to obtain the public key independently — do not use
        // the signer's own getPublicKey() helper, so we exercise the full
        // consumer-facing contract.
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        PublicKey pub = cert.getPublicKey();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pub);
        verifier.update(canonical);
        assertThat(verifier.verify(sigBytes))
                .as("ephemeral signer signature must verify against the cert in its PEM")
                .isTrue();
    }

    @Test
    void certificatePemContainsReferenceEphemeralMarker() throws Exception {
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

        String pem = signer.getSigningCertificatePem();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));

        // REFERENCE-EPHEMERAL appears in the Subject DN; that is the
        // observable marker downstream consumers filter on.
        assertThat(cert.getSubjectX500Principal().getName())
                .contains("REFERENCE-EPHEMERAL");
        assertThat(signer.getSignerIdentifier()).contains("REFERENCE-EPHEMERAL");
    }

    @Test
    void tamperedCanonicalBytesFailVerification() throws Exception {
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

        byte[] canonical = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] sigBytes = signer.sign(canonical);

        byte[] tampered = "hellO".getBytes(StandardCharsets.UTF_8);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(signer.getPublicKey());
        verifier.update(tampered);
        assertThat(verifier.verify(sigBytes)).isFalse();
    }
}
