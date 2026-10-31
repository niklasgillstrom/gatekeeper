package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fingerprint convention a relying party (railgate) must reproduce for the
 * gatekeeper's signing key: {@code publicKeyFingerprintHex} on
 * {@code GET /v1/gatekeeper/keys}, which is also the settlement verdict's
 * {@code signingKeyFingerprintHex}. It is the lowercase hexadecimal SHA-256 of
 * the DER SubjectPublicKeyInfo of the signing certificate's public key, 64
 * characters, no separators; not the SHA-256 of the certificate, and not the
 * colon-separated {@code Fingerprints} format used for supervised keys.
 */
class SigningKeyFingerprintConventionTest {

    @Test
    void theKeysFingerprintIsTheLowercaseHexSha256OfTheSubjectPublicKeyInfo() throws Exception {
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
        GatekeeperKeyDirectory directory = new GatekeeperKeyDirectory(signer, "");
        directory.initialise();
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(
                        signer.getSigningCertificatePem().getBytes(StandardCharsets.UTF_8)));
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        String published = directory.activeFingerprintHex();

        assertThat(published).matches("^[0-9a-f]{64}$");
        assertThat(published).isEqualTo(directory.allKeys().get(0).publicKeyFingerprintHex());
        assertThat(published).isEqualTo(HexFormat.of().formatHex(
                sha256.digest(certificate.getPublicKey().getEncoded())));
        assertThat(published).isNotEqualTo(HexFormat.of().formatHex(sha256.digest(certificate.getEncoded())));
    }
}
