package eu.gillstrom.gatekeeper.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link IssuerCaValidator}. The validator accepts an empty
 * configured bundle path and falls back to the classpath resource
 * {@code issuer-ca-bundle.pem}, which the reference implementation ships with
 * the Getswish issuer CA chain. A certificate that is not rooted at any of
 * those anchors must be rejected by {@link IssuerCaValidator#validate(X509Certificate)}.
 */
class IssuerCaValidatorTest {

    @Test
    void emptyPathFallsBackToClasspathAndLoadsAtLeastOneAnchor() {
        // Empty bundle path -> classpath fallback kicks in.
        IssuerCaValidator validator = new IssuerCaValidator("");

        // The reference implementation ships issuer-ca-bundle.pem on the
        // classpath, so there must be at least one trust anchor.
        assertThat(validator.trustAnchorCount()).isGreaterThan(0);
    }

    @Test
    void throwawayCertificateNotRootedAtGetswishIsRejected() throws Exception {
        IssuerCaValidator validator = new IssuerCaValidator("");

        // Build a throwaway self-signed cert that is not in the Getswish bundle.
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate selfSigned = TestPki.selfSignedCa(kp, "FAKE-NOT-GETSWISH");

        assertThat(validator.validate(selfSigned)).isFalse();
    }

    @Test
    void badBundlePathYieldsEmptyAnchorsAndValidateReturnsFalse(@TempDir Path tmp) throws Exception {
        // Point at a file that does not exist AND ensure the classpath
        // fallback is consulted. The fallback may still populate anchors
        // (reference bundle ships on classpath), so we assert behaviourally
        // against a throwaway cert rather than insisting on an empty set.
        Path missing = tmp.resolve("does-not-exist.pem");
        IssuerCaValidator validator = new IssuerCaValidator(missing.toAbsolutePath().toString());

        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate selfSigned = TestPki.selfSignedCa(kp, "FAKE-BAD-PATH");

        assertThat(validator.validate(selfSigned)).isFalse();
    }

    @Test
    void nullCertificateReturnsFalse() {
        IssuerCaValidator validator = new IssuerCaValidator("");
        assertThat(validator.validate(null)).isFalse();
    }
}
