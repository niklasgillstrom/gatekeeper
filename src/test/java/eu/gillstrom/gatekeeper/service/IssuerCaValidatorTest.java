package eu.gillstrom.gatekeeper.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import eu.gillstrom.gatekeeper.testsupport.TestPki;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    /**
     * A bundle the operator named is the bundle, or there is none. Until
     * 1.7.0 a path that named no file fell back to the demonstration chain on
     * the class path with a WARN, so the gatekeeper started on issuers the
     * operator had not chosen.
     */
    @Test
    void aConfiguredBundleThatIsNotAFileStopsStartUp(@TempDir Path tmp) {
        Path missing = tmp.resolve("does-not-exist.pem");
        for (Path notAFile : new Path[] {missing, tmp}) {
            assertThatThrownBy(() -> new IssuerCaValidator(notAFile.toString()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("gatekeeper.confirmation.issuer-ca-bundle-path names '" + notAFile
                            + "', which is not a file. The gatekeeper does not fall back to the bundled "
                            + "demonstration issuers; correct the path or unset the property.");
        }
    }

    @Test
    void aConfiguredBundleWithoutACertificateStopsStartUp(@TempDir Path tmp) throws Exception {
        for (String content : new String[] {"", "\n\n", "not a certificate",
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}) {
            Path bundle = tmp.resolve("empty.pem");
            Files.writeString(bundle, content);

            assertThatThrownBy(() -> new IssuerCaValidator(bundle.toString()))
                    .as("content: %s", content)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("gatekeeper.confirmation.issuer-ca-bundle-path '" + bundle
                            + "' holds no certificate. The gatekeeper does not fall back to the bundled "
                            + "demonstration issuers; correct the file or unset the property.");
        }
    }

    @Test
    void aConfiguredBundleReplacesTheShippedOne(@TempDir Path tmp) throws Exception {
        KeyPair rootKey = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKey, "Operator Root");
        Path bundle = tmp.resolve("operator.pem");
        Files.writeString(bundle, TestPki.toPem(root));

        IssuerCaValidator validator = new IssuerCaValidator(bundle.toString());

        assertThat(validator.trustAnchorCount()).as("the operator's root, and not the shipped one beside it")
                .isEqualTo(1);
        assertThat(validator.validate(TestPki.endEntity(TestPki.newRsaKeyPair(2048), "Leaf", root,
                rootKey.getPrivate()))).isTrue();
    }

    @Test
    void withoutAConfiguredPathTheShippedBundleIsUsed() {
        for (String unset : new String[] {null, "", "  "}) {
            assertThat(new IssuerCaValidator(unset).trustAnchorCount()).as("path: '%s'", unset).isEqualTo(1);
        }
    }

    @Test
    void nullCertificateReturnsFalse() {
        IssuerCaValidator validator = new IssuerCaValidator("");
        assertThat(validator.validate(null)).isFalse();
    }

    @Test
    void leafValidatesAgainstTheRootWhenItsIntermediateIsSubmitted(@TempDir Path tmp) throws Exception {
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKp, "TEST-ROOT");
        KeyPair intermediateKp = TestPki.newRsaKeyPair(2048);
        X509Certificate intermediate = TestPki.subordinateCa(
                intermediateKp, "TEST-INTERMEDIATE", root, rootKp.getPrivate());
        X509Certificate leaf = TestPki.endEntity(
                TestPki.newRsaKeyPair(2048), "TEST-LEAF", intermediate, intermediateKp.getPrivate());
        Path bundle = tmp.resolve("root-only.pem");
        Files.writeString(bundle, TestPki.toPem(root), StandardCharsets.UTF_8);
        IssuerCaValidator validator = new IssuerCaValidator(bundle.toString());

        assertThat(validator.trustAnchorCount()).isEqualTo(1);
        assertThat(validator.validateChain(List.of(leaf, intermediate))).isTrue();
    }

    @Test
    void leafDoesNotValidateWhenItsIntermediateIsMissing(@TempDir Path tmp) throws Exception {
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKp, "TEST-ROOT");
        KeyPair intermediateKp = TestPki.newRsaKeyPair(2048);
        X509Certificate intermediate = TestPki.subordinateCa(
                intermediateKp, "TEST-INTERMEDIATE", root, rootKp.getPrivate());
        X509Certificate leaf = TestPki.endEntity(
                TestPki.newRsaKeyPair(2048), "TEST-LEAF", intermediate, intermediateKp.getPrivate());
        Path bundle = tmp.resolve("root-only.pem");
        Files.writeString(bundle, TestPki.toPem(root), StandardCharsets.UTF_8);
        IssuerCaValidator validator = new IssuerCaValidator(bundle.toString());

        assertThat(validator.validateChain(List.of(leaf))).isFalse();
        assertThat(validator.validate(leaf)).isFalse();
    }

    @Test
    void intermediateInTheBundleCompletesThePathWithoutBecomingATrustAnchor(@TempDir Path tmp)
            throws Exception {
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKp, "TEST-ROOT");
        KeyPair intermediateKp = TestPki.newRsaKeyPair(2048);
        X509Certificate intermediate = TestPki.subordinateCa(
                intermediateKp, "TEST-INTERMEDIATE", root, rootKp.getPrivate());
        X509Certificate leaf = TestPki.endEntity(
                TestPki.newRsaKeyPair(2048), "TEST-LEAF", intermediate, intermediateKp.getPrivate());
        Path bundle = tmp.resolve("root-and-intermediate.pem");
        Files.writeString(bundle, TestPki.toPem(root) + TestPki.toPem(intermediate), StandardCharsets.UTF_8);
        IssuerCaValidator validator = new IssuerCaValidator(bundle.toString());

        assertThat(validator.trustAnchorCount()).isEqualTo(1);
        assertThat(validator.validate(leaf)).isTrue();
    }

    @Test
    void shippedBundleHasOneTrustAnchor() {
        assertThat(new IssuerCaValidator("").trustAnchorCount()).isEqualTo(1);
    }
}
