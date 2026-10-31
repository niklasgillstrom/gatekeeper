package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.DoraAttestationGatekeeperApplication;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.verification.TrustAnchors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code gatekeeper.trust-anchors.<key>} is bound to the {@link TrustAnchors} bean;
 * a file that cannot be used, or an unknown key, stops the context, and the
 * application, from starting.
 */
class TrustAnchorConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TrustAnchorConfiguration.class);

    @TempDir
    Path dir;

    @Test
    void withoutPropertiesOrWithEmptyOnesEveryAnchorIsPinned() {
        runner.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx.getBean(TrustAnchors.class).all())
                    .allMatch(a -> a.origin().equals(TrustAnchors.ORIGIN_PINNED) && a.path() == null);
        });
        runner.withPropertyValues("gatekeeper.trust-anchors.yubico=", "gatekeeper.trust-anchors.google-owner=",
                "gatekeeper.trust-anchors.entrust=").run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx.getBean(TrustAnchors.class).all())
                            .allMatch(a -> a.origin().equals(TrustAnchors.ORIGIN_PINNED));
                });
    }

    @Test
    void aNamedFileReplacesThatAnchorOnly() throws Exception {
        X509Certificate root = TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), "Operator Owner Root");
        Path file = dir.resolve("owner-root.pem");
        Files.writeString(file, TestPki.toPem(root));
        runner.withPropertyValues("gatekeeper.trust-anchors.google-owner=" + file).run(ctx -> {
            assertThat(ctx).hasNotFailed();
            TrustAnchors anchors = ctx.getBean(TrustAnchors.class);
            TrustAnchors.ActiveAnchor owner = anchors.active(TrustAnchors.GOOGLE_OWNER);
            assertThat(owner.origin()).isEqualTo(TrustAnchors.ORIGIN_OVERRIDE);
            assertThat(owner.path()).isEqualTo(file.toAbsolutePath().normalize().toString());
            assertThat(owner.subjects()).containsExactly("CN=Operator Owner Root");
            assertThat(owner.matchesPinned()).isFalse();
            assertThat(anchors.all()).filteredOn(a -> !a.anchor().equals(TrustAnchors.GOOGLE_OWNER))
                    .allMatch(a -> a.origin().equals(TrustAnchors.ORIGIN_PINNED));
        });
    }

    @Test
    void aMissingFileOrAnUnknownKeyFailsTheContext() {
        runner.withPropertyValues("gatekeeper.trust-anchors.yubico=" + dir.resolve("absent.pem")).run(ctx -> {
            assertThat(ctx).hasFailed();
            assertThat(ctx.getStartupFailure()).rootCause()
                    .hasMessageContaining("gatekeeper.trust-anchors.yubico").hasMessageContaining("no such file");
        });
        runner.withPropertyValues("gatekeeper.trust-anchors.yubikey=" + dir.resolve("absent.pem")).run(ctx -> {
            assertThat(ctx).hasFailed();
            assertThat(ctx.getStartupFailure()).rootCause()
                    .hasMessageContaining("Unknown trust anchor gatekeeper.trust-anchors.yubikey");
        });
    }

    @Test
    void aBadFileStopsTheApplicationFromStarting() throws Exception {
        Path bad = dir.resolve("securosys-root.pem");
        Files.writeString(bad, "this is not a certificate\n");
        // Command-line arguments, as an operator would pass them; they rank above
        // the packaged application.yaml, whose placeholder is empty by default.
        assertThatThrownBy(() -> new SpringApplicationBuilder(DoraAttestationGatekeeperApplication.class)
                .run("--server.port=0", "--spring.main.banner-mode=off",
                        "--gatekeeper.audit.path=" + dir.resolve("audit-log.jsonl"),
                        "--gatekeeper.registry.path=" + dir.resolve("approval-registry.jsonl"),
                        "--gatekeeper.trust-anchors.securosys=" + bad)
                .close())
                .rootCause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("gatekeeper.trust-anchors.securosys")
                .hasMessageContaining("no PEM block");
    }
}
