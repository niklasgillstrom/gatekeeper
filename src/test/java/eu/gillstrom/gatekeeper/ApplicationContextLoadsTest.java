package eu.gillstrom.gatekeeper;

import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.controller.GatekeeperController;
import eu.gillstrom.gatekeeper.controller.VerificationController;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.InMemoryApprovalRegistry;
import eu.gillstrom.gatekeeper.service.VerificationService;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The default-profile application context starts.
 *
 * <p>Version 1.3.0 shipped with a duplicated {@code audit:} key in
 * {@code application.yaml}. SnakeYAML rejects a duplicate mapping key, so
 * the application could not start at all — and the whole test suite passed,
 * because no test had ever loaded the Spring context. Every test used
 * {@code MockMvcBuilders.standaloneSetup} or constructed its collaborators
 * directly, which never reads {@code application.yaml}.</p>
 *
 * <p>This test is deliberately thin on assertions. Its value is that it
 * boots the real context from the real configuration files: a YAML parse
 * error, a missing bean, an ambiguous constructor or a property placeholder
 * that resolves to nothing fails here rather than on a deployment host.</p>
 *
 * <p>{@code MOCK} web environment: no port is bound, so the test can run in
 * any CI sandbox. The audit-log and registry paths are redirected into the
 * JVM temp directory — the defaults are relative paths that would otherwise
 * drop {@code audit-log.jsonl} into the working directory of whoever ran
 * the build.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = {
        "gatekeeper.audit.path=${java.io.tmpdir}/gatekeeper-context-test/audit-log.jsonl",
        "gatekeeper.registry.path=${java.io.tmpdir}/gatekeeper-context-test/approval-registry.jsonl"
})
class ApplicationContextLoadsTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void contextLoadsWithTheDefaultProfile() {
        assertThat(context).isNotNull();
        assertThat(context.getBean(VerificationService.class)).isNotNull();
        assertThat(context.getBean(VerificationController.class)).isNotNull();
        assertThat(context.getBean(GatekeeperController.class)).isNotNull();
        assertThat(context.getBean(AuditLog.class)).isNotNull();
    }

    /**
     * The reference defaults are what {@code application.yaml} documents:
     * in-memory registry, ephemeral signer. Asserted so that a change to
     * either default has to be made deliberately.
     */
    @Test
    void referenceDefaultsAreTheDocumentedOnes() {
        assertThat(context.getBean(ApprovalRegistry.class))
                .isInstanceOf(InMemoryApprovalRegistry.class);
        assertThat(context.getBean(ReceiptSigner.class))
                .isInstanceOf(EphemeralReceiptSigner.class);
    }
}
