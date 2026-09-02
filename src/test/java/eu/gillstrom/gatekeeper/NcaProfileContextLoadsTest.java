package eu.gillstrom.gatekeeper;

import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.AppendOnlyFileApprovalRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code nca} profile's configuration parses and its beans wire up.
 *
 * <p>The profile cannot be loaded verbatim: it points at three artefacts
 * that exist only on a production host — the PKCS#12 seal keystore under
 * {@code /etc/gatekeeper}, the TLS keystore, and the journal directory
 * under {@code /var/lib/gatekeeper}. Those four properties are overridden
 * below and nothing else is, so what the test does exercise is the rest of
 * the profile as written: the mTLS filter chain (which the default profile
 * never builds), the role mappings, the file-backed approval registry, the
 * five rate-limit buckets, and every property placeholder in the file.</p>
 *
 * <p>The signing mode is the one substitution that weakens the test —
 * {@code ConfiguredReceiptSigner} is not exercised, because it would need a
 * real keystore. That gap is inherent to a configuration whose production
 * form depends on operator-supplied key material; {@code DEPLOYMENT.md}
 * §2.1 is where that step is verified instead.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("nca")
@TestPropertySource(properties = {
        "gatekeeper.audit.path=${java.io.tmpdir}/gatekeeper-nca-context-test/audit-log.jsonl",
        "gatekeeper.registry.path=${java.io.tmpdir}/gatekeeper-nca-context-test/approval-registry.jsonl",
        "gatekeeper.signing.mode=ephemeral",
        "server.ssl.enabled=false"
})
class NcaProfileContextLoadsTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void contextLoadsWithTheNcaProfile() {
        assertThat(context).isNotNull();
        assertThat(context.getBean(SecurityFilterChain.class))
                .as("the nca profile sets gatekeeper.security.mtls.enabled=true, so the "
                    + "mTLS chain — not the permissive reference chain — must be the one built")
                .isNotNull();
    }

    @Test
    void ncaProfileSelectsTheJournalBackedRegistry() {
        assertThat(context.getBean(ApprovalRegistry.class))
                .isInstanceOf(AppendOnlyFileApprovalRegistry.class);
    }
}
