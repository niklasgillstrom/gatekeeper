package eu.gillstrom.gatekeeper;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.security.RoleMappingProperties;
import eu.gillstrom.gatekeeper.service.AppendOnlyFileApprovalRegistry;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.signing.ConfiguredReceiptSigner;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import eu.gillstrom.gatekeeper.signing.SigningKeyAttestation;
import eu.gillstrom.gatekeeper.testsupport.TestKeystores;
import eu.gillstrom.gatekeeper.timestamp.AuditTimestamping;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code org} profile's configuration parses and its beans wire up,
 * mirroring {@link NcaProfileContextLoadsTest}.
 *
 * <p>Unlike that test, the signer is not substituted: a throwaway PKCS#12
 * keystore stands in for the organisation's seal, so
 * {@link ConfiguredReceiptSigner} is the signer that loads. The overridden
 * properties are the paths of that keystore, its password, the audit log and
 * the registry journal, and {@code server.ssl.enabled} (the TLS keystore
 * exists only on a real host). Everything else is the profile as written.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("org")
class OrgProfileContextLoadsTest {

    private static TestKeystores.Written seal;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("gatekeeper-org-context-test");
        seal = TestKeystores.pkcs12(dir, "org-seal", "Example Organisation Seal", "test-password");
        registry.add("gatekeeper.audit.path", () -> dir.resolve("audit-log.jsonl").toString());
        registry.add("gatekeeper.registry.path", () -> dir.resolve("approval-registry.jsonl").toString());
        registry.add("gatekeeper.signing.keystore-path", () -> seal.path().toString());
        registry.add("gatekeeper.signing.keystore-password", () -> "test-password");
        registry.add("server.ssl.enabled", () -> "false");
    }

    @Autowired
    private ApplicationContext context;

    @Test
    void contextLoadsWithTheOrgProfileAndTheMtlsChain() {
        assertThat(context.getBean(SecurityFilterChain.class)).isNotNull();
        assertThat(context.getEnvironment().getProperty("gatekeeper.security.mtls.enabled")).isEqualTo("true");
        assertThat(context.getEnvironment().getProperty("server.ssl.client-auth")).isEqualTo("need");
    }

    @Test
    void theOrganisationsOwnSealSigns() throws Exception {
        ReceiptSigner signer = context.getBean(ReceiptSigner.class);
        assertThat(signer).isInstanceOf(ConfiguredReceiptSigner.class);
        assertThat(signer.getSignerIdentifier()).startsWith("CN=Example Organisation Seal");
        String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(seal.certificate().getPublicKey().getEncoded()));
        assertThat(context.getBean(GatekeeperKeyDirectory.class).activeFingerprintHex()).isEqualTo(expected);
    }

    @Test
    void theRegistryAndTheAuditLogAreFileBacked() {
        assertThat(context.getBean(ApprovalRegistry.class)).isInstanceOf(AppendOnlyFileApprovalRegistry.class);
        assertThat(context.getBean(AuditLog.class)).isInstanceOf(AppendOnlyFileAuditLog.class);
    }

    @Test
    void theRoleTemplatesMapInternalAuditAndTheCisoToolToSupervisorAndTheServicesToFe() {
        RoleMappingProperties roles = context.getBean(RoleMappingProperties.class);
        assertThat(roles.resolve("internal-audit-1")).containsExactly("SUPERVISOR");
        assertThat(roles.resolve("ciso-tool-prod")).containsExactly("SUPERVISOR");
        assertThat(roles.resolve("issuance-service-1")).containsExactly("FE");
        assertThat(roles.resolve("signing-service-1")).containsExactly("FE");
        assertThat(roles.resolve("RAIL-riksbank")).isEmpty();
        assertThat(roles.getDefaultRoles()).isEmpty();
    }

    @Test
    void theRateLimitsAreConfigured() {
        for (String bucket : List.of("verify", "batch", "registry", "settlement", "audit", "lifecycle")) {
            assertThat(context.getEnvironment().getProperty("gatekeeper.ratelimit." + bucket + ".capacity"))
                    .as(bucket).isNotBlank();
        }
        assertThat(context.getEnvironment().getProperty("gatekeeper.ratelimit.lifecycle.capacity"))
                .isEqualTo("6000");
    }

    /**
     * The evidence-chain options documented (commented out) in
     * application-org.yaml stay off: the seal is the PKCS#12 file, the seal
     * key's attestation is not configured, and the audit log is not
     * time-stamped.
     */
    @Test
    void theEvidenceChainOptionsAreDocumentedButOff() {
        var environment = context.getEnvironment();
        assertThat(environment.getProperty("gatekeeper.signing.keystore-type")).isNull();
        assertThat(environment.getProperty("gatekeeper.signing.provider-class")).isNull();
        assertThat(environment.getProperty("gatekeeper.signing.attestation.vendor")).isNull();
        assertThat(environment.getProperty("gatekeeper.timestamping.mode")).isNull();
        assertThat(context.getBean(SigningKeyAttestation.class).isConfigured()).isFalse();
        assertThat(context.getBean(AuditTimestamping.class).mode()).isEqualTo(AuditTimestamping.Mode.OFF);
    }
}
