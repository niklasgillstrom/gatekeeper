package eu.gillstrom.gatekeeper.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Role mappings from client-certificate principals to gatekeeper roles.
 *
 * <p>Each {@link Mapping} declares a regular expression that matches the
 * principal extracted from the X.509 client certificate (typically the
 * Subject CN, but the principal extractor is configurable via
 * {@code gatekeeper.security.mtls.principal-regex}). When a request comes
 * in, the mappings are tried in order; the first that matches contributes
 * its {@code roles} to the request's set of granted authorities. If no
 * mapping matches, {@link #defaultRoles} applies.</p>
 *
 * <p>Roles are bare names ({@code SUPERVISOR}, {@code FE}); Spring
 * Security's {@code hasRole(...)} matchers match these case-sensitively
 * after prepending {@code ROLE_}.</p>
 *
 * <h2>Defined roles</h2>
 *
 * <ul>
 *   <li><strong>{@code SUPERVISOR}</strong> — full access including audit
 *       export, range queries, registry statistics and anomaly listings.
 *       For NCA staff exercising powers under DORA Article 50.</li>
 *   <li><strong>{@code FE}</strong> — verify, confirm and batch-verify
 *       endpoints only. For financial entities calling the gatekeeper to
 *       satisfy their Article 6(10) verification duty before issuing a
 *       certificate.</li>
 * </ul>
 *
 * <h2>YAML configuration shape</h2>
 *
 * <pre>{@code
 * gatekeeper:
 *   security:
 *     roles:
 *       mappings:
 *         - cn-pattern: "^FI-supervisor-.*$"
 *           roles: [SUPERVISOR]
 *         - cn-pattern: "^GetSwish-FE-.*$"
 *           roles: [FE]
 *       default-roles: []   # empty = deny by default if no match
 * }</pre>
 *
 * <p>Production deployments are expected to override {@code mappings} per
 * the NCA's own naming conventions for issued client certificates. The
 * {@code application-nca.yaml} profile contains an example mapping that
 * works against the conventions used in the case study; an actual
 * deployment overrides this with the NCA's real CN policy.</p>
 *
 * <p>Legal basis: granular access control for NCA staff vs financial-
 * entity clients is implied by DORA Article 50 (administrative powers
 * conferred on the supervisor) read with Article 41 (harmonisation of
 * supervisory conditions) — only authorised supervisor staff may exercise
 * the audit-query and registry-inspection endpoints, while FE clients
 * are limited to the verification protocol they need to satisfy their
 * own Article 6(10) duty.</p>
 */
@ConfigurationProperties(prefix = "gatekeeper.security.roles")
@Data
public class RoleMappingProperties {

    /** Ordered list of CN-pattern → role-set mappings. First match wins. */
    private List<Mapping> mappings = new ArrayList<>();

    /** Roles assigned when no mapping matches. Empty = deny by default. */
    private List<String> defaultRoles = new ArrayList<>();

    /**
     * Resolve the set of roles that apply to a given client principal
     * (typically the CN extracted from the X.509 client certificate).
     */
    public List<String> resolve(String principal) {
        if (principal == null) {
            return defaultRoles;
        }
        for (Mapping m : mappings) {
            if (m.matches(principal)) {
                return m.getRoles();
            }
        }
        return defaultRoles;
    }

    @Data
    public static class Mapping {
        /** Regex matched against the client principal. */
        private String cnPattern;

        /** Bare role names (no {@code ROLE_} prefix). */
        private List<String> roles = new ArrayList<>();

        private transient Pattern compiled;

        public boolean matches(String principal) {
            if (cnPattern == null || cnPattern.isBlank()) {
                return false;
            }
            if (compiled == null) {
                compiled = Pattern.compile(cnPattern);
            }
            return compiled.matcher(principal).matches();
        }
    }
}
