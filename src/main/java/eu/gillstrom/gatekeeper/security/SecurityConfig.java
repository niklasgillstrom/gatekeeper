package eu.gillstrom.gatekeeper.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Spring Security configuration enforcing mutual TLS (client-certificate
 * authentication) and role-based authorisation on the gatekeeper API.
 *
 * <h2>Authentication</h2>
 *
 * <p>When {@code gatekeeper.security.mtls.enabled=true}, the
 * {@link #mtlsFilterChain(HttpSecurity, RoleMappingProperties, String)
 * mtlsFilterChain} bean is active. Every authenticated request is
 * required to present a valid client certificate, validated against the
 * Tomcat-configured truststore (per {@code application-nca.yaml}).
 * The CN of the client certificate is extracted via
 * {@code gatekeeper.security.mtls.principal-regex} (default
 * {@code CN=(.*?)(?:,|$)}) and used as the request principal.</p>
 *
 * <h2>Authorisation</h2>
 *
 * <p>Roles are assigned to a request principal by
 * {@link RoleMappingProperties}: a list of CN-pattern → role-set
 * mappings, configured via {@code gatekeeper.security.roles}.
 * The two defined roles are:</p>
 *
 * <ul>
 *   <li><strong>{@code SUPERVISOR}</strong> — NCA staff. Full access
 *       including {@code /v1/audit/**} (export, range, witness, entity
 *       queries) and {@code /v1/attestation/&#x7b;cc&#x7d;/registry/**}
 *       (statistics, anomalies, awaiting-confirmation listings).</li>
 *   <li><strong>{@code FE}</strong> — financial-entity client. Limited
 *       to the verification protocol endpoints
 *       ({@code /v1/attestation/&#x7b;cc&#x7d;/verify},
 *       {@code /v1/attestation/&#x7b;cc&#x7d;/verify/batch},
 *       {@code /v1/attestation/&#x7b;cc&#x7d;/confirm}).</li>
 * </ul>
 *
 * <p>{@code SUPERVISOR}-only paths are denied to {@code FE}; the verify/
 * confirm paths accept either role. Public paths (gatekeeper key
 * directory, chain anchor, health, supported-vendors list, OpenAPI docs)
 * remain reachable without authentication so a relying party can verify
 * retroactive evidence under DORA Article 28(6) without holding a
 * client certificate.</p>
 *
 * <h2>Reference (mTLS-disabled) chain</h2>
 *
 * <p>When {@code gatekeeper.security.mtls.enabled=false} (the default),
 * the open filter chain permits all access and emits a startup WARN —
 * the relaxed stance cannot be deployed to production unnoticed.</p>
 *
 * <h2>Legal basis</h2>
 *
 * <p>Granular access control between NCA staff and FE clients is
 * implied by DORA Article 50 (administrative powers conferred on the
 * supervisor) read with Article 41 (harmonisation of supervisory
 * conditions). Authorising the FE only to the verification endpoints
 * it actually needs to satisfy Article 6(10) is the principle of
 * least privilege applied to the supervisory protocol.</p>
 */
@Configuration
@EnableConfigurationProperties(RoleMappingProperties.class)
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    /**
     * mTLS-enforcing filter chain with role-based path authorisation.
     * Active when {@code gatekeeper.security.mtls.enabled=true}.
     */
    @Bean
    @ConditionalOnProperty(name = "gatekeeper.security.mtls.enabled", havingValue = "true")
    public SecurityFilterChain mtlsFilterChain(HttpSecurity http,
                                               RoleMappingProperties roleMappings,
                                               @Value("${gatekeeper.security.mtls.principal-regex:CN=(.*?)(?:,|$)}")
                                               String principalRegex) throws Exception {
        log.info("mTLS SecurityFilterChain enabled; principal regex='{}'; "
                + "{} role mapping(s) configured; default roles={}",
                principalRegex,
                roleMappings.getMappings().size(),
                roleMappings.getDefaultRoles());

        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Public — must remain reachable without a client cert
                // because relying parties (including the FE itself, after
                // receipt verification) need them to validate retroactive
                // evidence under DORA Article 28(6).
                .requestMatchers(
                        "/v1/attestation/health",
                        "/v1/attestation/supported-vendors",
                        "/v1/gatekeeper/keys",
                        "/v1/gatekeeper/anchor",
                        "/v1/gatekeeper/health",
                        "/swagger-ui/**",
                        "/swagger-ui.html",
                        "/v3/api-docs/**"
                ).permitAll()

                // Supervisor-only — audit query and registry inspection.
                // These endpoints expose the data triangulation substrate
                // described in SUPERVISORY_OPERATIONS.md §3.5; they must
                // not be reachable by FE clients.
                .requestMatchers("/v1/audit/**").hasRole("SUPERVISOR")
                .requestMatchers(HttpMethod.GET, "/v1/attestation/*/registry/**").hasRole("SUPERVISOR")

                // FE or supervisor — the verification protocol itself.
                // The supervisor can also call these (useful for sandbox
                // and incident-response scenarios), but the typical caller
                // is an FE satisfying its DORA Article 6(10) duty.
                .requestMatchers(HttpMethod.POST,
                        "/v1/attestation/*/verify",
                        "/v1/attestation/*/verify/batch",
                        "/v1/attestation/*/confirm"
                ).hasAnyRole("FE", "SUPERVISOR")

                // Settlement-rail enforcement (railgate or equivalent).
                // The typical caller is a central-bank settlement system
                // calling this endpoint at settlement-time to verify a
                // cryptographic signature against a previously audited
                // certificate. SUPERVISOR role is also accepted for sandbox
                // and incident-response scenarios.
                .requestMatchers(HttpMethod.POST, "/api/v1/verify")
                        .hasAnyRole("SETTLEMENT_RAIL", "SUPERVISOR")

                // Anything else under /v1/attestation that isn't covered
                // by an explicit matcher requires authentication; deny
                // everything outside /v1/* by default.
                .requestMatchers("/v1/attestation/**").authenticated()
                .anyRequest().denyAll()
            )
            .x509(x509 -> x509
                .x509PrincipalExtractor(principalExtractor(principalRegex))
                .userDetailsService(username -> {
                    List<String> bareRoles = roleMappings.resolve(username);
                    String[] authorities = bareRoles.stream()
                            .map(r -> "ROLE_" + r)
                            .toArray(String[]::new);
                    if (authorities.length == 0) {
                        log.warn("mTLS principal '{}' did not match any role mapping; "
                                + "no authorities granted (will be denied by hasRole/hasAnyRole matchers).",
                                username);
                    } else {
                        log.debug("mTLS principal '{}' resolved to authorities {}",
                                username, java.util.Arrays.toString(authorities));
                    }
                    return new User(username, "",
                            authorities.length == 0
                                    ? AuthorityUtils.NO_AUTHORITIES
                                    : AuthorityUtils.createAuthorityList(authorities));
                })
            );

        return http.build();
    }

    /**
     * Development / reference filter chain. Active when
     * {@code gatekeeper.security.mtls.enabled=false} (the default). Allows
     * anonymous access to all endpoints and emits a WARN log at startup so
     * the relaxed stance cannot be deployed to production unnoticed.
     */
    @Bean
    @ConditionalOnProperty(name = "gatekeeper.security.mtls.enabled", havingValue = "false", matchIfMissing = true)
    public SecurityFilterChain openFilterChain(HttpSecurity http) throws Exception {
        log.warn("mTLS SecurityFilterChain is DISABLED (gatekeeper.security.mtls.enabled=false). "
                + "All endpoints permit anonymous access. This is the REFERENCE configuration and "
                + "MUST NOT be deployed to production. Set gatekeeper.security.mtls.enabled=true "
                + "and provide a trust store via server.ssl.trust-store-type/path/password before "
                + "production deployment.");
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .anonymous(a -> a.principal("reference-anonymous")
                    .authorities(AuthorityUtils.createAuthorityList("ROLE_REFERENCE_ANON")));
        return http.build();
    }

    private X509PrincipalExtractor principalExtractor(String regex) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
        return (X509Certificate cert) -> {
            String dn = cert.getSubjectX500Principal().getName();
            java.util.regex.Matcher m = pattern.matcher(dn);
            if (m.find() && m.groupCount() >= 1) {
                return m.group(1);
            }
            return dn;
        };
    }

    // Suppress the unused-import warning when the project compiles without the
    // AnonymousAuthenticationToken import in some Spring versions.
    @SuppressWarnings("unused")
    private static final Class<?> KEEP_IMPORT = AnonymousAuthenticationToken.class;

    // Keep the X509AuthenticationFilter import referenced so static analysers
    // don't flag it as unused even though only the DSL is visible above.
    @SuppressWarnings("unused")
    private static final Class<?> KEEP_X509_IMPORT = X509AuthenticationFilter.class;
}
