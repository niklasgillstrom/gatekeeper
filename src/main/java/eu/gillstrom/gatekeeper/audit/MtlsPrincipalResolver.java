package eu.gillstrom.gatekeeper.audit;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Resolves the mTLS-authenticated client principal that should be recorded
 * in an {@link AuditEntry}.
 *
 * <p>Looks up the current Spring Security {@link
 * org.springframework.security.core.context.SecurityContext} and returns
 * the {@link Authentication#getName()} of the active authentication.
 * When the open (non-mTLS) reference filter chain is in use, Spring
 * Security still installs an
 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}
 * with principal {@code "reference-anonymous"} (see {@code SecurityConfig}),
 * so this resolver returns that string. When Spring Security is bypassed
 * entirely (e.g. unit tests), the resolver falls back to the constant
 * {@link #FALLBACK_ANONYMOUS_PRINCIPAL}.</p>
 *
 * <p>Centralising this lookup behind a bean has two benefits: tests can
 * replace it with a deterministic stub, and the production code path can
 * be hardened (e.g. require a non-anonymous principal for {@code VERIFY}
 * operations) in one place when the NCA's authorisation policy is
 * finalised.</p>
 */
@Component
public class MtlsPrincipalResolver {

    /**
     * Returned when no Spring Security context is available at all. Distinct
     * from {@code "reference-anonymous"} (the value the open filter chain
     * uses) so audit-trail readers can tell the two situations apart.
     */
    public static final String FALLBACK_ANONYMOUS_PRINCIPAL = "anonymous";

    /**
     * Resolve the principal name for the current request. Never returns
     * {@code null}; falls back to {@link #FALLBACK_ANONYMOUS_PRINCIPAL}
     * if no authentication is bound to the current thread.
     */
    public String currentPrincipal() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            return FALLBACK_ANONYMOUS_PRINCIPAL;
        }
        String name = auth.getName();
        if (name == null || name.isBlank()) {
            return FALLBACK_ANONYMOUS_PRINCIPAL;
        }
        return name;
    }
}
