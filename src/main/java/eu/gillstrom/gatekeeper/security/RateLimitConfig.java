package eu.gillstrom.gatekeeper.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Registers {@link RateLimitInterceptor} on the gatekeeper endpoints.
 *
 * <p>Pattern coverage:</p>
 * <ul>
 *   <li>{@code /v1/attestation/**} — verify, confirm, batch and registry
 *       endpoints.</li>
 *   <li>{@code /api/v1/**} — the settlement-time verification endpoint that
 *       railgate calls.</li>
 *   <li>{@code /v1/audit/**} — supervisory audit queries, including
 *       {@code /v1/audit/export}, which serialises the entire chain.</li>
 * </ul>
 *
 * <p>Only the first pattern was registered until an independent review
 * pointed out the gap. {@code /api/v1/verify} sits in the payment path and
 * performs an RSA verification plus an audit-log fsync per call;
 * {@code /v1/audit/export} is O(chain length) per call. Both were reachable
 * without any limit at all, and in the reference configuration (mTLS off)
 * without authentication either.</p>
 *
 * <p>The interceptor performs per-path bucket selection, so adding a pattern
 * here is sufficient — see {@code RateLimitInterceptor.selectStore}.</p>
 */
@Configuration
public class RateLimitConfig implements WebMvcConfigurer {

    private final RateLimitInterceptor rateLimitInterceptor;

    public RateLimitConfig(RateLimitInterceptor rateLimitInterceptor) {
        this.rateLimitInterceptor = rateLimitInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitInterceptor)
                .addPathPatterns("/v1/attestation/**", "/api/v1/**", "/v1/audit/**");
    }
}
