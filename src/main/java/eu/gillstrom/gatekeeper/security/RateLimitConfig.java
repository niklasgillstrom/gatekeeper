package eu.gillstrom.gatekeeper.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Registers {@link RateLimitInterceptor} on the gatekeeper endpoints.
 *
 * <p>Pattern coverage:</p>
 * <ul>
 *   <li>{@code /v1/attestation/**} — applies the rate limiter to verify,
 *       confirm, batch and registry endpoints.</li>
 * </ul>
 *
 * <p>The interceptor itself performs per-path bucket selection so a single
 * registration pattern is sufficient.</p>
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
                .addPathPatterns("/v1/attestation/**");
    }
}
