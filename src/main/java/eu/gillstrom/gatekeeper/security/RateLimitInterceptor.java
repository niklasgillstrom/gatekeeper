package eu.gillstrom.gatekeeper.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.security.Principal;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Token-bucket rate limiter for the gatekeeper API.
 *
 * <p>Per-principal buckets are keyed by the authenticated mTLS client
 * identifier extracted from {@link HttpServletRequest#getUserPrincipal()}.
 * Unauthenticated requests fall back to a single shared bucket keyed by
 * remote IP so the reference-default (mTLS disabled) still gets a usable
 * default protection.</p>
 *
 * <p>The verify-batch endpoint is assigned a separate, stricter bucket by
 * default because a single request can exercise the full verification
 * pipeline for dozens of entities — a naïve uniform limit would either let
 * batch abuse the per-request bucket or throttle interactive single-entity
 * use.</p>
 *
 * <p>All limits are configurable via Spring properties (see
 * {@code application-nca.yaml} for the production profile). Exceeding a
 * bucket returns HTTP 429 Too Many Requests with a {@code Retry-After}
 * header in seconds (RFC 9110 §10.2.3) and a structured JSON body.</p>
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(RateLimitInterceptor.class);

    private final long verifyCapacity;
    private final Duration verifyRefill;
    private final long batchCapacity;
    private final Duration batchRefill;
    private final long registryCapacity;
    private final Duration registryRefill;

    private final ConcurrentHashMap<String, Bucket> verifyBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Bucket> batchBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Bucket> registryBuckets = new ConcurrentHashMap<>();

    public RateLimitInterceptor(
            @Value("${gatekeeper.ratelimit.verify.capacity:600}") long verifyCapacity,
            @Value("${gatekeeper.ratelimit.verify.refill-seconds:60}") long verifyRefillSeconds,
            @Value("${gatekeeper.ratelimit.batch.capacity:10}") long batchCapacity,
            @Value("${gatekeeper.ratelimit.batch.refill-seconds:60}") long batchRefillSeconds,
            @Value("${gatekeeper.ratelimit.registry.capacity:120}") long registryCapacity,
            @Value("${gatekeeper.ratelimit.registry.refill-seconds:60}") long registryRefillSeconds) {
        this.verifyCapacity = verifyCapacity;
        this.verifyRefill = Duration.ofSeconds(verifyRefillSeconds);
        this.batchCapacity = batchCapacity;
        this.batchRefill = Duration.ofSeconds(batchRefillSeconds);
        this.registryCapacity = registryCapacity;
        this.registryRefill = Duration.ofSeconds(registryRefillSeconds);

        log.info("RateLimitInterceptor initialised: verify={}/{}s, batch={}/{}s, registry={}/{}s",
                verifyCapacity, verifyRefillSeconds,
                batchCapacity, batchRefillSeconds,
                registryCapacity, registryRefillSeconds);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String path = request.getRequestURI();

        // Health and OpenAPI docs are exempt — they must remain reachable for
        // liveness probes and operator tooling even under load.
        if (path.endsWith("/health")
                || path.startsWith("/swagger-ui")
                || path.startsWith("/v3/api-docs")) {
            return true;
        }

        String principal = extractPrincipal(request);
        BucketSelection selection = selectBucket(path, principal);
        Bucket bucket = selection.bucket();

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (probe.isConsumed()) {
            response.setHeader("X-RateLimit-Remaining", String.valueOf(probe.getRemainingTokens()));
            return true;
        }

        long retryAfterSeconds = TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill());
        if (retryAfterSeconds < 1) {
            retryAfterSeconds = 1;
        }

        log.warn("Rate limit exceeded for principal='{}' on path='{}' (bucket={}); retry-after={}s",
                principal, path, selection.name(), retryAfterSeconds);

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setHeader("X-RateLimit-Remaining", "0");
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(
                "{\"error\":\"rate_limit_exceeded\","
              + "\"message\":\"Too many requests; see Retry-After header.\","
              + "\"bucket\":\"" + selection.name() + "\","
              + "\"retryAfterSeconds\":" + retryAfterSeconds + "}");
        return false;
    }

    private String extractPrincipal(HttpServletRequest request) {
        Principal p = request.getUserPrincipal();
        if (p != null && p.getName() != null && !p.getName().isBlank()) {
            return "mtls:" + p.getName();
        }
        // Fall back to remote address for unauthenticated reference-default
        // deployments. Still provides basic DoS protection.
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            // Use the leftmost entry (originating client) for rate limiting.
            return "ip:" + forwardedFor.split(",")[0].trim();
        }
        return "ip:" + request.getRemoteAddr();
    }

    private BucketSelection selectBucket(String path, String principal) {
        if (path.contains("/verify/batch")) {
            return new BucketSelection("batch", batchBuckets.computeIfAbsent(principal,
                    k -> Bucket.builder().addLimit(Bandwidth.builder().capacity(batchCapacity).refillGreedy(batchCapacity, batchRefill).build()).build()));
        }
        if (path.contains("/registry/")) {
            return new BucketSelection("registry", registryBuckets.computeIfAbsent(principal,
                    k -> Bucket.builder().addLimit(Bandwidth.builder().capacity(registryCapacity).refillGreedy(registryCapacity, registryRefill).build()).build()));
        }
        // Default: /verify and /confirm share the same per-principal bucket.
        return new BucketSelection("verify", verifyBuckets.computeIfAbsent(principal,
                k -> Bucket.builder().addLimit(Bandwidth.builder().capacity(verifyCapacity).refillGreedy(verifyCapacity, verifyRefill).build()).build()));
    }

    private record BucketSelection(String name, Bucket bucket) {}
}
