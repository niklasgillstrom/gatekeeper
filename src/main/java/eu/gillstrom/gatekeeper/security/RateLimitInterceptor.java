package eu.gillstrom.gatekeeper.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.security.Principal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * Token-bucket rate limiter for the gatekeeper API.
 *
 * <p>Per-principal buckets are keyed by the authenticated mTLS client
 * identifier extracted from {@link HttpServletRequest#getUserPrincipal()}.
 * Unauthenticated requests fall back to a bucket keyed by remote IP so the
 * reference-default (mTLS disabled) still gets a usable default
 * protection.</p>
 *
 * <p>Bucket selection is per path family. The verify-batch endpoint is
 * assigned a separate, stricter bucket by default because a single request
 * can exercise the full verification pipeline for dozens of entities — a
 * naïve uniform limit would either let batch abuse the per-request bucket or
 * throttle interactive single-entity use. The settlement endpoint
 * ({@code POST /api/v1/verify}) gets its own, much larger bucket because it
 * sits in the payment path and a limit sized for supervisory traffic would
 * stall settlement.</p>
 *
 * <h2>Two defects corrected after independent review</h2>
 *
 * <p><strong>Coverage.</strong> The interceptor used to be registered only
 * on {@code /v1/attestation/**}, so {@code /api/v1/verify} and
 * {@code /v1/audit/**} were entirely unlimited. See {@link RateLimitConfig}
 * for the registration; this class now also carries bucket selections for
 * those two families.</p>
 *
 * <p><strong>Key derivation and unbounded growth.</strong> The bucket key
 * for unauthenticated callers used to be the leftmost entry of an
 * unvalidated {@code X-Forwarded-For} header, stored in a
 * {@link ConcurrentHashMap} that was never evicted from. Both halves of
 * that are attacker-controlled: any client could mint an unlimited number
 * of distinct keys by varying a header it writes itself, which both evaded
 * the limit and grew the map without bound. Now:</p>
 * <ul>
 *   <li>{@code X-Forwarded-For} is consulted only when the direct peer
 *       ({@link HttpServletRequest#getRemoteAddr()}) matches
 *       {@code gatekeeper.ratelimit.trusted-proxies}, which is <em>empty by
 *       default</em>. With no trusted proxy configured the header is ignored
 *       outright and the peer address is the key.</li>
 *   <li>Even when trusted, the header is walked right-to-left and the first
 *       entry that is not itself a trusted proxy is taken as the client —
 *       entries to the left of it are forgeable by the client and are
 *       discarded. The value must parse as an IP literal, the chain is read
 *       at most {@link #MAX_FORWARDED_FOR_ENTRIES} deep, and anything that
 *       fails either check falls back to the peer address.</li>
 *   <li>Each bucket map is bounded at
 *       {@code gatekeeper.ratelimit.max-tracked-keys} entries and sweeps
 *       keys idle for longer than
 *       {@code gatekeeper.ratelimit.key-idle-seconds}. At the ceiling, new
 *       keys share one overflow bucket rather than allocating: memory stays
 *       bounded and the degradation is a throttle, not an OOM.</li>
 * </ul>
 *
 * <p>All limits are configurable via Spring properties (see
 * {@code application-nca.yaml} for the production profile). Exceeding a
 * bucket returns HTTP 429 Too Many Requests with a {@code Retry-After}
 * header in seconds (RFC 9110 §10.2.3) and a structured JSON body.</p>
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(RateLimitInterceptor.class);

    /**
     * Upper bound on how many {@code X-Forwarded-For} entries are parsed.
     * A proxy chain deeper than this is not a deployment we support, and
     * without the bound a single header could cost arbitrary CPU per
     * request.
     */
    private static final int MAX_FORWARDED_FOR_ENTRIES = 20;

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9A-Fa-f:]{2,45}$");

    private final BucketStore verifyBuckets;
    private final BucketStore batchBuckets;
    private final BucketStore registryBuckets;
    private final BucketStore settlementBuckets;
    private final BucketStore auditBuckets;

    private final List<IpAddressMatcher> trustedProxies;

    @Autowired
    public RateLimitInterceptor(
            @Value("${gatekeeper.ratelimit.verify.capacity:600}") long verifyCapacity,
            @Value("${gatekeeper.ratelimit.verify.refill-seconds:60}") long verifyRefillSeconds,
            @Value("${gatekeeper.ratelimit.batch.capacity:10}") long batchCapacity,
            @Value("${gatekeeper.ratelimit.batch.refill-seconds:60}") long batchRefillSeconds,
            @Value("${gatekeeper.ratelimit.registry.capacity:120}") long registryCapacity,
            @Value("${gatekeeper.ratelimit.registry.refill-seconds:60}") long registryRefillSeconds,
            @Value("${gatekeeper.ratelimit.settlement.capacity:6000}") long settlementCapacity,
            @Value("${gatekeeper.ratelimit.settlement.refill-seconds:60}") long settlementRefillSeconds,
            @Value("${gatekeeper.ratelimit.audit.capacity:120}") long auditCapacity,
            @Value("${gatekeeper.ratelimit.audit.refill-seconds:60}") long auditRefillSeconds,
            @Value("${gatekeeper.ratelimit.max-tracked-keys:10000}") int maxTrackedKeys,
            @Value("${gatekeeper.ratelimit.key-idle-seconds:900}") long keyIdleSeconds,
            @Value("${gatekeeper.ratelimit.trusted-proxies:}") String trustedProxyList) {
        this(verifyCapacity, verifyRefillSeconds, batchCapacity, batchRefillSeconds,
                registryCapacity, registryRefillSeconds, settlementCapacity, settlementRefillSeconds,
                auditCapacity, auditRefillSeconds, maxTrackedKeys, keyIdleSeconds, trustedProxyList,
                System::nanoTime);
    }

    /** As above, with the clock the key sweep reads; tests pass a controllable one. */
    RateLimitInterceptor(long verifyCapacity, long verifyRefillSeconds, long batchCapacity,
                         long batchRefillSeconds, long registryCapacity, long registryRefillSeconds,
                         long settlementCapacity, long settlementRefillSeconds, long auditCapacity,
                         long auditRefillSeconds, int maxTrackedKeys, long keyIdleSeconds,
                         String trustedProxyList, LongSupplier nanoClock) {

        this.verifyBuckets = new BucketStore("verify", verifyCapacity,
                Duration.ofSeconds(verifyRefillSeconds), maxTrackedKeys, keyIdleSeconds, nanoClock);
        this.batchBuckets = new BucketStore("batch", batchCapacity,
                Duration.ofSeconds(batchRefillSeconds), maxTrackedKeys, keyIdleSeconds, nanoClock);
        this.registryBuckets = new BucketStore("registry", registryCapacity,
                Duration.ofSeconds(registryRefillSeconds), maxTrackedKeys, keyIdleSeconds, nanoClock);
        this.settlementBuckets = new BucketStore("settlement", settlementCapacity,
                Duration.ofSeconds(settlementRefillSeconds), maxTrackedKeys, keyIdleSeconds, nanoClock);
        this.auditBuckets = new BucketStore("audit", auditCapacity,
                Duration.ofSeconds(auditRefillSeconds), maxTrackedKeys, keyIdleSeconds, nanoClock);

        this.trustedProxies = parseTrustedProxies(trustedProxyList);

        log.info("RateLimitInterceptor initialised: verify={}/{}s, batch={}/{}s, registry={}/{}s, "
                + "settlement={}/{}s, audit={}/{}s; maxTrackedKeys={}, keyIdleSeconds={}, "
                + "trustedProxies={}",
                verifyCapacity, verifyRefillSeconds,
                batchCapacity, batchRefillSeconds,
                registryCapacity, registryRefillSeconds,
                settlementCapacity, settlementRefillSeconds,
                auditCapacity, auditRefillSeconds,
                maxTrackedKeys, keyIdleSeconds,
                trustedProxies.isEmpty() ? "(none — X-Forwarded-For ignored)" : trustedProxies);
    }

    private static List<IpAddressMatcher> parseTrustedProxies(String raw) {
        List<IpAddressMatcher> matchers = new ArrayList<>();
        // Blank tokens are skipped below, so an empty list needs no special case.
        for (String token : raw.split(",")) {
            String cidr = token.trim();
            if (cidr.isEmpty()) {
                continue;
            }
            try {
                matchers.add(new IpAddressMatcher(cidr));
            } catch (IllegalArgumentException e) {
                // Fail loudly but keep booting: a typo in one CIDR must not
                // take the gatekeeper down, and the remaining entries still
                // give the intended (narrower) trust set.
                log.error("gatekeeper.ratelimit.trusted-proxies: '{}' is not a valid IP or CIDR "
                        + "and is ignored. X-Forwarded-For from that peer will NOT be trusted. cause={}",
                        cidr, e.toString());
            }
        }
        return List.copyOf(matchers);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String path = request.getRequestURI();

        // Liveness and OpenAPI docs are exempt — they must remain reachable
        // for liveness probes and operator tooling even under load.
        //
        // The exemption used to be `path.endsWith("/health")`, which also
        // exempted /v1/gatekeeper/health. That endpoint is not a liveness
        // probe: it reads the audit chain and reports its integrity, so it
        // was the one unauthenticated, unlimited endpoint that did real
        // work per call. It is now authenticated (SUPERVISOR) and limited.
        // Only the trivial /v1/attestation/health, which returns a constant
        // string, remains exempt.
        if (path.equals("/v1/attestation/health")
                || path.startsWith("/swagger-ui")
                || path.startsWith("/v3/api-docs")) {
            return true;
        }

        String principal = extractPrincipal(request);
        BucketStore store = selectStore(path);
        Bucket bucket = store.bucketFor(principal);

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (probe.isConsumed()) {
            response.setHeader("X-RateLimit-Remaining", String.valueOf(probe.getRemainingTokens()));
            return true;
        }

        long retryAfterSeconds = Math.max(1, TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()));

        log.warn("Rate limit exceeded for principal='{}' on path='{}' (bucket={}); retry-after={}s",
                principal, path, store.name(), retryAfterSeconds);

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setHeader("X-RateLimit-Remaining", "0");
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(
                "{\"error\":\"rate_limit_exceeded\","
              + "\"message\":\"Too many requests; see Retry-After header.\","
              + "\"bucket\":\"" + store.name() + "\","
              + "\"retryAfterSeconds\":" + retryAfterSeconds + "}");
        return false;
    }

    /**
     * Derive the bucket key for this request.
     *
     * <p>An mTLS principal always wins: it is asserted by a certificate the
     * gatekeeper's truststore validated, so it is neither forgeable nor
     * unbounded. Only when there is no principal do we fall back to the
     * network address, and only then does {@code X-Forwarded-For} come into
     * play at all.</p>
     */
    String extractPrincipal(HttpServletRequest request) {
        Principal p = request.getUserPrincipal();
        if (p != null && p.getName() != null && !p.getName().isBlank()) {
            return "mtls:" + p.getName();
        }
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr == null || remoteAddr.isBlank()) {
            // No peer address at all (should not happen over TCP). One shared
            // bucket is the safe answer; it cannot be split by an attacker.
            return "ip:unknown";
        }
        String forwarded = clientFromForwardedFor(request, remoteAddr);
        return "ip:" + (forwarded != null ? forwarded : remoteAddr);
    }

    /**
     * Resolve the originating client from {@code X-Forwarded-For}, or
     * {@code null} if the header must not be trusted for this peer.
     *
     * <p>The chain is walked right-to-left. Entries appended by our own
     * trusted proxies are skipped; the first entry that is not a trusted
     * proxy is the closest address we have any reason to believe. Everything
     * further left was written by something upstream of our trust boundary
     * and is assumed forged.</p>
     */
    private String clientFromForwardedFor(HttpServletRequest request, String remoteAddr) {
        if (trustedProxies.isEmpty() || !isTrustedProxy(remoteAddr)) {
            return null;
        }
        String header = request.getHeader("X-Forwarded-For");
        if (header == null || header.isBlank()) {
            return null;
        }
        String[] parts = header.split(",");
        int start = Math.max(0, parts.length - MAX_FORWARDED_FOR_ENTRIES);
        for (int i = parts.length - 1; i >= start; i--) {
            String candidate = normaliseIp(parts[i].trim());
            if (candidate == null) {
                // A non-IP entry means the chain is malformed from here
                // leftwards; stop rather than keep scanning attacker text.
                return null;
            }
            if (!isTrustedProxy(candidate)) {
                return candidate;
            }
        }
        // Every entry in the (bounded) chain was one of our own proxies.
        return null;
    }

    private boolean isTrustedProxy(String address) {
        for (IpAddressMatcher matcher : trustedProxies) {
            if (matcher.matches(address)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Accept only IP literals, so that a bucket key can never be an
     * arbitrary attacker-chosen string and never triggers a DNS lookup.
     * Strips an {@code :port} suffix from IPv4 and the brackets from
     * {@code [::1]:443}. Returns {@code null} for anything else.
     */
    static String normaliseIp(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > 64) {
            return null;
        }
        String v = raw;
        if (v.startsWith("[")) {
            int close = v.indexOf(']');
            if (close == -1) {
                return null;
            }
            v = v.substring(1, close);
        } else {
            int colon = v.indexOf(':');
            if (colon >= 0 && v.indexOf(':', colon + 1) == -1) {
                // Exactly one colon: IPv4 with a port.
                v = v.substring(0, colon);
            }
        }
        if (IPV4.matcher(v).matches()) {
            for (String octet : v.split("\\.")) {
                if (Integer.parseInt(octet) > 255) {
                    return null;
                }
            }
            return v;
        }
        if (v.indexOf(':') >= 0 && IPV6.matcher(v).matches()) {
            return v;
        }
        return null;
    }

    private BucketStore selectStore(String path) {
        if (path.contains("/verify/batch")) {
            return batchBuckets;
        }
        if (path.startsWith("/api/v1")) {
            // Settlement-rail traffic: /api/v1/verify and anything added
            // alongside it later. Sits in the payment path, so its ceiling is
            // an order of magnitude above the supervisory buckets.
            return settlementBuckets;
        }
        if (path.startsWith("/v1/audit")) {
            return auditBuckets;
        }
        if (path.startsWith("/v1/gatekeeper")) {
            // /keys, /anchor and /health. Supervisory-shaped reads: /anchor
            // signs the head on every call and /health reads the chain, so
            // they belong under a limit, and the registry bucket is the one
            // sized for supervisory read volume. No sixth bucket is
            // introduced — five is what the deployment configures.
            return registryBuckets;
        }
        if (path.contains("/registry/")) {
            return registryBuckets;
        }
        // Default: /verify and /confirm share the same per-principal bucket.
        return verifyBuckets;
    }

    /**
     * A bounded map of per-key token buckets.
     *
     * <p>Two mechanisms keep it bounded. A periodic sweep drops keys that
     * have not been seen for {@code idleNanos} — under normal traffic this
     * alone keeps the map at roughly the number of active callers. If the map
     * still reaches {@code maxKeys} (the flooding case), no further keys are
     * allocated and everything new shares {@link #overflowBucket}. That
     * ceiling is the point: a caller who can mint keys can then only degrade
     * service for other unrecognised callers, and cannot consume memory.</p>
     */
    private static final class BucketStore {

        private final String name;
        private final long capacity;
        private final Duration refill;
        private final int maxKeys;
        private final long idleNanos;
        private final long sweepIntervalNanos;

        private final ConcurrentHashMap<String, Holder> map = new ConcurrentHashMap<>();
        private final Bucket overflowBucket;
        private final LongSupplier clock;
        private final AtomicLong lastSweepNanos;
        private final java.util.concurrent.atomic.AtomicBoolean overflowWarned =
                new java.util.concurrent.atomic.AtomicBoolean();

        BucketStore(String name, long capacity, Duration refill, int maxKeys, long keyIdleSeconds,
                    LongSupplier clock) {
            this.clock = clock;
            this.lastSweepNanos = new AtomicLong(clock.getAsLong());
            this.name = name;
            this.capacity = capacity;
            this.refill = refill;
            this.maxKeys = Math.max(1, maxKeys);
            this.idleNanos = TimeUnit.SECONDS.toNanos(Math.max(1, keyIdleSeconds));
            // Sweep at most once a minute, and never less often than the idle
            // window itself, so a short idle setting still takes effect.
            this.sweepIntervalNanos = Math.min(this.idleNanos, TimeUnit.SECONDS.toNanos(60));
            this.overflowBucket = newBucket();
        }

        String name() {
            return name;
        }

        Bucket bucketFor(String key) {
            long now = clock.getAsLong();
            Holder existing = map.get(key);
            if (existing != null) {
                existing.lastAccessNanos = now;
                return existing.bucket;
            }
            maybeSweep(now);
            if (map.size() >= maxKeys) {
                if (overflowWarned.compareAndSet(false, true)) {
                    log.warn("Rate-limit bucket map '{}' reached its ceiling of {} keys. "
                            + "New keys now share a single overflow bucket. This is the "
                            + "expected response to key flooding; if it happens under "
                            + "legitimate load, raise gatekeeper.ratelimit.max-tracked-keys.",
                            name, maxKeys);
                }
                return overflowBucket;
            }
            Holder holder = map.computeIfAbsent(key, k -> new Holder(newBucket(), now));
            holder.lastAccessNanos = now;
            return holder.bucket;
        }

        private void maybeSweep(long now) {
            long last = lastSweepNanos.get();
            if (now - last < sweepIntervalNanos) {
                return;
            }
            if (!lastSweepNanos.compareAndSet(last, now)) {
                // Another thread is sweeping; one sweep per interval is enough.
                return;
            }
            map.entrySet().removeIf(e -> now - e.getValue().lastAccessNanos > idleNanos);
        }

        private Bucket newBucket() {
            return Bucket.builder()
                    .addLimit(Bandwidth.builder()
                            .capacity(capacity)
                            .refillGreedy(capacity, refill)
                            .build())
                    .build();
        }

        /** Bucket plus a coarse last-access stamp used only by the sweep. */
        private static final class Holder {
            private final Bucket bucket;
            private volatile long lastAccessNanos;

            Holder(Bucket bucket, long lastAccessNanos) {
                this.bucket = bucket;
                this.lastAccessNanos = lastAccessNanos;
            }
        }
    }
}
