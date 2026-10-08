package eu.gillstrom.gatekeeper.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;

/** Request-level behaviour of the rate limiter: bucket choice, 429 response, key ceiling and sweep. */
class RateLimitInterceptorTest {

    /** verify 3, batch 1, registry 2, settlement 4, audit 5, all refilling over 60 s. */
    private static RateLimitInterceptor interceptor(int maxTrackedKeys, long keyIdleSeconds) {
        return new RateLimitInterceptor(3, 60, 1, 60, 2, 60, 4, 60, 5, 60,
                maxTrackedKeys, keyIdleSeconds, "");
    }

    private static MockHttpServletRequest request(String path, String peer) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.setRemoteAddr(peer);
        return request;
    }

    private record Outcome(boolean allowed, MockHttpServletResponse response) { }

    private static Outcome call(RateLimitInterceptor interceptor, MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean allowed = interceptor.preHandle(request, response, new Object());
        return new Outcome(allowed, response);
    }

    /** Calls until the first refusal and returns how many were allowed and the refusal. */
    private static int allowedBeforeRefusal(RateLimitInterceptor interceptor, String path, String peer,
                                            String expectedBucket) throws Exception {
        for (int n = 0; n < 50; n++) {
            Outcome outcome = call(interceptor, request(path, peer));
            if (!outcome.allowed()) {
                assertThat(outcome.response().getContentAsString())
                        .contains("\"bucket\":\"" + expectedBucket + "\"");
                return n;
            }
        }
        throw new AssertionError("no refusal on " + path);
    }

    @Test
    void eachPathFamilyDrawsOnItsOwnBucket() throws Exception {
        RateLimitInterceptor interceptor = interceptor(10_000, 900);

        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/verify", "192.0.2.1", "verify")).isEqualTo(3);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/verify/batch", "192.0.2.1", "batch")).isEqualTo(1);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/registry/x", "192.0.2.1", "registry")).isEqualTo(2);
        assertThat(allowedBeforeRefusal(interceptor, "/api/v1/verify", "192.0.2.1", "settlement")).isEqualTo(4);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/audit/range", "192.0.2.1", "audit")).isEqualTo(5);
        // /v1/gatekeeper shares the registry bucket, which is already empty.
        assertThat(allowedBeforeRefusal(interceptor, "/v1/gatekeeper/approval", "192.0.2.1", "registry")).isZero();
    }

    @Test
    void healthAndApiDocumentationAreNotLimited() throws Exception {
        RateLimitInterceptor interceptor = interceptor(10_000, 900);
        for (String path : new String[] {"/v1/attestation/health", "/swagger-ui/index.html", "/v3/api-docs"}) {
            for (int i = 0; i < 10; i++) {
                Outcome outcome = call(interceptor, request(path, "192.0.2.1"));
                assertThat(outcome.allowed()).as(path).isTrue();
                assertThat(outcome.response().getHeader("X-RateLimit-Remaining")).as(path).isNull();
            }
        }
    }

    @Test
    void anAllowedCallReportsTheRemainingTokensAndARefusalIsA429() throws Exception {
        RateLimitInterceptor interceptor = interceptor(10_000, 900);
        Outcome first = call(interceptor, request("/v1/attestation/verify", "192.0.2.1"));
        assertThat(first.allowed()).isTrue();
        assertThat(first.response().getHeader("X-RateLimit-Remaining")).isEqualTo("2");
        call(interceptor, request("/v1/attestation/verify", "192.0.2.1"));
        call(interceptor, request("/v1/attestation/verify", "192.0.2.1"));

        Outcome refused = call(interceptor, request("/v1/attestation/verify", "192.0.2.1"));

        assertThat(refused.allowed()).isFalse();
        MockHttpServletResponse response = refused.response();
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("X-RateLimit-Remaining")).isEqualTo("0");
        assertThat(response.getContentType()).isEqualTo("application/json;charset=UTF-8");
        // One token per 20 s (3 per 60 s): the wait is more than one second.
        long retryAfter = Long.parseLong(response.getHeader("Retry-After"));
        assertThat(retryAfter).isBetween(2L, 20L);
        assertThat(response.getContentAsString())
                .startsWith("{\"error\":\"rate_limit_exceeded\"")
                .contains("\"retryAfterSeconds\":" + retryAfter + "}");
    }

    @Test
    void aWaitBelowOneSecondIsReportedAsOneSecond() throws Exception {
        // 1 000 tokens per second: the next token is a millisecond away.
        RateLimitInterceptor interceptor = new RateLimitInterceptor(1_000, 1, 1, 60, 1, 60, 1, 60, 1, 60,
                10_000, 900, "");
        Outcome outcome;
        do {
            outcome = call(interceptor, request("/v1/attestation/verify", "192.0.2.1"));
        } while (outcome.allowed());
        assertThat(outcome.response().getHeader("Retry-After")).isEqualTo("1");
    }

    @Test
    void callersAreLimitedSeparatelyByCertificateAndByAddress() throws Exception {
        RateLimitInterceptor interceptor = interceptor(10_000, 900);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/verify", "192.0.2.1", "verify")).isEqualTo(3);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/verify", "192.0.2.2", "verify")).isEqualTo(3);

        MockHttpServletRequest withCertificate = request("/v1/attestation/verify", "192.0.2.1");
        Principal principal = () -> "CN=FI-Supervisor";
        withCertificate.setUserPrincipal(principal);
        assertThat(call(interceptor, withCertificate).allowed())
                .as("an mTLS principal has its own bucket even from an exhausted address").isTrue();
    }

    @Test
    void beyondTheKeyCeilingNewCallersShareOneOverflowBucket() throws Exception {
        RateLimitInterceptor interceptor = interceptor(1, 900);
        assertThat(call(interceptor, request("/v1/attestation/verify", "192.0.2.1")).allowed()).isTrue();

        // The map holds one key; the next three addresses share the overflow
        // bucket of three tokens, and the fourth is refused.
        for (int i = 2; i <= 4; i++) {
            assertThat(call(interceptor, request("/v1/attestation/verify", "192.0.2." + i)).allowed()).isTrue();
        }
        assertThat(call(interceptor, request("/v1/attestation/verify", "192.0.2.5")).allowed()).isFalse();
        // The tracked key still has its own bucket.
        assertThat(call(interceptor, request("/v1/attestation/verify", "192.0.2.1")).allowed()).isTrue();
    }

    @Test
    void idleKeysAreSweptSoTheCeilingFreesUp() throws Exception {
        RateLimitInterceptor interceptor = interceptor(1, 1);
        assertThat(call(interceptor, request("/v1/attestation/verify", "192.0.2.1")).allowed()).isTrue();

        Thread.sleep(1_200);

        // The idle key is swept, so 192.0.2.2 takes the free slot and the
        // overflow bucket is still full for the next two newcomers.
        assertThat(call(interceptor, request("/v1/attestation/verify", "192.0.2.2")).allowed()).isTrue();
        for (int i = 3; i <= 5; i++) {
            assertThat(call(interceptor, request("/v1/attestation/verify", "192.0.2." + i)).allowed())
                    .as("newcomer " + i).isTrue();
        }
        assertThat(call(interceptor, request("/v1/attestation/verify", "192.0.2.6")).allowed()).isFalse();
    }

    private static final long SECOND = 1_000_000_000L;

    /** One token per bucket, one tracked key, keys idle after 10 s, on a clock the test moves. */
    private static RateLimitInterceptor onClock(java.util.concurrent.atomic.AtomicLong clock) {
        return new RateLimitInterceptor(1, 60, 1, 60, 1, 60, 1, 60, 1, 60, 1, 10, "", clock::get);
    }

    private static boolean allowed(RateLimitInterceptor interceptor, String peer) throws Exception {
        return call(interceptor, request("/v1/attestation/verify", peer)).allowed();
    }

    @Test
    void theSweepRunsOnceTheIntervalHasPassedAndRemovesOnlyKeysIdleLongerThanTheLimit() throws Exception {
        java.util.concurrent.atomic.AtomicLong clock = new java.util.concurrent.atomic.AtomicLong(0);
        RateLimitInterceptor interceptor = onClock(clock);
        assertThat(allowed(interceptor, "192.0.2.1")).as("tracked key A").isTrue();

        clock.set(10 * SECOND - 1);
        assertThat(allowed(interceptor, "192.0.2.2")).as("before the interval: overflow").isTrue();
        assertThat(allowed(interceptor, "192.0.2.3")).as("overflow already spent").isFalse();

        clock.set(10 * SECOND);
        // The sweep runs, but A has been idle exactly the limit, not longer.
        assertThat(allowed(interceptor, "192.0.2.4")).as("A kept, so overflow").isFalse();

        clock.set(19 * SECOND);
        // Nine seconds after that sweep: no sweep yet, although A is now idle 19 s.
        assertThat(allowed(interceptor, "192.0.2.6")).as("no sweep before the interval").isFalse();

        clock.set(20 * SECOND);
        // Ten seconds after the last sweep it runs again; A, idle 20 s, goes.
        assertThat(allowed(interceptor, "192.0.2.5")).as("the freed slot").isTrue();
    }

    @Test
    void aKeyInUseSurvivesTheSweep() throws Exception {
        java.util.concurrent.atomic.AtomicLong clock = new java.util.concurrent.atomic.AtomicLong(0);
        RateLimitInterceptor interceptor = onClock(clock);
        assertThat(allowed(interceptor, "192.0.2.1")).isTrue();
        clock.set(5 * SECOND);
        assertThat(allowed(interceptor, "192.0.2.1")).as("A's own bucket is empty").isFalse();

        clock.set(15 * SECOND);
        // A was used 10 s ago: not idle beyond the limit, so the slot stays taken.
        assertThat(allowed(interceptor, "192.0.2.9")).as("overflow").isTrue();
        assertThat(allowed(interceptor, "192.0.2.10")).as("overflow spent").isFalse();
    }

    @Test
    void theOverflowWarningIsLoggedOnce() throws Exception {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(RateLimitInterceptor.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            RateLimitInterceptor interceptor = onClock(new java.util.concurrent.atomic.AtomicLong(0));
            for (int i = 1; i <= 4; i++) {
                allowed(interceptor, "192.0.2." + i);
            }
            assertThat(appender.list).filteredOn(e -> e.getFormattedMessage().contains("reached its ceiling"))
                    .hasSize(1);
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void theStartUpLogSaysWhichProxiesAreTrustedAndInvalidEntriesAreIgnored() throws Exception {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(RateLimitInterceptor.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            new RateLimitInterceptor(1, 60, 1, 60, 1, 60, 1, 60, 1, 60, 10, 900, "");
            assertThat(appender.list.get(appender.list.size() - 1).getFormattedMessage())
                    .endsWith("trustedProxies=(none — X-Forwarded-For ignored)");

            appender.list.clear();
            RateLimitInterceptor withProxies =
                    new RateLimitInterceptor(1, 60, 1, 60, 1, 60, 1, 60, 1, 60, 10, 900, "10.0.0.0/8, ,not-a-cidr");
            assertThat(appender.list).anySatisfy(e -> assertThat(e.getFormattedMessage())
                    .contains("'not-a-cidr' is not a valid IP or CIDR"));
            assertThat(appender.list.get(appender.list.size() - 1).getFormattedMessage())
                    .contains("trustedProxies=[").doesNotContain("(none");

            MockHttpServletRequest viaProxy = request("/v1/attestation/verify", "10.0.0.5");
            viaProxy.addHeader("X-Forwarded-For", "203.0.113.7");
            assertThat(withProxies.extractPrincipal(viaProxy)).isEqualTo("ip:203.0.113.7");
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void aTrustedPeerWithoutAClientBehindItIsKeyedByItsOwnAddress() {
        RateLimitInterceptor interceptor =
                new RateLimitInterceptor(1, 60, 1, 60, 1, 60, 1, 60, 1, 60, 10, 900, "10.0.0.0/8");
        MockHttpServletRequest noHeader = request("/v1/attestation/verify", "10.0.0.5");
        assertThat(interceptor.extractPrincipal(noHeader)).isEqualTo("ip:10.0.0.5");

        MockHttpServletRequest onlyProxies = request("/v1/attestation/verify", "10.0.0.5");
        onlyProxies.addHeader("X-Forwarded-For", "10.0.0.9, 10.0.0.8");
        assertThat(interceptor.extractPrincipal(onlyProxies)).isEqualTo("ip:10.0.0.5");

        MockHttpServletRequest blankHeader = request("/v1/attestation/verify", "10.0.0.5");
        blankHeader.addHeader("X-Forwarded-For", " ");
        assertThat(interceptor.extractPrincipal(blankHeader)).isEqualTo("ip:10.0.0.5");
    }

    @Test
    void aRequestWithoutAPeerAddressIsKeyedAsUnknown() {
        RateLimitInterceptor interceptor = interceptor(10, 900);
        assertThat(interceptor.extractPrincipal(request("/v1/attestation/verify", null))).isEqualTo("ip:unknown");
        assertThat(interceptor.extractPrincipal(request("/v1/attestation/verify", " "))).isEqualTo("ip:unknown");
    }
}
