package eu.gillstrom.gatekeeper.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.handler.MappedInterceptor;
import org.springframework.web.util.ServletRequestPathUtils;

import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The endpoints added with the evidence chain (anchor time-stamps, COSE
 * export) and with the key lifecycle (lifecycle events, triangulation) are
 * covered by the rate-limit registration and draw on the documented buckets:
 * {@code /v1/gatekeeper/anchor/timestamps} on {@code registry},
 * {@code /v1/audit/export?format=cose} on {@code audit},
 * {@code /v1/attestation/{cc}/lifecycle} on {@code lifecycle} and every
 * {@code /v1/triangulation/**} path on {@code audit}.
 */
class RateLimitNewEndpointsTest {

    private static final String[][] PATHS = {
            {"GET", "/v1/gatekeeper/anchor/timestamps", "registry"},
            {"GET", "/v1/audit/export", "audit"},
            {"POST", "/v1/attestation/SE/lifecycle", "lifecycle"},
            {"POST", "/v1/triangulation/SE/inquiries", "audit"},
            {"POST", "/v1/triangulation/SE/inquiries/i-1/bank-reports", "audit"},
            {"POST", "/v1/triangulation/SE/inquiries/i-1/operator-report", "audit"},
            {"GET", "/v1/triangulation/SE/inquiries/i-1/discrepancies", "audit"},
            {"DELETE", "/v1/triangulation/SE/inquiries/i-1", "audit"}};

    /** One token per bucket, so the second request on a path names the bucket it was refused by. */
    private static RateLimitInterceptor oneTokenEach() {
        return new RateLimitInterceptor(1, 60, 1, 60, 1, 60, 1, 60, 1, 60, 1, 60, 10_000, 900, "",
                System::nanoTime);
    }

    private static MockHttpServletResponse call(RateLimitInterceptor interceptor, String method, String path)
            throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        if (path.equals("/v1/audit/export")) {
            request.setParameter("format", "cose");
        }
        request.setRemoteAddr("192.0.2.9");
        MockHttpServletResponse response = new MockHttpServletResponse();
        interceptor.preHandle(request, response, new Object());
        return response;
    }

    @Test
    void eachNewEndpointDrawsOnItsDocumentedBucket() throws Exception {
        for (String[] p : PATHS) {
            RateLimitInterceptor interceptor = oneTokenEach();
            assertThat(call(interceptor, p[0], p[1]).getStatus()).as(p[1] + " first call").isEqualTo(200);
            MockHttpServletResponse refused = call(interceptor, p[0], p[1]);
            assertThat(refused.getStatus()).as(p[1] + " second call").isEqualTo(429);
            assertThat(refused.getContentAsString()).as(p[1]).contains("\"bucket\":\"" + p[2] + "\"");
        }
    }

    @Test
    void theRegistrationCoversEveryNewEndpoint() throws Exception {
        RateLimitInterceptor interceptor = oneTokenEach();
        InterceptorRegistry registry = new InterceptorRegistry();
        new RateLimitConfig(interceptor).addInterceptors(registry);
        Method getInterceptors = InterceptorRegistry.class.getDeclaredMethod("getInterceptors");
        getInterceptors.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Object> registered = (List<Object>) getInterceptors.invoke(registry);
        assertThat(registered).hasSize(1);
        MappedInterceptor mapped = (MappedInterceptor) registered.get(0);
        assertThat(mapped.getInterceptor()).isSameAs((HandlerInterceptor) interceptor);

        for (String[] p : PATHS) {
            MockHttpServletRequest request = new MockHttpServletRequest(p[0], p[1]);
            ServletRequestPathUtils.parseAndCache(request);
            assertThat(mapped.matches(request)).as(p[1]).isTrue();
        }
        MockHttpServletRequest outside = new MockHttpServletRequest("GET", "/not-an-endpoint");
        ServletRequestPathUtils.parseAndCache(outside);
        assertThat(mapped.matches(outside)).isFalse();
    }
}
