package eu.gillstrom.gatekeeper.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** The {@code lifecycle} bucket, and triangulation under the {@code audit} bucket. */
class RateLimitLifecycleBucketTest {

    private static int allowedBeforeRefusal(RateLimitInterceptor interceptor, String path, String expectedBucket)
            throws Exception {
        for (int n = 0; n < 50; n++) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
            request.setRemoteAddr("192.0.2.7");
            MockHttpServletResponse response = new MockHttpServletResponse();
            if (!interceptor.preHandle(request, response, new Object())) {
                assertThat(response.getContentAsString()).contains("\"bucket\":\"" + expectedBucket + "\"");
                return n;
            }
        }
        throw new AssertionError("no refusal on " + path);
    }

    @Test
    void lifecycleEventsDrawOnTheirOwnBucketAndTriangulationOnTheAuditBucket() throws Exception {
        // verify 3, batch 1, registry 2, settlement 4, audit 5, lifecycle 6.
        RateLimitInterceptor interceptor = new RateLimitInterceptor(3, 60, 1, 60, 2, 60, 4, 60, 5, 60, 6, 60,
                10_000, 900, "", System::nanoTime);

        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/SE/lifecycle", "lifecycle")).isEqualTo(6);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/SE/verify", "verify"))
                .as("the verify bucket is untouched by lifecycle events").isEqualTo(3);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/triangulation/SE/inquiries", "audit")).isEqualTo(5);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/audit/range", "audit"))
                .as("shared with triangulation, already empty").isZero();
    }

    @Test
    void withoutLifecycleLimitsTheLifecycleBucketTakesTheVerifyLimits() throws Exception {
        RateLimitInterceptor interceptor = new RateLimitInterceptor(3, 60, 1, 60, 2, 60, 4, 60, 5, 60,
                10_000, 900, "");

        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/SE/lifecycle", "lifecycle")).isEqualTo(3);
        assertThat(allowedBeforeRefusal(interceptor, "/v1/attestation/SE/verify", "verify")).isEqualTo(3);
    }
}
