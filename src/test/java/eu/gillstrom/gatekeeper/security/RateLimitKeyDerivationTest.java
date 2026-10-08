package eu.gillstrom.gatekeeper.security;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Rate-limit bucket key derivation.
 *
 * <p>The key used to be the leftmost entry of {@code X-Forwarded-For},
 * taken from any caller, and stored in a map that was never evicted from.
 * A client could therefore mint an unbounded number of buckets by varying
 * a header it writes itself — evading the limit and growing the map at the
 * same time. These tests pin the corrected behaviour: the header is ignored
 * unless the direct peer is a configured trusted proxy, and even then only
 * the portion of the chain our own proxies wrote is believed.</p>
 */
class RateLimitKeyDerivationTest {

    private static RateLimitInterceptor interceptorTrusting(String trustedProxies) {
        return new RateLimitInterceptor(
                600, 60,   // verify
                10, 60,    // batch
                120, 60,   // registry
                6000, 60,  // settlement
                120, 60,   // audit
                10_000,    // max tracked keys
                900,       // key idle seconds
                trustedProxies);
    }

    private static HttpServletRequest request(String remoteAddr, String forwardedFor) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn(remoteAddr);
        when(request.getHeader("X-Forwarded-For")).thenReturn(forwardedFor);
        return request;
    }

    @Test
    void forwardedForIsIgnoredWhenNoProxyIsTrusted() {
        RateLimitInterceptor interceptor = interceptorTrusting("");

        String key = interceptor.extractPrincipal(request("10.0.0.7", "203.0.113.5"));

        assertThat(key).isEqualTo("ip:10.0.0.7");
    }

    @Test
    void forwardedForIsIgnoredWhenThePeerIsNotATrustedProxy() {
        RateLimitInterceptor interceptor = interceptorTrusting("10.0.0.0/8");

        String key = interceptor.extractPrincipal(request("198.51.100.9", "203.0.113.5"));

        assertThat(key).isEqualTo("ip:198.51.100.9");
    }

    @Test
    void forwardedForIsBelievedWhenThePeerIsATrustedProxy() {
        RateLimitInterceptor interceptor = interceptorTrusting("10.0.0.0/8");

        String key = interceptor.extractPrincipal(request("10.0.0.7", "203.0.113.5"));

        assertThat(key).isEqualTo("ip:203.0.113.5");
    }

    @Test
    void chainIsWalkedRightToLeftSkippingOurOwnProxies() {
        RateLimitInterceptor interceptor = interceptorTrusting("10.0.0.0/8");

        // The client claimed 1.1.1.1; our edge proxy then appended the address
        // it actually saw (203.0.113.5) and our inner proxy appended 10.0.0.3.
        // Only the first non-proxy entry from the right is trustworthy.
        String key = interceptor.extractPrincipal(
                request("10.0.0.7", "1.1.1.1, 203.0.113.5, 10.0.0.3"));

        assertThat(key).isEqualTo("ip:203.0.113.5");
    }

    @Test
    void nonIpForwardedForFallsBackToThePeerAddress() {
        RateLimitInterceptor interceptor = interceptorTrusting("10.0.0.0/8");

        String key = interceptor.extractPrincipal(
                request("10.0.0.7", "unknown-host-name-not-an-ip"));

        assertThat(key).isEqualTo("ip:10.0.0.7");
    }

    @Test
    void mtlsPrincipalTakesPrecedenceOverAnyHeader() {
        RateLimitInterceptor interceptor = interceptorTrusting("10.0.0.0/8");
        HttpServletRequest request = request("10.0.0.7", "203.0.113.5");
        Principal principal = mock(Principal.class);
        when(principal.getName()).thenReturn("FI-Supervisor");
        when(request.getUserPrincipal()).thenReturn(principal);

        assertThat(interceptor.extractPrincipal(request)).isEqualTo("mtls:FI-Supervisor");
    }

    @Test
    void normaliseIpAcceptsOnlyIpLiterals() {
        assertThat(RateLimitInterceptor.normaliseIp("192.0.2.1")).isEqualTo("192.0.2.1");
        assertThat(RateLimitInterceptor.normaliseIp("192.0.2.1:8443")).isEqualTo("192.0.2.1");
        assertThat(RateLimitInterceptor.normaliseIp("[2001:db8::1]:443")).isEqualTo("2001:db8::1");
        assertThat(RateLimitInterceptor.normaliseIp("2001:db8::1")).isEqualTo("2001:db8::1");

        assertThat(RateLimitInterceptor.normaliseIp("example.com")).isNull();
        assertThat(RateLimitInterceptor.normaliseIp("999.0.2.1")).isNull();
        assertThat(RateLimitInterceptor.normaliseIp("")).isNull();
        assertThat(RateLimitInterceptor.normaliseIp(null)).isNull();
        // An attacker-supplied key must not be able to be arbitrarily long.
        assertThat(RateLimitInterceptor.normaliseIp("1".repeat(200))).isNull();
    }

    @Test
    void normaliseIpBoundaries() {
        // 255 is the largest octet, and an IPv6 literal may start with a colon.
        assertThat(RateLimitInterceptor.normaliseIp("255.255.255.255")).isEqualTo("255.255.255.255");
        assertThat(RateLimitInterceptor.normaliseIp("256.0.0.1")).isNull();
        assertThat(RateLimitInterceptor.normaliseIp("::1")).isEqualTo("::1");
        assertThat(RateLimitInterceptor.normaliseIp("[::1]:443")).isEqualTo("::1");
        // A bare port is not an address.
        assertThat(RateLimitInterceptor.normaliseIp(":80")).isNull();
        assertThat(RateLimitInterceptor.normaliseIp("[2001:db8::1")).isNull();
        // The 64-character cap, at the boundary: a bracketed literal plus trailing text.
        String literal = "::" + "a".repeat(43);
        String atCap = "[" + literal + "]" + "x".repeat(64 - 47);
        assertThat(atCap).hasSize(64);
        assertThat(RateLimitInterceptor.normaliseIp(atCap)).isEqualTo(literal);
        assertThat(RateLimitInterceptor.normaliseIp(atCap + "x")).isNull();
    }
}
