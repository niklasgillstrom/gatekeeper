package eu.gillstrom.gatekeeper.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Rejects HTTP requests whose body exceeds
 * {@code gatekeeper.limits.max-http-request-size}.
 *
 * <h2>Why this is a filter and not a property</h2>
 *
 * <p>Spring Boot has no {@code server.max-http-request-size}. It has
 * {@code server.max-http-request-header-size} (headers only),
 * {@code spring.servlet.multipart.max-request-size} (multipart only) and
 * {@code server.tomcat.max-http-form-post-size} (form-encoded bodies only).
 * None of the three bounds a JSON body, which is every request this
 * gatekeeper accepts. {@code PEER_REVIEW_GUIDE.md} already named the
 * remedy — "add a servlet filter that rejects requests with Content-Length
 * above a deployment-specific cap" — and this is that filter, with the cap
 * exposed as configuration so a deployment can size it.</p>
 *
 * <h2>Two paths</h2>
 *
 * <ol>
 *   <li><strong>Declared length.</strong> When {@code Content-Length} is
 *       present and above the cap, the request is rejected with 413 before
 *       a single body byte is read. This is the case for every ordinary
 *       client.</li>
 *   <li><strong>Chunked / undeclared length.</strong> When the length is
 *       unknown, the body stream is wrapped and counted, and the read fails
 *       once the cap is passed. The status in that case is whatever the
 *       container makes of an {@link IOException} mid-parse (typically 400
 *       or a dropped connection) rather than a clean 413 — by the time we
 *       know the size, the response may already be committed. The guarantee
 *       is the memory bound, not the status code.</li>
 * </ol>
 *
 * <p>The default cap of 2 MB is set against the field limits in
 * {@code VerificationRequest}: the largest single legitimate request is a
 * batch of attestations, each dominated by a ≤256 KiB attestation blob, and
 * a caller needing more than 2 MB should be splitting the batch — which
 * {@code VerificationController.MAX_BATCH_SIZE} already requires of them.</p>
 */
@Component
public class RequestSizeLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestSizeLimitFilter.class);

    private final long maxBytes;

    public RequestSizeLimitFilter(
            @Value("${gatekeeper.limits.max-http-request-size:2MB}") String maxRequestSize) {
        // Parsed here rather than bound as a DataSize so the property works
        // identically whether or not the ApplicationConversionService is in
        // play (it is not, for example, in a standalone filter unit test).
        this.maxBytes = DataSize.parse(maxRequestSize).toBytes();
        if (this.maxBytes <= 0) {
            throw new IllegalArgumentException(
                    "gatekeeper.limits.max-http-request-size must be positive, got " + maxRequestSize);
        }
        log.info("RequestSizeLimitFilter initialised: request bodies capped at {} bytes ({})",
                this.maxBytes, maxRequestSize);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        long declared = request.getContentLengthLong();

        if (declared > maxBytes) {
            log.warn("Rejecting request to {} : declared Content-Length {} exceeds cap {}",
                    request.getRequestURI(), declared, maxBytes);
            response.setStatus(HttpStatus.CONTENT_TOO_LARGE.value());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"error\":\"request_too_large\","
                  + "\"message\":\"Request body exceeds the configured maximum.\","
                  + "\"maxBytes\":" + maxBytes + "}");
            return;
        }

        if (declared >= 0) {
            // Length declared and within the cap; nothing to police.
            filterChain.doFilter(request, response);
            return;
        }

        // Undeclared length (chunked transfer encoding). Count as we read.
        filterChain.doFilter(new LimitedBodyRequest(request, maxBytes), response);
    }

    /** Raised when a chunked body passes the cap mid-read. */
    static class RequestBodyTooLargeException extends IOException {
        RequestBodyTooLargeException(long maxBytes) {
            super("Request body exceeded the configured maximum of " + maxBytes + " bytes");
        }
    }

    /**
     * Request wrapper whose body stream aborts once {@code maxBytes} have
     * been read. Only installed for requests with no {@code Content-Length}.
     */
    private static final class LimitedBodyRequest extends HttpServletRequestWrapper {

        private final long maxBytes;
        private ServletInputStream stream;
        private BufferedReader reader;

        LimitedBodyRequest(HttpServletRequest request, long maxBytes) {
            super(request);
            this.maxBytes = maxBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new CountingServletInputStream(super.getInputStream(), maxBytes);
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (reader == null) {
                String encoding = getCharacterEncoding();
                Charset charset = encoding == null
                        ? StandardCharsets.UTF_8
                        : Charset.forName(encoding);
                reader = new BufferedReader(new InputStreamReader(getInputStream(), charset));
            }
            return reader;
        }
    }

    /**
     * {@link ServletInputStream} that throws once more than {@code maxBytes}
     * have been read from the delegate.
     */
    private static final class CountingServletInputStream extends ServletInputStream {

        private final ServletInputStream delegate;
        private final long maxBytes;
        private long read;

        CountingServletInputStream(ServletInputStream delegate, long maxBytes) {
            this.delegate = delegate;
            this.maxBytes = maxBytes;
        }

        private void account(long n) throws IOException {
            read += Math.max(n, 0); // -1 is end of stream
            if (read > maxBytes) {
                log.warn("Aborting chunked request: body passed the {}-byte cap", maxBytes);
                throw new RequestBodyTooLargeException(maxBytes);
            }
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();
            if (b != -1) {
                account(1);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = delegate.read(b, off, len);
            account(n);
            return n;
        }

        @Override
        public int available() throws IOException {
            return delegate.available();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            delegate.setReadListener(readListener);
        }
    }
}
