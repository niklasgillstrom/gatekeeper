package eu.gillstrom.gatekeeper.timestamp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * RFC 3161 client over HTTP (RFC 3161 §3.4): POSTs a DER
 * {@code TimeStampReq} as {@code application/timestamp-query} and expects a
 * DER {@code TimeStampResp} as {@code application/timestamp-reply}.
 *
 * <p>Every request asks for the TSA certificate ({@code certReq=true}) and
 * carries a fresh 64-bit nonce; when a policy OID is configured it is sent
 * as {@code reqPolicy}. The response is checked with BouncyCastle's
 * {@link TimeStampResponse#validate(TimeStampRequest)} — status, nonce,
 * message imprint and, if requested, policy — and anything other than
 * {@code granted} or {@code grantedWithMods} is an {@link IOException}.
 * The token's signature and certificate chain are not checked here; the
 * caller does that with {@link TimestampTokenVerifier}.</p>
 *
 * <p>Connect and read timeouts bound how long a single request can take.
 * The response body is read up to {@link #MAX_RESPONSE_BYTES}; a TSA that
 * sends more is treated as failing. Redirects are not followed.</p>
 */
public final class HttpTsaClient implements TsaClient {

    /** Upper bound on the TSA response body. Real responses are a few KiB. */
    static final int MAX_RESPONSE_BYTES = 1 << 20;

    private static final SecureRandom NONCE_RANDOM = new SecureRandom();

    /** Opens the connection for one request; tests substitute one that records how it is set up. */
    @FunctionalInterface
    interface ConnectionOpener {
        HttpURLConnection open(URL url) throws IOException;
    }

    private final URL url;
    private final ASN1ObjectIdentifier policyOid;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;
    private final ConnectionOpener opener;

    /**
     * @param tsaUrl {@code http} or {@code https} URL of the TSA
     * @param policyOid requested TSA policy, or {@code null} for the TSA default
     * @param connectTimeoutMillis connect timeout, &gt; 0
     * @param readTimeoutMillis read timeout, &gt; 0
     */
    public HttpTsaClient(String tsaUrl, String policyOid, int connectTimeoutMillis, int readTimeoutMillis) {
        this(tsaUrl, policyOid, connectTimeoutMillis, readTimeoutMillis, u -> (HttpURLConnection) u.openConnection());
    }

    HttpTsaClient(String tsaUrl, String policyOid, int connectTimeoutMillis, int readTimeoutMillis,
                  ConnectionOpener opener) {
        this.opener = Objects.requireNonNull(opener, "opener");
        Objects.requireNonNull(tsaUrl, "tsaUrl");
        try {
            URI uri = URI.create(tsaUrl.trim());
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                throw new IllegalArgumentException("TSA URL must be http or https: " + tsaUrl);
            }
            this.url = uri.toURL();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid TSA URL: " + tsaUrl, e);
        }
        this.policyOid = policyOid == null || policyOid.isBlank() ? null : new ASN1ObjectIdentifier(policyOid.trim());
        if (connectTimeoutMillis <= 0 || readTimeoutMillis <= 0) {
            throw new IllegalArgumentException("TSA timeouts must be > 0");
        }
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
    }

    @Override
    public byte[] timestamp(byte[] sha256Imprint) throws IOException {
        if (sha256Imprint == null || sha256Imprint.length != 32) {
            throw new IllegalArgumentException("SHA-256 imprint must be 32 bytes");
        }
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        if (policyOid != null) {
            generator.setReqPolicy(policyOid);
        }
        BigInteger nonce = new BigInteger(64, NONCE_RANDOM);
        TimeStampRequest request = generator.generate(TSPAlgorithms.SHA256, sha256Imprint, nonce);
        byte[] body = request.getEncoded();

        HttpURLConnection connection = opener.open(url);
        try {
            connection.setConnectTimeout(connectTimeoutMillis);
            connection.setReadTimeout(readTimeoutMillis);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/timestamp-query");
            connection.setRequestProperty("Accept", "application/timestamp-reply");
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(body);
            }
            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("TSA " + url + " answered HTTP " + status);
            }
            byte[] responseBytes;
            try (InputStream in = connection.getInputStream()) {
                responseBytes = readBounded(in);
            }
            return tokenFrom(request, responseBytes);
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Parse and check a {@code TimeStampResp} against the request it answers
     * and return the DER token. Package-private for tests.
     */
    static byte[] tokenFrom(TimeStampRequest request, byte[] responseBytes) throws IOException {
        try {
            TimeStampResponse response = new TimeStampResponse(responseBytes);
            response.validate(request);
            int status = response.getStatus();
            if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
                throw new IOException("TSA refused the request: status=" + status
                        + (response.getStatusString() == null ? "" : " (" + response.getStatusString() + ")"));
            }
            TimeStampToken token = response.getTimeStampToken();
            if (token == null) {
                throw new IOException("TSA response carries no token");
            }
            return token.getEncoded();
        } catch (TSPException e) {
            throw new IOException("TSA response did not validate against the request: " + e.getMessage(), e);
        } catch (IllegalArgumentException | ClassCastException e) {
            throw new IOException("TSA response could not be parsed: " + e.getMessage(), e);
        }
    }

    private static byte[] readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        byte[] buffer = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buffer)) != -1) {
            total += n;
            if (total > MAX_RESPONSE_BYTES) {
                throw new IOException("TSA response exceeds " + MAX_RESPONSE_BYTES + " bytes");
            }
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
}
