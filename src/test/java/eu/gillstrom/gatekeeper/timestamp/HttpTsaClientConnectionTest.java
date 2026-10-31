package eu.gillstrom.gatekeeper.timestamp;

import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * How {@link HttpTsaClient} uses its connection, observed through a connection
 * that never touches the network, and how it reads a {@code TimeStampResp}.
 */
class HttpTsaClientConnectionTest {

    private static TestTsa tsa;
    private static final byte[] IMPRINT = sha256("head");

    @BeforeAll
    static void startTsa() throws Exception {
        tsa = new TestTsa();
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Answers with {@code answer} applied to the request body it was sent. */
    static final class FakeConnection extends HttpURLConnection {
        final ByteArrayOutputStream sent = new ByteArrayOutputStream();
        int status = 200;
        UnaryOperator<byte[]> answer = body -> new byte[0];
        boolean disconnected;

        FakeConnection(URL url) {
            super(url);
        }

        @Override
        public void connect() {
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void disconnect() {
            disconnected = true;
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            if (!getDoOutput()) {
                throw new ProtocolException("cannot write output after reading input / doOutput is false");
            }
            return sent;
        }

        @Override
        public int getResponseCode() {
            return status;
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(answer.apply(sent.toByteArray()));
        }

        int fixedLength() {
            return fixedContentLength;
        }
    }

    private FakeConnection connection;

    private HttpTsaClient client(UnaryOperator<FakeConnection> setUp) {
        return new HttpTsaClient("https://tsa.test/tsr", null, 1000, 2000, url -> {
            connection = setUp.apply(new FakeConnection(url));
            return connection;
        });
    }

    private static byte[] respond(byte[] request) {
        try {
            return tsa.respond(request);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void oneUncachedFixedLengthPostWithoutRedirectsAndTheRfc3161MediaTypes() throws Exception {
        byte[] token = client(c -> {
            c.answer = HttpTsaClientConnectionTest::respond;
            return c;
        }).timestamp(IMPRINT);

        assertThat(token).isNotEmpty();
        assertThat(connection.getConnectTimeout()).isEqualTo(1000);
        assertThat(connection.getReadTimeout()).isEqualTo(2000);
        assertThat(connection.getInstanceFollowRedirects()).isFalse();
        assertThat(connection.getUseCaches()).isFalse();
        assertThat(connection.getDoOutput()).isTrue();
        assertThat(connection.getRequestMethod()).isEqualTo("POST");
        assertThat(connection.getRequestProperty("Content-Type")).isEqualTo("application/timestamp-query");
        assertThat(connection.getRequestProperty("Accept")).isEqualTo("application/timestamp-reply");
        assertThat(connection.fixedLength()).isEqualTo(connection.sent.size()).isPositive();
        assertThat(connection.disconnected).isTrue();
    }

    @Test
    void anotherStatusIsAnIoExceptionAndTheConnectionIsStillDisconnected() {
        assertThatThrownBy(() -> client(c -> {
            c.status = 503;
            return c;
        }).timestamp(IMPRINT)).isInstanceOf(IOException.class).hasMessageEndingWith("answered HTTP 503");
        assertThat(connection.disconnected).isTrue();
    }

    @Test
    void aResponseOfExactlyTheLimitIsReadAndOneByteMoreIsRefused() {
        byte[] atLimit = new byte[HttpTsaClient.MAX_RESPONSE_BYTES];
        assertThatThrownBy(() -> client(c -> {
            c.answer = body -> atLimit;
            return c;
        }).timestamp(IMPRINT)).isInstanceOf(IOException.class).hasMessageNotContaining("exceeds");

        assertThatThrownBy(() -> client(c -> {
            c.answer = body -> Arrays.copyOf(atLimit, atLimit.length + 1);
            return c;
        }).timestamp(IMPRINT)).isInstanceOf(IOException.class)
                .hasMessage("TSA response exceeds " + HttpTsaClient.MAX_RESPONSE_BYTES + " bytes");
    }

    @Test
    void aResponseToAnotherRequestDoesNotValidate() throws Exception {
        TimeStampRequestGenerator g = new TimeStampRequestGenerator();
        g.setCertReq(true);
        TimeStampRequest mine = g.generate(TSPAlgorithms.SHA256, IMPRINT, BigInteger.ONE);
        TimeStampRequest other = g.generate(TSPAlgorithms.SHA256, IMPRINT, BigInteger.TWO);

        assertThatThrownBy(() -> HttpTsaClient.tokenFrom(mine, tsa.respond(other.getEncoded())))
                .isInstanceOf(IOException.class)
                .hasMessageStartingWith("TSA response did not validate against the request");
    }

    @Test
    void aRefusalIsReportedWithItsStatusAndTextWhenThereIsOne() throws Exception {
        TimeStampRequest request = new TimeStampRequestGenerator().generate(TSPAlgorithms.SHA256, IMPRINT);
        byte[] withText = new TimeStampResp(new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText("unsupported")),
                null).getEncoded();
        byte[] withoutText = new TimeStampResp(new PKIStatusInfo(PKIStatus.rejection), null).getEncoded();

        assertThatThrownBy(() -> HttpTsaClient.tokenFrom(request, withText))
                .isInstanceOf(IOException.class).hasMessage("TSA refused the request: status=2 (unsupported)");
        assertThatThrownBy(() -> HttpTsaClient.tokenFrom(request, withoutText))
                .isInstanceOf(IOException.class).hasMessage("TSA refused the request: status=2");
    }

    @Test
    void bothTimeoutsMustBePositive() {
        assertThatThrownBy(() -> new HttpTsaClient("https://tsa.test", null, 0, 1))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("TSA timeouts must be > 0");
        assertThatThrownBy(() -> new HttpTsaClient("https://tsa.test", null, 1, 0))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("TSA timeouts must be > 0");
        new HttpTsaClient("https://tsa.test", null, 1, 1);
    }
}
