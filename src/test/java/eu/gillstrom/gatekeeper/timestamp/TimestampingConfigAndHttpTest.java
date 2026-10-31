package eu.gillstrom.gatekeeper.timestamp;

import com.sun.net.httpserver.HttpServer;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link HttpTsaClient} against a TSA served over real HTTP
 * ({@link HttpServer} on the loopback interface), the Spring-property
 * constructor of {@link AuditTimestamping}, and its fail-closed checks.
 */
class TimestampingConfigAndHttpTest {

    @TempDir
    Path tempDir;

    private static TestTsa tsa;
    private HttpServer server;
    private String url;
    private final AtomicInteger status = new AtomicInteger(200);
    private final AtomicInteger delayMillis = new AtomicInteger(0);
    private final AtomicReference<String> seenContentType = new AtomicReference<>();

    @BeforeAll
    static void createTsa() throws Exception {
        tsa = new TestTsa();
    }

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/tsa", exchange -> {
            try (InputStream in = exchange.getRequestBody()) {
                byte[] request = in.readAllBytes();
                seenContentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
                if (delayMillis.get() > 0) {
                    Thread.sleep(delayMillis.get());
                }
                byte[] body = status.get() == 200 ? tsa.respond(request) : "no".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/timestamp-reply");
                exchange.sendResponseHeaders(status.get(), body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        });
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort() + "/tsa";
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private static byte[] sha256(String s) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void aTokenIsObtainedOverHttpAndValidates() throws Exception {
        HttpTsaClient client = new HttpTsaClient(url, "1.3.6.1.4.1.99999.7", 2000, 2000);

        byte[] token = client.timestamp(sha256("ab".repeat(32)));

        assertThat(seenContentType.get()).isEqualTo("application/timestamp-query");
        TimestampTokenVerifier.Verification v = tsa.verifier().verify(token,
                "ab".repeat(32).getBytes(StandardCharsets.UTF_8));
        assertThat(v.valid()).isTrue();
        assertThat(v.policyOid()).as("the requested policy").isEqualTo("1.3.6.1.4.1.99999.7");
        assertThat(new TimeStampToken(new org.bouncycastle.cms.CMSSignedData(token)).getCertificates()
                .getMatches(null)).as("certReq=true").isNotEmpty();
    }

    @Test
    void anHttpErrorOrASlowTsaIsAnIOException() throws Exception {
        status.set(503);
        assertThatThrownBy(() -> new HttpTsaClient(url, null, 2000, 2000).timestamp(sha256("x")))
                .isInstanceOf(IOException.class).hasMessageContaining("HTTP 503");

        status.set(200);
        delayMillis.set(1500);
        assertThatThrownBy(() -> new HttpTsaClient(url, null, 2000, 200).timestamp(sha256("x")))
                .isInstanceOf(IOException.class);
    }

    @Test
    void theAuditLogTimestampsEntriesThroughTheConfiguredHttpTsa() throws Exception {
        Path trust = tsa.writeTrustPem(tempDir.resolve("tsa-trust.pem"));
        Path audit = tempDir.resolve("audit.jsonl");
        AuditTimestamping ts = new AuditTimestamping("entry", url, "SHA-256", "", 2000, 5000, trust.toString(), 3600,
                audit + ".tsa-anchors.jsonl");
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(audit.toString(), new EphemeralReceiptSigner(2048),
                0, null, ts);
        log.initialise();

        AuditEntry e = log.append(new AuditAppendRequest("CN=fe", "VERIFY", "v-1", "cmVx", null, true));

        assertThat(e.timestampTokenBase64()).isNotNull();
        assertThat(tsa.verifier().verify(Base64.getDecoder().decode(e.timestampTokenBase64()),
                e.thisEntryHashHex().getBytes(StandardCharsets.UTF_8)).valid()).isTrue();
        assertThat(log.verifyChainIntegrity()).isTrue();
        assertThat(Files.exists(Path.of(audit + ".tsa-anchors.jsonl"))).as("entry mode writes no anchor file").isFalse();
    }

    private AuditTimestamping configured(String mode, String tsaUrl, String alg, String trust, long interval) {
        return new AuditTimestamping(mode, tsaUrl, alg, "", 1000, 1000, trust, interval,
                tempDir.resolve("a.jsonl.tsa-anchors.jsonl").toString());
    }

    @Test
    void offIsTheDefaultAndTouchesNothing() {
        for (String off : new String[] {"off", "OFF", "false", "", " "}) {
            AuditTimestamping ts = configured(off, "", "SHA-256", "", 0);
            assertThat(ts.mode()).isEqualTo(AuditTimestamping.Mode.OFF);
            assertThat(ts.verifier()).isEmpty();
            assertThat(ts.anchorStore()).isEmpty();
            assertThat(ts.timestampHashHex("ab".repeat(32))).isEmpty();
        }
    }

    @Test
    void misconfigurationStopsStartUp() throws Exception {
        String trust = tsa.writeTrustPem(tempDir.resolve("trust.pem")).toString();
        assertThatThrownBy(() -> configured("sometimes", url, "SHA-256", trust, 60))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("off, entry or anchor");
        assertThatThrownBy(() -> configured("entry", "", "SHA-256", trust, 60))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("requires gatekeeper.timestamping.tsa-url");
        assertThatThrownBy(() -> configured("anchor", url, "SHA-256", "", 60))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("trusted-certs-path");
        assertThatThrownBy(() -> configured("entry", url, "SHA-1", trust, 60))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("must be SHA-256");
        assertThatThrownBy(() -> configured("anchor", url, "SHA-256", trust, 0))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("anchor-interval-seconds");
        assertThatThrownBy(() -> configured("entry", "ftp://tsa.example", "SHA-256", trust, 60))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("http or https");
        assertThatThrownBy(() -> configured("entry", url, "SHA-256", tempDir.resolve("none.pem").toString(), 60))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("trusted-certs-path");
        Path empty = tempDir.resolve("empty.pem");
        Files.writeString(empty, "", StandardCharsets.UTF_8);
        assertThatThrownBy(() -> configured("entry", url, "SHA-256", empty.toString(), 60))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("No certificate");
        assertThatThrownBy(() -> new AuditTimestamping("entry", url, "SHA-256", "not-an-oid", 1000, 1000, trust, 60,
                tempDir.resolve("b").toString()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void trustedCertificatesAloneEnableValidationWithoutContactingATsa() throws Exception {
        String trust = tsa.writeTrustPem(tempDir.resolve("trust-only.pem")).toString();

        AuditTimestamping ts = configured("off", "", "SHA-256", trust, 0);

        assertThat(ts.mode()).isEqualTo(AuditTimestamping.Mode.OFF);
        assertThat(ts.verifier()).isPresent();
        assertThat(ts.anchorStore()).as("anchors on disk can be checked").isPresent();
        assertThat(ts.timestampHashHex("ab".repeat(32))).isEmpty();
    }
}
