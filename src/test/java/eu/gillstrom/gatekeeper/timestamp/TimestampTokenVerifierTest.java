package eu.gillstrom.gatekeeper.timestamp;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** The three checks of {@link TimestampTokenVerifier}: imprint, signature, chain to trusted certificates. */
class TimestampTokenVerifierTest {

    private static TestTsa tsa;
    private static TestTsa otherTsa;
    private static final byte[] DATA = "ab".repeat(32).getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void tsas() throws Exception {
        tsa = new TestTsa();
        otherTsa = new TestTsa();
    }

    private static byte[] token(TestTsa t, byte[] data) throws Exception {
        return t.timestamp(MessageDigest.getInstance("SHA-256").digest(data));
    }

    @Test
    void aTokenFromTheTrustedTsaOverTheDataValidates() throws Exception {
        Instant before = Instant.now().minusSeconds(1);

        TimestampTokenVerifier.Verification v = tsa.verifier().verify(token(tsa, DATA), DATA);

        assertThat(v.valid()).isTrue();
        assertThat(v.imprintMatches()).isTrue();
        assertThat(v.signatureValid()).isTrue();
        assertThat(v.chainValid()).isTrue();
        assertThat(v.error()).isNull();
        assertThat(v.policyOid()).isEqualTo(TestTsa.POLICY);
        assertThat(v.tsaSubjectDn()).isEqualTo("CN=Test TSA");
        assertThat(Duration.between(before, v.genTime()).abs()).isLessThan(Duration.ofMinutes(1));
    }

    @Test
    void aTokenOverOtherDataIsRefusedOnTheImprint() throws Exception {
        TimestampTokenVerifier.Verification v = tsa.verifier().verify(token(tsa, DATA),
                "cd".repeat(32).getBytes(StandardCharsets.UTF_8));

        assertThat(v.valid()).isFalse();
        assertThat(v.imprintMatches()).isFalse();
    }

    @Test
    void aTokenFromAnUntrustedTsaIsRefusedOnTheChain() throws Exception {
        TimestampTokenVerifier.Verification v = tsa.verifier().verify(token(otherTsa, DATA), DATA);

        assertThat(v.valid()).isFalse();
        assertThat(v.imprintMatches()).isTrue();
        assertThat(v.signatureValid()).isTrue();
        assertThat(v.chainValid()).isFalse();
        assertThat(v.error()).contains("does not chain");
    }

    @Test
    void trustingTheTsaCertificateItselfIsEnough() throws Exception {
        TimestampTokenVerifier direct = new TimestampTokenVerifier(List.of(tsa.tsaCertificate()));

        assertThat(direct.verify(token(tsa, DATA), DATA).valid()).isTrue();
    }

    @Test
    void aTamperedTokenIsRefused() throws Exception {
        byte[] token = token(tsa, DATA);
        token[token.length - 10] ^= 0x01;

        TimestampTokenVerifier.Verification tampered = tsa.verifier().verify(token, DATA);
        assertThat(tampered.valid()).isFalse();
        assertThat(tampered.signatureValid()).isFalse();
        TimestampTokenVerifier.Verification garbage = tsa.verifier().verify(new byte[] {1, 2, 3}, DATA);
        assertThat(garbage.error()).contains("not a parseable");
        assertThat(garbage.signatureValid()).isFalse();
    }

    @Test
    void aTokenWithoutCertificatesNeedsTheTsaCertificateAmongTheTrustedOnes() throws Exception {
        TimeStampRequestGenerator g = new TimeStampRequestGenerator();
        g.setCertReq(false);
        TimeStampRequest request = g.generate(TSPAlgorithms.SHA256,
                MessageDigest.getInstance("SHA-256").digest(DATA), BigInteger.TEN);
        byte[] token = new TimeStampResponse(tsa.respond(request.getEncoded())).getTimeStampToken().getEncoded();

        TimestampTokenVerifier.Verification withoutSigner = tsa.verifier().verify(token, DATA);
        assertThat(withoutSigner.error()).contains("neither in the token nor among the trusted");
        assertThat(withoutSigner.signatureValid()).isFalse();
        assertThat(new TimestampTokenVerifier(List.of(tsa.root(), tsa.tsaCertificate())).verify(token, DATA).valid())
                .isTrue();
    }
}
