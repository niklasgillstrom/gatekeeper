package eu.gillstrom.gatekeeper.timestamp;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An entry's RFC 3161 token must have been issued at the entry's own time.
 *
 * <p>Until 1.7.0 the chain check asked only whether a token was valid for
 * the entry's hash. Whoever held the log-signing key could therefore write
 * the chain again with other content, sign it, have every entry time-stamped
 * anew by the same TSA, and pass the check — although the external time
 * stamp is what is meant to hold against the key holder. A new token is
 * valid for the new hash; what gives it away is its {@code genTime}, the
 * time of the rewrite and not of the entry.</p>
 */
class EntryTokenTimeTest {

    private static final Duration TOLERANCE = Duration.ofSeconds(AuditTimestamping.DEFAULT_ENTRY_TOKEN_TOLERANCE_SECONDS);

    @TempDir
    Path tempDir;

    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

    private static AuditTimestamping entryMode(TestTsa tsa, Duration tolerance) {
        return new AuditTimestamping(AuditTimestamping.Mode.ENTRY, tsa, tsa.verifier(), null, 0, tolerance);
    }

    private AppendOnlyFileAuditLog open(Path file, AuditTimestamping ts) {
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(file.toString(), signer, 0, null, ts);
        log.initialise();
        return log;
    }

    private static AuditAppendRequest request(String id, boolean compliant) {
        return new AuditAppendRequest("CN=fe", "VERIFY", id, "cmVx", null, compliant);
    }

    /**
     * What the holder of the signing key can do to the file: every entry
     * written again as compliant with its original timestamp, hashed, linked
     * and signed, and time-stamped by an ordinary request to the TSA.
     */
    private void writeAgainAsCompliant(Path file, List<AuditEntry> original, AuditTimestamping ts) throws Exception {
        ObjectMapper json = new ObjectMapper().registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .setSerializationInclusion(JsonInclude.Include.ALWAYS);
        StringBuilder rewritten = new StringBuilder();
        String prev = AuditEntry.SENTINEL_PREV_HASH_HEX;
        for (AuditEntry o : original) {
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                    AuditEntry.canonicalBytesForHashV2(o.sequenceNumber(), o.timestamp(), o.mtlsClientPrincipal(),
                            o.operation(), o.verificationId(), o.requestDigestBase64(), o.receiptDigestBase64(),
                            true, prev, o.keyFingerprintHex(), o.certSerialHex(), o.certIssuerDn(),
                            o.hsmVendor(), o.hsmSerial(), o.registryStatus(), o.hsmFirmwareVersion(),
                            o.hsmFipsApprovedMode(), o.prevKeyEntryHashHex())));
            String signature = Base64.getEncoder().encodeToString(
                    signer.sign(AuditEntry.canonicalBytesForSignature(hash)));
            String token = ts.timestampHashHex(hash).orElseThrow().tokenBase64();
            rewritten.append(json.writeValueAsString(new AuditEntry(o.sequenceNumber(), o.timestamp(),
                    o.mtlsClientPrincipal(), o.operation(), o.verificationId(), o.requestDigestBase64(),
                    o.receiptDigestBase64(), true, prev, hash, signature, AuditEntry.CANONICAL_V2,
                    o.keyFingerprintHex(), o.certSerialHex(), o.certIssuerDn(), o.hsmVendor(), o.hsmSerial(),
                    o.registryStatus(), o.hsmFirmwareVersion(), o.hsmFipsApprovedMode(),
                    o.prevKeyEntryHashHex(), token))).append('\n');
            prev = hash;
        }
        Files.writeString(file, rewritten.toString(), StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
    }

    @Test
    void aChainWrittenAgainLaterCannotBeTimeStampedAnew() throws Exception {
        TestTsa tsa = new TestTsa();
        Path file = tempDir.resolve("written-again.jsonl");
        AuditTimestamping ts = entryMode(tsa, TOLERANCE);
        AppendOnlyFileAuditLog log = open(file, ts);
        List<AuditEntry> original = List.of(log.append(request("v-1", false)), log.append(request("v-2", false)),
                log.append(request("v-3", false)));
        assertThat(log.verifyChainIntegrity()).isTrue();

        // Written again at once, the result is a chain like any other: the
        // new tokens are of the entries' time, within the tolerance.
        writeAgainAsCompliant(file, original, ts);
        AppendOnlyFileAuditLog atOnce = open(file, entryMode(tsa, TOLERANCE));
        assertThat(atOnce.findByVerificationId("v-1").orElseThrow().compliant()).isTrue();
        assertThat(atOnce.verifyChainIntegrity()).isTrue();

        // Written again later, the new tokens carry the time of the rewrite.
        tsa.clockOffsetMillis.set(TOLERANCE.toMillis() + 60_000);
        writeAgainAsCompliant(file, original, ts);

        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        warnings.start();
        Logger logger = (Logger) LoggerFactory.getLogger(AppendOnlyFileAuditLog.class);
        logger.addAppender(warnings);
        try {
            AppendOnlyFileAuditLog later = open(file, entryMode(tsa, TOLERANCE));
            assertThat(later.findByVerificationId("v-1").orElseThrow().compliant()).isTrue();
            assertThat(later.untimestampedEntryCount()).as("every entry has a token valid for its hash").hasValue(0);
            assertThat(later.verifyChainIntegrity()).isFalse();
            assertThat(warnings.list).anyMatch(e -> e.getLevel() == Level.WARN && e.getFormattedMessage()
                    .startsWith("AuditLog chain check failed: timestamp token of entry sequenceNumber 1 was issued at ")
                    && e.getFormattedMessage().contains("more than 300s from the entry's timestamp "
                            + original.get(0).timestamp()));
        } finally {
            logger.detachAppender(warnings);
        }

        // Nothing else is wrong with that chain: under a tolerance that
        // covers the delay it verifies.
        assertThat(open(file, entryMode(tsa, TOLERANCE.plusSeconds(120))).verifyChainIntegrity()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(longs = {30_000, -30_000})
    void aTokenThatIsNotOfTheEntrysTimeIsNotStored(long tsaClockOffsetMillis) throws Exception {
        TestTsa tsa = new TestTsa();
        AuditTimestamping ts = entryMode(tsa, Duration.ofSeconds(5));
        AppendOnlyFileAuditLog log = open(tempDir.resolve("skewed.jsonl"), ts);

        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        warnings.start();
        Logger logger = (Logger) LoggerFactory.getLogger(AuditTimestamping.class);
        logger.addAppender(warnings);
        AuditEntry skewed;
        try {
            tsa.clockOffsetMillis.set(tsaClockOffsetMillis);
            skewed = log.append(request("v-1", true));
        } finally {
            logger.detachAppender(warnings);
        }
        tsa.clockOffsetMillis.set(0);
        AuditEntry timely = log.append(request("v-2", true));

        assertThat(tsa.requests.get()).isEqualTo(2);
        assertThat(skewed.timestampTokenBase64()).isNull();
        assertThat(warnings.list).anyMatch(e -> e.getLevel() == Level.WARN && e.getFormattedMessage()
                .startsWith("AuditTimestamping: TSA token for " + skewed.thisEntryHashHex() + " not stored: its genTime ")
                && e.getFormattedMessage().contains("is more than 5s from the entry's timestamp " + skewed.timestamp()));
        assertThat(timely.timestampTokenBase64()).isNotNull();
        assertThat(log.untimestampedEntryCount()).hasValue(1);
        assertThat(log.verifyChainIntegrity()).isTrue();
    }

    @Test
    void theToleranceIsInclusiveAndTheSameInBothDirections() {
        AuditTimestamping ts = new AuditTimestamping(AuditTimestamping.Mode.OFF, null, null, null, 0,
                Duration.ofSeconds(300));
        Instant written = Instant.parse("2026-11-09T12:00:00Z");

        assertThat(ts.isEntryTime(written, written)).isTrue();
        assertThat(ts.isEntryTime(written, written.plusSeconds(300))).isTrue();
        assertThat(ts.isEntryTime(written, written.plusSeconds(300).plusMillis(1))).isFalse();
        assertThat(ts.isEntryTime(written, written.minusSeconds(300))).isTrue();
        assertThat(ts.isEntryTime(written, written.minusSeconds(300).minusMillis(1))).isFalse();
        assertThat(ts.isEntryTime(written, null)).as("a token without a readable genTime").isFalse();
    }

    @Test
    void withoutTimeStampingThereIsNoEntryTokenAndTheDefaultToleranceApplies() {
        AuditTimestamping off = AuditTimestamping.off();

        assertThat(off.timestampEntry("ab".repeat(32), Instant.now())).isEmpty();
        assertThat(off.entryTokenTolerance()).isEqualTo(Duration.ofSeconds(300));
    }
}
