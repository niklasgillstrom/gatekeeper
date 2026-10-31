package eu.gillstrom.gatekeeper.timestamp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

/**
 * RFC 3161 time-stamping of the audit log ({@code gatekeeper.timestamping.*}).
 *
 * <h2>Modes</h2>
 * <ul>
 *   <li>{@code off} (default) — no TSA is contacted. Nothing changes.</li>
 *   <li>{@code entry} — after each audit entry is signed,
 *       {@link eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog} asks for a
 *       token over SHA-256 of the entry's signature input (the UTF-8 bytes of
 *       {@code thisEntryHashHex}), validates it, and stores it on the entry as
 *       {@code timestampTokenBase64}, outside the hash. A TSA failure leaves
 *       the entry without a token; the entry is still written.</li>
 *   <li>{@code anchor} — {@link TimestampAnchorService} periodically asks for a
 *       token over the current chain head's {@code thisEntryHashHex} and
 *       appends {@code {headSequenceNumber, headHashHex, tokenBase64,
 *       genTime}} to the anchor file.</li>
 * </ul>
 *
 * <h2>Fail-closed configuration</h2>
 *
 * <p>With {@code entry} or {@code anchor}, start-up fails unless
 * {@code tsa-url} is an http(s) URL, {@code trusted-certs-path} holds at least
 * one certificate, {@code hash-algorithm} is SHA-256, the policy OID (if set)
 * parses, the timeouts are positive and, for {@code anchor}, the interval is
 * positive. An unknown mode also fails start-up. YAML 1.1 reads an unquoted
 * {@code off} as boolean {@code false}; {@code false} and an empty value are
 * therefore also {@code off}.</p>
 *
 * <p>When {@code trusted-certs-path} is set — in any mode — the audit chain
 * check validates every token it finds (entry tokens and anchor records).
 * When it is not set there is nothing to validate against, and tokens found
 * on disk are not checked.</p>
 */
@Component
public class AuditTimestamping {

    private static final Logger log = LoggerFactory.getLogger(AuditTimestamping.class);

    /** Time-stamping mode. */
    public enum Mode {
        OFF, ENTRY, ANCHOR;

        static Mode parse(String raw) {
            String v = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
            return switch (v) {
                case "", "off", "false", "none" -> OFF;
                case "entry" -> ENTRY;
                case "anchor" -> ANCHOR;
                default -> throw new IllegalStateException(
                        "gatekeeper.timestamping.mode must be off, entry or anchor, got '" + raw + "'");
            };
        }

        public String label() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    private final Mode mode;
    private final TsaClient client;
    private final TimestampTokenVerifier verifier;
    private final TimestampAnchorStore anchorStore;
    private final long anchorIntervalSeconds;

    @Autowired
    public AuditTimestamping(
            @Value("${gatekeeper.timestamping.mode:off}") String mode,
            @Value("${gatekeeper.timestamping.tsa-url:}") String tsaUrl,
            @Value("${gatekeeper.timestamping.hash-algorithm:SHA-256}") String hashAlgorithm,
            @Value("${gatekeeper.timestamping.policy-oid:}") String policyOid,
            @Value("${gatekeeper.timestamping.connect-timeout-ms:5000}") int connectTimeoutMs,
            @Value("${gatekeeper.timestamping.read-timeout-ms:10000}") int readTimeoutMs,
            @Value("${gatekeeper.timestamping.trusted-certs-path:}") String trustedCertsPath,
            @Value("${gatekeeper.timestamping.anchor-interval-seconds:3600}") long anchorIntervalSeconds,
            @Value("${gatekeeper.timestamping.anchor-path:${gatekeeper.audit.path:./audit-log.jsonl}.tsa-anchors.jsonl}")
            String anchorPath) {
        this.mode = Mode.parse(mode);
        String alg = hashAlgorithm == null ? "" : hashAlgorithm.trim().toUpperCase(Locale.ROOT);
        if (!alg.equals("SHA-256") && !alg.equals("SHA256")) {
            throw new IllegalStateException("gatekeeper.timestamping.hash-algorithm must be SHA-256, got '"
                    + hashAlgorithm + "'");
        }
        boolean active = this.mode != Mode.OFF;
        if (active && (tsaUrl == null || tsaUrl.isBlank())) {
            throw new IllegalStateException("gatekeeper.timestamping.mode=" + this.mode.label()
                    + " requires gatekeeper.timestamping.tsa-url");
        }
        if (active && (trustedCertsPath == null || trustedCertsPath.isBlank())) {
            throw new IllegalStateException("gatekeeper.timestamping.mode=" + this.mode.label()
                    + " requires gatekeeper.timestamping.trusted-certs-path (PEM of the TSA certificate or its CA)");
        }
        if (this.mode == Mode.ANCHOR && anchorIntervalSeconds <= 0) {
            throw new IllegalStateException("gatekeeper.timestamping.anchor-interval-seconds must be > 0");
        }
        try {
            this.client = active ? new HttpTsaClient(tsaUrl, policyOid, connectTimeoutMs, readTimeoutMs) : null;
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("gatekeeper.timestamping: " + e.getMessage(), e);
        }
        try {
            this.verifier = trustedCertsPath == null || trustedCertsPath.isBlank()
                    ? null
                    : TimestampTokenVerifier.fromPemFile(Paths.get(trustedCertsPath.trim()));
        } catch (IOException e) {
            throw new IllegalStateException("gatekeeper.timestamping.trusted-certs-path: " + e.getMessage(), e);
        }
        this.anchorIntervalSeconds = anchorIntervalSeconds;
        this.anchorStore = loadAnchorStore(anchorPath, this.mode, this.verifier);
        if (active) {
            log.info("AuditTimestamping: mode={}, tsa-url={}, policy-oid={}, trusted TSA certificates={}, "
                            + "connect/read timeout={}ms/{}ms{}",
                    this.mode.label(), tsaUrl, policyOid == null || policyOid.isBlank() ? "(TSA default)" : policyOid,
                    verifier.trustedCertificates().size(), connectTimeoutMs, readTimeoutMs,
                    this.mode == Mode.ANCHOR ? ", anchor interval=" + anchorIntervalSeconds + "s, anchor file="
                            + anchorStore.path().toAbsolutePath() : "");
        }
    }

    /**
     * Test and composition constructor.
     *
     * @param anchorPath anchor file; may be {@code null} when not in
     *     {@code anchor} mode and no anchors are to be checked
     */
    public AuditTimestamping(Mode mode, TsaClient client, TimestampTokenVerifier verifier, Path anchorPath,
                             long anchorIntervalSeconds) {
        this.mode = mode;
        if (mode != Mode.OFF && (client == null || verifier == null)) {
            throw new IllegalStateException("mode " + mode.label() + " requires a TSA client and a verifier");
        }
        this.client = client;
        this.verifier = verifier;
        this.anchorIntervalSeconds = anchorIntervalSeconds;
        this.anchorStore = anchorPath == null ? null : loadAnchorStore(anchorPath.toString(), mode, verifier);
    }

    /** No time-stamping, no token validation. */
    public static AuditTimestamping off() {
        return new AuditTimestamping(Mode.OFF, null, null, null, 0);
    }

    private static TimestampAnchorStore loadAnchorStore(String anchorPath, Mode mode, TimestampTokenVerifier verifier) {
        // The anchor file is only touched when anchors are produced or can be
        // validated; in the default configuration nothing is read or created.
        if (anchorPath == null || anchorPath.isBlank() || (mode != Mode.ANCHOR && verifier == null)) {
            return null;
        }
        TimestampAnchorStore store = new TimestampAnchorStore(Paths.get(anchorPath));
        try {
            store.load();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load timestamp anchor file " + anchorPath + ": "
                    + e.getMessage(), e);
        }
        return store;
    }

    public Mode mode() {
        return mode;
    }

    public long anchorIntervalSeconds() {
        return anchorIntervalSeconds;
    }

    /** Validator for stored tokens, present when trusted TSA certificates are configured. */
    public Optional<TimestampTokenVerifier> verifier() {
        return Optional.ofNullable(verifier);
    }

    /** The anchor file, present in {@code anchor} mode or when tokens can be validated. */
    public Optional<TimestampAnchorStore> anchorStore() {
        return Optional.ofNullable(anchorStore);
    }

    /**
     * Obtain and validate a token over SHA-256 of {@code thisEntryHashHex}'s
     * UTF-8 bytes. Never throws: any TSA, transport or validation failure is
     * logged at WARN and returns empty, so the caller can carry on without a
     * token.
     */
    public Optional<Token> timestampHashHex(String thisEntryHashHex) {
        if (mode == Mode.OFF || client == null) {
            return Optional.empty();
        }
        byte[] data = thisEntryHashHex.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] imprint = MessageDigest.getInstance("SHA-256").digest(data);
            byte[] token = client.timestamp(imprint);
            TimestampTokenVerifier.Verification v = verifier.verify(token, data);
            if (!v.valid()) {
                log.warn("AuditTimestamping: TSA token for {} rejected: {}", thisEntryHashHex, v.error());
                return Optional.empty();
            }
            return Optional.of(new Token(Base64.getEncoder().encodeToString(token), v.genTime()));
        } catch (Exception e) {
            log.warn("AuditTimestamping: no TSA token for {}: {}", thisEntryHashHex, e.toString());
            return Optional.empty();
        }
    }

    /** A validated token and its {@code genTime}. */
    public record Token(String tokenBase64, Instant genTime) {
    }
}
