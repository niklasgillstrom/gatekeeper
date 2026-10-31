package eu.gillstrom.gatekeeper.timestamp;

import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * {@code gatekeeper.timestamping.mode=anchor}: time-stamps the audit-chain
 * head at a fixed interval and appends the result to the anchor file.
 *
 * <p>The first attempt runs at start-up (on the scheduler thread, not the
 * start-up thread) and then every {@code anchor-interval-seconds}. An attempt
 * is skipped when the log is empty or when the head is the one the latest
 * anchor already covers. A TSA failure is logged at WARN and leaves no
 * record; the next attempt tries again. In any other mode this bean starts no
 * thread.</p>
 */
@Component
public class TimestampAnchorService {

    private static final Logger log = LoggerFactory.getLogger(TimestampAnchorService.class);

    private final AuditLog auditLog;
    private final AuditTimestamping timestamping;
    private ScheduledExecutorService scheduler;

    public TimestampAnchorService(AuditLog auditLog, AuditTimestamping timestamping) {
        this.auditLog = auditLog;
        this.timestamping = timestamping;
    }

    @PostConstruct
    public void start() {
        if (timestamping.mode() != AuditTimestamping.Mode.ANCHOR) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "gatekeeper-tsa-anchor");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::anchorQuietly, 0, timestamping.anchorIntervalSeconds(),
                TimeUnit.SECONDS);
    }

    @PreDestroy
    public void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    private void anchorQuietly() {
        try {
            anchorNow();
        } catch (Exception e) {
            // A scheduled task that throws is never run again.
            log.warn("TimestampAnchorService: anchor attempt failed: {}", e.toString());
        }
    }

    /**
     * Time-stamp the current head now. Returns the new record, or empty when
     * the mode is not {@code anchor}, the log is empty, the head is already
     * anchored, or the TSA did not deliver a valid token.
     */
    public synchronized Optional<TimestampAnchorRecord> anchorNow() throws java.io.IOException {
        if (timestamping.mode() != AuditTimestamping.Mode.ANCHOR || timestamping.anchorStore().isEmpty()) {
            return Optional.empty();
        }
        TimestampAnchorStore store = timestamping.anchorStore().get();
        Optional<AuditEntry> headOpt = auditLog.head();
        if (headOpt.isEmpty()) {
            return Optional.empty();
        }
        AuditEntry head = headOpt.get();
        Optional<TimestampAnchorRecord> last = store.latest();
        if (last.isPresent() && last.get().headSequenceNumber() == head.sequenceNumber()
                && MessageDigest.isEqual(last.get().headHashHex().getBytes(StandardCharsets.UTF_8),
                        head.thisEntryHashHex().getBytes(StandardCharsets.UTF_8))) {
            return Optional.empty();
        }
        Optional<AuditTimestamping.Token> token = timestamping.timestampHashHex(head.thisEntryHashHex());
        if (token.isEmpty()) {
            return Optional.empty();
        }
        TimestampAnchorRecord record = new TimestampAnchorRecord(head.sequenceNumber(), head.thisEntryHashHex(),
                token.get().tokenBase64(), token.get().genTime());
        store.append(record);
        log.info("TimestampAnchorService: anchored head sequenceNumber={} hash={} genTime={}",
                record.headSequenceNumber(), record.headHashHex(), record.genTime());
        return Optional.of(record);
    }

    /** Latest anchor record, if any. */
    public Optional<TimestampAnchorRecord> latest() {
        return timestamping.anchorStore().flatMap(TimestampAnchorStore::latest);
    }

    /** All anchor records, oldest first. */
    public List<TimestampAnchorRecord> all() {
        return timestamping.anchorStore().map(TimestampAnchorStore::records).orElse(List.of());
    }

    public AuditTimestamping.Mode mode() {
        return timestamping.mode();
    }
}
