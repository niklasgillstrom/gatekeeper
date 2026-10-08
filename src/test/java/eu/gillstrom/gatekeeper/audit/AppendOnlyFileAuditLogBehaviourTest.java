package eu.gillstrom.gatekeeper.audit;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Locking, start-up loading, file permissions, the integrity cache and the
 * chain checks of {@link AppendOnlyFileAuditLog}, beyond the chain-growth
 * and tamper cases in {@link AppendOnlyFileAuditLogTest}.
 */
class AppendOnlyFileAuditLogBehaviourTest {

    @TempDir
    Path tempDir;

    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

    private AppendOnlyFileAuditLog open(Path file, long intervalSeconds) {
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(file.toString(), signer, intervalSeconds);
        log.initialise();
        return log;
    }

    private static AuditAppendRequest request(int n) {
        return new AuditAppendRequest("CN=client", "VERIFY", "verif-" + n, "cmVx", "cmNwdA==", true);
    }

    private static ReentrantLock lock(AppendOnlyFileAuditLog log, String name) throws Exception {
        Field field = AppendOnlyFileAuditLog.class.getDeclaredField(name);
        field.setAccessible(true);
        return (ReentrantLock) field.get(log);
    }

    private static void editLine(Path file, int index, java.util.function.Consumer<ObjectNode> edit) throws IOException {
        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        ObjectNode node = (ObjectNode) mapper.readTree(lines.get(index));
        edit.accept(node);
        lines.set(index, mapper.writeValueAsString(node));
        Files.write(file, lines, StandardCharsets.UTF_8);
    }

    private static ListAppender<ILoggingEvent> capture() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        ((Logger) LoggerFactory.getLogger(AppendOnlyFileAuditLog.class)).addAppender(appender);
        return appender;
    }

    private static void release(ListAppender<ILoggingEvent> appender) {
        ((Logger) LoggerFactory.getLogger(AppendOnlyFileAuditLog.class)).detachAppender(appender);
    }

    private static boolean logged(ListAppender<ILoggingEvent> appender, String fragment) {
        return appender.list.stream().anyMatch(e -> e.getFormattedMessage().contains(fragment));
    }

    // --- locking ------------------------------------------------------------

    @Test
    void everyReadReleasesTheLockSoAnotherThreadCanAppend() throws Exception {
        AppendOnlyFileAuditLog log = open(tempDir.resolve("a.jsonl"), 300);
        log.append(request(1));
        log.findByVerificationId("verif-1");
        log.findInRange(Instant.EPOCH, Instant.now().plusSeconds(60));
        log.findByPrincipal("CN=client");
        log.head();
        log.size();
        log.verifyChainIntegrity();

        AuditEntry second = CompletableFuture.supplyAsync(() -> log.append(request(2)))
                .get(2, TimeUnit.SECONDS);
        assertThat(second.sequenceNumber()).isEqualTo(2);
    }

    @Test
    void concurrentAppendsFormOneUnbrokenChain() throws Exception {
        AppendOnlyFileAuditLog log = open(tempDir.resolve("c.jsonl"), 0);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            int thread = t;
            futures.add(pool.submit(() -> {
                start.await();
                for (int i = 0; i < 25; i++) {
                    log.append(request(thread * 100 + i));
                }
                return null;
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(60, TimeUnit.SECONDS);
        }
        pool.shutdown();

        assertThat(log.size()).isEqualTo(200);
        assertThat(log.verifyChainIntegrity()).isTrue();
        assertThat(open(tempDir.resolve("c.jsonl"), 0).verifyChainIntegrity()).isTrue();
    }

    @Test
    void anAppendInterruptedWhileWaitingForTheLockFailsAndKeepsTheInterrupt() throws Exception {
        AppendOnlyFileAuditLog log = open(tempDir.resolve("i.jsonl"), 300);
        ReentrantLock appendLock = lock(log, "appendLock");
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            if (!tryLock(appendLock)) {
                return;
            }
            held.countDown();
            try {
                done.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            } finally {
                appendLock.unlock();
            }
        });
        holder.start();
        assertThat(held.await(2, TimeUnit.SECONDS)).as("helper thread holds the lock").isTrue();

        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<Boolean> interruptKept = new AtomicReference<>();
        Thread appender = new Thread(() -> {
            try {
                log.append(request(1));
            } catch (Throwable t) {
                failure.set(t);
                interruptKept.set(Thread.currentThread().isInterrupted());
            }
        });
        appender.start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (!appendLock.hasQueuedThread(appender)) {
            assertThat(System.nanoTime()).as("appender queued on the lock").isLessThan(deadline);
            Thread.onSpinWait();
        }
        appender.interrupt();
        appender.join(2_000);
        done.countDown();
        holder.join(2_000);

        assertThat(failure.get()).isInstanceOf(AuditLogException.class)
                .hasMessageContaining("Interrupted while waiting");
        assertThat(interruptKept.get()).isTrue();
        assertThat(log.size()).isZero();
    }

    // --- start-up -----------------------------------------------------------

    @Test
    void aLogInADirectoryThatDoesNotExistYetIsCreatedWith0640() throws Exception {
        Path file = tempDir.resolve("nested/deeper/audit.jsonl");
        AppendOnlyFileAuditLog log = open(file, 300);
        assertThat(Files.exists(file)).isTrue();
        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(file))).isEqualTo("rw-r-----");
        log.append(request(1));
        assertThat(log.size()).isEqualTo(1);
    }

    @Test
    void reloadingRestoresTheRestrictivePermissions() throws Exception {
        Path file = tempDir.resolve("p.jsonl");
        open(file, 300).append(request(1));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-rw-rw-"));

        open(file, 300);

        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(file))).isEqualTo("rw-r-----");
    }

    @Test
    void aTornLastLineIsCutAwaySoLaterAppendsReloadCleanly() throws Exception {
        Path file = tempDir.resolve("t.jsonl");
        AppendOnlyFileAuditLog first = open(file, 300);
        first.append(request(1));
        first.append(request(2));
        Files.writeString(file, "{\"sequenceNumber\":3,\"trunc", StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);

        AppendOnlyFileAuditLog recovered = open(file, 300);
        assertThat(recovered.size()).isEqualTo(2);
        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(file))).isEqualTo("rw-r-----");
        recovered.append(request(3));

        AppendOnlyFileAuditLog reloaded = open(file, 300);
        assertThat(reloaded.size()).isEqualTo(3);
        assertThat(reloaded.verifyChainIntegrity()).isTrue();
    }

    @Test
    void anUnparseableLineBeforeTheLastIsCorruptionNamingItsLine() throws Exception {
        Path file = tempDir.resolve("m.jsonl");
        AppendOnlyFileAuditLog first = open(file, 300);
        first.append(request(1));
        first.append(request(2));
        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        lines.set(0, "not json");
        Files.write(file, lines, StandardCharsets.UTF_8);

        assertThatThrownBy(() -> open(file, 300))
                .isInstanceOf(AuditLogException.class)
                .hasMessageContaining("corruption at line 1 of");
    }

    @Test
    void anExistingEmptyFileLoadsAsAnIntactEmptyLog() throws Exception {
        Path file = tempDir.resolve("e.jsonl");
        Files.createFile(file);
        ListAppender<ILoggingEvent> appender = capture();
        try {
            AppendOnlyFileAuditLog log = open(file, 300);
            assertThat(log.size()).isZero();
            assertThat(log.verifyChainIntegrity()).isTrue();
            assertThat(logged(appender, "FAILED at startup")).isFalse();
        } finally {
            release(appender);
        }
    }

    @Test
    void anIntactChainLoadsWithoutWarningsAndABrokenOneIsReportedAtStartUp() throws Exception {
        Path file = tempDir.resolve("w.jsonl");
        AppendOnlyFileAuditLog first = open(file, 300);
        for (int i = 1; i <= 3; i++) {
            first.append(request(i));
        }

        ListAppender<ILoggingEvent> appender = capture();
        try {
            open(file, 300);
            assertThat(appender.list).noneMatch(e -> e.getLevel() == ch.qos.logback.classic.Level.WARN);

            editLine(file, 1, n -> n.put("sequenceNumber", 7));
            editLine(file, 2, n -> n.put("prevEntryHashHex", "11".repeat(32)));
            appender.list.clear();
            AppendOnlyFileAuditLog broken = open(file, 300);
            assertThat(logged(appender, "chain anomaly at line 2")).isTrue();
            assertThat(logged(appender, "chain link broken at line 3")).isTrue();
            assertThat(logged(appender, "integrity check FAILED at startup")).isTrue();
            assertThat(broken.cachedIntegrityStatus().intact()).isFalse();
        } finally {
            release(appender);
        }
    }

    // --- integrity cache ----------------------------------------------------

    @Test
    void theStartUpCheckIsCachedForTheInterval() throws Exception {
        Path file = tempDir.resolve("s.jsonl");
        open(file, 300).append(request(1));
        AppendOnlyFileAuditLog log = open(file, 300);
        editLine(file, 0, n -> n.put("compliant", false));

        assertThat(log.cachedIntegrityStatus().intact()).as("served from the start-up check").isTrue();
        assertThat(log.verifyChainIntegrity()).isFalse();
        assertThat(log.cachedIntegrityStatus().intact()).as("the explicit check refreshes the cache").isFalse();
    }

    @Test
    void aOneSecondIntervalCachesWithinTheSecondAndRecomputesAfterIt() throws Exception {
        Path file = tempDir.resolve("one.jsonl");
        AppendOnlyFileAuditLog log = open(file, 1);
        log.append(request(1));
        assertThat(log.verifyChainIntegrity()).isTrue();
        editLine(file, 0, n -> n.put("compliant", false));

        assertThat(log.cachedIntegrityStatus().intact()).isTrue();
        Thread.sleep(1_100);
        assertThat(log.cachedIntegrityStatus().intact()).isFalse();
    }

    @Test
    void aRecomputeReleasesItsLockForTheNextCaller() throws Exception {
        Path file = tempDir.resolve("r.jsonl");
        AppendOnlyFileAuditLog log = open(file, 0);
        log.append(request(1));
        assertThat(log.cachedIntegrityStatus().intact()).isTrue();
        editLine(file, 0, n -> n.put("compliant", false));

        boolean intact = CompletableFuture.supplyAsync(() -> log.cachedIntegrityStatus().intact())
                .get(2, TimeUnit.SECONDS);
        assertThat(intact).as("recomputed by another thread, not served stale").isFalse();
    }

    @Test
    void whileARecomputeRunsTheStaleAnswerIsServedAndAFirstAnswerIsAwaited() throws Exception {
        Path file = tempDir.resolve("x.jsonl");
        AppendOnlyFileAuditLog stale = open(file, 0);
        stale.append(request(1));
        AuditLog.IntegrityStatus previous = stale.cachedIntegrityStatus();
        ReentrantLock computeLock = lock(stale, "integrityComputeLock");
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            if (!tryLock(computeLock)) {
                return;
            }
            held.countDown();
            try {
                done.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            } finally {
                computeLock.unlock();
            }
        });
        holder.start();
        assertThat(held.await(2, TimeUnit.SECONDS)).as("helper thread holds the lock").isTrue();
        try {
            assertThat(CompletableFuture.supplyAsync(stale::cachedIntegrityStatus).get(2, TimeUnit.SECONDS))
                    .as("health does not queue behind a running walk").isSameAs(previous);
        } finally {
            done.countDown();
            holder.join(2_000);
        }

        // With no answer yet, the caller waits for the one being computed.
        Path second = tempDir.resolve("y.jsonl");
        Files.createFile(second);
        AppendOnlyFileAuditLog fresh = new AppendOnlyFileAuditLog(second.toString(), signer, 300);
        ReentrantLock freshLock = lock(fresh, "integrityComputeLock");
        assertThat(tryLock(freshLock)).isTrue();
        CompletableFuture<AuditLog.IntegrityStatus> waiting = CompletableFuture.supplyAsync(fresh::cachedIntegrityStatus);
        Thread.sleep(200);
        assertThat(waiting).isNotDone();
        fresh.verifyChainIntegrity();
        AuditLog.IntegrityStatus computedMeanwhile = getCached(fresh);
        freshLock.unlock();
        assertThat(waiting.get(2, TimeUnit.SECONDS)).as("the answer computed meanwhile").isSameAs(computedMeanwhile);
    }

    private static boolean tryLock(ReentrantLock lock) {
        try {
            return lock.tryLock(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static AuditLog.IntegrityStatus getCached(AppendOnlyFileAuditLog log) throws Exception {
        Field field = AppendOnlyFileAuditLog.class.getDeclaredField("cachedIntegrity");
        field.setAccessible(true);
        return ((AtomicReference<AuditLog.IntegrityStatus>) field.get(log)).get();
    }

    // --- chain checks on disk -----------------------------------------------

    @Test
    void anUnreadableFileIsNotIntact() throws Exception {
        Path file = tempDir.resolve("gone.jsonl");
        AppendOnlyFileAuditLog log = open(file, 0);
        log.append(request(1));
        Files.delete(file);
        assertThat(log.verifyChainIntegrity()).isFalse();
    }

    @Test
    void aDifferentChainOfTheSameLengthOnDiskIsNotIntact() throws Exception {
        Path file = tempDir.resolve("mine.jsonl");
        Path other = tempDir.resolve("other.jsonl");
        AppendOnlyFileAuditLog log = open(file, 0);
        log.append(request(1));
        Thread.sleep(5);
        open(other, 0).append(request(1));
        Files.copy(other, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        assertThat(log.verifyChainIntegrity()).isFalse();
    }

    @Test
    void aSequenceGapAPrevHashMismatchOrAnUnreadableSignatureBreaksTheChain() throws Exception {
        String[][] edits = {
                {"sequenceNumber", "5"},
                {"prevEntryHashHex", "11".repeat(32)},
                {"entrySignatureBase64", "!!!"}};
        for (String[] edit : edits) {
            Path file = tempDir.resolve(edit[0] + ".jsonl");
            AppendOnlyFileAuditLog log = open(file, 0);
            log.append(request(1));
            log.append(request(2));
            editLine(file, 0, n -> {
                if (edit[0].equals("sequenceNumber")) {
                    n.put(edit[0], Long.parseLong(edit[1]));
                } else {
                    n.put(edit[0], edit[1]);
                }
            });
            assertThat(log.verifyChainIntegrity()).as(edit[0]).isFalse();
        }
    }
}
