package eu.gillstrom.gatekeeper.service;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Single-use enforcement of the Step-7 confirmation nonce under concurrency,
 * run against <em>both</em> {@link ApprovalRegistry} implementations.
 *
 * <p>The defect: {@code confirm} read {@code entry.getConfirmationNonce()},
 * compared it, and only then cleared it — three statements with no lock
 * around them. Two confirmations arriving at once with the same nonce both
 * read a non-null value, both compared equal, and both proceeded. The nonce
 * is the primitive that makes a Step-7 confirmation unrepeatable, so "at
 * most one" is the whole property; "usually one" is not a weaker version of
 * it.</p>
 *
 * <p>A second defect in the file-backed implementation: the nonce was
 * cleared <em>before</em> the journal append. An I/O failure on the journal
 * therefore burned the nonce — the caller received a 5xx telling it to
 * retry, and the retry could never succeed because the expected nonce was
 * now null. {@link #nonceSurvivesAJournalWriteFailure()} pins the corrected
 * ordering.</p>
 */
class ApprovalRegistryNonceConcurrencyTest {

    @TempDir
    Path tempDir;

    static Stream<Function<Path, ApprovalRegistry>> implementations() {
        return Stream.of(
                dir -> new InMemoryApprovalRegistry(),
                dir -> {
                    AppendOnlyFileApprovalRegistry registry =
                            new AppendOnlyFileApprovalRegistry(
                                    dir.resolve("registry-" + System.nanoTime() + ".jsonl").toString());
                    try {
                        registry.initialise();
                    } catch (Exception e) {
                        throw new IllegalStateException("Could not initialise file registry", e);
                    }
                    return registry;
                });
    }

    @ParameterizedTest
    @MethodSource("implementations")
    void twoConcurrentConfirmsWithTheSameNonceLeaveExactlyOneWinner(
            Function<Path, ApprovalRegistry> factory) throws Exception {
        ApprovalRegistry registry = factory.apply(tempDir);
        registry.register("SE-1", "the-one-nonce", true, "fp-se", "556000-0000", "Svensk TL",
                "SECUROSYS", "Primus HSM", "SE");

        AtomicInteger succeeded = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        CountDownLatch startLine = new CountDownLatch(1);

        Callable<Void> attempt = () -> {
            startLine.await();
            try {
                Optional<ApprovalRegistry.RegistryEntry> result =
                        registry.confirm("SE-1", "the-one-nonce", true, "fp-se", true);
                if (result.isPresent()) {
                    succeeded.incrementAndGet();
                }
            } catch (ApprovalRegistry.NonceMismatchException expectedForTheLoser) {
                rejected.incrementAndGet();
            }
            return null;
        };

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Void> a = pool.submit(attempt);
            Future<Void> b = pool.submit(attempt);
            startLine.countDown();
            a.get(10, TimeUnit.SECONDS);
            b.get(10, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }

        assertThat(succeeded.get())
                .as("exactly one of two concurrent confirmations with the same nonce may win")
                .isEqualTo(1);
        assertThat(rejected.get())
                .as("the other must be rejected as a nonce mismatch, i.e. as a replay")
                .isEqualTo(1);
        assertThat(registry.lookup("SE-1").orElseThrow().getConfirmationNonce())
                .as("the nonce is spent after the winning confirmation")
                .isNull();
    }

    /**
     * A sequential replay must fail for the same reason — kept alongside the
     * concurrent case so a future implementation cannot satisfy one by
     * breaking the other.
     */
    @ParameterizedTest
    @MethodSource("implementations")
    void replayedConfirmIsRejected(Function<Path, ApprovalRegistry> factory) {
        ApprovalRegistry registry = factory.apply(tempDir);
        registry.register("SE-2", "nonce-2", true, "fp-se", "556000-0000", "Svensk TL",
                "SECUROSYS", "Primus HSM", "SE");

        assertThat(registry.confirm("SE-2", "nonce-2", true, "fp-se", true)).isPresent();

        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> registry.confirm("SE-2", "nonce-2", true, "fp-se", true))
                .isInstanceOf(ApprovalRegistry.NonceMismatchException.class);
    }

    /**
     * Journal failure must not consume the nonce. The failure is produced by
     * replacing the journal file with a directory, so the {@code
     * RandomAccessFile} open inside {@code appendOp} throws.
     */
    @org.junit.jupiter.api.Test
    void nonceSurvivesAJournalWriteFailure() throws Exception {
        Path journal = tempDir.resolve("journal-failure.jsonl");
        AppendOnlyFileApprovalRegistry registry =
                new AppendOnlyFileApprovalRegistry(journal.toString());
        registry.initialise();
        registry.register("SE-3", "nonce-3", true, "fp-se", "556000-0000", "Svensk TL",
                "SECUROSYS", "Primus HSM", "SE");

        // Make the journal path unwritable as a file.
        Files.delete(journal);
        Files.createDirectory(journal);

        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> registry.confirm("SE-3", "nonce-3", true, "fp-se", true))
                .isInstanceOf(IllegalStateException.class);

        assertThat(registry.lookup("SE-3").orElseThrow().getConfirmationNonce())
                .as("a journal failure must leave the nonce spendable so the retry the "
                    + "caller is told to make can actually succeed")
                .isEqualTo("nonce-3");

        // Restore the journal and confirm that the retry now works.
        Files.delete(journal);
        Files.createFile(journal);
        List<ApprovalRegistry.RegistryEntry> unused = registry.findByCountry("SE");
        assertThat(unused).hasSize(1);
        assertThat(registry.confirm("SE-3", "nonce-3", true, "fp-se", true)).isPresent();
    }
}
