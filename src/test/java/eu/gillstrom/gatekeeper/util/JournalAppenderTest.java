package eu.gillstrom.gatekeeper.util;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.gatekeeper.testsupport.RecordingChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The audit log and the registry journal are appended to through
 * {@link JournalAppender}. Until 1.7.0 an append that failed part-way left a
 * fragment that the next append continued on, and the record that append
 * acknowledged was unreadable at the next start. The I/O failures here are
 * those of a channel that fails on request; the file is a real one.
 */
class JournalAppenderTest {

    @TempDir
    Path dir;

    private Path file;
    private final List<RecordingChannel> channels = new ArrayList<>();
    /** Applied to the next channel that is opened, once. */
    private Consumer<RecordingChannel> fault;
    private JournalAppender appender;
    private ListAppender<ILoggingEvent> log;

    @BeforeEach
    void setUp() throws Exception {
        file = dir.resolve("journal.jsonl");
        Files.createFile(file);
        appender = new JournalAppender(file, this::open);
        log = new ListAppender<>();
        log.start();
        ((Logger) LoggerFactory.getLogger(JournalAppender.class)).addAppender(log);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(JournalAppender.class)).detachAppender(log);
    }

    private FileChannel open(Path path, OpenOption... options) throws IOException {
        assertThat(options).containsExactlyInAnyOrder(
                StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
        RecordingChannel channel = new RecordingChannel(FileChannel.open(path, options));
        if (fault != null) {
            fault.accept(channel);
            fault = null;
        }
        channels.add(channel);
        return channel;
    }

    private RecordingChannel lastChannel() {
        return channels.get(channels.size() - 1);
    }

    private String content() throws IOException {
        return Files.readString(file, StandardCharsets.UTF_8);
    }

    private List<String> warnings() {
        return log.list.stream().filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage).toList();
    }

    // ---- the ordinary case ----------------------------------------------------------------------

    @Test
    void eachLineIsAppendedWithItsNewlineAndForcedOnce() throws Exception {
        appender.appendLine("{\"n\":1}");
        assertThat(content()).isEqualTo("{\"n\":1}\n");
        assertThat(lastChannel().forces).isEqualTo(1);
        assertThat(lastChannel().isOpen()).as("the channel is closed after the append").isFalse();

        appender.appendLine("{\"n\":2,\"name\":\"Åsa\"}");
        assertThat(content()).isEqualTo("{\"n\":1}\n{\"n\":2,\"name\":\"Åsa\"}\n");
        assertThat(lastChannel().forces).isEqualTo(1);

        assertThat(channels).hasSize(2).allSatisfy(c -> assertThat(c.truncations).isZero());
        assertThat(warnings()).isEmpty();
    }

    @Test
    void aJournalThatIsNotThereIsCreated() throws Exception {
        Files.delete(file);

        new JournalAppender(file).appendLine("first");

        assertThat(content()).isEqualTo("first\n");
    }

    // ---- what a stopped process left -------------------------------------------------------------

    @Test
    void whatFollowsTheLastNewlineIsRemovedBeforeTheAppend() throws Exception {
        Files.writeString(file, "{\"n\":1}\n{\"n\":2,\"na");

        appender.appendLine("{\"n\":3}");

        assertThat(content()).isEqualTo("{\"n\":1}\n{\"n\":3}\n");
        assertThat(lastChannel().truncations).isEqualTo(1);
        assertThat(lastChannel().forces).as("the cut and the record are each forced").isEqualTo(2);
        assertThat(warnings()).containsExactly(file + ": removed 10 bytes after the last complete line, "
                + "the remains of an append that did not complete");
    }

    @Test
    void aFileThatIsAllFragmentIsEmptiedBeforeTheAppend() throws Exception {
        // Longer than any buffer, and without a newline anywhere.
        Files.writeString(file, "x".repeat(20_000));

        appender.appendLine("first");

        assertThat(content()).isEqualTo("first\n");
        assertThat(warnings()).singleElement().asString().contains("removed 20000 bytes");
    }

    @Test
    void aBlankLastLineIsNotAFragment() throws Exception {
        Files.writeString(file, "a\n\n");

        appender.appendLine("b");

        assertThat(content()).isEqualTo("a\n\nb\n");
        assertThat(warnings()).isEmpty();
    }

    // ---- an append that fails ---------------------------------------------------------------------

    @Test
    void aWriteThatFailsPartWayLeavesNothingOfItsLine() throws Exception {
        appender.appendLine("a");
        IOException disk = new IOException("No space left on device");
        fault = channel -> {
            channel.failWrite = disk;
            channel.tornBytes = 3;
        };

        assertThatThrownBy(() -> appender.appendLine("{\"n\":2}")).isSameAs(disk);

        assertThat(disk.getSuppressed()).isEmpty();
        assertThat(content()).isEqualTo("a\n");
        assertThat(lastChannel().truncations).isEqualTo(1);
        assertThat(lastChannel().forces).as("the cut is forced").isEqualTo(1);
        assertThat(lastChannel().isOpen()).isFalse();

        // The file is whole again: the next append has nothing to repair.
        appender.appendLine("c");
        assertThat(content()).isEqualTo("a\nc\n");
        assertThat(lastChannel().truncations).isZero();
        assertThat(warnings()).isEmpty();
    }

    @Test
    void aRecordThatWasWrittenButNotForcedIsTakenBack() throws Exception {
        appender.appendLine("a");
        IOException disk = new IOException("Input/output error");
        fault = channel -> channel.failNextForce = disk;

        assertThatThrownBy(() -> appender.appendLine("b")).isSameAs(disk);

        assertThat(content()).as("the whole line had reached the file").isEqualTo("a\n");
        assertThat(lastChannel().truncations).isEqualTo(1);
        assertThat(lastChannel().forces).isEqualTo(1);
    }

    @Test
    void aRecordThatCouldNotBeTakenBackIsRemovedByTheNextAppend() throws Exception {
        appender.appendLine("a");
        IOException disk = new IOException("Input/output error");
        IOException second = new IOException("Read-only file system");
        fault = channel -> {
            channel.failNextForce = disk;
            channel.failTruncate = second;
        };

        assertThatThrownBy(() -> appender.appendLine("b")).isSameAs(disk);

        assertThat(disk.getSuppressed()).containsExactly(second);
        assertThat(content()).as("the record nobody acknowledged is still there").isEqualTo("a\nb\n");
        assertThat(warnings()).isEmpty();

        appender.appendLine("c");

        assertThat(content()).isEqualTo("a\nc\n");
        assertThat(lastChannel().truncations).isEqualTo(1);
        assertThat(lastChannel().forces).as("the cut and the record are each forced").isEqualTo(2);
        assertThat(warnings()).containsExactly(file + ": cut back to 2 bytes, removing a record whose append "
                + "failed and could not be taken back at the time");

        // Done once: the append after that cuts nothing.
        appender.appendLine("d");
        assertThat(content()).isEqualTo("a\nc\nd\n");
        assertThat(lastChannel().truncations).isZero();
        assertThat(warnings()).hasSize(1);
    }

    @Test
    void aFailureToRemoveAFragmentIsTheAppendsFailure() throws Exception {
        Files.writeString(file, "a\nfrag");
        IOException readOnly = new IOException("Read-only file system");
        fault = channel -> channel.failTruncate = readOnly;

        assertThatThrownBy(() -> appender.appendLine("b")).isSameAs(readOnly);

        assertThat(content()).isEqualTo("a\nfrag");
        assertThat(lastChannel().isOpen()).isFalse();
    }

    // ---- a whole last line without its newline --------------------------------------------------

    @Test
    void aLastLineWithoutANewlineGetsOne() throws Exception {
        Files.writeString(file, "a\n{\"n\":2}");

        assertThat(appender.terminateLastLine()).isTrue();

        assertThat(content()).isEqualTo("a\n{\"n\":2}\n");
        assertThat(lastChannel().forces).isEqualTo(1);
        assertThat(lastChannel().isOpen()).isFalse();
        // The record now survives the next append.
        appender.appendLine("{\"n\":3}");
        assertThat(content()).isEqualTo("a\n{\"n\":2}\n{\"n\":3}\n");
        assertThat(warnings()).isEmpty();
    }

    @Test
    void aFileOfOneUnterminatedLineGetsItsNewline() throws Exception {
        Files.writeString(file, "only");

        assertThat(appender.terminateLastLine()).isTrue();

        assertThat(content()).isEqualTo("only\n");
    }

    @Test
    void aFileThatEndsInANewlineOrIsEmptyIsLeftAlone() throws Exception {
        assertThat(appender.terminateLastLine()).isFalse();
        assertThat(content()).isEmpty();
        assertThat(lastChannel().forces).isZero();

        Files.writeString(file, "a\n");
        assertThat(appender.terminateLastLine()).isFalse();
        assertThat(content()).isEqualTo("a\n");
        assertThat(lastChannel().forces).isZero();
        assertThat(lastChannel().truncations).isZero();
    }
}
