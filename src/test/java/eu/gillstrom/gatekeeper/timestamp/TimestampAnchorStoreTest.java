package eu.gillstrom.gatekeeper.timestamp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link TimestampAnchorStore}: loading, appending and reading back the anchor file. */
class TimestampAnchorStoreTest {

    @TempDir
    Path tempDir;

    private static TimestampAnchorRecord record(long sequence) {
        return new TimestampAnchorRecord(sequence, "ab".repeat(32), "dG9rZW4=", Instant.parse("2026-10-30T12:00:00Z"));
    }

    private static String permissions(Path p) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    @Test
    void theFirstAppendCreatesTheDirectoryAndAFileReadableOnlyByOwnerAndGroup() throws Exception {
        Path file = tempDir.resolve("a").resolve("b").resolve("anchors.jsonl");
        TimestampAnchorStore store = new TimestampAnchorStore(file);
        assertThat(store.path()).isEqualTo(file);

        store.append(record(1));
        assertThat(permissions(file)).isEqualTo("rw-r-----");
        assertThat(store.records()).containsExactly(record(1));
    }

    @Test
    void loadingTwiceDoesNotDuplicateAndRestoresThePermissions() throws Exception {
        Path file = tempDir.resolve("anchors.jsonl");
        TimestampAnchorStore writer = new TimestampAnchorStore(file);
        writer.append(record(1));
        writer.append(record(2));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));

        TimestampAnchorStore store = new TimestampAnchorStore(file);
        store.load();
        store.load();
        assertThat(store.records()).containsExactly(record(1), record(2));
        assertThat(permissions(file)).isEqualTo("rw-r-----");
    }

    @Test
    void anUnparseableLineBeforeTheLastIsCorruptionNamedByItsLineNumber() throws Exception {
        Path file = tempDir.resolve("anchors.jsonl");
        TimestampAnchorStore writer = new TimestampAnchorStore(file);
        writer.append(record(1));
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        Files.write(file, List.of(lines.get(0), "{not json", lines.get(0)), StandardCharsets.UTF_8);

        assertThatThrownBy(() -> new TimestampAnchorStore(file).load())
                .isInstanceOf(IOException.class)
                .hasMessageStartingWith("Timestamp anchor file corruption at line 2 of ");
        assertThatThrownBy(() -> new TimestampAnchorStore(file).readFromDisk())
                .isInstanceOf(IOException.class)
                .hasMessage("Timestamp anchor file corruption at line 2");
    }

    @Test
    void readingBackIgnoresATornLastLine() throws Exception {
        Path file = tempDir.resolve("anchors.jsonl");
        TimestampAnchorStore writer = new TimestampAnchorStore(file);
        writer.append(record(1));
        Files.writeString(file, Files.readString(file) + "{\"headSequenceNumber\":2,", StandardCharsets.UTF_8);

        assertThat(new TimestampAnchorStore(file).readFromDisk()).containsExactly(record(1));
    }
}
