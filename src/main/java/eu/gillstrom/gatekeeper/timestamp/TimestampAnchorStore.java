package eu.gillstrom.gatekeeper.timestamp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;

/**
 * Append-only JSON-Lines file of {@link TimestampAnchorRecord}s, kept beside
 * the audit log.
 *
 * <p>Each append is written with {@code RandomAccessFile} in {@code rwd} mode
 * and {@code FileDescriptor.sync()} before returning, as the audit log is. The
 * file is created with POSIX permissions {@code 0640} where the filesystem
 * supports them.</p>
 *
 * <p>At start-up a trailing line that does not parse (an append cut off by a
 * crash) is removed; an unparseable line before the last one is corruption
 * and makes {@link #readFromDisk()} throw, which the audit chain check reports
 * as a broken chain. The in-memory list serves the endpoints; the chain check
 * reads the file back from disk.</p>
 */
public final class TimestampAnchorStore {

    private static final Logger log = LoggerFactory.getLogger(TimestampAnchorStore.class);

    private final Path path;
    private final ObjectMapper json;
    private final List<TimestampAnchorRecord> records = new ArrayList<>();

    public TimestampAnchorStore(Path path) {
        this.path = path;
        @SuppressWarnings("deprecation")
        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .setSerializationInclusion(JsonInclude.Include.ALWAYS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        this.json = mapper;
    }

    public Path path() {
        return path;
    }

    /**
     * Load the file if it exists, dropping a torn trailing line. A file that
     * does not exist yet is not created here; the first append creates it.
     *
     * @throws IOException if a line before the last does not parse
     */
    public synchronized void load() throws IOException {
        records.clear();
        if (!Files.exists(path)) {
            return;
        }
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        boolean tornTrailer = false;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            try {
                records.add(json.readValue(line, TimestampAnchorRecord.class));
            } catch (Exception e) {
                if (i == lines.size() - 1) {
                    tornTrailer = true;
                    log.warn("TimestampAnchorStore: trailing line {} of {} does not parse and is removed "
                            + "(aborted append). cause={}", i + 1, path.toAbsolutePath(), e.toString());
                    break;
                }
                throw new IOException("Timestamp anchor file corruption at line " + (i + 1) + " of "
                        + path.toAbsolutePath(), e);
            }
        }
        if (tornTrailer) {
            StringBuilder sb = new StringBuilder();
            for (TimestampAnchorRecord r : records) {
                sb.append(json.writeValueAsString(r)).append('\n');
            }
            Path tmp = path.resolveSibling(path.getFileName() + ".recover");
            Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(tmp, path, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception atomicFail) {
                Files.move(tmp, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        }
        applyRestrictivePermissions(path);
    }

    /** Append and fsync one record, then add it to the in-memory list. */
    public synchronized void append(TimestampAnchorRecord record) throws IOException {
        String line = json.writeValueAsString(record) + "\n";
        boolean created = false;
        if (!Files.exists(path)) {
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.createFile(path);
            created = true;
        }
        if (created) {
            applyRestrictivePermissions(path);
        }
        try (RandomAccessFile raf = new RandomAccessFile(path.toFile(), "rwd")) {
            raf.seek(raf.length());
            raf.write(line.getBytes(StandardCharsets.UTF_8));
            raf.getFD().sync();
        }
        records.add(record);
    }

    /** Records appended or loaded by this process, oldest first. */
    public synchronized List<TimestampAnchorRecord> records() {
        return Collections.unmodifiableList(new ArrayList<>(records));
    }

    public synchronized Optional<TimestampAnchorRecord> latest() {
        return records.isEmpty() ? Optional.empty() : Optional.of(records.get(records.size() - 1));
    }

    /**
     * Read the file back from disk, for the chain check. A missing file is an
     * empty list; a torn trailing line is ignored (it is removed at the next
     * start-up); any other unparseable line throws.
     */
    public List<TimestampAnchorRecord> readFromDisk() throws IOException {
        if (!Files.exists(path)) {
            return List.of();
        }
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        List<TimestampAnchorRecord> out = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            try {
                out.add(json.readValue(line, TimestampAnchorRecord.class));
            } catch (Exception e) {
                if (i == lines.size() - 1) {
                    break;
                }
                throw new IOException("Timestamp anchor file corruption at line " + (i + 1), e);
            }
        }
        return out;
    }

    private static void applyRestrictivePermissions(Path p) {
        try {
            Set640.apply(p);
        } catch (UnsupportedOperationException nonPosix) {
            log.warn("TimestampAnchorStore: non-POSIX filesystem at {}; cannot enforce 0640 permissions.",
                    p.toAbsolutePath());
        } catch (IOException ioe) {
            log.warn("TimestampAnchorStore: failed to set 0640 permissions on {}: {}", p.toAbsolutePath(),
                    ioe.toString());
        }
    }

    private static final class Set640 {
        static void apply(Path p) throws IOException {
            EnumSet<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ);
            Files.setPosixFilePermissions(p, PosixFilePermissions.asFileAttribute(perms).value());
        }
    }
}
