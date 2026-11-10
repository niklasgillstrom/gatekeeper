package eu.gillstrom.gatekeeper.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Appends lines to a journal so that the file consists of whole lines, each
 * of them one that an append has acknowledged.
 *
 * <p>The audit log and the approval-registry journal are JSON Lines files
 * that only grow. A line is committed when it and its terminating newline
 * have been forced to the device; only then does {@link #appendLine} return.
 * Until 1.7.0 both files were written with a plain seek to the end: an append
 * that failed part-way left a fragment without a newline, and the next
 * append continued on the same line. The two records became one line that
 * neither file's loader could read. For the registry that line was skipped
 * at the next start, so an acknowledged record, a {@code STATUS_CHANGE} to
 * {@code REVOKED} for instance, was gone; the audit log refused to start.</p>
 *
 * <p>Three rules prevent it:</p>
 * <ol>
 *   <li>An append that fails cuts the file back to the length it had before
 *       the append, and the failure is thrown.</li>
 *   <li>If that cut fails as well, the length is remembered and the cut is
 *       made first thing at the next append.</li>
 *   <li>Before every append, whatever follows the file's last newline is
 *       removed. No acknowledged record lies there: it is what an append
 *       left when the process stopped in the middle of it.</li>
 * </ol>
 *
 * <p>One instance per file. Not thread-safe: the audit log and the registry
 * call it under the lock they already hold for an append.</p>
 */
public final class JournalAppender {

    private static final Logger log = LoggerFactory.getLogger(JournalAppender.class);

    /** Opens a file channel; tests substitute one that fails. */
    @FunctionalInterface
    public interface ChannelOpener {
        FileChannel open(Path path, OpenOption... options) throws IOException;
    }

    private final Path file;
    private final ChannelOpener opener;
    /** The length to cut the file back to before anything else, or -1; rule 2. */
    private long cutBackTo = -1;

    public JournalAppender(Path file) {
        this(file, FileChannel::open);
    }

    public JournalAppender(Path file, ChannelOpener opener) {
        this.file = file;
        this.opener = opener;
    }

    /**
     * Appends {@code line} and a newline and forces them to the device.
     *
     * @param line one record, without a newline in it
     * @throws IOException when the record is not committed; the file is then
     *     as it was, or will be made so by the next append
     */
    public void appendLine(String line) throws IOException {
        byte[] record = (line + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel channel = open()) {
            long end = endOfWholeLines(channel);
            try {
                write(channel, end, record);
            } catch (IOException failure) {
                try {
                    channel.truncate(end);
                    channel.force(true);
                } catch (IOException second) {
                    cutBackTo = end;
                    failure.addSuppressed(second);
                }
                throw failure;
            }
        }
    }

    /**
     * Ends the last line with a newline when it lacks one. For a loader that
     * has just read that line as a whole record: without its newline the next
     * append would take the record for the remains of a failed one and remove
     * it.
     *
     * @return whether a newline was added
     */
    public boolean terminateLastLine() throws IOException {
        try (FileChannel channel = open()) {
            long size = channel.size();
            boolean unterminated = lastLineEnd(channel, size) != size;
            if (unterminated) {
                write(channel, size, new byte[] {'\n'});
            }
            return unterminated;
        }
    }

    /** The file is created when it is not there, as it was by the {@code RandomAccessFile} used until 1.7.0. */
    private FileChannel open() throws IOException {
        return opener.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
    }

    private static void write(FileChannel channel, long position, byte[] bytes) throws IOException {
        channel.position(position);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
        channel.force(true);
    }

    /** Applies rules 2 and 3 and returns the length of the file, which then ends in a whole line. */
    private long endOfWholeLines(FileChannel channel) throws IOException {
        if (cutBackTo != -1) {
            channel.truncate(cutBackTo);
            channel.force(true);
            log.warn("{}: cut back to {} bytes, removing a record whose append failed and could not be "
                    + "taken back at the time", file, cutBackTo);
            cutBackTo = -1;
        }
        long size = channel.size();
        long end = lastLineEnd(channel, size);
        if (end != size) {
            channel.truncate(end);
            channel.force(true);
            log.warn("{}: removed {} bytes after the last complete line, the remains of an append that "
                    + "did not complete", file, size - end);
        }
        return end;
    }

    /** The position after the last newline within the first {@code size} bytes; 0 when there is none. */
    private static long lastLineEnd(FileChannel channel, long size) throws IOException {
        ByteBuffer one = ByteBuffer.allocate(1);
        long end = size;
        while (end > 0) {
            one.clear();
            channel.read(one, end - 1);
            if (one.get(0) == '\n') {
                return end;
            }
            end--;
        }
        return 0;
    }
}
