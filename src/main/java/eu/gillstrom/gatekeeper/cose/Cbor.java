package eu.gillstrom.gatekeeper.cose;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Minimal deterministic CBOR encoder (RFC 8949), sufficient for COSE_Sign1
 * and the audit-export payload. No third-party CBOR library is used.
 *
 * <p>Every function returns the complete encoding of one data item. The
 * output follows the core deterministic encoding requirements of RFC 8949
 * §4.2.1 for the item types supported here: integers, lengths and tags use
 * the shortest head; every string, array and map has a definite length; map
 * keys are sorted by the bytewise lexicographic order of their encodings and
 * duplicate keys are rejected. Floating-point numbers and indefinite lengths
 * are not supported.</p>
 */
public final class Cbor {

    private static final int MAJOR_UNSIGNED = 0;
    private static final int MAJOR_NEGATIVE = 1;
    private static final int MAJOR_BYTES = 2;
    private static final int MAJOR_TEXT = 3;
    private static final int MAJOR_ARRAY = 4;
    private static final int MAJOR_MAP = 5;
    private static final int MAJOR_TAG = 6;

    private static final byte[] FALSE = {(byte) 0xf4};
    private static final byte[] TRUE = {(byte) 0xf5};
    private static final byte[] NULL = {(byte) 0xf6};

    private Cbor() {
    }

    /** An integer (major type 0 for {@code v >= 0}, 1 otherwise). */
    public static byte[] integer(long v) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(9);
        if (v >= 0) {
            head(out, MAJOR_UNSIGNED, v);
        } else {
            head(out, MAJOR_NEGATIVE, -1 - v);
        }
        return out.toByteArray();
    }

    /** A byte string. */
    public static byte[] bytes(byte[] value) {
        Objects.requireNonNull(value, "value");
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length + 9);
        head(out, MAJOR_BYTES, value.length);
        out.writeBytes(value);
        return out.toByteArray();
    }

    /** A UTF-8 text string. */
    public static byte[] text(String value) {
        Objects.requireNonNull(value, "value");
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(utf8.length + 9);
        head(out, MAJOR_TEXT, utf8.length);
        out.writeBytes(utf8);
        return out.toByteArray();
    }

    public static byte[] bool(boolean value) {
        return (value ? TRUE : FALSE).clone();
    }

    public static byte[] nul() {
        return NULL.clone();
    }

    /** An array of already-encoded items. */
    public static byte[] array(List<byte[]> items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        head(out, MAJOR_ARRAY, items.size());
        for (byte[] item : items) {
            out.writeBytes(item);
        }
        return out.toByteArray();
    }

    public static byte[] array(byte[]... items) {
        return array(Arrays.asList(items));
    }

    /** A tagged item. */
    public static byte[] tag(long tag, byte[] item) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(item.length + 9);
        head(out, MAJOR_TAG, tag);
        out.writeBytes(item);
        return out.toByteArray();
    }

    /** A new map builder. */
    public static MapBuilder map() {
        return new MapBuilder();
    }

    /**
     * Collects encoded key/value pairs and emits them sorted by encoded key
     * (bytewise lexicographic), rejecting duplicates.
     */
    public static final class MapBuilder {
        private final List<byte[][]> entries = new ArrayList<>();

        private MapBuilder() {
        }

        public MapBuilder put(byte[] encodedKey, byte[] encodedValue) {
            Objects.requireNonNull(encodedKey, "encodedKey");
            Objects.requireNonNull(encodedValue, "encodedValue");
            for (byte[][] e : entries) {
                if (Arrays.equals(e[0], encodedKey)) {
                    throw new IllegalArgumentException("duplicate CBOR map key");
                }
            }
            entries.add(new byte[][] {encodedKey, encodedValue});
            return this;
        }

        public MapBuilder put(long key, byte[] encodedValue) {
            return put(integer(key), encodedValue);
        }

        public MapBuilder put(String key, byte[] encodedValue) {
            return put(text(key), encodedValue);
        }

        /** Put a text value under a text key, or nothing when {@code value} is {@code null}. */
        public MapBuilder putTextIfPresent(String key, String value) {
            return value == null ? this : put(key, text(value));
        }

        public byte[] build() {
            List<byte[][]> sorted = new ArrayList<>(entries);
            sorted.sort((a, b) -> Arrays.compareUnsigned(a[0], b[0]));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            head(out, MAJOR_MAP, sorted.size());
            for (byte[][] e : sorted) {
                out.writeBytes(e[0]);
                out.writeBytes(e[1]);
            }
            return out.toByteArray();
        }
    }

    /** Write a head with the shortest argument encoding; {@code value} is unsigned. */
    private static void head(ByteArrayOutputStream out, int major, long value) {
        int mt = major << 5;
        if (value < 0) {
            // Arguments (lengths, tags, the magnitude of an integer) are
            // non-negative longs; integer() maps negatives to -1 - v >= 0.
            throw new IllegalArgumentException("CBOR argument out of range");
        }
        if (value < 24) {
            out.write(mt | (int) value);
        } else if (value <= 0xffL) {
            out.write(mt | 24);
            out.write((int) value);
        } else if (value <= 0xffffL) {
            out.write(mt | 25);
            out.write((int) (value >>> 8));
            out.write((int) value & 0xff);
        } else if (value <= 0xffffffffL) {
            out.write(mt | 26);
            for (int shift = 24; shift >= 0; shift -= 8) {
                out.write((int) (value >>> shift) & 0xff);
            }
        } else {
            out.write(mt | 27);
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.write((int) (value >>> shift) & 0xff);
            }
        }
    }
}
