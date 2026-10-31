package eu.gillstrom.gatekeeper.cose;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal CBOR decoder for tests (RFC 8949): unsigned and negative integers
 * (as {@link Long}), byte strings ({@code byte[]}), text strings, arrays
 * ({@link List}), maps ({@link LinkedHashMap}, in encoded order, with
 * {@code byte[]} keys wrapped as {@link Bytes}), tags ({@link Tagged}),
 * {@code true}/{@code false}/{@code null}. Definite lengths only. It also
 * reports whether each item used the shortest head, so the deterministic
 * encoding can be asserted.
 */
public final class CborDecoder {

    private final byte[] in;
    private int pos;
    private boolean allShortest = true;

    public CborDecoder(byte[] in) {
        this.in = in;
    }

    public boolean atEnd() {
        return pos == in.length;
    }

    public int position() {
        return pos;
    }

    /** Whether every head decoded so far used its shortest form. */
    public boolean allShortest() {
        return allShortest;
    }

    /** A tagged data item. */
    public record Tagged(long tag, Object value) {
    }

    /** A byte-string map key with value equality. */
    public record Bytes(byte[] value) {
        @Override
        public boolean equals(Object o) {
            return o instanceof Bytes b && Arrays.equals(value, b.value);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(value);
        }
    }

    /** Decode the next item. */
    public Object next() {
        int initial = in[pos++] & 0xff;
        int major = initial >>> 5;
        int info = initial & 0x1f;
        if (major == 7) {
            return switch (info) {
                case 20 -> Boolean.FALSE;
                case 21 -> Boolean.TRUE;
                case 22 -> null;
                default -> throw new IllegalArgumentException("unsupported simple/float " + info);
            };
        }
        long arg = argument(info);
        switch (major) {
            case 0:
                return arg;
            case 1:
                return -1 - arg;
            case 2:
                return take((int) arg);
            case 3:
                return new String(take((int) arg), StandardCharsets.UTF_8);
            case 4: {
                List<Object> list = new ArrayList<>();
                for (long i = 0; i < arg; i++) {
                    list.add(next());
                }
                return list;
            }
            case 5: {
                Map<Object, Object> map = new LinkedHashMap<>();
                for (long i = 0; i < arg; i++) {
                    Object k = next();
                    if (k instanceof byte[] b) {
                        k = new Bytes(b);
                    }
                    Object v = next();
                    if (map.containsKey(k)) {
                        throw new IllegalArgumentException("duplicate map key " + k);
                    }
                    map.put(k, v);
                }
                return map;
            }
            case 6:
                return new Tagged(arg, next());
            default:
                throw new IllegalArgumentException("major type " + major);
        }
    }

    /** The encoded bytes of the next item, without decoding it into objects. */
    public byte[] nextRaw() {
        int start = pos;
        next();
        return Arrays.copyOfRange(in, start, pos);
    }

    private long argument(int info) {
        long v;
        if (info < 24) {
            return info;
        } else if (info == 24) {
            v = in[pos++] & 0xffL;
            if (v < 24) {
                allShortest = false;
            }
        } else if (info == 25) {
            v = ((in[pos++] & 0xffL) << 8) | (in[pos++] & 0xffL);
            if (v <= 0xff) {
                allShortest = false;
            }
        } else if (info == 26) {
            v = 0;
            for (int i = 0; i < 4; i++) {
                v = (v << 8) | (in[pos++] & 0xffL);
            }
            if (v <= 0xffff) {
                allShortest = false;
            }
        } else if (info == 27) {
            v = 0;
            for (int i = 0; i < 8; i++) {
                v = (v << 8) | (in[pos++] & 0xffL);
            }
            if (v >= 0 && v <= 0xffffffffL) {
                allShortest = false;
            }
        } else {
            throw new IllegalArgumentException("indefinite or reserved length " + info);
        }
        return v;
    }

    private byte[] take(int n) {
        byte[] out = Arrays.copyOfRange(in, pos, pos + n);
        pos += n;
        return out;
    }

    /** Decode a whole CBOR sequence. */
    public static List<Object> decodeSequence(byte[] seq) {
        CborDecoder d = new CborDecoder(seq);
        List<Object> out = new ArrayList<>();
        while (!d.atEnd()) {
            out.add(d.next());
        }
        return out;
    }

    /** Hex helper for assertions. */
    public static String hex(byte[] b) {
        return java.util.HexFormat.of().formatHex(b);
    }
}
