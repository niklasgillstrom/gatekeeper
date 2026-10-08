package eu.gillstrom.gatekeeper.verification;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Builds synthetic Marvell attestations in the two layouts {@link MarvellAttestation} reads. */
final class MarvellBlobs {

    private final Map<Integer, byte[]> attributes = new LinkedHashMap<>();

    static MarvellBlobs privateKey(RSAPublicKey key, String id) throws Exception {
        return withKey(key, id, 3)
                .put(MarvellAttestation.ATTR_EXTRACTABLE, new byte[] {0})
                .put(MarvellAttestation.ATTR_NEVER_EXTRACTABLE, new byte[] {1})
                .put(MarvellAttestation.ATTR_LOCAL, new byte[] {1});
    }

    static MarvellBlobs publicKey(RSAPublicKey key, String id) throws Exception {
        return withKey(key, id, 2);
    }

    private static MarvellBlobs withKey(RSAPublicKey key, String id, int objectClass) throws Exception {
        byte[] spki = key.getEncoded();
        return new MarvellBlobs()
                .put(MarvellAttestation.ATTR_CLASS, new byte[] {(byte) objectClass})
                .put(MarvellAttestation.ATTR_KEY_TYPE, new byte[] {0})
                .put(MarvellAttestation.ATTR_ID, id.getBytes(StandardCharsets.UTF_8))
                .put(MarvellAttestation.ATTR_MODULUS, unsigned(key.getModulus()))
                .put(MarvellAttestation.ATTR_PUBLIC_EXPONENT, unsigned(key.getPublicExponent()))
                .put(MarvellAttestation.ATTR_KCV, Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(spki), 3))
                .put(MarvellAttestation.ATTR_EKCV, MessageDigest.getInstance("SHA-256").digest(spki));
    }

    MarvellBlobs put(int type, byte[] value) {
        attributes.put(type, value);
        return this;
    }

    MarvellBlobs remove(int type) {
        attributes.remove(type);
        return this;
    }

    /** One key object: {@code >III} header and {@code >II} records. */
    byte[] object() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(ByteBuffer.allocate(12).putInt(0).putInt(attributes.size()).putInt(0).array());
        attributes.forEach((type, value) -> {
            out.writeBytes(ByteBuffer.allocate(8).putInt(type).putInt(value.length).array());
            out.writeBytes(value);
        });
        return out.toByteArray();
    }

    /** Firmware 2.x: 20 bytes, then one object. */
    byte[] fw2Data() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[MarvellAttestation.FW2_ATTRIBUTE_OFFSET]);
        out.writeBytes(object());
        return out.toByteArray();
    }

    /** Firmware 3.x with this single object. */
    byte[] fw3Data() {
        return fw3Data(this, null);
    }

    /**
     * Firmware 3.x as Marvell documents a key-pair response:
     * {@code ResponseHeader} (code, flags, total size, buffer size), the two
     * 8-byte key handles, then the attribute buffer ({@code TLVKeyInfo} and
     * the objects), which ends where the signature starts.
     */
    static byte[] fw3Data(MarvellBlobs key1, MarvellBlobs key2) {
        byte[] first = key1.object();
        byte[] second = key2 == null ? new byte[0] : key2.object();
        int buffer = 8 + first.length + second.length;
        int total = 32 + buffer + MarvellAttestation.SIGNATURE_SIZE;
        ByteBuffer b = ByteBuffer.allocate(32 + buffer);
        b.putInt(0).putInt(0).putInt(total).putInt(buffer);
        b.putLong(0x37).putLong(0x38);
        b.putShort((short) 1).putShort((short) 0).putShort((short) 8)
                .putShort((short) (key2 == null ? 0 : 8 + first.length));
        b.put(first).put(second);
        return b.array();
    }

    static byte[] signed(byte[] data, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(data);
        byte[] sig = s.sign();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(data);
        out.writeBytes(sig);
        return out.toByteArray();
    }

    static byte[] unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        return b[0] == 0 && b.length > 1 ? Arrays.copyOfRange(b, 1, b.length) : b;
    }
}
