package eu.gillstrom.gatekeeper.cose;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import java.util.function.Function;

/**
 * COSE_Sign1 (RFC 9052 §4.2) construction with a detached signing function.
 *
 * <pre>
 * COSE_Sign1 = #6.18([ protected : bstr .cbor {1: alg, 4: kid},
 *                      unprotected : {},
 *                      payload : bstr,
 *                      signature : bstr ])
 * Sig_structure = [ "Signature1", protected, external_aad = h'', payload ]
 * </pre>
 *
 * <p>The signature is computed over the deterministic CBOR encoding of
 * {@code Sig_structure}. For RSA (RFC 8812: RS256/RS384/RS512, i.e.
 * RSASSA-PKCS1-v1_5) the JCA signature is used as is. For ECDSA the JCA
 * DER {@code ECDSA-Sig-Value} is converted to the fixed-length
 * {@code r || s} that RFC 9053 §2.1 requires, each half as long as the
 * curve order.</p>
 */
public final class CoseSign1 {

    /** CBOR tag of COSE_Sign1. */
    public static final long TAG = 18;

    private static final int HEADER_ALG = 1;
    private static final int HEADER_KID = 4;

    /** JCA signature algorithm → COSE algorithm identifier (RFC 9053, RFC 8812). */
    private static final Map<String, Integer> ALGORITHMS = Map.of(
            "SHA256withRSA", -257,
            "SHA384withRSA", -258,
            "SHA512withRSA", -259,
            "SHA256withECDSA", -7,
            "SHA384withECDSA", -35,
            "SHA512withECDSA", -36);

    private CoseSign1() {
    }

    /** Thrown for a JCA algorithm with no COSE mapping here. */
    public static final class UnsupportedAlgorithmException extends RuntimeException {
        public UnsupportedAlgorithmException(String jcaAlgorithm) {
            super("No COSE algorithm mapping for " + jcaAlgorithm + "; supported: " + ALGORITHMS.keySet());
        }
    }

    /** The COSE algorithm identifier for a JCA algorithm name. */
    public static int algorithmId(String jcaAlgorithm) {
        Integer id = ALGORITHMS.get(jcaAlgorithm);
        if (id == null) {
            throw new UnsupportedAlgorithmException(jcaAlgorithm);
        }
        return id;
    }

    static boolean isEcdsa(int alg) {
        return alg == -7 || alg == -35 || alg == -36;
    }

    /** Encoded protected header map {@code {1: alg, 4: kid}}. */
    public static byte[] protectedHeader(int alg, byte[] kid) {
        return Cbor.map()
                .put(HEADER_ALG, Cbor.integer(alg))
                .put(HEADER_KID, Cbor.bytes(kid))
                .build();
    }

    /** Encoded {@code Sig_structure} with empty external AAD. */
    public static byte[] sigStructure(byte[] protectedHeader, byte[] payload) {
        return Cbor.array(
                Cbor.text("Signature1"),
                Cbor.bytes(protectedHeader),
                Cbor.bytes(new byte[0]),
                Cbor.bytes(payload));
    }

    /**
     * Build and sign one COSE_Sign1.
     *
     * @param jcaAlgorithm the signer's JCA algorithm name
     * @param signerPublicKey the signer's public key (for the ECDSA
     *     signature length)
     * @param kid key identifier for the protected header
     * @param payload the payload bytes
     * @param jcaSign signs bytes with {@code jcaAlgorithm} and returns the JCA
     *     signature (DER for ECDSA)
     */
    public static byte[] sign(String jcaAlgorithm, PublicKey signerPublicKey, byte[] kid, byte[] payload,
                              Function<byte[], byte[]> jcaSign) {
        int alg = algorithmId(jcaAlgorithm);
        byte[] protectedHeader = protectedHeader(alg, kid);
        byte[] signature = jcaSign.apply(sigStructure(protectedHeader, payload));
        if (isEcdsa(alg)) {
            signature = derToRaw(signature, fieldLength(signerPublicKey));
        }
        return Cbor.tag(TAG, Cbor.array(
                Cbor.bytes(protectedHeader),
                Cbor.map().build(),
                Cbor.bytes(payload),
                Cbor.bytes(signature)));
    }

    /** Length in bytes of each of r and s for an EC key: the byte length of the curve order. */
    static int fieldLength(PublicKey key) {
        if (!(key instanceof ECPublicKey ec)) {
            throw new IllegalArgumentException("ECDSA algorithm configured but the signing key is " + key.getAlgorithm());
        }
        return (ec.getParams().getOrder().bitLength() + 7) / 8;
    }

    /** DER {@code ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }} → {@code r || s}. */
    public static byte[] derToRaw(byte[] der, int fieldLength) {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        if (seq.size() != 2) {
            throw new IllegalArgumentException("ECDSA signature is not a two-element SEQUENCE");
        }
        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
        byte[] out = new byte[2 * fieldLength];
        writeFixed(r, out, 0, fieldLength);
        writeFixed(s, out, fieldLength, fieldLength);
        return out;
    }

    private static void writeFixed(BigInteger v, byte[] out, int offset, int length) {
        if (v.bitLength() > 8 * length) {
            throw new IllegalArgumentException("ECDSA signature component longer than the curve order");
        }
        System.arraycopy(BigIntegers.asUnsignedByteArray(length, v), 0, out, offset, length);
    }
}
