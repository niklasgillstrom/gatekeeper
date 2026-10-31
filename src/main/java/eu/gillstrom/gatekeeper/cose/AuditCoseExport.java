package eu.gillstrom.gatekeeper.cose;

import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;

import java.io.ByteArrayOutputStream;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

/**
 * {@code GET /v1/audit/export?...&format=cose}: one COSE_Sign1 per audit
 * entry, concatenated as a CBOR sequence (RFC 8742,
 * {@code application/cbor-seq}).
 *
 * <h2>What the COSE signature is — and is not</h2>
 *
 * <p>Each COSE_Sign1 is signed at export time by the gatekeeper's
 * <em>active</em> signer, whatever key signed the entry originally. It is an
 * <b>export seal</b>: it says "this gatekeeper, under this key, exported these
 * fields". It is not the entry's evidence. The original evidence is the
 * entry's own {@code entrySignature} (made at write time, over the UTF-8 bytes
 * of {@code thisEntryHash}), the hash chain, and the RFC 3161
 * {@code timestampToken} when present — all carried inside the payload, so a
 * verifier can check them without trusting the seal.</p>
 *
 * <h2>Payload</h2>
 *
 * <p>A deterministic CBOR map with text keys (absent when the entry field is
 * {@code null}):</p>
 * <ul>
 *   <li>{@code eventType} (text) — the entry's {@code operation}</li>
 *   <li>{@code sequence} (uint), {@code timestamp} (text,
 *       {@code Instant.toString()} as hashed), {@code principal},
 *       {@code verificationId}, {@code requestDigest},
 *       {@code receiptDigest} (text, Base64 as stored), {@code compliant}
 *       (bool)</li>
 *   <li>{@code canonicalVersion} (text, {@code "v1"} or {@code "v2"} — the
 *       canonical form {@code thisEntryHash} is computed over)</li>
 *   <li>{@code keyFingerprint}, {@code certSerial}, {@code certIssuerDn},
 *       {@code hsmVendor}, {@code hsmSerial}, {@code registryStatus},
 *       {@code hsmFirmwareVersion}, {@code hsmFipsApprovedMode} (text)</li>
 *   <li>{@code prevEntryHash}, {@code prevKeyEntryHash},
 *       {@code thisEntryHash} (text, hex as stored)</li>
 *   <li>{@code entrySignature} (bstr) — the original entry signature</li>
 *   <li>{@code timestampToken} (bstr, DER) — when present</li>
 * </ul>
 *
 * <p>Every field that {@code thisEntryHash} covers is in the payload in the
 * string form that was hashed, so the hash can be recomputed from the
 * payload alone.</p>
 *
 * <h2>Protected header</h2>
 *
 * <p>{@code {1: alg, 4: kid}}, with {@code kid} the 32-byte SHA-256 of the
 * active signing certificate's SubjectPublicKeyInfo — the bytes of
 * {@code signingKeyFingerprintHex} on the JSON export and
 * {@code publicKeyFingerprintHex} on {@code GET /v1/gatekeeper/keys}.</p>
 */
public final class AuditCoseExport {

    /** Media type of the response (RFC 8742). */
    public static final String MEDIA_TYPE = "application/cbor-seq";

    private AuditCoseExport() {
    }

    /** The deterministic CBOR payload map for one entry. */
    public static byte[] payload(AuditEntry e) {
        Cbor.MapBuilder m = Cbor.map()
                .put("eventType", Cbor.text(e.operation()))
                .put("sequence", Cbor.integer(e.sequenceNumber()))
                .put("timestamp", Cbor.text(e.timestamp().toString()))
                .put("principal", Cbor.text(e.mtlsClientPrincipal()))
                .put("verificationId", Cbor.text(e.verificationId()))
                .put("requestDigest", Cbor.text(e.requestDigestBase64()))
                .putTextIfPresent("receiptDigest", e.receiptDigestBase64())
                .put("compliant", Cbor.bool(e.compliant()))
                .put("canonicalVersion", Cbor.text(e.canonicalVersion() == null ? "v1" : e.canonicalVersion()))
                .putTextIfPresent("keyFingerprint", e.keyFingerprintHex())
                .putTextIfPresent("certSerial", e.certSerialHex())
                .putTextIfPresent("certIssuerDn", e.certIssuerDn())
                .putTextIfPresent("hsmVendor", e.hsmVendor())
                .putTextIfPresent("hsmSerial", e.hsmSerial())
                .putTextIfPresent("registryStatus", e.registryStatus())
                .putTextIfPresent("hsmFirmwareVersion", e.hsmFirmwareVersion())
                .putTextIfPresent("hsmFipsApprovedMode", e.hsmFipsApprovedMode())
                .put("prevEntryHash", Cbor.text(e.prevEntryHashHex()))
                .putTextIfPresent("prevKeyEntryHash", e.prevKeyEntryHashHex())
                .put("thisEntryHash", Cbor.text(e.thisEntryHashHex()))
                .put("entrySignature", Cbor.bytes(decode(e.entrySignatureBase64(), "entrySignature", e)));
        if (e.timestampTokenBase64() != null) {
            m.put("timestampToken", Cbor.bytes(decode(e.timestampTokenBase64(), "timestampToken", e)));
        }
        return m.build();
    }

    /**
     * Seal every entry with the active signer and return the CBOR sequence.
     *
     * @param kid the active key's fingerprint bytes
     * @param signerPublicKey the active key (for the ECDSA signature length)
     * @throws CoseSign1.UnsupportedAlgorithmException when the signer's
     *     algorithm has no COSE mapping
     */
    public static byte[] export(List<AuditEntry> entries, ReceiptSigner signer, PublicKey signerPublicKey, byte[] kid) {
        String algorithm = signer.getSignatureAlgorithm();
        CoseSign1.algorithmId(algorithm);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (AuditEntry e : entries) {
            out.writeBytes(CoseSign1.sign(algorithm, signerPublicKey, kid, payload(e), signer::sign));
        }
        return out.toByteArray();
    }

    private static byte[] decode(String base64, String field, AuditEntry e) {
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("audit entry " + e.sequenceNumber() + " has an undecodable " + field, ex);
        }
    }
}
