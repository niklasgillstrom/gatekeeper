package eu.gillstrom.gatekeeper.util;

import java.security.MessageDigest;
import java.security.PublicKey;

/**
 * The single canonical public-key fingerprint format used across gatekeeper.
 *
 * <p>SHA-256 over the SubjectPublicKeyInfo encoding, rendered as LOWERCASE hex
 * with colon separators ({@code "ab:cd:..."}).</p>
 *
 * <p>This class exists because the format was previously reimplemented at four
 * sites — two in production code, two in tests — and the two production
 * implementations disagreed on case. Registry entries were written in lowercase
 * by {@code VerificationService} and looked up in uppercase by
 * {@code SignatureVerificationService}, whose lookup is a case-sensitive
 * {@code equals}. Every settlement-time query therefore fell through to
 * CERT_NOT_FOUND and {@code /api/v1/verify} could never return
 * compliant=true. Both test doubles recomputed the fingerprint in the uppercase
 * form, so the defect was invisible.</p>
 *
 * <p>Do not reimplement this format. Call it from production code and from
 * tests alike, so that a test cannot encode a format the production writer does
 * not produce.</p>
 */
public final class Fingerprints {

    private Fingerprints() {
    }

    /** Canonical fingerprint of a public key. */
    public static String ofPublicKey(PublicKey key) {
        return ofSubjectPublicKeyInfo(key.getEncoded());
    }

    /** Canonical fingerprint of an already-encoded SubjectPublicKeyInfo. */
    public static String ofSubjectPublicKeyInfo(byte[] subjectPublicKeyInfo) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(subjectPublicKeyInfo);
            StringBuilder sb = new StringBuilder(hash.length * 3);
            for (int i = 0; i < hash.length; i++) {
                if (i > 0) {
                    sb.append(':');
                }
                sb.append(String.format("%02x", hash[i] & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            // SHA-256 is mandatory in every JRE (JCA guarantee).
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
