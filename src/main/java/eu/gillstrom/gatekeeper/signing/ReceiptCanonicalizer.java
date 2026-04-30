package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.model.VerificationResponse;

import java.nio.charset.StandardCharsets;
import java.util.StringJoiner;

/**
 * Produces the canonical byte representation of a verification receipt that
 * is covered by {@link ReceiptSigner#sign(byte[])}.
 *
 * <p>The canonical form is a UTF-8 string built from a fixed, documented
 * ordering of decision-relevant fields, each escaped by URL-encoding the
 * pipe character so ambiguity between field separators and field contents
 * is impossible. Null fields are rendered as the empty string; boolean fields
 * render as {@code true} / {@code false}; instants as ISO-8601 with offset
 * {@code Z}. A {@code v1} version marker is prefixed so that future canonical
 * changes can be introduced non-ambiguously.</p>
 *
 * <p>If a future receipt field becomes decision-relevant it MUST be added
 * here, and the version marker MUST be bumped. Signatures produced under
 * {@code v1} will still validate against the v1 canonicalizer; a mixed-
 * version receipt simply won't verify.</p>
 */
public final class ReceiptCanonicalizer {

    private ReceiptCanonicalizer() {
    }

    public static final String CANONICAL_VERSION = "v1";

    public static byte[] canonicalize(VerificationResponse r) {
        if (r == null) {
            throw new IllegalArgumentException("Receipt must not be null");
        }
        StringJoiner j = new StringJoiner("|");
        j.add(CANONICAL_VERSION);
        j.add(safe(r.getVerificationId()));
        j.add(Boolean.toString(r.isCompliant()));
        j.add(r.getVerificationTimestamp() == null ? "" : r.getVerificationTimestamp().toString());
        j.add(safe(r.getPublicKeyFingerprint()));
        j.add(safe(r.getPublicKeyAlgorithm()));
        j.add(safe(r.getHsmVendor()));
        j.add(safe(r.getHsmModel()));
        j.add(safe(r.getHsmSerialNumber()));
        j.add(safe(r.getSupplierIdentifier()));
        j.add(safe(r.getSupplierName()));
        j.add(safe(r.getKeyPurpose()));
        j.add(safe(r.getCountryCode()));

        // Key properties — decision-relevant
        if (r.getKeyProperties() != null) {
            j.add(Boolean.toString(r.getKeyProperties().isGeneratedOnDevice()));
            j.add(Boolean.toString(r.getKeyProperties().isExportable()));
            j.add(Boolean.toString(r.getKeyProperties().isAttestationChainValid()));
            j.add(Boolean.toString(r.getKeyProperties().isPublicKeyMatchesAttestation()));
        } else {
            j.add("").add("").add("").add("");
        }

        // DORA article bits — decision-relevant
        if (r.getDoraCompliance() != null) {
            var d = r.getDoraCompliance();
            j.add(Boolean.toString(d.isArticle5_2b()));
            j.add(Boolean.toString(d.isArticle6_10()));
            j.add(Boolean.toString(d.isArticle9_3c()));
            j.add(Boolean.toString(d.isArticle9_3d()));
            j.add(Boolean.toString(d.isArticle9_4d()));
            j.add(Boolean.toString(d.isArticle28_1a()));
        } else {
            j.add("").add("").add("").add("").add("").add("");
        }

        return j.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Escape pipe characters in field values by percent-encoding, so a field
     * that happens to contain {@code |} cannot desynchronise the canonical form.
     */
    private static String safe(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("%", "%25").replace("|", "%7C");
    }
}
