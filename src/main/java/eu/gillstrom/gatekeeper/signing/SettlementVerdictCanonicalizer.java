package eu.gillstrom.gatekeeper.signing;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Canonical bytes of a settlement verdict, the answer of
 * {@code POST /api/v1/verify} (and of a {@code SIGNED} event on
 * {@code POST /v1/attestation/{cc}/lifecycle}), covered by
 * {@code verdictSignatureBase64}.
 *
 * <p>Format, version {@code sv1}, as one UTF-8 string:</p>
 *
 * <pre>
 * sv1|verifiedAt|certSerialHex|issuerDn|digestHex|signatureValid|compliant|reason|auditEntryId|auditEntryHashHex
 * </pre>
 *
 * <ul>
 *   <li>{@code verifiedAt} — {@link java.time.Instant#toString()} of the
 *       verification instant truncated to milliseconds, as it appears in the
 *       response.</li>
 *   <li>{@code certSerialHex} — {@code new BigInteger(s, 16).toString(16)},
 *       where {@code s} is the request's {@code certSerial} without an
 *       optional leading {@code 0x} or {@code 0X}. Nothing else is stripped.</li>
 *   <li>{@code issuerDn} — {@code new X500Principal(requestIssuerDn)
 *       .getName(X500Principal.RFC2253)}.</li>
 *   <li>{@code digestHex} — the request's {@code digestHex} lower-cased
 *       ({@link Locale#ROOT}). It must be hexadecimal of even length
 *       ({@link HexFormat#parseHex}); otherwise it cannot be normalised.</li>
 *   <li>{@code signatureValid}, {@code compliant} — {@code true} or
 *       {@code false}.</li>
 *   <li>A {@code null} string renders as the empty string.</li>
 *   <li>In {@code verifiedAt}, {@code issuerDn}, {@code reason},
 *       {@code auditEntryId} and {@code auditEntryHashHex}, {@code %} is
 *       replaced by {@code %25} first, then {@code |} by {@code %7C}. The
 *       other fields cannot contain {@code |} once normalised.</li>
 * </ul>
 *
 * <p>When {@code certSerial}, {@code issuerDn} or {@code digestHex} cannot be
 * normalised as above, {@link #canonicalize} throws
 * {@link IllegalArgumentException} and the caller returns its response
 * unsigned.</p>
 *
 * <p><strong>Cross-repo consequence.</strong> The {@code railgate}
 * repository recomputes these bytes to verify the verdict and pins the same
 * golden value as {@code SettlementVerdictCanonicalizerGoldenTest}; both
 * repositories must change together.</p>
 */
public final class SettlementVerdictCanonicalizer {

    public static final String CANONICAL_VERSION = "sv1";

    private SettlementVerdictCanonicalizer() {
    }

    /** As {@link #canonicalString}, UTF-8 encoded. */
    public static byte[] canonicalize(String verifiedAt, String certSerial, String issuerDn, String digestHex,
                                      boolean signatureValid, boolean compliant, String reason,
                                      String auditEntryId, String auditEntryHashHex) {
        return canonicalString(verifiedAt, certSerial, issuerDn, digestHex, signatureValid, compliant, reason,
                auditEntryId, auditEntryHashHex).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * The canonical string. {@code certSerial}, {@code issuerDn} and
     * {@code digestHex} are the values from the request, before
     * normalisation.
     *
     * @throws IllegalArgumentException if one of them cannot be normalised
     */
    public static String canonicalString(String verifiedAt, String certSerial, String issuerDn,
                                         String digestHex, boolean signatureValid, boolean compliant,
                                         String reason, String auditEntryId, String auditEntryHashHex) {
        return CANONICAL_VERSION
                + '|' + escape(verifiedAt)
                + '|' + normaliseSerial(certSerial)
                + '|' + escape(normaliseIssuerDn(issuerDn))
                + '|' + normaliseDigestHex(digestHex)
                + '|' + signatureValid
                + '|' + compliant
                + '|' + escape(reason)
                + '|' + escape(auditEntryId)
                + '|' + escape(auditEntryHashHex);
    }

    /**
     * {@code new BigInteger(serial without 0x/0X, 16).toString(16)}.
     *
     * @throws IllegalArgumentException for {@code null} or a value
     *     {@link BigInteger} does not parse as hexadecimal
     */
    public static String normaliseSerial(String certSerial) {
        if (certSerial == null) {
            throw new IllegalArgumentException("certSerial is null");
        }
        String hex = certSerial;
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }
        return new BigInteger(hex, 16).toString(16);
    }

    /**
     * {@code new X500Principal(issuerDn).getName(X500Principal.RFC2253)}.
     *
     * @throws IllegalArgumentException for {@code null} or an unparseable name
     */
    public static String normaliseIssuerDn(String issuerDn) {
        if (issuerDn == null) {
            throw new IllegalArgumentException("issuerDn is null");
        }
        return new X500Principal(issuerDn).getName(X500Principal.RFC2253);
    }

    /**
     * The digest lower-cased. {@code null} renders as the empty string.
     *
     * @throws IllegalArgumentException if it is not hexadecimal of even length
     */
    public static String normaliseDigestHex(String digestHex) {
        if (digestHex == null) {
            return "";
        }
        HexFormat.of().parseHex(digestHex);
        return digestHex.toLowerCase(Locale.ROOT);
    }

    /** {@code null} to empty; {@code %} to {@code %25}, then {@code |} to {@code %7C}. */
    static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("%", "%25").replace("|", "%7C");
    }
}
