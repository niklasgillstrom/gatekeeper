package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.StringJoiner;

/**
 * Canonical bytes of a Step-7 confirmation response, covered by the
 * gatekeeper's signature in {@link IssuanceConfirmationResponse#getSignature()}.
 *
 * <p>Until 1.6.0 the confirmation response was unsigned. Its integrity rested
 * on TLS alone, so anyone able to answer the confirm call could return a
 * {@code loopClosed=true} envelope and the financial entity would record the
 * supervisory loop as closed. The response is now signed with the same key as
 * the verification receipt.</p>
 *
 * <p>Format: {@code c1|verificationId|loopClosed|publicKeyMatch|
 * expectedPublicKeyFingerprint|actualPublicKeyFingerprint|registryStatus|
 * processedTimestamp|anomalies}. Null renders as the empty string;
 * {@code publicKeyMatch} as {@code true}, {@code false} or empty; anomalies are
 * joined with {@code ;}. Field contents escape {@code %}, {@code |} and
 * {@code ;} by percent-encoding, so no field can desynchronise the form.</p>
 *
 * <p><strong>Cross-repo consequence.</strong> The {@code hsm} repository
 * recomputes these bytes to verify the signature and carries the same golden
 * literal in its {@code ConfirmationCanonicalizerGoldenBytesTest}; both
 * repositories must change together.</p>
 */
public final class ConfirmationCanonicalizer {

    public static final String CANONICAL_VERSION = "c1";

    private ConfirmationCanonicalizer() {
    }

    public static byte[] canonicalize(IssuanceConfirmationResponse r) {
        if (r == null) {
            throw new IllegalArgumentException("Confirmation response must not be null");
        }
        StringJoiner j = new StringJoiner("|");
        j.add(CANONICAL_VERSION);
        j.add(safe(r.getVerificationId()));
        j.add(Boolean.toString(r.isLoopClosed()));
        j.add(r.getPublicKeyMatch() == null ? "" : r.getPublicKeyMatch().toString());
        j.add(safe(r.getExpectedPublicKeyFingerprint()));
        j.add(safe(r.getActualPublicKeyFingerprint()));
        j.add(r.getRegistryStatus() == null ? "" : r.getRegistryStatus().name());
        j.add(safe(r.getProcessedTimestamp()));
        j.add(anomalies(r.getAnomalies()));
        return j.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String anomalies(List<String> anomalies) {
        if (anomalies == null || anomalies.isEmpty()) {
            return "";
        }
        StringJoiner j = new StringJoiner(";");
        anomalies.forEach(a -> j.add(safe(a)));
        return j.toString();
    }

    private static String safe(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("%", "%25").replace("|", "%7C").replace(";", "%3B");
    }
}
