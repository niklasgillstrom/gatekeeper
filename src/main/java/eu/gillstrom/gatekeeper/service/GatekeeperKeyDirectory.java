package eu.gillstrom.gatekeeper.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Directory of every gatekeeper signing key — both the active key in use
 * for new receipts and any retired keys that may still appear on
 * historical receipts within the DORA Article 28(6) 5-year retention
 * window.
 *
 * <p>This bean is the source of truth for the {@code GET /v1/gatekeeper/keys}
 * endpoint that supervisors and relying parties (e.g. Finansinspektionen,
 * the certificate issuer) consume to verify gatekeeper-signed evidence
 * retroactively. Without a published key directory, a relying party
 * cannot validate a receipt that was signed by a now-retired key.</p>
 *
 * <p>Retired keys are configured via the {@code gatekeeper.signing.retired-keys}
 * property as a comma-separated list of PEM strings (each PEM may contain
 * either {@code \n} line breaks or {@code \\n} escape sequences). Each
 * entry is parsed as an X.509 certificate, fingerprinted, and surfaced
 * with status {@code RETIRED}. A malformed PEM is logged at WARN and
 * skipped; the gatekeeper does not refuse to start over a misconfigured
 * historical key.</p>
 *
 * <p>Legal basis:</p>
 * <ul>
 *   <li>DORA Article 28(6) — 5-year retention obligates retroactive
 *       verifiability of receipts up to five years old.</li>
 *   <li>EBA Regulation 1093/2010 Article 35(1) — supervisory access to
 *       the signing certificates a supervisor needs to verify records.</li>
 * </ul>
 */
@Component
public class GatekeeperKeyDirectory {

    private static final Logger log = LoggerFactory.getLogger(GatekeeperKeyDirectory.class);

    private final ReceiptSigner activeSigner;
    private final String retiredKeysRaw;
    private final List<KeyEntry> directory = new ArrayList<>();
    private KeyEntry activeEntry;

    public GatekeeperKeyDirectory(
            ReceiptSigner activeSigner,
            @Value("${gatekeeper.signing.retired-keys:}") String retiredKeysRaw) {
        this.activeSigner = activeSigner;
        this.retiredKeysRaw = retiredKeysRaw == null ? "" : retiredKeysRaw;
    }

    @PostConstruct
    public void initialise() {
        // Active key first, so it always heads the directory.
        try {
            X509Certificate active = parseFirstCertificate(activeSigner.getSigningCertificatePem());
            this.activeEntry = toKeyEntry(active, activeSigner.getSigningCertificatePem(), "ACTIVE");
            directory.add(activeEntry);
            log.info("GatekeeperKeyDirectory: active signing key registered: keyId={}, fingerprint={}, validUntil={}",
                    activeEntry.keyId(), activeEntry.publicKeyFingerprintHex(), activeEntry.validTo());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to register active gatekeeper signing key", e);
        }

        // Retired keys (best-effort: a malformed historical entry is
        // logged but does not prevent boot).
        if (!retiredKeysRaw.isBlank()) {
            String[] pemBlobs = retiredKeysRaw.split(",");
            for (String pemBlob : pemBlobs) {
                String pem = normaliseRetiredPem(pemBlob);
                if (pem.isBlank()) {
                    continue;
                }
                try {
                    X509Certificate cert = parseFirstCertificate(pem);
                    KeyEntry retired = toKeyEntry(cert, pem, "RETIRED");
                    directory.add(retired);
                    log.info("GatekeeperKeyDirectory: retired signing key registered: keyId={}, fingerprint={}, validUntil={}",
                            retired.keyId(), retired.publicKeyFingerprintHex(), retired.validTo());
                } catch (Exception e) {
                    log.warn("GatekeeperKeyDirectory: skipping malformed retired key PEM: {}", e.toString());
                }
            }
        }
    }

    /**
     * Active signing keys (typically one). Returned as an unmodifiable
     * snapshot so callers cannot mutate the internal directory.
     */
    public List<KeyEntry> activeKeys() {
        List<KeyEntry> out = new ArrayList<>();
        for (KeyEntry e : directory) {
            if ("ACTIVE".equals(e.status())) {
                out.add(e);
            }
        }
        return Collections.unmodifiableList(out);
    }

    /**
     * Active and retired keys, ordered active-first then retired in
     * configuration order. Returned as an unmodifiable snapshot.
     */
    public List<KeyEntry> allKeys() {
        return Collections.unmodifiableList(new ArrayList<>(directory));
    }

    /**
     * Look up a key by hex SHA-256 fingerprint of its DER-encoded public
     * key. Used by relying parties to confirm which directory entry was
     * used to sign a particular receipt or audit anchor.
     */
    public Optional<KeyEntry> findByFingerprint(String fingerprintHex) {
        if (fingerprintHex == null || fingerprintHex.isBlank()) {
            return Optional.empty();
        }
        for (KeyEntry e : directory) {
            // Constant-time compare: the fingerprint is authenticated data.
            if (MessageDigest.isEqual(
                    e.publicKeyFingerprintHex().getBytes(StandardCharsets.UTF_8),
                    fingerprintHex.getBytes(StandardCharsets.UTF_8))) {
                return Optional.of(e);
            }
        }
        return Optional.empty();
    }

    /**
     * Convenience accessor for callers that want the fingerprint of the
     * currently-active signing key (e.g. {@code AuditAnchor}).
     */
    public String activeFingerprintHex() {
        return activeEntry == null ? "" : activeEntry.publicKeyFingerprintHex();
    }

    private static String normaliseRetiredPem(String raw) {
        // Properties files frequently encode newlines as the two-character
        // sequence "\n"; convert those to real newlines so the certificate
        // factory can parse the PEM.
        return raw.replace("\\n", "\n").trim();
    }

    private static X509Certificate parseFirstCertificate(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    }

    private static KeyEntry toKeyEntry(X509Certificate cert, String pem, String status) throws Exception {
        PublicKey pk = cert.getPublicKey();
        String fingerprint = sha256Hex(pk.getEncoded());
        String keyId = cert.getSubjectX500Principal().getName()
                + "/serial=" + cert.getSerialNumber().toString(16);
        return new KeyEntry(
                keyId,
                pem,
                fingerprint,
                cert.getNotBefore().toInstant(),
                cert.getNotAfter().toInstant(),
                pk.getAlgorithm(),
                status);
    }

    private static String sha256Hex(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(in);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Public, supervisor-facing view of a single signing key.
     *
     * @param keyId fully-qualified identifier (subject DN + serial)
     * @param certificatePem PEM-encoded certificate (may be a chain)
     * @param publicKeyFingerprintHex hex SHA-256 of the DER-encoded public key
     * @param validFrom certificate notBefore
     * @param validTo certificate notAfter
     * @param algorithm public-key algorithm (e.g. "RSA", "EC")
     * @param status {@code "ACTIVE"} or {@code "RETIRED"}
     */
    public record KeyEntry(
            String keyId,
            String certificatePem,
            String publicKeyFingerprintHex,
            Instant validFrom,
            Instant validTo,
            String algorithm,
            String status) {
    }
}
