package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Start-up verification of the HSM attestation of the gatekeeper's own
 * signing key — the key that signs receipts, audit entries, anchors and
 * exports ({@code gatekeeper.signing.attestation.*}).
 *
 * <p>Configuration:</p>
 * <pre>
 * gatekeeper.signing.attestation.vendor=YUBICO|SECUROSYS     # blank = not configured (default)
 * # YUBICO
 * gatekeeper.signing.attestation.yubico.chain-path=...       # PEM: attestation cert, device cert, Yubico intermediate(s)
 * # SECUROSYS
 * gatekeeper.signing.attestation.securosys.xml-path=...      # the attestation XML, raw bytes as delivered by the HSM
 * gatekeeper.signing.attestation.securosys.signature-path=...# Base64 text of the signature over those bytes
 * gatekeeper.signing.attestation.securosys.chain-path=...    # PEM: attestation cert first, then its issuers
 * </pre>
 *
 * <p>The evidence is verified with the same {@link YubicoVerifier} or
 * {@link SecurosysVerifier} that verifies supervised entities' keys, against
 * the public key of the first certificate of
 * {@link ReceiptSigner#getSigningCertificatePem()} — the active signing
 * certificate. Outcomes:</p>
 * <ul>
 *   <li><b>configured and valid</b> — the result and the evidence are kept
 *       and published on {@code GET /v1/gatekeeper/keys};
 *       {@code GET /v1/gatekeeper/health} reports {@code activeKeyAttested=true}.</li>
 *   <li><b>configured and invalid, or unreadable</b> — the constructor throws
 *       and the application does not start.</li>
 *   <li><b>not configured</b> — a WARN at start-up, as the ephemeral signer
 *       gives, and nothing is published.</li>
 * </ul>
 *
 * <p>The attestation is checked once, at start-up. It is a statement about
 * how the key was generated and whether it can leave the HSM; it says nothing
 * about who can use the key while it is inside the HSM.</p>
 */
@Component
public class SigningKeyAttestation {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyAttestation.class);

    /** Vendors whose attestation of the signing key can be verified. */
    public enum Vendor { YUBICO, SECUROSYS }

    private final KeyAttestation attestation;

    @Autowired
    public SigningKeyAttestation(
            ReceiptSigner signer,
            YubicoVerifier yubicoVerifier,
            SecurosysVerifier securosysVerifier,
            @Value("${gatekeeper.signing.attestation.vendor:}") String vendor,
            @Value("${gatekeeper.signing.attestation.yubico.chain-path:}") String yubicoChainPath,
            @Value("${gatekeeper.signing.attestation.securosys.xml-path:}") String securosysXmlPath,
            @Value("${gatekeeper.signing.attestation.securosys.signature-path:}") String securosysSignaturePath,
            @Value("${gatekeeper.signing.attestation.securosys.chain-path:}") String securosysChainPath) {
        if (vendor == null || vendor.isBlank()) {
            this.attestation = null;
            log.warn("SigningKeyAttestation: the gatekeeper signing key is NOT attested "
                    + "(gatekeeper.signing.attestation.vendor is not set). Nothing on GET /v1/gatekeeper/keys "
                    + "shows that the key which signs receipts, audit entries and anchors was generated in, and "
                    + "cannot leave, an HSM. Configure gatekeeper.signing.attestation.* with the HSM's attestation "
                    + "of the signing key before any relying party treats the audit trail as HSM-sealed.");
            return;
        }
        Vendor v;
        try {
            v = Vendor.valueOf(vendor.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("gatekeeper.signing.attestation.vendor must be YUBICO or SECUROSYS, got '"
                    + vendor + "'");
        }
        PublicKey signingKey = activeSigningKey(signer);
        try {
            this.attestation = switch (v) {
                case YUBICO -> verifyYubico(yubicoVerifier, required(yubicoChainPath, "yubico.chain-path"), signingKey);
                case SECUROSYS -> verifySecurosys(securosysVerifier,
                        required(securosysXmlPath, "securosys.xml-path"),
                        required(securosysSignaturePath, "securosys.signature-path"),
                        required(securosysChainPath, "securosys.chain-path"), signingKey);
            };
        } catch (IOException e) {
            throw new IllegalStateException("gatekeeper.signing.attestation: evidence could not be read: "
                    + e.getMessage(), e);
        }
        if (!attestation.valid()) {
            throw new IllegalStateException("gatekeeper.signing.attestation: the " + v
                    + " attestation of the active signing key did not verify (chainValid=" + attestation.chainValid()
                    + ", publicKeyMatch=" + attestation.publicKeyMatch() + ", keyOrigin=" + attestation.keyOrigin()
                    + ", exportable=" + attestation.exportable() + "): " + attestation.errors());
        }
        log.info("SigningKeyAttestation: active signing key attested by {} HSM serial={}, keyOrigin={}, "
                        + "exportable={}, root sha256={}",
                attestation.vendor(), attestation.hsmSerial(), attestation.keyOrigin(), attestation.exportable(),
                attestation.verifiedAgainstRootSha256Hex());
    }

    /** The verified attestation, present only when configured (and, therefore, valid). */
    public Optional<KeyAttestation> attestation() {
        return Optional.ofNullable(attestation);
    }

    /** Whether {@code gatekeeper.signing.attestation.vendor} is configured. */
    public boolean isConfigured() {
        return attestation != null;
    }

    /** {@code true} when the active signing key's attestation was configured and verified. */
    public boolean isActiveKeyAttested() {
        return attestation != null && attestation.valid();
    }

    private static KeyAttestation verifyYubico(YubicoVerifier verifier, Path chainPath, PublicKey signingKey)
            throws IOException {
        List<String> chain = readPemCertificates(chainPath);
        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(chain, signingKey);
        return new KeyAttestation(
                Vendor.YUBICO.name(),
                r.getDeviceSerial(),
                r.isValid(),
                r.isChainValid(),
                r.isPublicKeyMatch(),
                null,
                r.getKeyOrigin(),
                r.isKeyExportable(),
                r.getFirmware(),
                sha256Hex(verifier.getRootCertificate()),
                Instant.now(),
                List.copyOf(r.getErrors()),
                new KeyAttestation.Evidence(chain, null, null));
    }

    private static KeyAttestation verifySecurosys(SecurosysVerifier verifier, Path xmlPath, Path signaturePath,
                                                  Path chainPath, PublicKey signingKey) throws IOException {
        String xmlBase64 = Base64.getEncoder().encodeToString(Files.readAllBytes(xmlPath));
        String signatureBase64 = Files.readString(signaturePath, StandardCharsets.US_ASCII).replaceAll("\\s", "");
        try {
            Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException e) {
            throw new IOException(signaturePath + " does not hold Base64 text", e);
        }
        List<String> chain = readPemCertificates(chainPath);
        SecurosysVerifier.SecurosysAttestationResult r =
                verifier.verifySecurosysAttestation(xmlBase64, signatureBase64, chain, signingKey);
        return new KeyAttestation(
                Vendor.SECUROSYS.name(),
                r.getHsmSerialNumber(),
                r.isValid(),
                r.isChainValid(),
                r.isPublicKeyMatch(),
                r.isSignatureValid(),
                r.getKeyOrigin(),
                r.isExtractable(),
                null,
                sha256Hex(verifier.getRootCertificate()),
                Instant.now(),
                List.copyOf(r.getErrors()),
                new KeyAttestation.Evidence(chain, xmlBase64, signatureBase64));
    }

    private static Path required(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("gatekeeper.signing.attestation." + name + " is required for this vendor");
        }
        return Paths.get(value.trim());
    }

    private static PublicKey activeSigningKey(ReceiptSigner signer) {
        try {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(signer.getSigningCertificatePem().getBytes(StandardCharsets.UTF_8)));
            return cert.getPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("active signing certificate could not be parsed", e);
        }
    }

    /** Every certificate in a PEM file, re-encoded one PEM block per element, in file order. */
    static List<String> readPemCertificates(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        List<String> out = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (Certificate c : cf.generateCertificates(new ByteArrayInputStream(bytes))) {
                out.add("-----BEGIN CERTIFICATE-----\n"
                        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(c.getEncoded())
                        + "\n-----END CERTIFICATE-----\n");
            }
        } catch (Exception e) {
            throw new IOException(path + " could not be parsed as PEM certificates: " + e.getMessage(), e);
        }
        if (out.isEmpty()) {
            throw new IOException(path + " holds no certificate");
        }
        return List.copyOf(out);
    }

    private static String sha256Hex(X509Certificate cert) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException("root certificate could not be fingerprinted", e);
        }
    }
}
