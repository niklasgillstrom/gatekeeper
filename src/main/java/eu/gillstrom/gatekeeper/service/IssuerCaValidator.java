package eu.gillstrom.gatekeeper.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Validates that a signing certificate submitted in a Step 7 issuance
 * confirmation is issued by one of the configured authorised issuer CAs.
 *
 * <p>Purpose: the gatekeeper cannot rely on a client-supplied certificate's
 * existence alone — the certificate must chain to a trusted issuer CA
 * (the NCA's list of participant PKIs, e.g. Getswish AB's root). Without
 * this check, an attacker with a valid verificationId could post an
 * arbitrary certificate for comparison against the approved public-key
 * fingerprint.</p>
 *
 * <p>Trust anchors are loaded from:</p>
 * <ol>
 *   <li>A PEM bundle configured via
 *       {@code gatekeeper.confirmation.issuer-ca-bundle-path} (file path), OR</li>
 *   <li>A fallback classpath resource {@code classpath:issuer-ca-bundle.pem}
 *       that the reference implementation ships with the Getswish CA chain
 *       for demonstration.</li>
 * </ol>
 *
 * <p>If neither source yields any usable certificates, the validator loads
 * with an empty anchor set and {@link #validate(X509Certificate)} returns
 * {@code false} for every input. A startup WARN log makes the mis-
 * configuration loud.</p>
 */
@Component
public class IssuerCaValidator {

    private static final Logger log = LoggerFactory.getLogger(IssuerCaValidator.class);

    private final Set<TrustAnchor> trustAnchors;

    public IssuerCaValidator(
            @Value("${gatekeeper.confirmation.issuer-ca-bundle-path:}") String bundlePath) {
        Set<TrustAnchor> anchors = new HashSet<>();
        try {
            List<X509Certificate> loaded = new ArrayList<>();
            if (bundlePath != null && !bundlePath.isBlank()) {
                Path p = Path.of(bundlePath);
                if (Files.exists(p)) {
                    try (FileInputStream in = new FileInputStream(bundlePath)) {
                        loaded.addAll(parseBundle(in));
                    }
                } else {
                    log.warn("IssuerCaValidator: configured bundle path '{}' does not exist.", bundlePath);
                }
            }
            if (loaded.isEmpty()) {
                // Fallback: try classpath resource shipped with the reference
                // implementation. This gives the gatekeeper a working default
                // when co-deployed with the GetSwish reference issuer.
                try (var is = getClass().getClassLoader().getResourceAsStream("issuer-ca-bundle.pem")) {
                    if (is != null) {
                        loaded.addAll(parseBundle(is));
                    }
                }
            }
            for (X509Certificate c : loaded) {
                anchors.add(new TrustAnchor(c, null));
            }
            if (anchors.isEmpty()) {
                log.warn("IssuerCaValidator constructed with an EMPTY trust-anchor set. Every "
                        + "Step 7 confirmation will be rejected. Configure "
                        + "gatekeeper.confirmation.issuer-ca-bundle-path=/path/to/issuer-ca-bundle.pem "
                        + "or place issuer-ca-bundle.pem on the classpath.");
            } else {
                log.info("IssuerCaValidator loaded {} issuer CA trust anchor(s).", anchors.size());
            }
        } catch (Exception e) {
            log.error("Failed to load issuer CA bundle — all Step 7 confirmations will be rejected.", e);
        }
        this.trustAnchors = Collections.unmodifiableSet(anchors);
    }

    /**
     * PKIX-validate the submitted certificate against the configured issuer
     * CA trust anchors. Revocation checking is disabled; revocation status
     * of the signing cert is out of scope for the Step 7 binding check —
     * the point is simply that the cert must chain to a known issuer.
     *
     * @return true iff the cert chains cryptographically to one of the
     *         configured issuer CA trust anchors.
     */
    public boolean validate(X509Certificate cert) {
        if (cert == null || trustAnchors.isEmpty()) {
            return false;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath path = cf.generateCertPath(List.of(cert));
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            CertPathValidator v = CertPathValidator.getInstance("PKIX");
            v.validate(path, params);
            return true;
        } catch (Exception e) {
            log.warn("Step 7 issuer-CA validation failed for subject '{}': {}",
                    cert.getSubjectX500Principal().getName(), e.getMessage());
            return false;
        }
    }

    public int trustAnchorCount() {
        return trustAnchors.size();
    }

    private static Collection<X509Certificate> parseBundle(java.io.InputStream in) throws Exception {
        byte[] bytes = in.readAllBytes();
        String pem = new String(bytes, StandardCharsets.UTF_8);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> out = new ArrayList<>();
        for (String part : pem.split("-----END CERTIFICATE-----")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) continue;
            if (!trimmed.endsWith("-----END CERTIFICATE-----")) {
                trimmed += "\n-----END CERTIFICATE-----";
            }
            try {
                X509Certificate c = (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(trimmed.getBytes(StandardCharsets.UTF_8)));
                out.add(c);
            } catch (Exception e) {
                log.warn("Skipping unparsable certificate in issuer CA bundle: {}", e.getMessage());
            }
        }
        return out;
    }
}
