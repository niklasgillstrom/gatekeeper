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
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
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
 *   <li>the PEM bundle named by
 *       {@code gatekeeper.confirmation.issuer-ca-bundle-path}, when the
 *       property is set. The file must then exist, be readable and hold at
 *       least one certificate, or the gatekeeper does not start. Until 1.7.0
 *       a path that named no file, or a file without a certificate, fell
 *       back to the bundle below with a WARN: an operator who had configured
 *       the supervisor's own issuers was running on the demonstration
 *       chain;</li>
 *   <li>otherwise, the classpath resource {@code classpath:issuer-ca-bundle.pem}
 *       that the reference implementation ships with the Getswish CA chain
 *       for demonstration.</li>
 * </ol>
 *
 * <p>A bundle certificate that is issued by another certificate in the same
 * bundle is an intermediate, not a trust anchor: it is offered to the path
 * builder but a path must still end at one of the anchors. Every other
 * bundle certificate is a trust anchor.</p>
 *
 * <p>If no path is configured and the classpath resource yields no usable
 * certificate, the validator loads with an empty anchor set and
 * {@link #validateChain(List)} returns {@code false} for every input. A
 * startup WARN log makes the mis-configuration loud.</p>
 */
@Component
public class IssuerCaValidator {

    private static final Logger log = LoggerFactory.getLogger(IssuerCaValidator.class);

    private final Set<TrustAnchor> trustAnchors;
    private final List<X509Certificate> bundleIntermediates;

    public IssuerCaValidator(
            @Value("${gatekeeper.confirmation.issuer-ca-bundle-path:}") String bundlePath) {
        Set<TrustAnchor> anchors = new HashSet<>();
        List<X509Certificate> intermediates = new ArrayList<>();
        boolean configured = bundlePath != null && !bundlePath.isBlank();
        List<X509Certificate> configuredBundle = configured ? configuredBundle(bundlePath) : List.of();
        try {
            List<X509Certificate> loaded = new ArrayList<>(configuredBundle);
            if (!configured) {
                // No bundle configured: the classpath resource shipped with
                // the reference implementation. This gives the gatekeeper a
                // working default when co-deployed with the GetSwish
                // reference issuer.
                try (var is = getClass().getClassLoader().getResourceAsStream("issuer-ca-bundle.pem")) {
                    if (is != null) {
                        loaded.addAll(parseBundle(is));
                    }
                }
            }
            for (X509Certificate c : loaded) {
                if (isIssuedByAnotherBundleCertificate(c, loaded)) {
                    intermediates.add(c);
                } else {
                    anchors.add(new TrustAnchor(c, null));
                }
            }
            if (anchors.isEmpty()) {
                log.warn("IssuerCaValidator constructed with an EMPTY trust-anchor set. Every "
                        + "Step 7 confirmation will be rejected. Configure "
                        + "gatekeeper.confirmation.issuer-ca-bundle-path=/path/to/issuer-ca-bundle.pem "
                        + "or place issuer-ca-bundle.pem on the classpath.");
            } else {
                log.info("IssuerCaValidator loaded {} issuer CA trust anchor(s) and {} intermediate(s).",
                        anchors.size(), intermediates.size());
            }
        } catch (Exception e) {
            log.error("Failed to load issuer CA bundle — all Step 7 confirmations will be rejected.", e);
        }
        this.trustAnchors = Collections.unmodifiableSet(anchors);
        this.bundleIntermediates = List.copyOf(intermediates);
    }

    /**
     * The certificates of the bundle the operator named.
     *
     * @throws IllegalStateException when the path names no readable file, or
     *     the file holds no certificate; start-up stops
     */
    private static List<X509Certificate> configuredBundle(String bundlePath) {
        Path path = Path.of(bundlePath);
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("gatekeeper.confirmation.issuer-ca-bundle-path names '" + bundlePath
                    + "', which is not a file. The gatekeeper does not fall back to the bundled "
                    + "demonstration issuers; correct the path or unset the property.");
        }
        List<X509Certificate> certificates;
        try (FileInputStream in = new FileInputStream(bundlePath)) {
            certificates = List.copyOf(parseBundle(in));
        } catch (Exception e) {
            throw new IllegalStateException("gatekeeper.confirmation.issuer-ca-bundle-path '" + bundlePath
                    + "' could not be read: " + e, e);
        }
        if (certificates.isEmpty()) {
            throw new IllegalStateException("gatekeeper.confirmation.issuer-ca-bundle-path '" + bundlePath
                    + "' holds no certificate. The gatekeeper does not fall back to the bundled "
                    + "demonstration issuers; correct the file or unset the property.");
        }
        return certificates;
    }

    public boolean validate(X509Certificate cert) {
        if (cert == null) {
            return false;
        }
        return validateChain(List.of(cert));
    }

    /**
     * Build and PKIX-validate a path from the submitted certificate to one
     * of the configured issuer CA trust anchors. The first element of
     * {@code submitted} is the certificate under test; any further
     * elements, together with the intermediates in the bundle, are offered
     * to the {@link CertPathBuilder} as candidate intermediates. Revocation
     * checking is disabled; revocation status of the signing cert is out
     * of scope for the Step 7 binding check — the point is simply that the
     * cert must chain to a known issuer.
     *
     * @return true iff a path from the first certificate to one of the
     *         configured issuer CA trust anchors can be built and validated.
     */
    public boolean validateChain(List<X509Certificate> submitted) {
        if (submitted == null || submitted.isEmpty() || submitted.get(0) == null
                || trustAnchors.isEmpty()) {
            return false;
        }
        X509Certificate cert = submitted.get(0);
        try {
            List<X509Certificate> candidates = new ArrayList<>();
            for (X509Certificate c : submitted) {
                if (c != null) {
                    candidates.add(c);
                }
            }
            candidates.addAll(bundleIntermediates);
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(cert);
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            params.setRevocationEnabled(false);
            params.addCertStore(CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(candidates)));
            CertPathBuilder.getInstance("PKIX").build(params);
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

    private static boolean isIssuedByAnotherBundleCertificate(X509Certificate cert,
                                                              List<X509Certificate> bundle) {
        if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        for (X509Certificate candidate : bundle) {
            if (candidate != cert
                    && candidate.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                try {
                    cert.verify(candidate.getPublicKey());
                    return true;
                } catch (Exception e) {
                    log.debug("Bundle certificate '{}' names '{}' as issuer but its signature does "
                            + "not verify under that certificate's key.",
                            cert.getSubjectX500Principal().getName(),
                            candidate.getSubjectX500Principal().getName());
                }
            }
        }
        return false;
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
