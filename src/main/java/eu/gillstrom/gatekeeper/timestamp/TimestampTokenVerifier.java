package eu.gillstrom.gatekeeper.timestamp;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Validates an RFC 3161 time-stamp token against the data it is claimed to
 * cover and a configured set of trusted TSA certificates.
 *
 * <p>Three checks, all of which must pass:</p>
 * <ol>
 *   <li><b>Imprint.</b> The token's message-imprint algorithm is SHA-256 and
 *       its imprint equals SHA-256 of the data (constant-time compare).</li>
 *   <li><b>Signature.</b> The signer certificate is taken from the token's
 *       own certificate set or, when the token carries none, from the trusted
 *       set, matched by the CMS SignerIdentifier. BouncyCastle's
 *       {@link TimeStampToken#validate} then checks the ESS
 *       signing-certificate binding, that the certificate has the critical
 *       {@code id-kp-timeStamping} extended key usage, that it was valid at
 *       {@code genTime}, and the CMS signature itself.</li>
 *   <li><b>Chain.</b> The signer certificate is one of the trusted
 *       certificates, or a PKIX path is built from it to one of them (every
 *       trusted certificate is a trust anchor; intermediates may come from
 *       the token or the trusted file). The path is validated at
 *       {@code genTime}, not at the time of checking, so a token stays
 *       verifiable after the TSA certificate expires. Revocation is not
 *       checked.</li>
 * </ol>
 *
 * <p>The TSA policy is not checked here: {@link HttpTsaClient} checks the
 * requested policy when the token is obtained, and a later policy change
 * must not invalidate tokens already issued.</p>
 */
public final class TimestampTokenVerifier {

    private final List<X509Certificate> trusted;
    private final Set<TrustAnchor> anchors;

    public TimestampTokenVerifier(List<X509Certificate> trustedCertificates) {
        if (trustedCertificates == null || trustedCertificates.isEmpty()) {
            throw new IllegalArgumentException("at least one trusted TSA certificate is required");
        }
        this.trusted = List.copyOf(trustedCertificates);
        Set<TrustAnchor> set = new HashSet<>();
        for (X509Certificate c : trusted) {
            set.add(new TrustAnchor(c, null));
        }
        this.anchors = Set.copyOf(set);
    }

    /** Load every certificate in a PEM file (one or more {@code CERTIFICATE} blocks). */
    public static TimestampTokenVerifier fromPemFile(Path pemFile) throws IOException {
        byte[] bytes = Files.readAllBytes(pemFile);
        List<X509Certificate> certs = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (Certificate c : cf.generateCertificates(new ByteArrayInputStream(bytes))) {
                certs.add((X509Certificate) c);
            }
        } catch (Exception e) {
            throw new IOException("Trusted TSA certificates in " + pemFile + " could not be parsed: " + e.getMessage(), e);
        }
        if (certs.isEmpty()) {
            throw new IOException("No certificate in trusted TSA certificate file " + pemFile);
        }
        return new TimestampTokenVerifier(certs);
    }

    public List<X509Certificate> trustedCertificates() {
        return trusted;
    }

    /**
     * Validate a token over {@code data} (the token's imprint must be
     * SHA-256 of these bytes).
     */
    public Verification verify(byte[] tokenDer, byte[] data) {
        TimeStampToken token;
        try {
            token = new TimeStampToken(new CMSSignedData(tokenDer));
        } catch (Exception e) {
            return Verification.failure(false, false, false, null, null, null, "token is not a parseable RFC 3161 token: " + e.getMessage());
        }
        TimeStampTokenInfo info = token.getTimeStampInfo();
        Instant genTime = info.getGenTime() == null ? null : info.getGenTime().toInstant();
        String policy = info.getPolicy() == null ? null : info.getPolicy().getId();

        boolean imprintMatches;
        try {
            byte[] expected = MessageDigest.getInstance("SHA-256").digest(data);
            imprintMatches = TSPAlgorithms.SHA256.equals(info.getMessageImprintAlgOID())
                    && MessageDigest.isEqual(expected, info.getMessageImprintDigest());
        } catch (Exception e) {
            imprintMatches = false;
        }
        if (!imprintMatches) {
            return Verification.failure(false, false, false, genTime, null, policy,
                    "message imprint is not SHA-256 of the covered data");
        }

        X509CertificateHolder signerHolder = findSignerCertificate(token);
        if (signerHolder == null) {
            return Verification.failure(true, false, false, genTime, null, policy,
                    "TSA signer certificate is neither in the token nor among the trusted certificates");
        }
        String tsaSubject = signerHolder.getSubject().toString();
        try {
            token.validate(new JcaSimpleSignerInfoVerifierBuilder().build(signerHolder));
        } catch (Exception e) {
            return Verification.failure(true, false, false, genTime, tsaSubject, policy,
                    "token signature did not validate: " + e.getMessage());
        }

        String chainError = chainError(signerHolder, token, genTime);
        if (chainError != null) {
            return Verification.failure(true, true, false, genTime, tsaSubject, policy, chainError);
        }
        return new Verification(true, true, true, true, genTime, tsaSubject, policy, null);
    }

    private X509CertificateHolder findSignerCertificate(TimeStampToken token) {
        SignerId sid = token.getSID();
        @SuppressWarnings("unchecked")
        Store<X509CertificateHolder> store = token.getCertificates();
        if (store != null) {
            Collection<X509CertificateHolder> matches = store.getMatches(sid);
            if (!matches.isEmpty()) {
                return matches.iterator().next();
            }
        }
        for (X509Certificate c : trusted) {
            try {
                X509CertificateHolder holder = new JcaX509CertificateHolder(c);
                if (sid.match(holder)) {
                    return holder;
                }
            } catch (Exception ignored) {
                // An unencodable trusted certificate cannot be the signer.
            }
        }
        return null;
    }

    /** {@code null} if the signer chains to a trusted certificate at {@code genTime}. */
    private String chainError(X509CertificateHolder signerHolder, TimeStampToken token, Instant genTime) {
        try {
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            X509Certificate signer = converter.getCertificate(signerHolder);
            if (trusted.contains(signer)) {
                return null;
            }
            List<Object> pool = new ArrayList<>();
            pool.add(signer);
            @SuppressWarnings("unchecked")
            Store<X509CertificateHolder> store = token.getCertificates();
            if (store != null) {
                for (X509CertificateHolder h : store.getMatches(null)) {
                    pool.add(converter.getCertificate(h));
                }
            }
            pool.addAll(trusted);
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(signer);
            PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
            params.setRevocationEnabled(false);
            if (genTime != null) {
                params.setDate(Date.from(genTime));
            }
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool)));
            CertPathBuilder.getInstance("PKIX").build(params);
            return null;
        } catch (Exception e) {
            return "TSA certificate does not chain to a trusted TSA certificate: " + e.getMessage();
        }
    }

    /**
     * Outcome of {@link #verify}.
     *
     * @param valid all three checks passed
     * @param imprintMatches the imprint is SHA-256 of the covered data
     * @param signatureValid the CMS signature and ESS binding verified under
     *     the signer certificate
     * @param chainValid the signer certificate is, or chains to, a trusted one
     * @param genTime the token's {@code genTime}, when parseable
     * @param tsaSubjectDn subject of the signer certificate, when found
     * @param policyOid the token's TSA policy
     * @param error the first failing check, or {@code null}
     */
    public record Verification(boolean valid, boolean imprintMatches, boolean signatureValid,
                               boolean chainValid, Instant genTime, String tsaSubjectDn,
                               String policyOid, String error) {

        static Verification failure(boolean imprintMatches, boolean signatureValid, boolean chainValid,
                                    Instant genTime, String tsaSubjectDn, String policyOid, String error) {
            return new Verification(false, imprintMatches, signatureValid, chainValid, genTime, tsaSubjectDn,
                    policyOid, error);
        }
    }
}
