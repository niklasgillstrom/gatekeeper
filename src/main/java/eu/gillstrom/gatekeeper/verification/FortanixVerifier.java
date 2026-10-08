package eu.gillstrom.gatekeeper.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Fortanix DSM key attestation statement verifier.
 *
 * <p>Follows Fortanix's "Fortanix DSM for Verifying Key Attestation
 * Statements". The input is the JSON that DSM returns
 * ({@code key_attestation_<key UUID>.json}): {@code authority_chain}, base64
 * DER certificates in any order, and {@code attestation_statement} with
 * {@code format} {@code x509_certificate} and the DER statement.</p>
 *
 * <ol>
 * <li>The Key Attestation Authority certificate (the one that is no CA) must
 * form a PKIX path through the chain's CA certificates to the pinned Fortanix
 * Attestation and Provisioning Root CA, with
 * {@code fortanixKeyAttestationPkiCertificatePolicy}
 * ({@code 1.3.6.1.4.1.49690.6.1.2}) as the initial policy, and must carry EKU
 * {@code fortanixKeyAttestationSigning} ({@code 1.3.6.1.4.1.49690.8.1}),
 * digital signature in any Key Usage and no CA flag.</li>
 * <li>The statement must be signed by the authority, name it as issuer, carry
 * no unknown critical extension, and its "not before", which is when it was
 * signed, must lie within the authority's validity and not in the future. The
 * path is validated at that time: Fortanix issues authority certificates for a
 * month, and its procedure checks the statement against the authority's
 * validity rather than against the current date.</li>
 * <li>The statement's public key must be the CSR key, and it must carry
 * {@code fortanixKeyGeneratedInDSM} ({@code 1.3.6.1.4.1.49690.2.4.1.1}) and
 * {@code fortanixKeyNeverExportable} ({@code .2.4.1.2}: "never exported from
 * Fortanix DSM and may not be exported in the future. This prohibition also
 * includes export in encrypted form").</li>
 * </ol>
 *
 * <p>The root is the self-signed certificate in the sample statement of
 * Fortanix's own documentation (Fortanix publishes it at
 * {@code pki.fortanix.com}, which this build cannot reach), pinned by its
 * key.</p>
 */
@Component
public class FortanixVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(FortanixVerifier.class);

    /** SHA-256 of the Fortanix Attestation and Provisioning Root CA's DER SubjectPublicKeyInfo. */
    static final String FORTANIX_ROOT_KEY_SHA256 = "d01275cc16bdc2dad8cd51532bcfc9e69edb9963a4324aa5e12945372afb5e15";

    /**
     * Fortanix Attestation and Provisioning Root CA, 2023-09-01 to 2033-08-29,
     * from the sample in "Fortanix DSM for Verifying Key Attestation Statements".
     * SHA-256 D7:1A:15:B3:4E:78:1E:9E:F9:13:54:FA:BA:E8:B1:15:E0:62:B8:97:95:FE:C3:AE:C0:E0:45:FE:D2:66:C2:C2
     */
    static final String FORTANIX_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIF5DCCA8ygAwIBAgIUbJke8FQ1Waqplu/N/rDpkRD6+3wwDQYJKoZIhvcNAQEL
            BQAwgYkxCzAJBgNVBAYMAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRQwEgYDVQQH
            DAtTYW50YSBDbGFyYTEXMBUGA1UECgwORm9ydGFuaXgsIEluYy4xNjA0BgNVBAMM
            LUZvcnRhbml4IEF0dGVzdGF0aW9uIGFuZCBQcm92aXNpb25pbmcgUm9vdCBDQTAe
            Fw0yMzA5MDExNjM4MTJaFw0zMzA4MjkxNjM4MTJaMIGJMQswCQYDVQQGDAJVUzET
            MBEGA1UECAwKQ2FsaWZvcm5pYTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExFzAVBgNV
            BAoMDkZvcnRhbml4LCBJbmMuMTYwNAYDVQQDDC1Gb3J0YW5peCBBdHRlc3RhdGlv
            biBhbmQgUHJvdmlzaW9uaW5nIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4IC
            DwAwggIKAoICAQCmjKH3KAHI03MrY5MBt7ENpn11pT4RJFC1A89xVknimcYpVnAU
            Kq4oKSv8OyBiGXPXVVmr7n6FyY2Zmgv8FlQKvc8S0yCuJ171IEB0AQSXSWXk6E6K
            w7WpUUNMGXAoCBuKB17IxqrM8MR/RztfIjWyrABmFHN+DSrzleuRbQgi8R4J6RvD
            zZVYnLzNE8xg86ZYbf2+n2vZlA0LIb6J1V+6lQcwFUBPepDX7NRgepnpMoawsMei
            ZLb0YQ4nuwRTSzwwy/5L25ME8p+4drGkC01MZ0R7nr60AAHRonWJrG41AfHmgZ9f
            ApiByIWWWdFgUikHgMl4mGpONuCyI0PozUWrrQvsYbV77LJVOnv4QqS+F7epZR8B
            hunXyoANunm8qKW+JkKcRn93t7Q8JDDKhlTN20RjFGTxrrnMIDdQhsh8FCWuE7cQ
            FFKDFksPeyTzMKALws582UM3bFuljxZk1TGyYjrwnAKX6H+t9SS7Dmw5Gb0hAG4J
            QGdFe1E2N7KcvI80gOiTG11N0WVVHoBkgWI7/r6kA/P5exsbqe+DZjRcx+FuK4yn
            Www/Fq1qzsOOiAq2Yd6dtu7GXWiQeTfWyJBH5HJ8Z5ZPxGsYEFdHH51X1s2czkI4
            VZ+ddnQ6lr1HeBgnMjS/GgtTIDk8D0rDY83wexfUyG6mo2VDMbCS5ayvGwIDAQAB
            o0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
            A9E/WHvUwa6ArrMsoa0z5De2qFQwDQYJKoZIhvcNAQELBQADggIBAD7g0wzncoD6
            xgucFkkw9CUPBW3R7aj5sWE7ETTDa7+m7/O3RTEZT/TJkO8r8XWcDbsUYWLI4fts
            ya+q1D4BNZbo8TODPTObdKFzj9W0NBkgJmInuNqQpGC+7sIrO90ua74Zs5TJIf79
            u0ae4lLBOUsP012UINzyL5ciAVf7Q2PUNCGt7k1Rye9QU23qOc7CZXksd9NkHIqX
            5eZ/YEComTr68iMX3Thn3KMqbA2hxp+5EHNy/LhOcrYJSmCqmNQk6tNqs1aqOvI8
            gpNHwN9G/pIY2+AAzIBuY9JYf06gspBVrPIJyNJuv2aYQeoK8tN9t/QisLHdmyH9
            q+/cIlJIK8fQ6w86ZzTQWJLhjrlsJnU3sR5ThAUk4GAS02BEca6i1HWjuv2iQvJt
            My1Das2A1zyybYxxF373FEtD1a8ogOHYM5e6wtgs+SFFc+K4AM97bLcVHJ9iPN0a
            q/NnWfn2jMPj1G3XLA5KPFpmbkRM0EGULK2gm19/8qis1lsEqYTdfxHk4tW/HGC2
            WxZTi53gKyOosEcwEwjaDO3qwgNHBuRxXp6d0VoNkN9yt0aku58yjW0ytOtXO4+B
            YXcSA5mOkETzDBYhA+BhdXgu3ieRB5f62peMh5fjuXjiUZZ0BuAs0FGfSmL31xHH
            Vy7C0XDshbtkYyLwng8do2UtM4FT0fYV
            -----END CERTIFICATE-----""";

    static final String POLICY_KEY_ATTESTATION_PKI = "1.3.6.1.4.1.49690.6.1.2";
    static final String EKU_KEY_ATTESTATION_SIGNING = "1.3.6.1.4.1.49690.8.1";
    static final String KEY_GENERATED_IN_DSM = "1.3.6.1.4.1.49690.2.4.1.1";
    static final String KEY_NEVER_EXPORTABLE = "1.3.6.1.4.1.49690.2.4.1.2";
    /** Critical extensions a statement may carry: Key Usage. */
    static final Set<String> KNOWN_CRITICAL = Set.of("2.5.29.15");
    static final int MAX_JSON_SIZE = 64 * 1024;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final X509Certificate root;

    public FortanixVerifier() {
        this(MarvellAttestation.certificate(FORTANIX_ROOT_PEM));
        if (!FORTANIX_ROOT_KEY_SHA256.equals(ThalesLunaVerifier.sha256(root.getPublicKey().getEncoded()))) {
            throw new IllegalStateException("Pinned Fortanix root key does not match its fingerprint");
        }
    }

    /** For tests: another root. */
    FortanixVerifier(X509Certificate root) {
        this.root = root;
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.FORTANIX;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        return false; // Use verifyFortanixAttestation instead
    }

    /**
     * @param json         the key attestation JSON, or its base64
     * @param csrPublicKey the CSR's public key
     */
    public FortanixResult verifyFortanixAttestation(String json, PublicKey csrPublicKey) {
        FortanixResult result = new FortanixResult();
        try {
            String text = json.trim().startsWith("{")
                    ? json : new String(Base64.getMimeDecoder().decode(json.trim()), java.nio.charset.StandardCharsets.UTF_8);
            if (text.length() > MAX_JSON_SIZE) {
                result.addError("FORTANIX_STATEMENT_MALFORMED: JSON exceeds " + MAX_JSON_SIZE + " bytes");
                return result;
            }
            JsonNode node = objectMapper.readTree(text);
            JsonNode chainNode = node.get("authority_chain");
            JsonNode statementNode = node.get("attestation_statement");
            if (chainNode == null || !chainNode.isArray() || statementNode == null) {
                result.addError("FORTANIX_STATEMENT_MALFORMED: authority_chain and attestation_statement are required");
                return result;
            }
            if (!"x509_certificate".equals(statementNode.path("format").asText())) {
                result.addError("FORTANIX_STATEMENT_MALFORMED: unsupported format " + statementNode.path("format").asText());
                return result;
            }
            List<X509Certificate> chain = new ArrayList<>();
            for (JsonNode c : chainNode) {
                chain.add(certificate(Base64.getDecoder().decode(c.asText())));
            }
            X509Certificate statement = certificate(Base64.getDecoder().decode(statementNode.path("statement").asText()));

            X509Certificate authority = null;
            List<X509Certificate> cas = new ArrayList<>();
            for (X509Certificate c : chain) {
                if (Arrays.equals(c.getPublicKey().getEncoded(), root.getPublicKey().getEncoded())) {
                    continue; // a copy of the root is not trusted, the pinned one is
                }
                if (c.getBasicConstraints() >= 0) {
                    cas.add(c);
                } else if (authority == null) {
                    authority = c;
                } else {
                    result.addError("FORTANIX_CHAIN_INVALID: more than one non-CA certificate in authority_chain");
                    return result;
                }
            }
            if (authority == null) {
                result.addError("FORTANIX_CHAIN_INVALID: no Key Attestation Authority certificate");
                return result;
            }

            Date signedAt = statement.getNotBefore();
            String statementError = statementError(statement, authority, signedAt);
            if (statementError != null) {
                result.addError("FORTANIX_STATEMENT_INVALID: " + statementError);
                return result;
            }
            result.setSignatureValid(true);
            String chainError = authorityError(authority, cas, signedAt);
            if (chainError != null) {
                result.addError("FORTANIX_CHAIN_INVALID: " + chainError);
                return result;
            }
            result.setChainValid(true);

            result.setKeyId(keyId(statement));
            if (csrPublicKey != null && Arrays.equals(statement.getPublicKey().getEncoded(), csrPublicKey.getEncoded())) {
                result.setPublicKeyMatch(true);
            } else {
                result.addError("FORTANIX_PUBLIC_KEY_MISMATCH: the statement attests another key");
            }
            boolean generated = statement.getNonCriticalExtensionOIDs() != null
                    && statement.getNonCriticalExtensionOIDs().contains(KEY_GENERATED_IN_DSM);
            boolean neverExportable = statement.getNonCriticalExtensionOIDs() != null
                    && statement.getNonCriticalExtensionOIDs().contains(KEY_NEVER_EXPORTABLE);
            if (!generated) {
                result.addError("FORTANIX_KEY_NOT_GENERATED: fortanixKeyGeneratedInDSM is absent");
            }
            if (!neverExportable) {
                result.addError("FORTANIX_KEY_EXPORTABLE: fortanixKeyNeverExportable is absent");
            }
            result.setKeyOrigin(generated ? "generated" : "unverified");
            result.setExportable(!neverExportable);
            result.setValid(result.isChainValid() && result.isSignatureValid() && result.isPublicKeyMatch()
                    && !result.isExportable() && result.getErrors().isEmpty());
        } catch (Exception e) {
            result.addError("FORTANIX_STATEMENT_MALFORMED: " + e.getMessage());
            log.warn("Fortanix key attestation verification failed: {}", e.getMessage());
        }
        return result;
    }

    private static X509Certificate certificate(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    /** Null when the statement is signed by {@code authority} within its validity. */
    private static String statementError(X509Certificate statement, X509Certificate authority, Date signedAt) {
        try {
            if (!statement.getIssuerX500Principal().equals(authority.getSubjectX500Principal())) {
                return "issuer is not the Key Attestation Authority";
            }
            statement.verify(authority.getPublicKey());
            Set<String> critical = statement.getCriticalExtensionOIDs();
            if (critical != null && !KNOWN_CRITICAL.containsAll(critical)) {
                return "unknown critical extension in " + critical;
            }
            if (signedAt.after(new Date())) {
                return "signed in the future (" + signedAt.toInstant() + ")";
            }
            authority.checkValidity(signedAt);
            return null;
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    /** Null when the authority certificate is valid for key attestation under the pinned root at {@code at}. */
    private String authorityError(X509Certificate authority, List<X509Certificate> cas, Date at) {
        try {
            List<String> eku = authority.getExtendedKeyUsage();
            if (eku == null || !eku.contains(EKU_KEY_ATTESTATION_SIGNING)) {
                return "authority lacks EKU fortanixKeyAttestationSigning";
            }
            boolean[] ku = authority.getKeyUsage();
            if (ku != null && !ku[0]) {
                return "authority Key Usage does not allow digital signature";
            }
            List<X509Certificate> path = new ArrayList<>();
            path.add(authority);
            X509Certificate current = authority;
            for (int i = 0; i < cas.size() && !current.getIssuerX500Principal().equals(root.getSubjectX500Principal()); i++) {
                X509Certificate next = null;
                for (X509Certificate ca : cas) {
                    if (ca.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
                        next = ca;
                    }
                }
                if (next == null) {
                    return "no CA certificate for " + current.getIssuerX500Principal();
                }
                path.add(next);
                current = next;
            }
            PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
            params.setRevocationEnabled(false);
            params.setDate(at);
            params.setInitialPolicies(Set.of(POLICY_KEY_ATTESTATION_PKI));
            params.setExplicitPolicyRequired(true);
            CertPathValidator.getInstance("PKIX").validate(
                    CertificateFactory.getInstance("X.509").generateCertPath(path), params);
            return null;
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    private static String keyId(X509Certificate statement) {
        try {
            var name = org.bouncycastle.asn1.x500.X500Name.getInstance(statement.getSubjectX500Principal().getEncoded());
            var rdns = name.getRDNs(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.49690.1.2.2"));
            return rdns.length == 1 ? rdns[0].getFirst().getValue().toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        return authorityError(attestationCert, chain == null ? List.of() : Arrays.asList(chain),
                new Date()) == null;
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return attestationCert.getSerialNumber().toString(16);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        return "Fortanix DSM";
    }

    public static class FortanixResult {
        private boolean valid;
        private boolean chainValid;
        private boolean signatureValid;
        private boolean publicKeyMatch;
        private boolean exportable = true;
        private String keyOrigin = "unverified";
        private String keyId;
        private List<String> errors = new ArrayList<>();

        public void addError(String error) {
            errors.add(error);
        }

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public boolean isChainValid() {
            return chainValid;
        }

        public void setChainValid(boolean chainValid) {
            this.chainValid = chainValid;
        }

        public boolean isSignatureValid() {
            return signatureValid;
        }

        public void setSignatureValid(boolean signatureValid) {
            this.signatureValid = signatureValid;
        }

        public boolean isPublicKeyMatch() {
            return publicKeyMatch;
        }

        public void setPublicKeyMatch(boolean publicKeyMatch) {
            this.publicKeyMatch = publicKeyMatch;
        }

        public boolean isExportable() {
            return exportable;
        }

        public void setExportable(boolean exportable) {
            this.exportable = exportable;
        }

        public String getKeyOrigin() {
            return keyOrigin;
        }

        public void setKeyOrigin(String keyOrigin) {
            this.keyOrigin = keyOrigin;
        }

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public List<String> getErrors() {
            return errors;
        }
    }
}
