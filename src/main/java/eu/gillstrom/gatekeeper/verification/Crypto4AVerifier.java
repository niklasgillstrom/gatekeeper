package eu.gillstrom.gatekeeper.verification;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.HsmVendor;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Crypto4A QASM attestation message verifier.
 *
 * <p>Follows Crypto4A's "Attestation using the QASM" (C4A-302-0043). An
 * attestation message is
 * {@code SEQUENCE { version, claims SetOfClaims, signatures SEQUENCE OF
 * SignatureBlock, relatedCertificates [0] IMPLICIT SEQUENCE OF Certificate
 * OPTIONAL }}. Each signature block covers the DER encoding of
 * {@code claims}; as Crypto4A's {@code spa-attest verify} does, every block
 * must verify, its certificate must carry EKU
 * {@code 1.3.6.1.4.1.39901.4.1.1} and must chain to the root. Supported
 * blocks are ECDSA P-384 with SHA-384 and HSS/LMS
 * ({@code 1.2.840.113549.1.9.16.3.17}); a message signed only with other
 * algorithms is refused.</p>
 *
 * <p>Each claim is a predicate OID under {@code 1.3.6.1.4.1.39901.6}, an
 * optional subject (the object's UUID) and an optional complement. The QASM
 * checks every claim before signing and claims are only present when true.
 * The key must be the CSR key through {@code key-spki} (.2.1) or
 * {@code key-spki-sha256} (.2.3), and the same subject must carry
 * {@code object-class} private key (.2.4 = 4), {@code key-is-confined}
 * (.2.7: "generated on the claiming QASM and can not be transferred in any
 * way out of the QASM"), {@code key-is-hardware-generated} (.2.8) and
 * {@code key-never-extracted} (.2.9). The message must also carry
 * {@code qasm-certified-production} (.1.4) and
 * {@code attestation-keys-are-unique} (.2.0). These are the CA/Browser Forum
 * template's required claims plus the three that Crypto4A lists as optional
 * there, because without them DORA Art. 9.3 d cannot be shown.</p>
 *
 * <p>The specification writes the subject as {@code [0] EXPLICIT Subject};
 * Crypto4A's published message encodes it implicitly (the UUID's {@code [0]}
 * directly inside the claim's {@code [0]}). Both are read. The root is the
 * C4A_RCA published by the PKI Consortium's Remote Key Attestation project
 * (validation/crypto4a-qasm.md), pinned by its key.</p>
 */
@Component
public class Crypto4AVerifier implements HsmAttestationVerifier {

    private static final Logger log = LoggerFactory.getLogger(Crypto4AVerifier.class);

    static {
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** SHA-256 of C4A_RCA's DER SubjectPublicKeyInfo. */
    static final String C4A_ROOT_KEY_SHA256 = "40146cbf7912e0a29ca601f9a1635e37ba8d69a4cdb88a9af1631633e7349bf0";

    /**
     * C4A_RCA, 2020-07-13 to 2045-07-13, from the PKI Consortium's Remote Key
     * Attestation project, validation/crypto4a-qasm.md.
     * SHA-256 63:7E:6A:7E:95:DE:D7:27:2F:5B:3E:5A:0D:94:41:4D:23:E1:B5:4F:9E:2E:65:93:B6:41:75:62:BB:B5:43:3C
     */
    static final String C4A_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIICVDCCAdqgAwIBAgIULNg2gybw50xYlV7zvhXBRcggip8wCgYIKoZIzj0EAwMw
            WTEPMA0GA1UEBgwGQ2FuYWRhMRAwDgYDVQQIDAdPbnRhcmlvMQ8wDQYDVQQHDAZP
            dHRhd2ExETAPBgNVBAoMCENyeXB0bzRBMRAwDgYDVQQDDAdDNEFfUkNBMB4XDTIw
            MDcxMzEzMDYzM1oXDTQ1MDcxMzEzMDYzM1owWTEPMA0GA1UEBgwGQ2FuYWRhMRAw
            DgYDVQQIDAdPbnRhcmlvMQ8wDQYDVQQHDAZPdHRhd2ExETAPBgNVBAoMCENyeXB0
            bzRBMRAwDgYDVQQDDAdDNEFfUkNBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsUwR
            2USPKBZ9pXJqiYG7tAO8MEsyQFVgK1qwdhLtV/HRSgjoQcp8Y3C2g/c8WRn87s2f
            QZYTxuFB0VBLo7dCMYnQlAAxE5P0uAu7GOfhh3IDWxf9HoSnm7/G6YaJMGffo2Mw
            YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBR9
            0A5hkSyKifm5taKiJlbiitUtbTAdBgNVHQ4EFgQUfdAOYZEsion5ubWioiZW4orV
            LW0wCgYIKoZIzj0EAwMDaAAwZQIxAICTsGjiIwc4BMyOf6st1eZIiGSgReQxyZXg
            HjCXDRN3iqjM2Tq37YdAcDGw/X5iwwIwNFnyuELboI6A5yTfoZZuCYQrLbAnX9lH
            3c3cdoK2Gu5PufZUgQptXznFvg1fz2Pb
            -----END CERTIFICATE-----""";

    static final String EKU_ATTESTATION = "1.3.6.1.4.1.39901.4.1.1";
    static final String OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
    static final String OID_HSS_LMS = "1.2.840.113549.1.9.16.3.17";

    private static final String CLAIM = "1.3.6.1.4.1.39901.6.";
    static final String QASM_SERIAL = CLAIM + "1.1";
    static final String CERTIFIED_PRODUCTION = CLAIM + "1.4";
    static final String ATTESTATION_KEYS_UNIQUE = CLAIM + "2.0";
    static final String KEY_SPKI = CLAIM + "2.1";
    static final String KEY_SPKI_SHA256 = CLAIM + "2.3";
    static final String OBJECT_CLASS = CLAIM + "2.4";
    static final String KEY_IS_CONFINED = CLAIM + "2.7";
    static final String KEY_HARDWARE_GENERATED = CLAIM + "2.8";
    static final String KEY_NEVER_EXTRACTED = CLAIM + "2.9";
    static final BigInteger CLASS_PRIVATE_KEY = BigInteger.valueOf(4);

    static final int MAX_MESSAGE_SIZE = 256 * 1024;
    static final int MAX_CHAIN_DEPTH = 4;

    private final PublicKey rootKey;

    public Crypto4AVerifier() {
        this(MarvellAttestation.certificate(C4A_ROOT_PEM).getPublicKey());
        if (!C4A_ROOT_KEY_SHA256.equals(ThalesLunaVerifier.sha256(rootKey.getEncoded()))) {
            throw new IllegalStateException("Pinned C4A_RCA key does not match its fingerprint");
        }
    }

    /** For tests: another root key. */
    Crypto4AVerifier(PublicKey rootKey) {
        this.rootKey = rootKey;
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.CRYPTO4A;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        return false; // Use verifyCrypto4AAttestation instead
    }

    /** One claim: predicate, subject UUID (hex) or null, complement or null. */
    record Claim(String predicate, String subject, ASN1Primitive complement) {
    }

    /**
     * @param message      base64 of the DER attestation message, or the PEM
     *                     {@code ATTESTATION MESSAGE} block
     * @param csrPublicKey the CSR's public key
     */
    public Crypto4AResult verifyCrypto4AAttestation(String message, PublicKey csrPublicKey) {
        Crypto4AResult result = new Crypto4AResult();
        try {
            byte[] der = decode(message);
            if (der.length > MAX_MESSAGE_SIZE) {
                result.addError("C4A_MESSAGE_MALFORMED: message exceeds " + MAX_MESSAGE_SIZE + " bytes");
                return result;
            }
            ASN1Sequence msg = ASN1Sequence.getInstance(der);
            if (msg.size() < 3 || msg.size() > 4) {
                result.addError("C4A_MESSAGE_MALFORMED: AttestationMessage has " + msg.size() + " elements");
                return result;
            }
            byte[] signedClaims = msg.getObjectAt(1).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            List<X509Certificate> related = new ArrayList<>();
            if (msg.size() == 4) {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(msg.getObjectAt(3));
                if (tagged.getTagNo() != 0) {
                    result.addError("C4A_MESSAGE_MALFORMED: relatedCertificates is not [0]");
                    return result;
                }
                for (ASN1Encodable c : ASN1Sequence.getInstance(tagged, false)) {
                    related.add(certificate(c.toASN1Primitive().getEncoded()));
                }
            }

            ASN1Sequence blocks = ASN1Sequence.getInstance(msg.getObjectAt(2));
            if (blocks.size() == 0) {
                result.addError("C4A_SIGNATURE_INVALID: no signature block");
                return result;
            }
            for (int i = 0; i < blocks.size(); i++) {
                String error = blockError(ASN1Sequence.getInstance(blocks.getObjectAt(i)), signedClaims, related);
                if (error != null) {
                    result.addError("C4A_SIGNATURE_INVALID: block " + i + ": " + error);
                    return result;
                }
            }
            result.setChainValid(true);
            result.setSignatureValid(true);

            List<Claim> claims = claims(ASN1Sequence.getInstance(msg.getObjectAt(1)));
            evaluate(claims, csrPublicKey, result);
            result.setValid(result.isChainValid() && result.isSignatureValid() && result.isPublicKeyMatch()
                    && !result.isExportable() && result.getErrors().isEmpty());
        } catch (Exception e) {
            result.addError("C4A_MESSAGE_MALFORMED: " + e.getMessage());
            log.warn("Crypto4A attestation verification failed: {}", e.getMessage());
        }
        return result;
    }

    private static byte[] decode(String message) {
        String m = message.trim();
        if (m.startsWith("-----BEGIN ATTESTATION MESSAGE-----")) {
            m = m.replace("-----BEGIN ATTESTATION MESSAGE-----", "")
                    .replace("-----END ATTESTATION MESSAGE-----", "");
        }
        return Base64.getMimeDecoder().decode(m);
    }

    private static X509Certificate certificate(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
                .generateCertificate(new ByteArrayInputStream(der));
    }

    /** Null when the block's signature, signer EKU and chain to the pinned root all hold. */
    private String blockError(ASN1Sequence block, byte[] signedClaims, List<X509Certificate> related) throws Exception {
        if (block.size() != 3) {
            return "SignatureBlock has " + block.size() + " elements";
        }
        X509Certificate signer = null;
        for (ASN1Encodable e : ASN1Sequence.getInstance(block.getObjectAt(0))) {
            ASN1TaggedObject t = ASN1TaggedObject.getInstance(e);
            if (t.getTagNo() == 2) {
                signer = certificate(t.getExplicitBaseObject().toASN1Primitive().getEncoded());
            }
        }
        if (signer == null) {
            return "signer identifier carries no certificate";
        }
        List<String> eku = signer.getExtendedKeyUsage();
        if (eku == null || !eku.contains(EKU_ATTESTATION)) {
            return "signer certificate lacks the attestation EKU";
        }
        String oid = ASN1ObjectIdentifier.getInstance(
                ASN1Sequence.getInstance(block.getObjectAt(1)).getObjectAt(0)).getId();
        String algorithm = switch (oid) {
            case OID_ECDSA_SHA384 -> "SHA384withECDSA";
            case OID_HSS_LMS -> "LMS";
            default -> null;
        };
        if (algorithm == null) {
            return "unsupported signature algorithm " + oid;
        }
        Signature s = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        s.initVerify(signer.getPublicKey());
        s.update(signedClaims);
        if (!s.verify(ASN1BitString.getInstance(block.getObjectAt(2)).getOctets())) {
            return "signature over the claims does not verify";
        }
        return chainError(signer, related);
    }

    /** Walks issuer by issuer through {@code related} until a certificate the pinned root key signed. */
    private String chainError(X509Certificate signer, List<X509Certificate> related) {
        X509Certificate current = signer;
        for (int depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
            try {
                current.checkValidity();
                if (depth > 0 && current.getBasicConstraints() < 0) {
                    return current.getSubjectX500Principal() + " is not a CA";
                }
                try {
                    current.verify(rootKey);
                    return null;
                } catch (Exception notRoot) {
                    // not issued by the root; look for its issuer below
                }
                X509Certificate issuer = null;
                for (X509Certificate c : related) {
                    if (!c.equals(current) && c.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
                        try {
                            current.verify(c.getPublicKey());
                            issuer = c;
                            break;
                        } catch (Exception ignored) {
                            // same name, other key
                        }
                    }
                }
                if (issuer == null) {
                    return "no issuer for " + current.getSubjectX500Principal() + " leads to the pinned root";
                }
                current = issuer;
            } catch (Exception e) {
                return e.getMessage();
            }
        }
        return "chain longer than " + MAX_CHAIN_DEPTH;
    }

    static List<Claim> claims(ASN1Sequence setOfClaims) {
        List<Claim> out = new ArrayList<>();
        for (ASN1Encodable e : ASN1Sequence.getInstance(setOfClaims.getObjectAt(1))) {
            ASN1Sequence c = ASN1Sequence.getInstance(e);
            String predicate = ASN1ObjectIdentifier.getInstance(c.getObjectAt(0)).getId();
            String subject = null;
            ASN1Primitive complement = null;
            for (int i = 1; i < c.size(); i++) {
                ASN1TaggedObject t = ASN1TaggedObject.getInstance(c.getObjectAt(i));
                if (t.getTagNo() == 0) {
                    subject = HexFormat.of().formatHex(uuid(t));
                } else if (t.getTagNo() == 1) {
                    complement = t.getExplicitBaseObject().toASN1Primitive();
                }
            }
            out.add(new Claim(predicate, subject, complement));
        }
        return out;
    }

    /** The subject's UUID, encoded implicitly ([0] holding [0] uuid) or explicitly ([0] holding SEQUENCE). */
    private static byte[] uuid(ASN1TaggedObject subject) {
        ASN1Primitive inner = subject.getBaseObject().toASN1Primitive();
        if (inner instanceof ASN1Sequence seq && seq.size() == 1) {
            inner = seq.getObjectAt(0).toASN1Primitive();
        }
        byte[] uuid = ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(inner), false).getOctets();
        if (uuid.length != 16) {
            throw new IllegalArgumentException("subject UUID is " + uuid.length + " bytes");
        }
        return uuid;
    }

    private static void evaluate(List<Claim> claims, PublicKey csrKey, Crypto4AResult result) throws Exception {
        Set<String> global = new HashSet<>();
        Map<String, Set<String>> bySubject = new HashMap<>();
        Map<String, BigInteger> objectClass = new HashMap<>();
        Set<String> keySubjects = new HashSet<>();
        byte[] spki = csrKey == null ? null : csrKey.getEncoded();
        byte[] spkiSha256 = spki == null ? null : MessageDigest.getInstance("SHA-256").digest(spki);

        for (Claim c : claims) {
            if (c.subject() == null) {
                global.add(c.predicate());
                if (QASM_SERIAL.equals(c.predicate()) && c.complement() instanceof ASN1TaggedObject t) {
                    result.setHsmSerial(ASN1UTF8String.getInstance(t, false).getString());
                }
                continue;
            }
            bySubject.computeIfAbsent(c.subject(), k -> new HashSet<>()).add(c.predicate());
            if (OBJECT_CLASS.equals(c.predicate()) && c.complement() instanceof ASN1TaggedObject t) {
                objectClass.put(c.subject(), ASN1Integer.getInstance(t, false).getValue());
            }
            if ((KEY_SPKI.equals(c.predicate()) || KEY_SPKI_SHA256.equals(c.predicate()))
                    && c.complement() instanceof ASN1TaggedObject t) {
                byte[] value = ASN1OctetString.getInstance(t, false).getOctets();
                byte[] expected = KEY_SPKI.equals(c.predicate()) ? spki : spkiSha256;
                if (expected != null && MessageDigest.isEqual(value, expected)) {
                    keySubjects.add(c.subject());
                }
            }
        }

        if (!global.contains(CERTIFIED_PRODUCTION)) {
            result.addError("C4A_NOT_CERTIFIED_PRODUCTION: qasm-certified-production (.1.4) is absent");
        }
        if (!global.contains(ATTESTATION_KEYS_UNIQUE)) {
            result.addError("C4A_ATTESTATION_KEYS_NOT_UNIQUE: attestation-keys-are-unique (.2.0) is absent");
        }
        if (keySubjects.size() != 1) {
            result.addError("C4A_PUBLIC_KEY_MISMATCH: " + keySubjects.size()
                    + " attested objects carry the CSR key's SPKI; exactly one is required");
            return;
        }
        result.setPublicKeyMatch(true);
        String key = keySubjects.iterator().next();
        result.setKeyId(key);
        Set<String> asserted = bySubject.get(key);
        if (!CLASS_PRIVATE_KEY.equals(objectClass.get(key))) {
            result.addError("C4A_NOT_A_PRIVATE_KEY: object-class (.2.4) is not private key");
        }
        boolean confined = asserted.contains(KEY_IS_CONFINED);
        boolean generated = asserted.contains(KEY_HARDWARE_GENERATED);
        boolean neverExtracted = asserted.contains(KEY_NEVER_EXTRACTED);
        if (!confined || !neverExtracted) {
            result.addError("C4A_KEY_EXTRACTABLE: key-is-confined (.2.7) " + (confined ? "present" : "absent")
                    + ", key-never-extracted (.2.9) " + (neverExtracted ? "present" : "absent"));
        }
        if (!generated) {
            result.addError("C4A_KEY_NOT_GENERATED: key-is-hardware-generated (.2.8) is absent");
        }
        result.setExportable(!(confined && neverExtracted));
        result.setKeyOrigin(generated && confined ? "generated" : "unverified");
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        return chainError(attestationCert, chain == null ? List.of() : Arrays.asList(chain)) == null;
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return attestationCert.getSerialNumber().toString(16);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        return "Crypto4A QASM";
    }

    public static class Crypto4AResult {
        private boolean valid;
        private boolean chainValid;
        private boolean signatureValid;
        private boolean publicKeyMatch;
        private boolean exportable = true;
        private String keyOrigin = "unverified";
        private String keyId;
        private String hsmSerial;
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

        public String getHsmSerial() {
            return hsmSerial;
        }

        public void setHsmSerial(String hsmSerial) {
            this.hsmSerial = hsmSerial;
        }

        public List<String> getErrors() {
            return errors;
        }
    }
}
