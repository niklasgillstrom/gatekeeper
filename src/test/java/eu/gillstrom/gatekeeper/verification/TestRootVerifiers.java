package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Yubico and Securosys verifiers anchored at a test root, and attestation
 * evidence for an arbitrary public key that chains to it. Shaped like the
 * vendors' real evidence: Yubico — attestation certificate with the
 * 1.3.6.1.4.1.41482.4.x extensions, issued by a device certificate named
 * {@code YubiHSM Attestation (serial)}; Securosys — signed
 * {@code <private_key>} XML, attestation certificate issued by a device
 * certificate named {@code PRIMUS HSM KEY (SN: serial)}.
 */
public final class TestRootVerifiers {

    private static final String YUBICO_OID = "1.3.6.1.4.1.41482.4";
    private static final byte[] NON_EXPORTABLE_CAPABILITIES = {0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x06, 0x60};

    private TestRootVerifiers() {
    }

    public static YubicoVerifier yubico(X509Certificate root) {
        return new YubicoVerifier(root);
    }

    public static SecurosysVerifier securosys(X509Certificate root) {
        return new SecurosysVerifier(root);
    }

    /** A test root CA and its key. */
    public record Root(KeyPair keyPair, X509Certificate certificate) {
        public static Root create(String cn) throws Exception {
            KeyPair kp = TestPki.newRsaKeyPair(2048);
            return new Root(kp, TestPki.selfSignedCa(kp, cn));
        }
    }

    /**
     * Yubico-shaped chain [attestation, device] under {@code root} attesting
     * {@code attested}: generated on the device, no export capability,
     * firmware 2.4.0.
     */
    public static List<String> yubicoChain(Root root, PublicKey attested, String deviceSerial) throws Exception {
        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate device = TestPki.subordinateCa(deviceKp, "YubiHSM Attestation (" + deviceSerial + ")",
                root.certificate(), root.keyPair().getPrivate());
        Map<String, ASN1Encodable> ext = new LinkedHashMap<>();
        ext.put(YUBICO_OID + ".1", new DEROctetString(new byte[] {2, 4, 0}));
        ext.put(YUBICO_OID + ".3", new DERBitString(new byte[] {0x01}));
        ext.put(YUBICO_OID + ".5", new DERBitString(NON_EXPORTABLE_CAPABILITIES));
        ext.put(YUBICO_OID + ".6", new ASN1Integer(0x24));
        X500Name issuer = new X500Name(device.getSubjectX500Principal().getName());
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(now),
                new Date(now - 60_000L), new Date(now + 3600_000L),
                new X500Name("CN=YubiHSM Attestation id:0x0024"), attested);
        for (Map.Entry<String, ASN1Encodable> e : ext.entrySet()) {
            b.addExtension(new ASN1ObjectIdentifier(e.getKey()), false, e.getValue());
        }
        X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(deviceKp.getPrivate())));
        return List.of(TestPki.toPem(leaf), TestPki.toPem(device));
    }

    /** Securosys-shaped evidence. */
    public record SecurosysEvidence(byte[] xml, String signatureBase64, List<String> chainPem) {
    }

    /**
     * Securosys-shaped evidence under {@code root} attesting {@code attested}:
     * {@code creation="generated"}, non-extractable, sensitive.
     */
    public static SecurosysEvidence securosysEvidence(Root root, PublicKey attested, String hsmSerial)
            throws Exception {
        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate device = TestPki.subordinateCa(deviceKp, "PRIMUS HSM KEY (SN: " + hsmSerial + ")",
                root.certificate(), root.keyPair().getPrivate());
        KeyPair attestationKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestationCert = TestPki.endEntity(attestationKp, "attestation-key", device,
                deviceKp.getPrivate());
        String xml = "<private_key creation=\"generated\">"
                + "<public_key>" + Base64.getEncoder().encodeToString(attested.getEncoded()) + "</public_key>"
                + "<label>nca-log-seal</label><algorithm>RSA</algorithm><key_size>2048</key_size>"
                + "<attributes><extractable>false</extractable><never_extractable>true</never_extractable>"
                + "<sensitive>true</sensitive><always_sensitive>true</always_sensitive></attributes>"
                + "</private_key>";
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(attestationKp.getPrivate());
        sig.update(bytes);
        return new SecurosysEvidence(bytes, Base64.getEncoder().encodeToString(sig.sign()),
                List.of(TestPki.toPem(attestationCert), TestPki.toPem(device), TestPki.toPem(root.certificate())));
    }
}
