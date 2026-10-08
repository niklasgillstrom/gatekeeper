package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.util.Fingerprints;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Settlement-time lookup against the real {@link InMemoryApprovalRegistry}:
 * the registry entry behind a settlement is the one whose confirmation
 * stored this exact issued certificate, and only {@code VERIFIED_AND_ISSUED}
 * settles.
 */
class SettlementLookupTest {

    @TempDir
    Path tempDir;

    private InMemoryApprovalRegistry registry;
    private SignatureVerificationService service;
    private KeyPair issuerKp;
    private X509Certificate issuerCa;

    @BeforeEach
    void setUp() throws Exception {
        registry = new InMemoryApprovalRegistry();
        AppendOnlyFileAuditLog auditLog = new AppendOnlyFileAuditLog(
                tempDir.resolve("audit.jsonl").toString(), new EphemeralReceiptSigner(2048));
        auditLog.initialise();
        service = new SignatureVerificationService(registry, auditLog, new MtlsPrincipalResolver());
        issuerKp = TestPki.newRsaKeyPair(2048);
        issuerCa = TestPki.selfSignedCa(issuerKp, "TEST-ISSUER-CA");
    }

    @Test
    @DisplayName("A foreign confirmation with the victim's certificate does not affect the victim's settlement")
    void foreignMismatchConfirmationDoesNotPoisonSettlement() throws Exception {
        KeyPair victim = TestPki.newRsaKeyPair(2048);
        X509Certificate victimCert = TestPki.endEntity(victim, "VICTIM", issuerCa, issuerKp.getPrivate());
        registerAndConfirm("V", victim, victimCert, true);

        // Attacker FE: a genuine compliant verification of its own key, then a
        // confirmation that submits the victim's public certificate.
        KeyPair attacker = TestPki.newRsaKeyPair(2048);
        Thread.sleep(5);
        registry.register("A", "na", true, Fingerprints.ofPublicKey(attacker.getPublic()),
                "2", "Attacker", "SECUROSYS", "P", "SE", "attacker");
        registry.confirm("A", "na", true, Fingerprints.ofPublicKey(victimCert.getPublicKey()), false,
                ApprovalRegistry.IssuedCertificate.of(victimCert));
        assertThat(registry.lookup("A").orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);

        SignatureVerificationResponse r = service.verify(signed(victim, victimCert, false));

        assertThat(r.isCompliant()).isTrue();
        assertThat(r.getAuditEntryId()).isEqualTo("V");
        assertThat(r.getReason()).isEqualTo("OK");
    }

    @Test
    @DisplayName("A key that was verified but never confirmed does not settle, even with a certificate presented")
    void unconfirmedKeyDoesNotSettle() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        registry.register("N", "nn", true, Fingerprints.ofPublicKey(kp.getPublic()),
                "1", "X", "SECUROSYS", "P", "SE", "fe");
        X509Certificate selfSigned = TestPki.selfSignedCa(kp, "NOT-ISSUED-BY-ANY-TRUSTED-CA");

        SignatureVerificationResponse r = service.verify(signed(kp, selfSigned, true));

        assertThat(r.isCompliant()).isFalse();
        assertThat(r.getReason()).isEqualTo("CERT_NOT_FOUND");
    }

    @Test
    @DisplayName("A key confirmed as not issued does not settle")
    void verifiedNotIssuedDoesNotSettle() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        registry.register("N", "nn", true, Fingerprints.ofPublicKey(kp.getPublic()),
                "1", "X", "SECUROSYS", "P", "SE", "fe");
        registry.confirm("N", "nn", false, null, false, null);
        X509Certificate selfSigned = TestPki.selfSignedCa(kp, "NOT-ISSUED-BY-ANY-TRUSTED-CA");

        SignatureVerificationResponse r = service.verify(signed(kp, selfSigned, true));

        assertThat(r.isCompliant()).isFalse();
        assertThat(r.getReason()).isEqualTo("CERT_NOT_FOUND");
    }

    @Test
    @DisplayName("A presented certificate must be the one stored at confirmation")
    void presentedCertificateMustMatchTheStoredOne() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate issued = TestPki.endEntity(kp, "ISSUED", issuerCa, issuerKp.getPrivate());
        registerAndConfirm("V", kp, issued, true);
        // Same serial and issuer DN, different certificate: re-signed by a key
        // that only copies the issuer's name.
        KeyPair rogue = TestPki.newRsaKeyPair(2048);
        X509Certificate forged = certificate(kp, issued.getSerialNumber(),
                issued.getIssuerX500Principal().getName(), rogue, 3600_000L);

        SignatureVerificationResponse r = service.verify(signed(kp, forged, true));

        assertThat(r.isCompliant()).isFalse();
        assertThat(r.getReason()).isEqualTo("CERT_NOT_FOUND");
    }

    @Test
    @DisplayName("An expired certificate does not settle")
    void expiredCertificateDoesNotSettle() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate expired = certificate(kp, BigInteger.valueOf(424242),
                issuerCa.getSubjectX500Principal().getName(), issuerKp, -60_000L);
        registerAndConfirm("E", kp, expired, true);

        SignatureVerificationResponse r = service.verify(signed(kp, expired, false));

        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isCompliant()).isFalse();
        assertThat(r.getReason()).isEqualTo("CERT_EXPIRED");
    }

    // ---------------------------------------------------------------- helpers

    private void registerAndConfirm(String id, KeyPair kp, X509Certificate cert, boolean match)
            throws Exception {
        String fp = Fingerprints.ofPublicKey(kp.getPublic());
        registry.register(id, "n-" + id, true, fp, "1", "FE", "SECUROSYS", "P", "SE", "fe");
        registry.confirm(id, "n-" + id, true, fp, match, ApprovalRegistry.IssuedCertificate.of(cert));
        assertThat(registry.lookup(id).orElseThrow().getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
    }

    /** A certificate valid from one hour ago until {@code validForMillis} from now (negative: expired). */
    private static X509Certificate certificate(KeyPair subject, BigInteger serial, String issuerDn,
            KeyPair signer, long validForMillis) throws Exception {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuerDn), serial,
                new Date(now - 3600_000L), new Date(now + validForMillis), new X500Name("CN=SUBJECT"),
                subject.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())));
    }

    private static SignatureVerificationRequest signed(KeyPair kp, X509Certificate cert, boolean withPem)
            throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest("payload".getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("SHA512withRSA");
        s.initSign(kp.getPrivate());
        s.update(digest);
        return SignatureVerificationRequest.builder()
                .certSerial(cert.getSerialNumber().toString(16))
                .issuerDn(cert.getIssuerX500Principal().getName())
                .digestHex(HexFormat.of().formatHex(digest))
                .signatureBase64(Base64.getEncoder().encodeToString(s.sign()))
                .signingCertificatePem(withPem ? TestPki.toPem(cert) : null)
                .build();
    }
}
