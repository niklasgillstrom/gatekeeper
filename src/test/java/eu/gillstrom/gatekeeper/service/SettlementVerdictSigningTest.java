package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.signing.SettlementVerdictCanonicalizer;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.util.Fingerprints;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The signed settlement verdict of {@code POST /api/v1/verify}: every answer
 * is signed over {@link SettlementVerdictCanonicalizer}, denials included,
 * unless the request's identifying fields cannot be normalised.
 */
class SettlementVerdictSigningTest {

    @TempDir
    Path tempDir;

    private EphemeralReceiptSigner signer;
    private GatekeeperKeyDirectory keyDirectory;
    private AppendOnlyFileAuditLog auditLog;
    private InMemoryApprovalRegistry registry;
    private SignatureVerificationService service;
    private KeyPair issuerKp;
    private X509Certificate issuerCa;
    private KeyPair leafKp;
    private X509Certificate leaf;

    @BeforeEach
    void setUp() throws Exception {
        signer = new EphemeralReceiptSigner(2048);
        keyDirectory = new GatekeeperKeyDirectory(signer, "");
        keyDirectory.initialise();
        auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(), signer);
        auditLog.initialise();
        registry = new InMemoryApprovalRegistry();
        service = new SignatureVerificationService(registry, auditLog, new MtlsPrincipalResolver(), signer,
                keyDirectory);
        issuerKp = TestPki.newRsaKeyPair(2048);
        issuerCa = TestPki.selfSignedCa(issuerKp, "Verdict Issuer CA");
        leafKp = TestPki.newRsaKeyPair(2048);
        leaf = TestPki.endEntity(leafKp, "Verdict Leaf", issuerCa, issuerKp.getPrivate());
    }

    private void confirmLeaf() throws Exception {
        String fp = Fingerprints.ofPublicKey(leafKp.getPublic());
        registry.register("VID-V", "n", true, fp, "1", "FE", "SECUROSYS", "P", "SE", "fe");
        registry.confirm("VID-V", "n", true, fp, true, ApprovalRegistry.IssuedCertificate.of(leaf));
    }

    private SignatureVerificationRequest request(String serial, String issuerDn, String payload) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(payload.getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("SHA512withRSA");
        s.initSign(leafKp.getPrivate());
        s.update(digest);
        return SignatureVerificationRequest.builder()
                .certSerial(serial)
                .issuerDn(issuerDn)
                .digestHex(HexFormat.of().formatHex(digest).toUpperCase())
                .signatureBase64(Base64.getEncoder().encodeToString(s.sign()))
                .build();
    }

    /** Recompute the canonical bytes from the request and the response, as railgate does, and verify. */
    private boolean verdictVerifies(SignatureVerificationRequest req, SignatureVerificationResponse r)
            throws Exception {
        byte[] canonical = SettlementVerdictCanonicalizer.canonicalize(r.getVerifiedAt(), req.getCertSerial(),
                req.getIssuerDn(), req.getDigestHex(), r.isSignatureValid(), r.isCompliant(), r.getReason(),
                r.getAuditEntryId(), r.getAuditEntryHashHex());
        Signature v = Signature.getInstance(r.getVerdictSignatureAlgorithm());
        v.initVerify(signer.getPublicKey());
        v.update(canonical);
        return v.verify(Base64.getDecoder().decode(r.getVerdictSignatureBase64()));
    }

    @Test
    void anAllowedSettlementCarriesAVerdictSignedByTheActiveKey() throws Exception {
        confirmLeaf();
        SignatureVerificationRequest req = request("0x" + leaf.getSerialNumber().toString(16).toUpperCase(),
                leaf.getIssuerX500Principal().getName(), "payload-ok");

        SignatureVerificationResponse r = service.verify(req);

        assertThat(r.getReason()).isEqualTo("OK");
        assertThat(r.getVerdictSignatureAlgorithm()).isEqualTo(signer.getSignatureAlgorithm());
        assertThat(r.getSigningKeyFingerprintHex())
                .as("the fingerprint GET /v1/gatekeeper/keys publishes for the active key")
                .isEqualTo(keyDirectory.allKeys().get(0).publicKeyFingerprintHex())
                .matches("^[0-9a-f]{64}$");
        assertThat(verdictVerifies(req, r)).isTrue();
    }

    @Test
    void verifiedAtIsAnInstantTruncatedToMilliseconds() throws Exception {
        confirmLeaf();
        Instant before = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        SignatureVerificationResponse r = service.verify(request(leaf.getSerialNumber().toString(16),
                leaf.getIssuerX500Principal().getName(), "payload-time"));
        Instant verifiedAt = Instant.parse(r.getVerifiedAt());

        assertThat(verifiedAt).isEqualTo(verifiedAt.truncatedTo(ChronoUnit.MILLIS));
        assertThat(r.getVerifiedAt()).isEqualTo(verifiedAt.toString());
        assertThat(verifiedAt).isBetween(before, Instant.now());
    }

    @Test
    void aDenialIsSignedToo() throws Exception {
        // No registry entry: CERT_NOT_FOUND with a null auditEntryId.
        SignatureVerificationRequest req = request(leaf.getSerialNumber().toString(16),
                leaf.getIssuerX500Principal().getName(), "payload-denied");

        SignatureVerificationResponse r = service.verify(req);

        assertThat(r.getReason()).isEqualTo("CERT_NOT_FOUND");
        assertThat(r.getAuditEntryId()).isNull();
        assertThat(r.getVerdictSignatureBase64()).isNotBlank();
        assertThat(verdictVerifies(req, r)).isTrue();
    }

    @Test
    void theVerdictSignatureCoversTheOutcomeAndTheAuditEntry() throws Exception {
        confirmLeaf();
        SignatureVerificationRequest req = request(leaf.getSerialNumber().toString(16),
                leaf.getIssuerX500Principal().getName(), "payload-bound");
        SignatureVerificationResponse r = service.verify(req);
        assertThat(r.getAuditEntryHashHex()).isEqualTo(auditLog.head().orElseThrow().thisEntryHashHex());

        r.setCompliant(false);
        assertThat(verdictVerifies(req, r)).as("a flipped outcome").isFalse();
        r.setCompliant(true);
        r.setAuditEntryHashHex("0".repeat(64));
        assertThat(verdictVerifies(req, r)).as("another audit entry").isFalse();
    }

    @Test
    void aRequestWhoseSerialCannotBeNormalisedIsAnsweredUnsigned() throws Exception {
        SignatureVerificationResponse r = service.verify(request("not-hex",
                leaf.getIssuerX500Principal().getName(), "payload-bad-serial"));

        assertThat(r.getReason()).isEqualTo("MALFORMED_INPUT");
        assertThat(r.getAuditEntryHashHex()).as("still audited").isNotBlank();
        assertThat(r.getVerifiedAt()).isNull();
        assertThat(r.getVerdictSignatureBase64()).isNull();
        assertThat(r.getVerdictSignatureAlgorithm()).isNull();
        assertThat(r.getSigningKeyFingerprintHex()).isNull();
    }

    @Test
    void aRequestWhoseDigestIsNotHexIsAnsweredUnsigned() throws Exception {
        SignatureVerificationRequest req = request(leaf.getSerialNumber().toString(16),
                leaf.getIssuerX500Principal().getName(), "payload-bad-digest");
        req.setDigestHex("zz|true");

        SignatureVerificationResponse r = service.verify(req);

        assertThat(r.getReason()).isEqualTo("MALFORMED_INPUT");
        assertThat(r.getVerdictSignatureBase64()).isNull();
    }

    @Test
    void theUnsignedConstructorLeavesTheVerdictFieldsEmpty() throws Exception {
        confirmLeaf();
        SignatureVerificationService unsigned =
                new SignatureVerificationService(registry, auditLog, new MtlsPrincipalResolver());

        SignatureVerificationResponse r = unsigned.verify(request(leaf.getSerialNumber().toString(16),
                leaf.getIssuerX500Principal().getName(), "payload-unsigned"));

        assertThat(r.getReason()).isEqualTo("OK");
        assertThat(r.getVerifiedAt()).isNull();
        assertThat(r.getVerdictSignatureBase64()).isNull();
    }
}
