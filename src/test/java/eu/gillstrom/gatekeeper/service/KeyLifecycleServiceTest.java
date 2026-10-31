package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.KeyLifecycleRequest;
import eu.gillstrom.gatekeeper.model.KeyStatusChangeResponse;
import eu.gillstrom.gatekeeper.model.SignatureVerificationRequest;
import eu.gillstrom.gatekeeper.model.SignatureVerificationResponse;
import eu.gillstrom.gatekeeper.model.SignedEventResponse;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.signing.SettlementVerdictCanonicalizer;
import eu.gillstrom.gatekeeper.testsupport.TestPki;
import eu.gillstrom.gatekeeper.util.Fingerprints;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Key-lifecycle events against the real in-memory registry, a real audit log
 * and the signing settlement service: what each event does to the registry,
 * what it does to settlement, and what lands in the audit chain.
 */
class KeyLifecycleServiceTest {

    @TempDir
    Path tempDir;

    private EphemeralReceiptSigner signer;
    private AppendOnlyFileAuditLog auditLog;
    private InMemoryApprovalRegistry registry;
    private SignatureVerificationService settlement;
    private KeyPair issuerKp;
    private X509Certificate issuerCa;
    private KeyPair leafKp;
    private X509Certificate leaf;

    @BeforeEach
    void setUp() throws Exception {
        signer = new EphemeralReceiptSigner(2048);
        GatekeeperKeyDirectory keyDirectory = new GatekeeperKeyDirectory(signer, "");
        keyDirectory.initialise();
        auditLog = new AppendOnlyFileAuditLog(tempDir.resolve("audit.jsonl").toString(), signer);
        auditLog.initialise();
        registry = new InMemoryApprovalRegistry();
        settlement = new SignatureVerificationService(registry, auditLog, new MtlsPrincipalResolver(), signer,
                keyDirectory);
        issuerKp = TestPki.newRsaKeyPair(2048);
        issuerCa = TestPki.selfSignedCa(issuerKp, "Lifecycle Issuer CA");
        leafKp = TestPki.newRsaKeyPair(2048);
        leaf = TestPki.endEntity(leafKp, "Lifecycle Leaf", issuerCa, issuerKp.getPrivate());
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private KeyLifecycleService lifecycle(boolean mtlsEnabled) {
        return new KeyLifecycleService(settlement, registry, auditLog, new MtlsPrincipalResolver(), mtlsEnabled);
    }

    private void issue(String id, KeyPair kp, X509Certificate cert, String country, String principal)
            throws Exception {
        String fp = Fingerprints.ofPublicKey(kp.getPublic());
        registry.register(id, "n-" + id, true, fp, "5569743098", "TL AB", "SECUROSYS", "Primus HSM", country,
                principal);
        registry.confirm(id, "n-" + id, true, fp, true, ApprovalRegistry.IssuedCertificate.of(cert));
        Thread.sleep(2);
    }

    private KeyLifecycleRequest event(String type, X509Certificate cert) {
        return KeyLifecycleRequest.builder()
                .eventType(type)
                .certSerial(cert.getSerialNumber().toString(16))
                .issuerDn(cert.getIssuerX500Principal().getName())
                .reason(KeyLifecycleRequest.SIGNED.equals(type) ? null : "reason for " + type)
                .build();
    }

    private static byte[] digest(String payload) throws Exception {
        return MessageDigest.getInstance("SHA-512").digest(payload.getBytes(StandardCharsets.UTF_8));
    }

    private static String sign(KeyPair kp, byte[] digest) throws Exception {
        Signature s = Signature.getInstance("SHA512withRSA");
        s.initSign(kp.getPrivate());
        s.update(digest);
        return Base64.getEncoder().encodeToString(s.sign());
    }

    private KeyLifecycleRequest signedEvent(KeyPair kp, X509Certificate cert, String payload) throws Exception {
        byte[] d = digest(payload);
        KeyLifecycleRequest r = event(KeyLifecycleRequest.SIGNED, cert);
        r.setDigestHex(HexFormat.of().formatHex(d));
        r.setSignatureBase64(sign(kp, d));
        return r;
    }

    private SignatureVerificationResponse settle(KeyPair kp, X509Certificate cert) throws Exception {
        byte[] d = digest("settlement");
        return settlement.verify(SignatureVerificationRequest.builder()
                .certSerial(cert.getSerialNumber().toString(16))
                .issuerDn(cert.getIssuerX500Principal().getName())
                .digestHex(HexFormat.of().formatHex(d))
                .signatureBase64(sign(kp, d))
                .build());
    }

    private AuditEntry head() {
        return auditLog.head().orElseThrow();
    }

    // ------------------------------------------------------------ status changes

    @Test
    void eachStatusChangingEventMovesTheEntryAndStopsTheCertificateSettling() throws Exception {
        String[][] cases = {
                {KeyLifecycleRequest.ROTATED, "SUPERSEDED", "CERT_SUPERSEDED"},
                {KeyLifecycleRequest.REVOKED, "REVOKED", "CERT_REVOKED"},
                {KeyLifecycleRequest.DECOMMISSIONED, "DECOMMISSIONED", "CERT_DECOMMISSIONED"}};
        for (String[] c : cases) {
            KeyPair kp = TestPki.newRsaKeyPair(2048);
            X509Certificate cert = TestPki.endEntity(kp, "Leaf " + c[0], issuerCa, issuerKp.getPrivate());
            issue("VID-" + c[0], kp, cert, "SE", "fe");
            assertThat(settle(kp, cert).getReason()).isEqualTo("OK");

            KeyStatusChangeResponse r = lifecycle(false).changeStatus("SE", event(c[0], cert));

            assertThat(r.getReason()).isEqualTo("OK");
            assertThat(r.isApplied()).isTrue();
            assertThat(r.getEventType()).isEqualTo(c[0]);
            assertThat(r.getVerificationId()).isEqualTo("VID-" + c[0]);
            assertThat(r.getPreviousStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
            assertThat(r.getRegistryStatus()).isEqualTo(RegistryStatus.valueOf(c[1]));
            assertThat(registry.lookup("VID-" + c[0]).orElseThrow().getStatusChangeReason())
                    .isEqualTo("reason for " + c[0]);

            SignatureVerificationResponse denied = settle(kp, cert);
            assertThat(denied.getReason()).isEqualTo(c[2]);
            assertThat(denied.isSignatureValid()).isTrue();
            assertThat(denied.isCompliant()).isFalse();
            assertThat(denied.getAuditEntryId()).isEqualTo("VID-" + c[0]);
            assertThat(denied.getVerdictSignatureBase64()).as("the denial is signed").isNotBlank();
        }
    }

    @Test
    void aSupersededKeyMayStillBeRevokedOrDecommissionedButNothingElse() throws Exception {
        issue("VID-L", leafKp, leaf, "SE", "fe");
        KeyLifecycleService service = lifecycle(false);
        assertThat(service.changeStatus("SE", event(KeyLifecycleRequest.ROTATED, leaf)).isApplied()).isTrue();

        KeyStatusChangeResponse again = service.changeStatus("SE", event(KeyLifecycleRequest.ROTATED, leaf));
        assertThat(again.getReason()).isEqualTo("TRANSITION_NOT_ALLOWED");
        assertThat(again.isApplied()).isFalse();
        assertThat(again.getPreviousStatus()).isEqualTo(RegistryStatus.SUPERSEDED);
        assertThat(again.getRegistryStatus()).isEqualTo(RegistryStatus.SUPERSEDED);

        KeyStatusChangeResponse revoked = service.changeStatus("SE", event(KeyLifecycleRequest.REVOKED, leaf));
        assertThat(revoked.getReason()).isEqualTo("OK");
        assertThat(revoked.getPreviousStatus()).isEqualTo(RegistryStatus.SUPERSEDED);

        for (String type : new String[] {KeyLifecycleRequest.ROTATED, KeyLifecycleRequest.REVOKED,
                KeyLifecycleRequest.DECOMMISSIONED}) {
            KeyStatusChangeResponse r = service.changeStatus("SE", event(type, leaf));
            assertThat(r.getReason()).as(type + " after REVOKED").isEqualTo("TRANSITION_NOT_ALLOWED");
            assertThat(r.getRegistryStatus()).isEqualTo(RegistryStatus.REVOKED);
        }
    }

    @Test
    void anUnknownCertificateOrAnotherJurisdictionIsNotFound() throws Exception {
        KeyLifecycleService service = lifecycle(false);
        KeyStatusChangeResponse unknown = service.changeStatus("SE", event(KeyLifecycleRequest.REVOKED, leaf));
        assertThat(unknown.getReason()).isEqualTo("CERT_NOT_FOUND");
        assertThat(unknown.getVerificationId()).isNull();
        assertThat(unknown.getPreviousStatus()).isNull();
        assertThat(head().verificationId()).isEqualTo(SignatureVerificationService.NO_REGISTRY_MATCH);

        issue("VID-SE", leafKp, leaf, "SE", "fe");
        assertThat(service.changeStatus("DE", event(KeyLifecycleRequest.REVOKED, leaf)).getReason())
                .isEqualTo("CERT_NOT_FOUND");
        assertThat(registry.lookup("VID-SE").orElseThrow().getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
    }

    @Test
    void anUnparseableSerialOrIssuerIsMalformedInputAndAudited() {
        KeyLifecycleRequest bad = KeyLifecycleRequest.builder().eventType(KeyLifecycleRequest.REVOKED)
                .certSerial("not-hex").issuerDn("CN=X").reason("r").build();

        KeyStatusChangeResponse r = lifecycle(false).changeStatus("SE", bad);

        assertThat(r.getReason()).isEqualTo("MALFORMED_INPUT");
        assertThat(r.getAuditEntryHashHex()).isEqualTo(head().thisEntryHashHex());
        bad.setCertSerial("0a");
        bad.setIssuerDn("no equals sign here");
        assertThat(lifecycle(false).changeStatus("SE", bad).getReason()).isEqualTo("MALFORMED_INPUT");
    }

    @Test
    void aRotationNamesAnExistingSuccessorOrIsRefused() throws Exception {
        issue("VID-OLD", leafKp, leaf, "SE", "fe");
        KeyPair next = TestPki.newRsaKeyPair(2048);
        registry.register("VID-NEW", "n", true, Fingerprints.ofPublicKey(next.getPublic()), "5569743098", "TL AB",
                "SECUROSYS", "Primus HSM", "SE", "fe");
        registry.register("VID-DE", "n", true, "fp-de", "5569743098", "TL AB", "SECUROSYS", "Primus HSM", "DE", "fe");
        KeyLifecycleService service = lifecycle(false);

        for (String successor : new String[] {"VID-MISSING", "VID-DE", "VID-OLD"}) {
            KeyLifecycleRequest r = event(KeyLifecycleRequest.ROTATED, leaf);
            r.setSuccessorVerificationId(successor);
            KeyStatusChangeResponse refused = service.changeStatus("SE", r);
            assertThat(refused.getReason()).as(successor).isEqualTo("SUCCESSOR_NOT_FOUND");
            assertThat(refused.getVerificationId()).isEqualTo("VID-OLD");
            assertThat(refused.isApplied()).isFalse();
            assertThat(registry.lookup("VID-OLD").orElseThrow().getStatus())
                    .isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);
        }

        KeyLifecycleRequest ok = event(KeyLifecycleRequest.ROTATED, leaf);
        ok.setSuccessorVerificationId("VID-NEW");
        KeyStatusChangeResponse applied = service.changeStatus("SE", ok);
        assertThat(applied.getReason()).isEqualTo("OK");
        assertThat(applied.getSuccessorVerificationId()).isEqualTo("VID-NEW");
        assertThat(registry.lookup("VID-OLD").orElseThrow().getSuccessorVerificationId()).isEqualTo("VID-NEW");
    }

    @Test
    void everyOutcomeIsAuditedUnderTheEventsOwnOperation() throws Exception {
        issue("VID-A", leafKp, leaf, "SE", "fe");
        KeyLifecycleService service = lifecycle(false);
        long before = auditLog.size();

        KeyStatusChangeResponse applied = service.changeStatus("SE", event(KeyLifecycleRequest.DECOMMISSIONED, leaf));
        AuditEntry appliedEntry = head();
        KeyStatusChangeResponse refused = service.changeStatus("SE", event(KeyLifecycleRequest.REVOKED, leaf));
        AuditEntry refusedEntry = head();

        assertThat(auditLog.size()).isEqualTo(before + 2);
        assertThat(appliedEntry.operation()).isEqualTo("DECOMMISSIONED");
        assertThat(appliedEntry.verificationId()).isEqualTo("VID-A");
        assertThat(appliedEntry.compliant()).isTrue();
        assertThat(applied.getAuditEntryHashHex()).isEqualTo(appliedEntry.thisEntryHashHex());
        assertThat(refusedEntry.operation()).isEqualTo("REVOKED");
        assertThat(refusedEntry.compliant()).as("refused").isFalse();
        assertThat(refused.getAuditEntryHashHex()).isEqualTo(refusedEntry.thisEntryHashHex());
        assertThat(appliedEntry.requestDigestBase64()).isEqualTo(Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(KeyLifecycleService.canonicalRequestBytes("SE",
                        event(KeyLifecycleRequest.DECOMMISSIONED, leaf)))));
        assertThat(appliedEntry.receiptDigestBase64()).isEqualTo(Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(KeyLifecycleService.canonicalResponseBytes(applied))));
        assertThat(auditLog.verifyChainIntegrity()).isTrue();
    }

    @Test
    void theCanonicalFormsAreTheDocumentedOnes() {
        KeyLifecycleRequest r = KeyLifecycleRequest.builder().eventType("ROTATED").certSerial("0a")
                .issuerDn("CN=A|B").successorVerificationId("S").reason("50%").build();
        assertThat(new String(KeyLifecycleService.canonicalRequestBytes("SE", r), StandardCharsets.UTF_8))
                .isEqualTo("v1|lifecycle|ROTATED|SE|0a|CN=A%7CB|S|50%25");
        KeyStatusChangeResponse resp = KeyStatusChangeResponse.builder().eventType("ROTATED").verificationId("V")
                .applied(true).previousStatus(RegistryStatus.VERIFIED_AND_ISSUED)
                .registryStatus(RegistryStatus.SUPERSEDED).successorVerificationId("S").reason("OK")
                .processedAt("2026-10-30T12:00:00Z").build();
        assertThat(new String(KeyLifecycleService.canonicalResponseBytes(resp), StandardCharsets.UTF_8))
                .isEqualTo("v1|lifecycle-response|ROTATED|V|true|VERIFIED_AND_ISSUED|SUPERSEDED|S|OK"
                        + "|2026-10-30T12:00:00Z");
    }

    // ------------------------------------------------------------ who may change

    @Test
    void withMtlsAFinancialEntityChangesOnlyWhatItVerifiedAndTheSupervisorAnything() throws Exception {
        issue("VID-P", leafKp, leaf, "SE", "fe-a");
        KeyLifecycleService service = lifecycle(true);

        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("fe-b", null, "ROLE_FE"));
        assertThat(service.changeStatus("SE", event(KeyLifecycleRequest.REVOKED, leaf)).getReason())
                .as("another financial entity").isEqualTo("CERT_NOT_FOUND");
        assertThat(registry.lookup("VID-P").orElseThrow().getStatus()).isEqualTo(RegistryStatus.VERIFIED_AND_ISSUED);

        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("fe-a", null, "ROLE_FE"));
        assertThat(service.changeStatus("SE", event(KeyLifecycleRequest.ROTATED, leaf)).getReason())
                .as("the financial entity that verified it").isEqualTo("OK");

        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("internal-audit-1", null, "ROLE_SUPERVISOR"));
        assertThat(service.changeStatus("SE", event(KeyLifecycleRequest.REVOKED, leaf)).getReason())
                .as("the supervisor").isEqualTo("OK");
        assertThat(head().mtlsClientPrincipal()).isEqualTo("internal-audit-1");
    }

    @Test
    void withMtlsAnEntryBoundToNoPrincipalMayBeChangedByAnyCaller() throws Exception {
        issue("VID-N", leafKp, leaf, "SE", null);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("fe-x", null, "ROLE_FE"));
        assertThat(lifecycle(true).changeStatus("SE", event(KeyLifecycleRequest.ROTATED, leaf)).getReason())
                .isEqualTo("OK");
    }

    @Test
    void withMtlsAndNoAuthenticationTheCallerIsNotTheSupervisor() throws Exception {
        issue("VID-Q", leafKp, leaf, "SE", "fe-a");
        SecurityContextHolder.clearContext();
        assertThat(lifecycle(true).changeStatus("SE", event(KeyLifecycleRequest.REVOKED, leaf)).getReason())
                .isEqualTo("CERT_NOT_FOUND");
    }

    @Test
    void onlyARefusedCallerIsWarnedAbout() throws Exception {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(KeyLifecycleService.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> logs =
                new ch.qos.logback.core.read.ListAppender<>();
        logs.start();
        logger.addAppender(logs);
        try {
            issue("VID-W", leafKp, leaf, "SE", "fe-a");
            KeyLifecycleService service = lifecycle(true);
            SecurityContextHolder.getContext().setAuthentication(
                    new TestingAuthenticationToken("fe-a", null, "ROLE_FE"));
            service.changeStatus("SE", event(KeyLifecycleRequest.ROTATED, leaf));
            assertThat(logs.list).noneMatch(e -> e.getFormattedMessage().startsWith("Lifecycle event refused"));

            SecurityContextHolder.getContext().setAuthentication(
                    new TestingAuthenticationToken("fe-b", null, "ROLE_FE"));
            service.changeStatus("SE", event(KeyLifecycleRequest.REVOKED, leaf));
            assertThat(logs.list).anyMatch(e -> e.getFormattedMessage().startsWith(
                    "Lifecycle event refused for verificationId=VID-W: calling principal 'fe-b'"));
        } finally {
            logger.detachAppender(logs);
        }
    }

    @Test
    void aSignedEventIsNotBoundToThePrincipalThatVerified() throws Exception {
        issue("VID-S", leafKp, leaf, "SE", "issuance-service-1");
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("signing-service-1", null, "ROLE_FE"));

        SignedEventResponse r = lifecycle(true).signed("SE", signedEvent(leafKp, leaf, "signed-by-service"));

        assertThat(r.getVerdict().getReason()).isEqualTo("OK");
    }

    // ------------------------------------------------------------ SIGNED

    @Test
    void aSignedEventIsVerifiedAsASettlementAndSignedTheSameWay() throws Exception {
        issue("VID-SIG", leafKp, leaf, "SE", "fe");
        KeyLifecycleRequest req = signedEvent(leafKp, leaf, "org-signature");

        SignedEventResponse r = lifecycle(false).signed("SE", req);
        SignatureVerificationResponse v = r.getVerdict();

        assertThat(r.getEventType()).isEqualTo("SIGNED");
        assertThat(v.isSignatureValid()).isTrue();
        assertThat(v.isCompliant()).isTrue();
        assertThat(v.getReason()).isEqualTo("OK");
        assertThat(v.getAuditEntryId()).isEqualTo("VID-SIG");
        AuditEntry entry = head();
        assertThat(entry.operation()).isEqualTo("SIGNED");
        assertThat(entry.compliant()).isTrue();
        assertThat(v.getAuditEntryHashHex()).isEqualTo(entry.thisEntryHashHex());

        byte[] canonical = SettlementVerdictCanonicalizer.canonicalize(v.getVerifiedAt(), req.getCertSerial(),
                req.getIssuerDn(), req.getDigestHex(), true, true, "OK", "VID-SIG", v.getAuditEntryHashHex());
        Signature check = Signature.getInstance(v.getVerdictSignatureAlgorithm());
        check.initVerify(signer.getPublicKey());
        check.update(canonical);
        assertThat(check.verify(Base64.getDecoder().decode(v.getVerdictSignatureBase64()))).isTrue();
    }

    @Test
    void aSignedEventIsDeniedLikeASettlement() throws Exception {
        issue("VID-D", leafKp, leaf, "SE", "fe");
        KeyLifecycleService service = lifecycle(false);

        KeyLifecycleRequest tampered = signedEvent(leafKp, leaf, "one");
        tampered.setDigestHex(HexFormat.of().formatHex(digest("two")));
        assertThat(service.signed("SE", tampered).getVerdict().getReason()).isEqualTo("SIGNATURE_INVALID");

        assertThat(service.signed("DE", signedEvent(leafKp, leaf, "x")).getVerdict().getReason())
                .as("another jurisdiction").isEqualTo("CERT_NOT_FOUND");

        service.changeStatus("SE", event(KeyLifecycleRequest.REVOKED, leaf));
        SignatureVerificationResponse revoked = service.signed("SE", signedEvent(leafKp, leaf, "after")).getVerdict();
        assertThat(revoked.getReason()).isEqualTo("CERT_REVOKED");
        assertThat(revoked.isSignatureValid()).isTrue();
        assertThat(revoked.isCompliant()).isFalse();
        assertThat(head().operation()).isEqualTo("SIGNED");
        assertThat(head().compliant()).isFalse();
    }

    @Test
    void aLifecycleDenialComesAfterTheSignatureCheckAndBeforeExpiry() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        long now = System.currentTimeMillis();
        X509Certificate expired = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                new X500Name(issuerCa.getSubjectX500Principal().getName()), BigInteger.valueOf(777_001),
                new Date(now - 7200_000L), new Date(now - 60_000L), new X500Name("CN=Expired"), kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKp.getPrivate())));
        issue("VID-X", kp, expired, "SE", "fe");
        assertThat(settle(kp, expired).getReason()).isEqualTo("CERT_EXPIRED");

        lifecycle(false).changeStatus("SE", event(KeyLifecycleRequest.REVOKED, expired));

        assertThat(settle(kp, expired).getReason()).isEqualTo("CERT_REVOKED");
        assertThat(settle(leafKp, expired).getReason()).as("wrong key").isEqualTo("SIGNATURE_INVALID");
    }

    @Test
    void theManuscriptEventsMapToTheseOperationLabels() {
        assertThat(List.of(SignatureVerificationService.SIGNED_EVENT_OPERATION,
                SignatureVerificationService.AUDIT_OPERATION,
                KeyLifecycleRequest.ROTATED, KeyLifecycleRequest.REVOKED, KeyLifecycleRequest.DECOMMISSIONED))
                .containsExactly("SIGNED", "SETTLEMENT_VERIFY", "ROTATED", "REVOKED", "DECOMMISSIONED");
        assertThat(KeyLifecycleService.targetStatus("ROTATED")).isEqualTo(RegistryStatus.SUPERSEDED);
        assertThat(KeyLifecycleService.targetStatus("REVOKED")).isEqualTo(RegistryStatus.REVOKED);
        assertThat(KeyLifecycleService.targetStatus("DECOMMISSIONED")).isEqualTo(RegistryStatus.DECOMMISSIONED);
    }
}
