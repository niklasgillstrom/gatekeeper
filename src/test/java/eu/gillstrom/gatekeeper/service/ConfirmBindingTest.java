package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.MtlsPrincipalResolver;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmation;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.verification.AzureHsmVerifier;
import eu.gillstrom.gatekeeper.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.gatekeeper.verification.SecurosysVerifier;
import eu.gillstrom.gatekeeper.verification.YubicoVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Step 7 is bound to the jurisdiction in the request path and to the client
 * that performed the verification.
 *
 * <p>Two defects are pinned here. {@code POST
 * /v1/attestation/&#x7b;cc&#x7d;/confirm} took a country code in the path and
 * looked the entry up without it, so a confirmation posted to
 * {@code /DE/confirm} could close the loop on a Swedish registry entry —
 * across a boundary that DORA Article 55 professional secrecy runs along.
 * And nothing tied the confirmation to the caller: any client holding a
 * {@code verificationId} and its nonce could confirm another entity's
 * verification.</p>
 *
 * <p>Both failures are reported as an unknown {@code verificationId}. That
 * is the second half of the fix: a distinct "wrong jurisdiction" or "wrong
 * client" answer would turn the endpoint into an oracle for the existence
 * of entries the caller is not allowed to see.</p>
 */
class ConfirmBindingTest {

    @TempDir
    Path tempDir;

    private static final String VERIFIER_PRINCIPAL = "CN=FE-Alpha";
    private static final String OTHER_PRINCIPAL = "CN=FE-Beta";

    private InMemoryApprovalRegistry registry;
    private MtlsPrincipalResolver principalResolver;
    private AppendOnlyFileAuditLog auditLog;

    @BeforeEach
    void setUp() {
        registry = new InMemoryApprovalRegistry();
        principalResolver = mock(MtlsPrincipalResolver.class);
        auditLog = new AppendOnlyFileAuditLog(
                tempDir.resolve("audit-" + System.nanoTime() + ".jsonl").toString(),
                new EphemeralReceiptSigner(2048));
        auditLog.initialise();
    }

    /**
     * The verification pipeline itself is not under test here — only the two
     * bindings that gate the registry lookup — so the vendor verifiers and
     * the issuer-CA validator are mocked and never called: every
     * confirmation below is a non-issuance notice, which carries no
     * certificate.
     */
    private final EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);

    @Test
    void theNonceMismatchRefusalIsSigned() throws Exception {
        registerSwedishEntry("SE-9");
        when(principalResolver.currentPrincipal()).thenReturn(VERIFIER_PRINCIPAL);
        IssuanceConfirmation replayed = nonIssuanceNotice("SE-9");
        replayed.setConfirmationNonce("not-the-bound-nonce");

        IssuanceConfirmationResponse rejection = serviceWithMtls(true).confirmIssuance(replayed, "SE");

        assertThat(rejection.getSigningCertificate()).isEqualTo(signer.getSigningCertificatePem());
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(
                        new java.io.ByteArrayInputStream(rejection.getSigningCertificate()
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        java.security.Signature sig = java.security.Signature.getInstance(signer.getSignatureAlgorithm());
        sig.initVerify(cert.getPublicKey());
        sig.update(eu.gillstrom.gatekeeper.signing.ConfirmationCanonicalizer.canonicalize(rejection));
        assertThat(sig.verify(java.util.Base64.getDecoder().decode(rejection.getSignature()))).isTrue();
    }

    private VerificationService serviceWithMtls(boolean mtlsEnabled) {
        VerificationService service = new VerificationService(
                mock(SecurosysVerifier.class),
                mock(YubicoVerifier.class),
                mock(AzureHsmVerifier.class),
                mock(GoogleCloudHsmVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.MarvellHsmVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.ThalesLunaVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.Crypto4AVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.FortanixVerifier.class),
                mock(eu.gillstrom.gatekeeper.verification.NShieldVerifier.class),
                registry,
                signer,
                mock(IssuerCaValidator.class),
                auditLog,
                principalResolver,
                KeyPolicy.defaults(),
                mtlsEnabled);
        service.warnIfPrincipalBindingDisabled();
        return service;
    }

    private void registerSwedishEntry(String verificationId) {
        registry.register(verificationId, "nonce-" + verificationId, true, "fp",
                "556000-0000", "Svensk TL", "SECUROSYS", "Primus HSM", "SE",
                VERIFIER_PRINCIPAL);
    }

    private static IssuanceConfirmation nonIssuanceNotice(String verificationId) {
        IssuanceConfirmation confirmation = new IssuanceConfirmation();
        confirmation.setVerificationId(verificationId);
        confirmation.setConfirmationNonce("nonce-" + verificationId);
        confirmation.setIssued(false);
        confirmation.setNonIssuanceReason("TL withdrew the request");
        confirmation.setTimestamp(Instant.now().toString());
        return confirmation;
    }

    @Test
    void confirmForAnotherJurisdictionDoesNotResolveTheEntry() {
        registerSwedishEntry("SE-1");
        when(principalResolver.currentPrincipal()).thenReturn(VERIFIER_PRINCIPAL);
        VerificationService service = serviceWithMtls(true);

        IssuanceConfirmationResponse response =
                service.confirmIssuance(nonIssuanceNotice("SE-1"), "DE");

        assertThat(response.getRegistryStatus())
                .isEqualTo(RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION);
        assertThat(response.isLoopClosed()).isFalse();
        // The entry itself is untouched: still awaiting Step 7, nonce unspent.
        ApprovalRegistry.RegistryEntry entry = registry.lookup("SE-1").orElseThrow();
        assertThat(entry.getStatus()).isNull();
        assertThat(entry.getConfirmationNonce()).isEqualTo("nonce-SE-1");
    }

    @Test
    void confirmFromAnotherClientDoesNotResolveTheEntry() {
        registerSwedishEntry("SE-2");
        when(principalResolver.currentPrincipal()).thenReturn(OTHER_PRINCIPAL);
        VerificationService service = serviceWithMtls(true);

        IssuanceConfirmationResponse response =
                service.confirmIssuance(nonIssuanceNotice("SE-2"), "SE");

        assertThat(response.getRegistryStatus())
                .isEqualTo(RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION);
        assertThat(registry.lookup("SE-2").orElseThrow().getStatus()).isNull();
    }

    /**
     * The wrong-jurisdiction and wrong-client answers must be
     * indistinguishable from a genuinely unknown identifier, otherwise the
     * endpoint reports on the existence of entries the caller may not see.
     */
    @Test
    void refusalIsIndistinguishableFromAnUnknownVerificationId() {
        registerSwedishEntry("SE-3");
        when(principalResolver.currentPrincipal()).thenReturn(OTHER_PRINCIPAL);
        VerificationService service = serviceWithMtls(true);

        IssuanceConfirmationResponse wrongClient =
                service.confirmIssuance(nonIssuanceNotice("SE-3"), "SE");
        IssuanceConfirmationResponse neverExisted =
                service.confirmIssuance(nonIssuanceNotice("does-not-exist"), "SE");

        assertThat(wrongClient.getRegistryStatus()).isEqualTo(neverExisted.getRegistryStatus());
        assertThat(wrongClient.isLoopClosed()).isEqualTo(neverExisted.isLoopClosed());
        assertThat(wrongClient.getExpectedPublicKeyFingerprint())
                .isEqualTo(neverExisted.getExpectedPublicKeyFingerprint());
        // Only the echoed verificationId differs between the two bodies.
        assertThat(wrongClient.getAnomalies())
                .hasSameSizeAs(neverExisted.getAnomalies());
    }

    @Test
    void confirmFromTheVerifyingClientInTheRightJurisdictionSucceeds() {
        registerSwedishEntry("SE-4");
        when(principalResolver.currentPrincipal()).thenReturn(VERIFIER_PRINCIPAL);
        VerificationService service = serviceWithMtls(true);

        IssuanceConfirmationResponse response =
                service.confirmIssuance(nonIssuanceNotice("SE-4"), "SE");

        assertThat(response.getRegistryStatus()).isEqualTo(RegistryStatus.VERIFIED_NOT_ISSUED);
        assertThat(response.isLoopClosed()).isTrue();
        assertThat(registry.lookup("SE-4").orElseThrow().getConfirmationNonce()).isNull();
    }

    /**
     * With the permissive reference chain there is no authenticated caller to
     * bind to, so the principal check is skipped — the startup WARN emitted
     * by {@code warnIfPrincipalBindingDisabled()} is what carries the fact.
     * The jurisdiction binding still applies, because it does not depend on
     * authentication.
     */
    @Test
    void principalBindingIsSkippedWhenMtlsIsDisabledButJurisdictionStillBinds() {
        registerSwedishEntry("SE-5");
        registerSwedishEntry("SE-6");
        when(principalResolver.currentPrincipal()).thenReturn(OTHER_PRINCIPAL);
        VerificationService service = serviceWithMtls(false);

        assertThat(service.confirmIssuance(nonIssuanceNotice("SE-5"), "SE").getRegistryStatus())
                .isEqualTo(RegistryStatus.VERIFIED_NOT_ISSUED);
        assertThat(service.confirmIssuance(nonIssuanceNotice("SE-6"), "DE").getRegistryStatus())
                .isEqualTo(RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION);
    }

    /**
     * Entries registered before the binding existed (or under the permissive
     * chain) carry no principal. They must stay confirmable: failing them
     * closed would make every entry in an upgraded deployment's journal
     * permanently unconfirmable.
     */
    @Test
    void entriesWithNoBoundPrincipalRemainConfirmable() {
        registry.register("SE-7", "nonce-SE-7", true, "fp", "556000-0000", "Svensk TL",
                "SECUROSYS", "Primus HSM", "SE");
        when(principalResolver.currentPrincipal()).thenReturn(OTHER_PRINCIPAL);
        VerificationService service = serviceWithMtls(true);

        assertThat(service.confirmIssuance(nonIssuanceNotice("SE-7"), "SE").getRegistryStatus())
                .isEqualTo(RegistryStatus.VERIFIED_NOT_ISSUED);
    }

    @Test
    void nonceMismatchIsWrittenToTheAuditLog() {
        registerSwedishEntry("SE-8");
        when(principalResolver.currentPrincipal()).thenReturn(VERIFIER_PRINCIPAL);
        VerificationService service = serviceWithMtls(true);
        IssuanceConfirmation replayed = nonIssuanceNotice("SE-8");
        replayed.setConfirmationNonce("not-the-bound-nonce");

        IssuanceConfirmationResponse rejection = service.confirmIssuance(replayed, "SE");

        assertThat(rejection.getRegistryStatus()).isEqualTo(RegistryStatus.ANOMALY_NONCE_MISMATCH);
        assertThat(rejection.isLoopClosed()).isFalse();

        AuditEntry entry = auditLog.findByVerificationId("SE-8").orElseThrow();
        assertThat(entry.operation()).isEqualTo("CONFIRM");
        assertThat(entry.compliant()).isFalse();
        assertThat(entry.mtlsClientPrincipal()).isEqualTo(VERIFIER_PRINCIPAL);
        assertThat(registry.lookup("SE-8").orElseThrow().getStatus()).isNull();
    }
}
