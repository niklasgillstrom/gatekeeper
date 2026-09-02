package eu.gillstrom.gatekeeper.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Public-facing endpoints that publish the gatekeeper's verifiability
 * primitives — the keys it signs receipts with, and a periodic
 * commitment to the head of the audit chain — so that supervisors and
 * relying parties can verify gatekeeper-signed evidence retroactively
 * for the full DORA Article 28(6) 5-year retention period.
 *
 * <p>Endpoints under {@code /v1/gatekeeper}:</p>
 * <ul>
 *   <li>{@code GET /keys} — active and retired signing certificates.
 *       Finansinspektionen pastes the JSON into its
 *       {@code swish.gatekeeper.trusted-keys-config} list to trust
 *       receipts in supervisory tooling.</li>
 *   <li>{@code GET /anchor} — current chain head, signed. Published
 *       periodically (e.g. daily) to a public commitment log so the
 *       audit trail cannot be retroactively rewritten without
 *       detection.</li>
 *   <li>{@code GET /health} — operational health, including the most
 *       recent outcome of {@link AuditLog#verifyChainIntegrity()} as
 *       served by {@link AuditLog#cachedIntegrityStatus()} and the
 *       instant it was computed. Requires the {@code SUPERVISOR} role;
 *       unlike {@code /keys} and {@code /anchor} it is not evidence a
 *       relying party needs, and it reports operational state.</li>
 * </ul>
 *
 * <p>Legal basis:</p>
 * <ul>
 *   <li>DORA (EU 2022/2554) Article 28(6) — 5-year retention with
 *       discoverable verifiability requires the publication of seal
 *       certificates and chain anchors.</li>
 *   <li>EBA Regulation (EU) 1093/2010 Article 35(1) — supervisory
 *       cooperation: the supervisor needs the keys to verify records.</li>
 * </ul>
 */
@RestController
@RequestMapping("/v1/gatekeeper")
@Tag(name = "Gatekeeper Verifiability",
     description = "Publishes signing keys and audit-chain anchors so receipts and the audit "
         + "trail can be verified retroactively under DORA Article 28(6).")
public class GatekeeperController {

    private final GatekeeperKeyDirectory keyDirectory;
    private final AuditLog auditLog;
    private final ReceiptSigner signer;
    private final String mode;

    public GatekeeperController(GatekeeperKeyDirectory keyDirectory,
                                AuditLog auditLog,
                                ReceiptSigner signer,
                                @Value("${gatekeeper.signing.mode:ephemeral}") String mode) {
        this.keyDirectory = keyDirectory;
        this.auditLog = auditLog;
        this.signer = signer;
        this.mode = mode;
    }

    @GetMapping("/keys")
    @Operation(
        summary = "Publish active and retired gatekeeper signing keys",
        description = """
                Returns the certificates a relying party needs in order to
                verify gatekeeper-signed receipts and audit anchors. The
                response includes the currently-active key plus every
                retired key configured via gatekeeper.signing.retired-keys.
                Operators paste this list into Finansinspektionen's
                swish.gatekeeper.trusted-keys-config.""")
    public ResponseEntity<List<GatekeeperKeyDirectory.KeyEntry>> publishKeys() {
        return ResponseEntity.ok(keyDirectory.allKeys());
    }

    @GetMapping("/anchor")
    @Operation(
        summary = "Current audit-chain head, signed",
        description = """
                Returns a signed anchor over the head of the audit chain.
                A supervisor publishes this periodically (e.g. daily) to a
                public commitment so the chain cannot be retroactively
                rewritten without detection. The headSignatureBase64 is
                the gatekeeper's signature (in production, the NCA's
                organisation-certificate-backed signing key — the
                certificate the NCA uses for ordinary administrative
                signing of supervisory acts) over the UTF-8 bytes of
                headHashHex.""")
    public ResponseEntity<AuditAnchor> currentAnchor() {
        Optional<AuditEntry> headOpt = auditLog.head();
        if (headOpt.isEmpty()) {
            // Empty-log anchor: still signed so a supervisor can prove the
            // gatekeeper observed an empty trail at this moment.
            String emptyHashHex = AuditEntry.SENTINEL_PREV_HASH_HEX;
            byte[] sig = signer.sign(emptyHashHex.getBytes(StandardCharsets.UTF_8));
            AuditAnchor anchor = new AuditAnchor(
                    0L,
                    emptyHashHex,
                    null,
                    Base64.getEncoder().encodeToString(sig),
                    keyDirectory.activeFingerprintHex(),
                    0L);
            return ResponseEntity.ok(anchor);
        }
        AuditEntry head = headOpt.get();
        byte[] sig = signer.sign(AuditEntry.canonicalBytesForSignature(head));
        AuditAnchor anchor = new AuditAnchor(
                head.sequenceNumber(),
                head.thisEntryHashHex(),
                head.timestamp(),
                Base64.getEncoder().encodeToString(sig),
                keyDirectory.activeFingerprintHex(),
                auditLog.size());
        return ResponseEntity.ok(anchor);
    }

    @GetMapping("/health")
    @Operation(
        summary = "Operational health including audit-chain integrity",
        description = """
                Returns whether the audit log is readable, the most recent
                chain-integrity result together with the instant it was
                computed, the head sequence number and timestamp, the total
                number of entries, the fingerprint of the active signing
                key, and the signing mode (configured or ephemeral).
                Monitoring systems should fail closed if chainIntact is
                false or mode is "ephemeral" in production.

                The integrity result is cached: it is recomputed at most
                once per gatekeeper.audit.integrity-check-interval-seconds
                (default 300) rather than on every request, because the
                walk is O(chain length) with one signature verification per
                entry. chainCheckedAt tells the caller how old the answer
                is; a monitoring system that needs it fresher lowers the
                interval rather than polling harder.

                Requires the SUPERVISOR role: the response discloses the
                chain length and head sequence number, i.e. how much
                supervisory activity the gatekeeper has recorded, and the
                integrity check is not work an anonymous caller should be
                able to trigger.""")
    public ResponseEntity<HealthStatus> health() {
        boolean readable;
        long size = 0;
        long headSeq = 0;
        java.time.Instant headTs = null;
        try {
            size = auditLog.size();
            Optional<AuditEntry> head = auditLog.head();
            if (head.isPresent()) {
                headSeq = head.get().sequenceNumber();
                headTs = head.get().timestamp();
            }
            readable = true;
        } catch (Exception e) {
            readable = false;
        }
        AuditLog.IntegrityStatus integrity;
        try {
            integrity = auditLog.cachedIntegrityStatus();
        } catch (Exception e) {
            integrity = new AuditLog.IntegrityStatus(false, null);
        }
        HealthStatus status = new HealthStatus(
                readable, integrity.intact(), integrity.checkedAt(),
                headSeq, headTs, size,
                keyDirectory.activeFingerprintHex(), mode);
        return ResponseEntity.ok(status);
    }
}
