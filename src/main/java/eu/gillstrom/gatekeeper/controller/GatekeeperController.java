package eu.gillstrom.gatekeeper.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import eu.gillstrom.gatekeeper.signing.SigningKeyAttestation;
import eu.gillstrom.gatekeeper.timestamp.AuditTimestamping;
import eu.gillstrom.gatekeeper.timestamp.TimestampAnchorRecord;
import eu.gillstrom.gatekeeper.timestamp.TimestampAnchorService;

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
 *       detection. Carries the latest RFC 3161 anchor record as
 *       {@code latestTimestamp} when one exists.</li>
 *   <li>{@code GET /anchor/timestamps?offset=&limit=} — the RFC 3161
 *       anchor records, oldest first, paged
 *       ({@link TimestampAnchorList}). Public, like {@code /anchor}.</li>
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

    /** Upper bound on {@code limit} for {@code GET /anchor/timestamps}. */
    static final int MAX_ANCHOR_PAGE = 1000;

    private final GatekeeperKeyDirectory keyDirectory;
    private final AuditLog auditLog;
    private final ReceiptSigner signer;
    private final String mode;
    private final SigningKeyAttestation signingKeyAttestation;
    private final AuditTimestamping timestamping;
    private final TimestampAnchorService anchorService;

    public GatekeeperController(GatekeeperKeyDirectory keyDirectory,
                                AuditLog auditLog,
                                ReceiptSigner signer,
                                String mode) {
        this(keyDirectory, auditLog, signer, mode, null, null, null);
    }

    @Autowired
    public GatekeeperController(GatekeeperKeyDirectory keyDirectory,
                                AuditLog auditLog,
                                ReceiptSigner signer,
                                @Value("${gatekeeper.signing.mode:ephemeral}") String mode,
                                SigningKeyAttestation signingKeyAttestation,
                                AuditTimestamping timestamping,
                                TimestampAnchorService anchorService) {
        this.keyDirectory = keyDirectory;
        this.auditLog = auditLog;
        this.signer = signer;
        this.mode = mode;
        this.signingKeyAttestation = signingKeyAttestation;
        this.timestamping = timestamping;
        this.anchorService = anchorService;
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
                swish.gatekeeper.trusted-keys-config.

                When gatekeeper.signing.attestation.* is configured, the
                ACTIVE entry also carries "attestation": the verified HSM
                attestation of the signing key (vendor, hsmSerial, valid,
                chainValid, publicKeyMatch, keyOrigin, exportable, ...) and
                the evidence itself, so a relying party can re-verify it
                against the vendor root.""")
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
                headHashHex.

                latestTimestamp, present only when an RFC 3161 anchor record
                exists, is the most recent one: a TSA token over SHA-256 of
                the UTF-8 bytes of that record's headHashHex.""")
    public ResponseEntity<AuditAnchor> currentAnchor() {
        TimestampAnchorRecord latestTimestamp = anchorService == null ? null : anchorService.latest().orElse(null);
        Optional<AuditEntry> headOpt = auditLog.head();
        if (headOpt.isEmpty()) {
            // Empty-log anchor: the sentinel, signed. The signed bytes are a
            // constant, so the signature shows that this key answers for an
            // empty trail and not at which moment the trail was empty.
            String emptyHashHex = AuditEntry.SENTINEL_PREV_HASH_HEX;
            byte[] sig = signer.sign(emptyHashHex.getBytes(StandardCharsets.UTF_8));
            AuditAnchor anchor = new AuditAnchor(
                    0L,
                    emptyHashHex,
                    null,
                    Base64.getEncoder().encodeToString(sig),
                    keyDirectory.activeFingerprintHex(),
                    0L,
                    latestTimestamp);
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
                auditLog.size(),
                latestTimestamp);
        return ResponseEntity.ok(anchor);
    }

    @GetMapping("/anchor/timestamps")
    @Operation(
        summary = "RFC 3161 anchor records of the audit-chain head",
        description = """
                Lists the anchor records written under
                gatekeeper.timestamping.mode=anchor, oldest first:
                headSequenceNumber, headHashHex, tokenBase64 (DER
                TimeStampToken over SHA-256 of the UTF-8 bytes of
                headHashHex) and genTime. Paged with offset (default 0) and
                limit (default 100, at most 1000). Empty when no anchor file
                is in use.""")
    public ResponseEntity<TimestampAnchorList> anchorTimestamps(
            @RequestParam(defaultValue = "0") int offset,
            @RequestParam(defaultValue = "100") int limit) {
        if (offset < 0 || limit < 1 || limit > MAX_ANCHOR_PAGE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "offset must be >= 0 and limit between 1 and " + MAX_ANCHOR_PAGE);
        }
        List<TimestampAnchorRecord> all = anchorService == null ? List.of() : anchorService.all();
        int from = (int) Math.min(offset, all.size());
        int to = (int) Math.min((long) from + limit, all.size());
        String timestampingMode = timestamping == null ? AuditTimestamping.Mode.OFF.label() : timestamping.mode().label();
        return ResponseEntity.ok(new TimestampAnchorList(timestampingMode, all.size(), offset,
                List.copyOf(all.subList(from, to))));
    }

    /**
     * A page of anchor records.
     *
     * @param timestampingMode {@code off}, {@code entry} or {@code anchor}
     * @param total number of records in the anchor file
     * @param offset index of the first record returned
     * @param records the records, oldest first
     */
    public record TimestampAnchorList(String timestampingMode, long total, int offset,
                                      List<TimestampAnchorRecord> records) {
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

                Optional fields, absent unless the feature is configured:
                activeKeyAttested (gatekeeper.signing.attestation.*),
                timestampingMode, untimestampedEntries (entry mode),
                latestTimestampAnchorSequenceNumber and
                latestTimestampAnchorGenTime (anchor mode).

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
        Boolean activeKeyAttested = signingKeyAttestation != null && signingKeyAttestation.isConfigured()
                ? signingKeyAttestation.isActiveKeyAttested() : null;
        AuditTimestamping.Mode tsMode = timestamping == null ? AuditTimestamping.Mode.OFF : timestamping.mode();
        Long untimestamped = null;
        if (tsMode == AuditTimestamping.Mode.ENTRY) {
            java.util.OptionalLong count = auditLog.untimestampedEntryCount();
            untimestamped = count.isPresent() ? count.getAsLong() : null;
        }
        Long anchorSeq = null;
        java.time.Instant anchorGenTime = null;
        if (tsMode == AuditTimestamping.Mode.ANCHOR && anchorService != null) {
            Optional<TimestampAnchorRecord> latest = anchorService.latest();
            if (latest.isPresent()) {
                anchorSeq = latest.get().headSequenceNumber();
                anchorGenTime = latest.get().genTime();
            }
        }
        HealthStatus status = new HealthStatus(
                readable, integrity.intact(), integrity.checkedAt(),
                headSeq, headTs, size,
                keyDirectory.activeFingerprintHex(), mode,
                activeKeyAttested,
                tsMode == AuditTimestamping.Mode.OFF ? null : tsMode.label(),
                untimestamped, anchorSeq, anchorGenTime);
        return ResponseEntity.ok(status);
    }
}
