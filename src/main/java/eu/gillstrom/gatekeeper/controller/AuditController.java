package eu.gillstrom.gatekeeper.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.cose.AuditCoseExport;
import eu.gillstrom.gatekeeper.cose.CoseSign1;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Supervisory audit-query API.
 *
 * <p>Exposes the gatekeeper's tamper-evident audit log to authorised
 * supervisory clients. All endpoints are read-only — appends are
 * triggered only by the gatekeeper's own decision-making code paths
 * (verify / confirm / batch-verify). Queries read the in-memory copy of
 * the log; {@link AuditLog#verifyChainIntegrity()} reads the file back
 * from disk, so a change made to the file under a running gatekeeper is
 * reported by the integrity check, not reflected in query results.</p>
 *
 * <p>Endpoints under {@code /v1/audit}:</p>
 * <ul>
 *   <li>{@code GET /witness/{verificationId}} — the earliest entry with
 *       that verification ID, which for an issuance is the {@code VERIFY}
 *       or {@code BATCH_VERIFY} entry. {@code 404} if absent.</li>
 *   <li>{@code GET /range?from=...&to=...} — entries in a half-open
 *       time window. The maximum allowed window is 90 days to bound the
 *       resource cost of a malicious or careless query.</li>
 *   <li>{@code GET /entity/{principal}} — entries for a given mTLS
 *       principal, compared exactly with the value recorded at append:
 *       the value of the subject attribute named by {@code gatekeeper.security.mtls.principal-attribute}
 *       (by default the CN value). A certificate without exactly one such
 *       attribute is not authenticated. {@code principal} is URL-decoded.</li>
 *   <li>{@code GET /export?from=...&to=...&inspectionId=...} —
 *       packaged, signed export for a supervisory inspection. With
 *       {@code format=cose} the same window is returned as
 *       {@code application/cbor-seq}: one COSE_Sign1 per entry, each sealed
 *       at export time by the active signing key (see
 *       {@link AuditCoseExport}; the seal is not the entry's original
 *       evidence). {@code format} defaults to {@code json}.</li>
 * </ul>
 *
 * <p>Legal basis:</p>
 * <ul>
 *   <li>DORA Article 28(6) — 5-year retention with discoverable access
 *       to records of every gatekeeper decision.</li>
 *   <li>DORA Article 17 (incident reporting) — the audit trail is the
 *       primary input to incident investigation.</li>
 *   <li>EBA Regulation (EU) 1093/2010 Article 35(1) — supervisory
 *       cooperation: the supervisor obtains records via this API.</li>
 *   <li>The export is signed with the NCA's organisation-certificate-
 *       backed signing key — the certificate the NCA uses for ordinary
 *       administrative signing of supervisory acts. Counterparties verify
 *       the signature substantively against the canonical bytes and the
 *       certificate published via {@code GET /v1/gatekeeper/keys}.</li>
 * </ul>
 */
@RestController
@RequestMapping("/v1/audit")
@Tag(name = "Supervisory Audit Query",
     description = "Read-only access to the tamper-evident audit log. "
         + "Operated by the NCA; consumed by supervisory inspection teams.")
public class AuditController {

    private static final Duration MAX_RANGE = Duration.ofDays(90);

    private final AuditLog auditLog;
    private final ReceiptSigner signer;
    private final GatekeeperKeyDirectory keyDirectory;

    public AuditController(AuditLog auditLog,
                           ReceiptSigner signer,
                           GatekeeperKeyDirectory keyDirectory) {
        this.auditLog = auditLog;
        this.signer = signer;
        this.keyDirectory = keyDirectory;
    }

    @GetMapping("/witness/{verificationId}")
    @Operation(
        summary = "Earliest audit entry with a verification ID",
        description = "Returns the VERIFY or BATCH_VERIFY entry of an issuance; CONFIRM and "
                + "SETTLEMENT_VERIFY entries with the same ID are listed by /range. "
                + "Returns 404 if the verification ID is unknown.")
    public ResponseEntity<AuditEntry> findEntry(@PathVariable String verificationId) {
        Optional<AuditEntry> entry = auditLog.findByVerificationId(verificationId);
        return entry.map(ResponseEntity::ok)
                .orElseThrow(() -> new ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND,
                        "No audit entry for verificationId=" + verificationId));
    }

    @GetMapping("/range")
    @Operation(
        summary = "Audit entries in a [from, to) time window",
        description = "Validates from <= to; rejects windows wider than 90 days to cap "
                + "resource usage. Returns entries in ascending sequence-number order.")
    public ResponseEntity<List<AuditEntry>> findInRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        validateRange(from, to);
        return ResponseEntity.ok(auditLog.findInRange(from, to));
    }

    @GetMapping("/entity/{principal}")
    @Operation(
        summary = "Audit entries for a given mTLS principal",
        description = "Principal is URL-decoded and compared exactly with the recorded "
                + "principal: the value of the subject attribute named by gatekeeper.security.mtls.principal-attribute "
                + "(by default the CN value, e.g. swishTL), not the full DN.")
    public ResponseEntity<List<AuditEntry>> findByEntity(@PathVariable String principal) {
        String decoded = URLDecoder.decode(principal, StandardCharsets.UTF_8);
        return ResponseEntity.ok(auditLog.findByPrincipal(decoded));
    }

    @GetMapping("/export")
    @Operation(
        summary = "Signed export of audit entries for a supervisory inspection",
        description = """
                Returns an AuditExport bundle covering the requested
                [from, to) window, sealed under the gatekeeper's active
                signing key. If inspectionId is omitted the gatekeeper
                generates a UUID. The bundle includes the chain-head hash
                at the moment of export so a supervisor can also verify
                the rest of the chain via the /v1/gatekeeper/anchor
                endpoint at the same moment.

                format=json (default) returns that bundle. format=cose
                returns application/cbor-seq: one COSE_Sign1 (RFC 9052,
                tag 18) per entry in the window, protected header
                {1: alg, 4: kid = SHA-256 of the active key's
                SubjectPublicKeyInfo}, payload a CBOR map of the entry
                fields including its original entry signature and RFC 3161
                token. The COSE signature is an export seal made now by the
                active key; the entry's own signature, chain hashes and
                token remain the evidence. inspectionId is not used by the
                COSE form, which has no bundle envelope.""")
    public ResponseEntity<?> exportRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) String inspectionId,
            @RequestParam(required = false) String format) {
        validateRange(from, to);
        if (format != null && !format.isBlank() && !"json".equalsIgnoreCase(format)) {
            if (!"cose".equalsIgnoreCase(format)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "format must be json or cose");
            }
            return exportCose(auditLog.findInRange(from, to));
        }

        String resolvedInspectionId = (inspectionId == null || inspectionId.isBlank())
                ? UUID.randomUUID().toString()
                : inspectionId;
        Instant generatedAt = Instant.now();
        List<AuditEntry> entries = auditLog.findInRange(from, to);
        Optional<AuditEntry> head = auditLog.head();
        String chainHeadHash = head.map(AuditEntry::thisEntryHashHex)
                .orElse(AuditEntry.SENTINEL_PREV_HASH_HEX);
        String fingerprint = keyDirectory.activeFingerprintHex();

        byte[] canonical = AuditExport.canonicalBytesForSignature(
                resolvedInspectionId, generatedAt, from, to,
                entries.size(), entries, chainHeadHash, fingerprint);
        byte[] sig = signer.sign(canonical);

        AuditExport export = new AuditExport(
                resolvedInspectionId,
                generatedAt,
                from,
                to,
                entries.size(),
                entries,
                chainHeadHash,
                Base64.getEncoder().encodeToString(sig),
                fingerprint);
        return ResponseEntity.ok(export);
    }

    private ResponseEntity<byte[]> exportCose(List<AuditEntry> entries) {
        byte[] kid = HexFormat.of().parseHex(keyDirectory.activeFingerprintHex());
        java.security.PublicKey activeKey;
        try {
            activeKey = java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(
                            signer.getSigningCertificatePem().getBytes(StandardCharsets.UTF_8)))
                    .getPublicKey();
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "active signing certificate could not be parsed", e);
        }
        byte[] body;
        try {
            body = AuditCoseExport.export(entries, signer, activeKey, kid);
        } catch (CoseSign1.UnsupportedAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED, e.getMessage(), e);
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(AuditCoseExport.MEDIA_TYPE))
                .body(body);
    }

    private static void validateRange(Instant from, Instant to) {
        if (from == null || to == null) {
            throw new ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST,
                    "from and to are required");
        }
        if (from.isAfter(to)) {
            throw new ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST,
                    "from must be <= to");
        }
        if (Duration.between(from, to).compareTo(MAX_RANGE) > 0) {
            throw new ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST,
                    "Range must be <= 90 days; supervisory exports beyond that "
                            + "must be requested in multiple windows.");
        }
    }
}
