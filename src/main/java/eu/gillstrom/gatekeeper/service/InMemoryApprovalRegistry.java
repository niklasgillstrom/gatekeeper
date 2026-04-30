package eu.gillstrom.gatekeeper.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory implementation of {@link ApprovalRegistry}, backed by a
 * {@link ConcurrentHashMap}.
 *
 * <p>Activated when {@code gatekeeper.registry.mode=in-memory} (the
 * default if the property is unset). Suitable for development, CI, and
 * the reference flow. <strong>Not suitable for production</strong>:
 * pending {@code verificationId}s are lost on every restart, so any
 * Step 7 confirmation that arrives after a gatekeeper restart will fail
 * to find its corresponding {@code verify} record. The
 * {@code application-nca.yaml} profile selects
 * {@link AppendOnlyFileApprovalRegistry} instead.</p>
 */
@Component
@ConditionalOnProperty(name = "gatekeeper.registry.mode", havingValue = "in-memory", matchIfMissing = true)
public class InMemoryApprovalRegistry implements ApprovalRegistry {

    private static final Logger log = LoggerFactory.getLogger(InMemoryApprovalRegistry.class);

    private final ConcurrentHashMap<String, RegistryEntry> entries = new ConcurrentHashMap<>();

    public InMemoryApprovalRegistry() {
        log.info("InMemoryApprovalRegistry initialised (gatekeeper.registry.mode=in-memory). "
                + "State is lost on restart; do not deploy to production. Set "
                + "gatekeeper.registry.mode=file to use AppendOnlyFileApprovalRegistry.");
    }

    @Override
    public RegistryEntry register(String verificationId,
                                  String confirmationNonce,
                                  boolean compliant,
                                  String publicKeyFingerprint,
                                  String supplierIdentifier,
                                  String supplierName,
                                  String hsmVendor,
                                  String hsmModel,
                                  String countryCode) {
        RegistryEntry entry = RegistryEntry.builder()
                .verificationId(verificationId)
                .confirmationNonce(confirmationNonce)
                .compliant(compliant)
                .publicKeyFingerprint(publicKeyFingerprint)
                .supplierIdentifier(supplierIdentifier)
                .supplierName(supplierName)
                .hsmVendor(hsmVendor)
                .hsmModel(hsmModel)
                .countryCode(countryCode)
                .verificationTimestamp(Instant.now().toString())
                .status(compliant ? RegistryStatus.VERIFIED_AND_ISSUED : RegistryStatus.REJECTED_NOT_ISSUED)
                .certificateReceived(false)
                .build();

        // For compliant entries, status is provisional until Step 7 confirms issuance
        if (compliant) {
            entry.setStatus(null); // Awaiting confirmation
        }

        entries.put(verificationId, entry);
        return entry;
    }

    @Override
    public Optional<RegistryEntry> confirm(String verificationId,
                                           String submittedNonce,
                                           boolean issued,
                                           String actualPublicKeyFingerprint,
                                           boolean publicKeyMatch) {
        RegistryEntry entry = entries.get(verificationId);
        if (entry == null) {
            return Optional.empty();
        }

        // Constant-time nonce comparison. Mismatch is a Step-7 replay attempt.
        String expectedNonce = entry.getConfirmationNonce();
        if (expectedNonce == null
                || submittedNonce == null
                || !java.security.MessageDigest.isEqual(
                        expectedNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        submittedNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            log.warn("Nonce mismatch on confirm for verificationId={} — possible Step-7 replay attempt", verificationId);
            throw new NonceMismatchException(verificationId);
        }

        entry.setConfirmationTimestamp(Instant.now().toString());
        entry.setCertificateReceived(issued);

        if (entry.isCompliant() && issued && publicKeyMatch) {
            entry.setStatus(RegistryStatus.VERIFIED_AND_ISSUED);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
        } else if (entry.isCompliant() && issued && !publicKeyMatch) {
            entry.setStatus(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
        } else if (entry.isCompliant() && !issued) {
            entry.setStatus(RegistryStatus.VERIFIED_NOT_ISSUED);
        } else if (!entry.isCompliant() && issued) {
            entry.setStatus(RegistryStatus.ANOMALY_ISSUED_DESPITE_REJECTION);
            entry.setActualPublicKeyFingerprint(actualPublicKeyFingerprint);
        } else {
            entry.setStatus(RegistryStatus.REJECTED_NOT_ISSUED);
        }

        return Optional.of(entry);
    }

    @Override
    public Optional<RegistryEntry> lookup(String verificationId) {
        return Optional.ofNullable(entries.get(verificationId));
    }

    @Override
    public List<RegistryEntry> findByCountry(String countryCode) {
        return entries.values().stream()
                .filter(e -> countryCode.equals(e.getCountryCode()))
                .collect(Collectors.toList());
    }

    @Override
    public List<RegistryEntry> findAnomalies() {
        return entries.values().stream()
                .filter(e -> e.getStatus() != null && e.getStatus().name().startsWith("ANOMALY"))
                .collect(Collectors.toList());
    }

    @Override
    public List<RegistryEntry> findAwaitingConfirmation() {
        return entries.values().stream()
                .filter(e -> e.getStatus() == null)
                .collect(Collectors.toList());
    }

    @Override
    public ComplianceStats getStats(String countryCode) {
        List<RegistryEntry> countryEntries = findByCountry(countryCode);
        long total = countryEntries.size();
        long compliant = countryEntries.stream()
                .filter(e -> e.getStatus() == RegistryStatus.VERIFIED_AND_ISSUED)
                .count();
        long anomalies = countryEntries.stream()
                .filter(e -> e.getStatus() != null && e.getStatus().name().startsWith("ANOMALY"))
                .count();
        return new ComplianceStats(total, compliant, anomalies,
                total > 0 ? (double) compliant / total * 100.0 : 0.0);
    }
}
