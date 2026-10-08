package eu.gillstrom.gatekeeper.controller;

import eu.gillstrom.gatekeeper.model.BatchVerificationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmation;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.model.VerificationRequest;
import eu.gillstrom.gatekeeper.model.VerificationResponse;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.InMemoryApprovalRegistry;
import eu.gillstrom.gatekeeper.service.VerificationService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** What the controller adds to the service: the country from the path, status codes, nonce redaction. */
class VerificationControllerTest {

    private final VerificationService service = mock(VerificationService.class);
    private final ApprovalRegistry registry = new InMemoryApprovalRegistry();
    private final VerificationController controller = new VerificationController(service, registry);

    @Test
    void verifyTakesTheCountryFromThePathAndReturnsTheReceipt() {
        VerificationResponse receipt = VerificationResponse.builder().verificationId("V").build();
        when(service.verify(any())).thenReturn(receipt);
        VerificationRequest request = new VerificationRequest();
        request.setCountryCode("DE");

        ResponseEntity<VerificationResponse> response = controller.verify("se", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(receipt);
        assertThat(request.getCountryCode()).isEqualTo("SE");
    }

    @Test
    void aBatchTakesTheCountryFromThePathForEveryEntry() {
        BatchVerificationResponse batch = BatchVerificationResponse.builder().totalEntities(2).build();
        when(service.verifyBatch(anyList())).thenReturn(batch);
        VerificationRequest first = new VerificationRequest();
        VerificationRequest second = new VerificationRequest();
        second.setCountryCode("DE");

        ResponseEntity<BatchVerificationResponse> response = controller.verifyBatch("se", List.of(first, second));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(batch);
        assertThat(first.getCountryCode()).isEqualTo("SE");
        assertThat(second.getCountryCode()).isEqualTo("SE");
    }

    private ResponseEntity<IssuanceConfirmationResponse> confirm(RegistryStatus status) {
        IssuanceConfirmationResponse body = IssuanceConfirmationResponse.builder().registryStatus(status).build();
        when(service.confirmIssuance(any(), eq("SE"))).thenReturn(body);
        ResponseEntity<IssuanceConfirmationResponse> response = controller.confirmIssuance("se", new IssuanceConfirmation());
        assertThat(response.getBody()).isSameAs(body);
        return response;
    }

    @Test
    void aConfirmationIsAnsweredByItsOutcome() {
        assertThat(confirm(RegistryStatus.VERIFIED_AND_ISSUED).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(confirm(RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(confirm(RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(confirm(RegistryStatus.ANOMALY_NONCE_MISMATCH).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void theRegistryViewsAreScopedToThePathCountryAndCarryNoNonce() {
        registry.register("AWAIT", "nonce-await", true, "fp-1", "5569743098", "Supplier AB",
                "SECUROSYS", "Primus HSM", "SE");
        registry.register("ANOM", "nonce-anom", false, "fp-2", "5569743098", "Supplier AB", null, null, "SE");
        registry.confirm("ANOM", "nonce-anom", true, "fp-2", true);
        registry.register("DE", "nonce-de", true, "fp-3", "DE1", "Lieferant", "SECUROSYS", "Primus HSM", "DE");

        List<ApprovalRegistry.RegistryEntry> awaiting = controller.registryAwaiting("se").getBody();
        assertThat(awaiting).extracting(ApprovalRegistry.RegistryEntry::getVerificationId).containsExactly("AWAIT");
        assertThat(awaiting).extracting(ApprovalRegistry.RegistryEntry::getConfirmationNonce).containsOnlyNulls();
        assertThat(registry.lookup("AWAIT").orElseThrow().getConfirmationNonce())
                .as("redaction does not touch the registry").isEqualTo("nonce-await");

        List<ApprovalRegistry.RegistryEntry> anomalies = controller.registryAnomalies("se").getBody();
        assertThat(anomalies).extracting(ApprovalRegistry.RegistryEntry::getVerificationId).containsExactly("ANOM");

        assertThat(controller.registryStats("se").getBody())
                .isEqualTo(new ApprovalRegistry.ComplianceStats(2, 0, 1, 0.0));
        assertThat(controller.registryAwaiting("se").getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void theVendorListAndHealthAreServed() {
        assertThat(controller.supportedVendors().getBody())
                .extracting(VerificationController.VendorInfo::vendorId)
                .containsExactly("SECUROSYS", "YUBICO", "AZURE", "GOOGLE", "MARVELL", "THALES", "CRYPTO4A",
                        "FORTANIX", "ENTRUST");
        assertThat(controller.health().getBody()).isEqualTo("DORA Attestation Gatekeeper: OK");
    }
}
