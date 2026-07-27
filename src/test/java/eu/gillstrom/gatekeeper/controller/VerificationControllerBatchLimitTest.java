package eu.gillstrom.gatekeeper.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.gillstrom.gatekeeper.model.BatchVerificationResponse;
import eu.gillstrom.gatekeeper.model.VerificationRequest;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.VerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Batch-size ceiling on
 * {@code POST /v1/attestation/&#x7b;cc&#x7d;/verify/batch}.
 *
 * <p>The endpoint accepted a list of any length. Each element runs PKIX
 * validation, an audit-log append with an fsync and a receipt signature,
 * synchronously on the request thread, so one request could occupy a worker
 * for as long as the caller wanted. The per-principal rate limit does not
 * help: it counts requests, not the work inside one.</p>
 *
 * <p>{@link VerificationService} is mocked here on purpose. The assertion is
 * about the controller's admission decision — that an oversized batch is
 * refused <em>before</em> any verification work starts — and a real service
 * would make the "never invoked" half of that unverifiable.</p>
 */
class VerificationControllerBatchLimitTest {

    private MockMvc mockMvc;
    private ObjectMapper json;
    private VerificationService verificationService;

    @BeforeEach
    void setUp() {
        verificationService = mock(VerificationService.class);
        ApprovalRegistry approvalRegistry = mock(ApprovalRegistry.class);
        VerificationController controller =
                new VerificationController(verificationService, approvalRegistry);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
        json = new ObjectMapper();
        json.registerModule(new JavaTimeModule());
    }

    @Test
    void batchAboveTheCeilingIsRejectedWithoutRunningAnyVerification() throws Exception {
        List<VerificationRequest> oversized = batchOf(VerificationController.MAX_BATCH_SIZE + 1);

        mockMvc.perform(post("/v1/attestation/SE/verify/batch")
                        .contentType("application/json")
                        .content(json.writeValueAsString(oversized)))
                // 413. Asserted numerically because the matcher for this
                // status was renamed between Spring versions (isPayloadTooLarge
                // → isContentTooLarge) and the number did not change.
                .andExpect(status().is(413));

        verify(verificationService, never()).verifyBatch(anyList());
    }

    @Test
    void batchAtTheCeilingIsAccepted() throws Exception {
        List<VerificationRequest> atLimit = batchOf(VerificationController.MAX_BATCH_SIZE);
        when(verificationService.verifyBatch(anyList())).thenReturn(
                BatchVerificationResponse.builder()
                        .verificationTimestamp(Instant.now())
                        .totalEntities(atLimit.size())
                        .compliantCount(0)
                        .nonCompliantCount(atLimit.size())
                        .complianceRate(0.0)
                        .results(List.of())
                        .build());

        mockMvc.perform(post("/v1/attestation/SE/verify/batch")
                        .contentType("application/json")
                        .content(json.writeValueAsString(atLimit)))
                .andExpect(status().isOk());

        verify(verificationService, times(1)).verifyBatch(anyList());
    }

    /**
     * Elements carry the fields {@code VerificationRequest} marks
     * {@code @NotBlank}, so that the oversized case is rejected by the size
     * ceiling and not incidentally by field validation.
     */
    private static List<VerificationRequest> batchOf(int size) {
        List<VerificationRequest> batch = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            VerificationRequest request = new VerificationRequest();
            request.setPublicKey("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----");
            request.setHsmVendor("SECUROSYS");
            request.setSupplierIdentifier("55600000" + i);
            batch.add(request);
        }
        return batch;
    }
}
