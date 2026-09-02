package eu.gillstrom.gatekeeper.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmation;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse;
import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import eu.gillstrom.gatekeeper.service.ApprovalRegistry;
import eu.gillstrom.gatekeeper.service.VerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The {@code countryCode} path variable on {@code confirm} reaches the
 * service, and a confirmation the service refuses to resolve is answered
 * with 404.
 *
 * <p>The path variable used to be accepted and discarded — the endpoint
 * signature said the confirmation belonged to a jurisdiction and the code
 * did not act on it. The 404 mapping is the second half: an unresolved
 * confirmation was answered 200 with an anomaly body, which contradicted
 * the endpoint's own documented contract and made "no such verification"
 * look like a processed request.</p>
 */
class VerificationControllerConfirmScopeTest {

    private MockMvc mockMvc;
    private ObjectMapper json;
    private VerificationService verificationService;

    @BeforeEach
    void setUp() {
        verificationService = mock(VerificationService.class);
        ApprovalRegistry approvalRegistry = mock(ApprovalRegistry.class);
        mockMvc = MockMvcBuilders
                .standaloneSetup(new VerificationController(verificationService, approvalRegistry))
                .build();
        json = new ObjectMapper();
        json.registerModule(new JavaTimeModule());
    }

    @Test
    void countryCodeFromThePathIsPassedToTheServiceUpperCased() throws Exception {
        when(verificationService.confirmIssuance(any(), eq("SE")))
                .thenReturn(IssuanceConfirmationResponse.builder()
                        .verificationId("v-1")
                        .loopClosed(true)
                        .registryStatus(RegistryStatus.VERIFIED_NOT_ISSUED)
                        .processedTimestamp(Instant.now().toString())
                        .anomalies(List.of())
                        .build());

        mockMvc.perform(post("/v1/attestation/se/confirm")
                        .contentType("application/json")
                        .content(json.writeValueAsString(confirmation("v-1"))))
                .andExpect(status().isOk());

        ArgumentCaptor<String> country = ArgumentCaptor.forClass(String.class);
        verify(verificationService).confirmIssuance(any(), country.capture());
        assertThat(country.getValue()).isEqualTo("SE");
    }

    @Test
    void unresolvedConfirmationIsAnsweredWith404() throws Exception {
        when(verificationService.confirmIssuance(any(), any()))
                .thenReturn(IssuanceConfirmationResponse.builder()
                        .verificationId("v-2")
                        .loopClosed(false)
                        .registryStatus(RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION)
                        .processedTimestamp(Instant.now().toString())
                        .anomalies(List.of("ANOMALY: Confirmation received for unknown "
                                + "verification ID: v-2"))
                        .build());

        mockMvc.perform(post("/v1/attestation/SE/confirm")
                        .contentType("application/json")
                        .content(json.writeValueAsString(confirmation("v-2"))))
                .andExpect(status().isNotFound());
    }

    @Test
    void nonceMismatchIsStill400() throws Exception {
        when(verificationService.confirmIssuance(any(), any()))
                .thenThrow(new ApprovalRegistry.NonceMismatchException("v-3"));

        mockMvc.perform(post("/v1/attestation/SE/confirm")
                        .contentType("application/json")
                        .content(json.writeValueAsString(confirmation("v-3"))))
                .andExpect(status().isBadRequest());
    }

    private static IssuanceConfirmation confirmation(String verificationId) {
        IssuanceConfirmation confirmation = new IssuanceConfirmation();
        confirmation.setVerificationId(verificationId);
        confirmation.setConfirmationNonce("nonce");
        confirmation.setIssued(false);
        confirmation.setTimestamp(Instant.now().toString());
        return confirmation;
    }
}
