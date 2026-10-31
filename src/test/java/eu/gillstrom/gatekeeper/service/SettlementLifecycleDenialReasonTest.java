package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.model.IssuanceConfirmationResponse.RegistryStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The settlement reason for an entry a lifecycle event has moved on, and none for any other status. */
class SettlementLifecycleDenialReasonTest {

    @Test
    void eachLifecycleStatusHasItsReasonAndEveryOtherStatusNone() {
        assertThat(SignatureVerificationService.lifecycleDenialReason(RegistryStatus.SUPERSEDED))
                .isEqualTo("CERT_SUPERSEDED");
        assertThat(SignatureVerificationService.lifecycleDenialReason(RegistryStatus.REVOKED))
                .isEqualTo("CERT_REVOKED");
        assertThat(SignatureVerificationService.lifecycleDenialReason(RegistryStatus.DECOMMISSIONED))
                .isEqualTo("CERT_DECOMMISSIONED");
        assertThat(SignatureVerificationService.lifecycleDenialReason(RegistryStatus.VERIFIED_AND_ISSUED)).isNull();
        assertThat(SignatureVerificationService.lifecycleDenialReason(null)).isNull();
    }
}
