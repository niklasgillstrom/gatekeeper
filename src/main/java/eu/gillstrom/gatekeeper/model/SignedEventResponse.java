package eu.gillstrom.gatekeeper.model;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonUnwrapped;

import java.util.Objects;

/**
 * Answer to a {@code SIGNED} event on
 * {@code POST /v1/attestation/{countryCode}/lifecycle}: the fields of the
 * {@code POST /api/v1/verify} answer ({@link SignatureVerificationResponse},
 * including the signed verdict) plus {@code eventType}.
 */
@JsonPropertyOrder({"eventType"})
public final class SignedEventResponse {

    private final String eventType;
    private final SignatureVerificationResponse verdict;

    public SignedEventResponse(SignatureVerificationResponse verdict) {
        this.eventType = KeyLifecycleRequest.SIGNED;
        this.verdict = Objects.requireNonNull(verdict, "verdict");
    }

    /** Always {@code SIGNED}. */
    public String getEventType() {
        return eventType;
    }

    /** The settlement-shaped verdict, serialised inline. */
    @JsonUnwrapped
    public SignatureVerificationResponse getVerdict() {
        return verdict;
    }
}
