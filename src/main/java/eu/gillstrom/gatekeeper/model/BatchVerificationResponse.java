package eu.gillstrom.gatekeeper.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

/**
 * EBA Batch Verification Response.
 * 
 * Aggregate compliance statistics for multiple entities.
 * Designed for EBA's Article 17(6) investigations and
 * Article 29 supervisory convergence assessments.
 */
@Data
@Builder
public class BatchVerificationResponse {

    private Instant verificationTimestamp;

    /**
     * Total number of entities verified in this batch.
     */
    private int totalEntities;

    /**
     * Number of entities with valid HSM attestation.
     */
    private int compliantCount;

    /**
     * Number of entities that could not provide valid HSM attestation.
     */
    private int nonCompliantCount;

    /**
     * Compliance rate as percentage (0-100).
     * A rate significantly below 100% indicates a systemic supervisory failure.
     */
    private double complianceRate;

    /**
     * Individual verification results for each entity.
     */
    private List<VerificationResponse> results;
}
