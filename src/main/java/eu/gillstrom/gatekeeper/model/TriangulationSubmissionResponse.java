package eu.gillstrom.gatekeeper.model;

/**
 * Answer to a bank report or the operator report on a triangulation inquiry.
 *
 * @param inquiryId the inquiry
 * @param reporterId the {@code bankId} or {@code operatorId}
 * @param entriesAccepted entries in this submission
 * @param entriesHeld entries now held for this reporter (several submissions
 *     from one reporter accumulate)
 * @param sha256Hex lower-case hex SHA-256 of this reporter's canonical input
 *     as it now stands, the value the discrepancy report will list for it
 */
public record TriangulationSubmissionResponse(String inquiryId, String reporterId, int entriesAccepted,
                                              int entriesHeld, String sha256Hex) {
}
