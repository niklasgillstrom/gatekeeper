package eu.gillstrom.gatekeeper.model;

/**
 * Answer to {@code POST /v1/triangulation/{countryCode}/inquiries}.
 *
 * @param inquiryId random UUID naming the inquiry in the other calls
 * @param countryCode jurisdiction, upper-cased
 * @param createdAt ISO-8601 instant
 */
public record TriangulationInquiryResponse(String inquiryId, String countryCode, String createdAt) {
}
