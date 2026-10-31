package eu.gillstrom.gatekeeper.timestamp;

import java.io.IOException;

/**
 * Obtains RFC 3161 time-stamp tokens from a Time-Stamping Authority.
 *
 * <p>The production implementation is {@link HttpTsaClient} (RFC 3161 §3.4,
 * HTTP transport). Tests supply an in-process implementation built on
 * BouncyCastle's {@code TimeStampResponseGenerator}. The caller validates
 * every token it receives with {@link TimestampTokenVerifier} before storing
 * it; an implementation does not need to be trusted to return a token over
 * the right imprint.</p>
 */
public interface TsaClient {

    /**
     * Request a token over a SHA-256 message imprint.
     *
     * @param sha256Imprint the 32-byte SHA-256 digest of the data to be
     *     time-stamped
     * @return the DER encoding of the {@code TimeStampToken} (a CMS
     *     {@code ContentInfo})
     * @throws IOException on any transport, protocol or TSA-status failure
     */
    byte[] timestamp(byte[] sha256Imprint) throws IOException;
}
