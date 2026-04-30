package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.model.VerificationResponse;

/**
 * Signs verification receipts produced by the gatekeeper.
 *
 * <p>The primary operator in the production topology is a National Competent
 * Authority (NCA); in Sweden this is Finansinspektionen (FI). Receipts are
 * signed in production with the NCA's organisation-certificate-backed signing
 * key — the certificate the NCA uses for ordinary administrative signing of
 * supervisory acts. This interface abstracts the signing operation so that
 * the reference implementation can be wired up with either:</p>
 *
 * <ul>
 *   <li>A {@code ConfiguredReceiptSigner} that loads a production signing key
 *       and certificate chain from a PKCS#12 keystore via Spring configuration,
 *       or</li>
 *   <li>An {@code EphemeralReceiptSigner} that generates a fresh RSA key pair
 *       at application startup. The ephemeral variant is intended for reference
 *       use and emits a loud {@code WARN} log at every startup and every
 *       signing operation so it cannot be deployed to production unnoticed.</li>
 * </ul>
 *
 * <p>The interface enforces two properties beyond the placeholder it replaces:
 * (i) the signature is computed with a real asymmetric algorithm using a
 * controlled private key, and (ii) the signature is verifiable against the
 * corresponding public certificate. Both properties are testable in isolation
 * by {@link ReceiptSignerTest}.</p>
 */
public interface ReceiptSigner {

    /**
     * The canonical signer identifier ({@code REFERENCE-EPHEMERAL} or the
     * certificate serial + issuer DN for the configured variant) — intended
     * for operational diagnostics, not for cryptographic decisions.
     */
    String getSignerIdentifier();

    /**
     * Signs a verification receipt. The receipt's {@code signature} and
     * {@code signingCertificate} fields are populated by the caller with
     * the return values of {@link #sign(byte[])} and
     * {@link #getSigningCertificatePem()} respectively.
     *
     * <p>The canonical byte representation signed is defined in
     * {@link ReceiptCanonicalizer} and contains every field that affects the
     * compliance decision (verificationId, compliant, timestamp, fingerprint,
     * hsmVendor, hsmModel, supplier identifier, DORA article bits). A future
     * field addition that is decision-relevant MUST be added to the canonical
     * form or it will not be covered by the signature.</p>
     *
     * @return Base64-encoded detached signature
     */
    byte[] sign(byte[] canonicalReceipt);

    /**
     * @return PEM-encoded signing certificate (including chain if available)
     */
    String getSigningCertificatePem();

    /**
     * Helper that populates {@code signature} and {@code signingCertificate}
     * on the provided response, using {@link ReceiptCanonicalizer} to compute
     * the canonical byte representation.
     */
    default void signInto(VerificationResponse receipt) {
        byte[] canonical = ReceiptCanonicalizer.canonicalize(receipt);
        byte[] signature = sign(canonical);
        receipt.setSignature(java.util.Base64.getEncoder().encodeToString(signature));
        receipt.setSigningCertificate(getSigningCertificatePem());
    }
}
