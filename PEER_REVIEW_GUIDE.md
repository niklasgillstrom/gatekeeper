# Peer-review guide — gatekeeper

This document is written for a peer reviewer of Article 1 (Gillström, in preparation; target venue: *Capital Markets Law Journal*) and Article 2 (Gillström, in preparation; target venue: *Computer Law & Security Review*) who wants to reproduce the central gatekeeper-level verification claims these articles make. Companion repos `hsm/` and `railgate/` complete the **triadic system** described in Article 1 §4.2 and Article 2 §9.3:

- **hsm** carries the verifier core (financial-entity side).
- **gatekeeper** (this repo) is the NCA-facing supervisory API that wraps those verifiers for regulatory use, and from v1.2.0 also exposes the settlement-time signature verification endpoint that railgate consumes.
- **railgate** is the central-bank settlement-rail enforcement layer that calls gatekeeper's verification endpoint at settlement time (RIX-INST in Sweden; generalisable to TIPS, FedNow, FPS, NPP).

The three components together operationalise the data-minimised quadruple-triangulation model: only digest, signature, and certificate identifiers traverse the supervisor boundary — no transaction payload content is exposed at any layer.

## Version 1.3.0 — what changed and what to verify

A systematic check of the triad against its own documentation found places where a described protection was not implemented in the code. v1.3.0 fixes them and records what was wrong; see "Corrections after documentation-versus-code review" below. In summary:

- `/api/v1/verify` could never return `compliant=true` — the settlement-time path was inoperable — because the fingerprint was written in lowercase and read in uppercase. There is now one canonical implementation in `util/Fingerprints` that production code and tests share.
- The Step-7 confirmation nonce is no longer published by the registry query endpoints and is cleared on use.
- The signature algorithm is taken from a whitelist rather than from the caller.
- Azure and Google attestation attributes fail closed; an empty certificate path no longer counts as a validated chain.
- Settlement-time decisions are written to the audit log, rate limiting covers the remaining endpoints with bounded and proxy-aware keying, registry queries respect `countryCode`, and request sizes are bounded.

Reviewers should start with `mvn -B test` (80 tests) and then read the corrections section.

---

## Version 1.2.0 — what changed and what to verify

Reviewers approaching v1.2.0 should focus on the following additions relative to v1.0.0:

1. **`POST /api/v1/verify`** — a new settlement-time signature verification endpoint added in v1.1.0 and documented fully in v1.2.0. See `SignatureVerificationController` and `SignatureVerificationService`. Reviewers should confirm:
   - The verifier never receives the original transaction payload — only a SHA-512 digest. The digest is a 64-byte cryptographic hash that is collision-resistant (SHA-512 security level: 256-bit), so a valid signature over the digest uniquely binds the signature to the transaction performed.
   - Audit lookup is performed by the SHA-256 fingerprint of the SubjectPublicKeyInfo (uppercase hex, colon-separated) — same canonical form used elsewhere in gatekeeper.
   - The cryptographic verification mirrors the production signing flow: `Signature.getInstance("SHA512withRSA").initVerify(publicKey).update(digest).verify(signature)`.
   - The response is binary `{signatureValid, compliant}` plus a structured reason code and the audit-entry identifier when found.
2. **`SETTLEMENT_RAIL` role** — added to `SecurityConfig` to authorise central-bank settlement-system clients. Reviewers should confirm the matcher on `POST /api/v1/verify` requires either `SETTLEMENT_RAIL` or `SUPERVISOR`.
3. **`ApprovalRegistry.findByPublicKeyFingerprint`** — added as a default method on the interface and implemented in both `InMemoryApprovalRegistry` and `AppendOnlyFileApprovalRegistry`. Reviewers should confirm the implementations search both `publicKeyFingerprint` and `actualPublicKeyFingerprint` and prefer compliant entries when multiple match.
4. **Tests** — `SignatureVerificationServiceTest` (8 cases) and `SignatureVerificationControllerTest` (4 cases). Reviewers should run `mvn -B clean verify` and confirm 55 tests pass.

---

## What this repo is / isn't

**Is:**

- A **reference implementation** of the supervisory gatekeeper architecture described in Article 1 §4.2 and Article 2 §6.1. The gatekeeper exposes a REST API that an NCA (in Sweden, Finansinspektionen) or EBA can use to verify HSM attestations at certificate issuance (Article 1 §4.2) and to maintain a registry of verified approvals (Article 2 §6).
- A **demonstrator** of the Step-7 issuance confirmation flow: after the gatekeeper verifies attestation, the issuer CA produces a signing certificate and asks the gatekeeper to confirm — the gatekeeper checks the submitted certificate is signed by a trusted issuer CA (via `IssuerCaValidator`) and that its public key matches the attested key.
- **MIT-licensed**.

**Isn't:**

- A production deployment. The receipt signer defaults to `EphemeralReceiptSigner` (self-signed, in-process key pair), which emits `WARN` at startup and on every signature. The `ApprovalRegistry` is `ConcurrentHashMap`-based and lost on restart. Rate-limit buckets are per-process and in-memory, so a horizontally scaled deployment enforces the configured limit per instance rather than per cluster. mTLS is off by default.
- A production-deployed NCA signing service. The `ConfiguredReceiptSigner` path loads a PKCS#12 keystore but the reference does not ship with the NCA's actual organisation certificate.
- A full implementation of the forward-secure event stream that Article 2 §6.3 specifies. The hash-chained append-only audit log (`AppendOnlyFileAuditLog`) plus per-entry signing is implemented; what remains as GAP is COSE encoding of entries, RFC 3161 timestamping per batch, and forward-secure key rotation per Ma–Tsudik (2008).

**What is pinned.** Each verifier embeds a single trust anchor as a Java text-block constant in the verifier source and parses it in the constructor. Constructor failure throws `IllegalStateException` and Spring Boot refuses to start. Additionally, `IssuerCaValidator` loads a configurable issuer-CA bundle (for Step-7 confirmation binding) from `gatekeeper.confirmation.issuer-ca-bundle-path` or the bundled `issuer-ca-bundle.pem` resource. **All four verifiers pin real vendor-issued roots: Securosys pins Securosys's CA; Yubico pins the YubiHSM Root CA fetched from `developers.yubico.com`; Azure and Google Cloud HSM both pin Marvell/Cavium's LiquidSecurity Root CA fetched from Marvell's official distribution at `marvell.com/.../liquid_security_certificate.zip` (the same anchor referenced by Google Cloud HSM's open-source verification code).**

**What is placeholder.** Receipt signing defaults to `EphemeralReceiptSigner` (RSA-3072 self-signed, fresh on every boot). The registry is in-memory. The supervisory-role authorisation policy beyond mTLS is marked `TODO-NCA`. Rate limiting is bucket-based but uses a default in-memory configuration.

**Rotation note for cloud-HSM trust anchor.** The Marvell LiquidSecurity Root CA bundled in `AzureHsmVerifier` and `GoogleCloudHsmVerifier` (SHA-256 `97:57:57:F0:D7:66:40:E0:3D:14:76:0F:8F:C9:E3:A5:58:26:FA:78:07:B2:C3:92:F7:80:1A:95:BD:69:CC:28`) expired on 2025-11-16. Marvell has presumably published a successor at the same URL; deployers should fetch the current certificate, verify its fingerprint against Marvell's documentation, and replace the constant before relying on chain validation for attestations created after the expiry date. PKIX does not check the trust anchor's own validity period, so the structural rejection-path tests still pass with the expired anchor.

**Dual-chain verification model not implemented.** Google Cloud HSM's published Python sample (`verify_chains.py`, copyright 2021, last modified ~2023) verifies attestations against **two parallel chains**: the Marvell manufacturer chain (the anchor we bundle) and Google's own "Hawksbill Root v1 prod" CA owner chain (the anchor we do not bundle). Azure Managed HSM is expected to follow an analogous pattern with a Microsoft-controlled owner root. This verifier implements only the manufacturer chain — the owner-chain layer is out of scope for the academic case study, which uses Securosys Primus rather than Google Cloud HSM or Azure Managed HSM in production. Deployers planning to use the Azure or Google paths in production must add owner-chain validation per current cloud-vendor documentation; the verification protocol may have evolved since the 2021 Google sample, so consult the latest documentation rather than treating this code as the production model. The SECURITY NOTE in each verifier flags this explicitly.

---

## Requirements

- **Java 21**.
- **Maven ≥ 3.6.3** (enforced at build time by `maven-enforcer-plugin`; this matches Spring Boot 4.x's own Maven floor and OWASP Dependency-Check 12.x's requirement). Tested on Maven 3.9.15.
- **BouncyCastle** (pulled in via Maven).
- **Internet-less sandbox is fine**. The test suite uses in-memory `TestPki`.
- No HSM hardware required to run the test suite.

---

## Build and test

```bash
cd gatekeeper
mvn -B test
```

Expected result: **BUILD SUCCESS** with all tests green.

Test count at submission time: **43 tests across 11 test classes** under `src/test/java/eu/gillstrom/gatekeeper/`:

| Test class | Test count | What it covers |
| ---------- | ----------:| -------------- |
| `verification.YubicoVerifierTest` | 2 | Pinned-root rejection of a throwaway PKI built with `TestPki`. |
| `verification.SecurosysVerifierTest` | 3 | Pinned-root rejection, tampered-signature rejection, empty-chain rejection. |
| `verification.AzureHsmVerifierTest` | 2 | Pinned-Marvell rejection, structural rejection of attestations missing the `certificates` field. |
| `verification.GoogleCloudHsmVerifierTest` | 2 | Pinned-Marvell rejection, empty-chain rejection. |
| `signing.ReceiptCanonicalizerTest` | 4 | Version prefix invariant, mutation sensitivity, null guard, pipe escaping. |
| `signing.EphemeralReceiptSignerTest` | 3 | Round-trip verification, `CN=REFERENCE-EPHEMERAL` marker, tampered-bytes rejection. |
| `signing.WireFormatGoldenBytesTest` | 3 | Cross-repo golden-bytes literal (byte-identical to the financial entity repo's `WireFormatGoldenBytesTest`), pipe / percent escaping, null-field empty rendering. |
| `service.IssuerCaValidatorTest` | 4 | Step-7 trust-bundle PKIX validation. |
| `audit.AppendOnlyFileAuditLogTest` | 8 | Hash-chain integrity, tamper detection on every row position, persistence across restart, fsync per append, sequence-number monotonicity. |
| `controller.AuditControllerTest` | 7 | Witness lookup, range query (with 90-day cap), entity query (URL-decoded principal), signed export bundle. |
| `controller.GatekeeperControllerTest` | 5 | Public-key directory, signed audit-chain anchor, health (chainIntact / mode), empty-log anchor handling. |

The table above is the count at v1.0.0 submission. Three test classes were added with the corrections recorded under "Corrections after documentation-versus-code review", and two existing classes gained cases; the totals stated here and in the v1.2.0 section have not been re-counted against a build and should be taken from `mvn -B test` rather than from this document. The added classes are:

| Test class | What it covers |
| ---------- | -------------- |
| `service.ApprovalRegistryCountryScopeTest` | Jurisdiction scoping of `findByCountry`, `findAnomalies`, `findAwaitingConfirmation` and `getStats`, run against both `InMemoryApprovalRegistry` and `AppendOnlyFileApprovalRegistry` from one parameterised source. Includes the case that matters: an entry registered under `DE` is absent from every `SE` query. |
| `controller.VerificationControllerBatchLimitTest` | A batch above `MAX_BATCH_SIZE` is refused with 413 and no verification is attempted; a batch exactly at the ceiling is accepted. |
| `security.RateLimitKeyDerivationTest` | `X-Forwarded-For` ignored with no trusted proxy configured and when the peer is not one; right-to-left chain walk past our own proxies; non-IP entries rejected; mTLS principal takes precedence; IP-literal normalisation. |

`service.SignatureVerificationServiceTest` and `controller.SignatureVerificationControllerTest` additionally now assert that `/api/v1/verify` appends a `SETTLEMENT_VERIFY` audit entry, that two different requests produce two different request digests, and that the journal file contains neither the transaction digest, the signature, nor the certificate body verbatim.

**Where the test PKI is built.** `src/test/java/eu/gillstrom/gatekeeper/testsupport/TestPki.java` — a direct sibling of `hsm`'s test PKI helper. Same idea: build a throwaway root + intermediate + leaf, assert the production verifier rejects it because it does not anchor at the pinned vendor root.

### Audit-log integrity guarantees

A reviewer can independently reproduce the following claims about the hash-chained audit log without any external infrastructure beyond `mvn -B test`:

1. **Tamper detection at every row position.** `AppendOnlyFileAuditLogTest` writes a sequence of entries, then mutates one row at a time (first, middle, last) and asserts that `verifyChainIntegrity()` returns `false` in each case. The mutation is targeted at decision-relevant fields (`compliant`, `verificationId`, `requestDigestBase64`) so that a future reviewer can be confident that the chain covers what it claims to cover, not a ceremonial subset.
2. **Persistence across process restart.** The test instantiates a second `AppendOnlyFileAuditLog` against the same file path, asserts that the chain is read back deterministically, and asserts that `verifyChainIntegrity()` returns `true` after restart.
3. **fsync per append.** The append code path opens the file with `RandomAccessFile` in `"rwd"` mode and calls `getFD().sync()` after every write. The test exercises this by appending, killing the in-process log, and re-reading from disk; the entry is present.
4. **Sequence-number monotonicity.** `AuditEntry`'s record-constructor rejects sequence numbers `< 1`, and the log itself increments strictly monotonically.

These four properties together substantiate the DORA Regulation (EU) 2022/2554 Article 28(6) retention claim — the audit trail kept for 5 years is not merely persisted, it is verifiably untampered.

### End-to-end test across the three repositories

`e2e/` starts the built gatekeeper, hsm and railgate jars on loopback ports and drives the real HTTP flow: Steps 2–7 with the real Yubico and Securosys attestation fixtures, and settlement both directly and through railgate. It is not part of `mvn verify`; clone hsm and railgate next to this repository, build all three, then run `e2e/run.sh`. `e2e/README.md` lists what it proves and what it cannot prove locally (the hsm issuance path needs a BankID signature, an allowed settlement needs a signature from the attested HSM key).

---

## Reproducible assertions

A reviewer can make the following assertions by running `mvn -B test`.

1. **YubicoVerifierTest.chainNotRootedAtPinnedYubicoRootIsRejected** — a throwaway chain does NOT pass PKIX against the pinned Yubico root. This is the core fail-closed guarantee for the Yubico path, mirrored from the sibling repo.
2. **SecurosysVerifierTest.fakeChainIsNotRootedAtPinnedSecurosysRoot** — same, Securosys. Directly substantiates Article 1 §4.2's independence-from-entity claim.
3. **SecurosysVerifierTest.tamperedSignatureIsRejected** — flipping a byte in a signed attestation blob fails verification.
4. **SecurosysVerifierTest.emptyChainProducesError** — empty chain is rejection.
5. **AzureHsmVerifierTest.chainNotRootedAtPinnedTrustAnchorIsRejected** — Azure Managed HSM verification anchors at Microsoft's published attestation CA in production (Marvell LiquidSecurity is the underlying hardware but Microsoft's CA is the practical pinning point); this test confirms the chain-rejection guarantee against the configured trust anchor.
6. **AzureHsmVerifierTest.missingCertificatesFieldIsRejected** — structural rejection of attestations without `certificates`.
7. **GoogleCloudHsmVerifierTest.chainNotRootedAtPinnedTrustAnchorIsRejected** — parallel to Azure; Google Cloud HSM verification anchors at Google's published attestation CA in production (Marvell LiquidSecurity is the underlying hardware shared with Azure, but Google's CA is the practical pinning point for Google-deployed HSMs).
8. **GoogleCloudHsmVerifierTest.emptyChainIsRejected** — empty input fails.
9. **ReceiptCanonicalizerTest.canonicalBytesStartWithVersionPrefix** — every canonical byte sequence begins `v2|` (it was `v1|` before release 1.4.0 brought `confirmationNonce` inside the signed form). Protects against silent format migrations.
10. **ReceiptCanonicalizerTest.mutatingCompliantFieldChangesCanonicalBytes** — flipping `compliant` produces different canonical bytes; the receipt therefore signs over the compliance decision, not over a ceremonial subset. Directly substantiates Article 2 §8.5's authenticity claim.
11. **ReceiptCanonicalizerTest.pipeCharactersInFieldsAreEscaped** — no field boundary can be smuggled.
12. **EphemeralReceiptSignerTest.signAndVerifyRoundTripsAgainstExposedCertificate** — the signer produces RSA signatures verifiable against its own exposed certificate.
13. **EphemeralReceiptSignerTest.certificatePemContainsReferenceEphemeralMarker** — exposed certificate carries `CN=REFERENCE-EPHEMERAL`; this guarantees that anyone inspecting the certificate in operational use can tell at a glance that it is the reference signer, not the NCA's production organisation certificate. The marker exists specifically so that accidental production deployment is conspicuous.
14. **EphemeralReceiptSignerTest.tamperedCanonicalBytesFailVerification** — changing the receipt content without resigning invalidates the signature.

Reviewer takeaway: the gatekeeper verifies attestations deterministically against pinned vendor roots; emits receipts whose signatures cover every decision-relevant field and whose canonical form cannot be smuggled past a pipe character; and the ephemeral signer's `CN=REFERENCE-EPHEMERAL` marker is a structural guardrail against production misuse.

---

## Configuration knobs

| Property | Reference default | Production value | Source |
| -------- | ----------------- | ---------------- | ------ |
| `gatekeeper.signing.mode` | `ephemeral` (matchIfMissing) | `configured` — with the NCA's organisation-certificate PKCS#12 keystore in production | `EphemeralReceiptSigner.java`, `ConfiguredReceiptSigner.java` |
| `gatekeeper.signing.keystore-path` | unset | `/etc/gatekeeper/signing.p12` (or secrets-manager path) | `ConfiguredReceiptSigner.java` |
| `gatekeeper.signing.keystore-password` | unset | pulled from Spring secrets | `ConfiguredReceiptSigner.java` |
| `gatekeeper.signing.key-alias` | unset | site-specific | `ConfiguredReceiptSigner.java` |
| `gatekeeper.signing.algorithm` | `SHA256withRSA` (common sensible default) | match certificate (`SHA384withECDSA` for EC P-384, etc.) | `ConfiguredReceiptSigner.java`; `AppendOnlyFileAuditLog.java` verifies audit-entry signatures with the same algorithm |
| `gatekeeper.security.mtls.enabled` | `false` (matchIfMissing) — startup emits WARN | `true` in any NCA/EBA deployment | `SecurityConfig.java` |
| `gatekeeper.security.mtls.principal-regex` | `CN=(.*?)(?:,|$)` | site-specific NCA credential format | `SecurityConfig.java` |
| `server.ssl.trust-store` | unset | path to NCA-issued client-CA bundle | Spring Boot / Tomcat connector |
| `server.ssl.client-auth` | unset | `need` (hard requirement) | Spring Boot / Tomcat connector |
| `gatekeeper.confirmation.issuer-ca-bundle-path` | unset — falls back to `classpath:issuer-ca-bundle.pem` placeholder | path to the NCA's issuer-CA bundle PEM | `IssuerCaValidator.java`, `VerificationService.confirmIssuance()` |
| Spring profile `eba` | `application-eba.yaml` scaffolding | activate for EBA-facing deployment | `src/main/resources/application-eba.yaml` |
| Spring profile `nca` | `application-nca.yaml` activates mTLS, configured signer, fail-closed signatory rights | activate for NCA-operated deployment | `src/main/resources/application-nca.yaml` |

Notes:

- **`EphemeralReceiptSigner` is the default.** It exists only so the repo is runnable out of the box. A deployer who forgets to set `gatekeeper.signing.mode=configured` will immediately see `WARN` logs announcing that the signer is ephemeral, self-signed, and "MUST NOT be deployed to production". The cost of accidental misuse is therefore high visibility, not silent weakness.
- **`gatekeeper.security.mtls.enabled=false` is the reference default** because the sandbox environment used to reproduce tests does not have a client-CA bundle. Production NCA deployments must set `true` and supply `server.ssl.trust-store` + `server.ssl.client-auth=need`.
- **The `eba` vs `nca` profiles** reflect Article 1 §6.2's operational distinction: the gatekeeper is primarily operated by NCAs under DORA with EBA invoking supervisory cross-border powers via Regulation (EU) 1093/2010 Art 17 / Art 29. Both profiles exist for completeness; `application-nca.yaml` is the one that activates production-lite security defaults.

---

## Corrections after documentation-versus-code review

Checking this guide against the code found defects in protections the guide described as working. The code has been changed; this section records what was wrong rather than silently rewriting the claim.

- **`/api/v1/verify` could never return `compliant=true`.** `SignatureVerificationService` rendered the public-key fingerprint in uppercase hex while `VerificationService` wrote registry entries in lowercase, and registry lookup is a case-sensitive `equals`. Every settlement-time query fell through to `CERT_NOT_FOUND`, which also means railgate would have denied every payment. The defect was invisible because both test doubles recomputed the fingerprint in the same uppercase form as the reader. There is now a single canonical implementation in `util/Fingerprints`, and production code and tests both call it, so a test can no longer encode a format the writer does not produce.
- **Azure/Google key attributes were asserted, not verified**, and **an empty certificate path returned `chainValid=true`** in three of four verifiers. Both are described in the hsm repository's corresponding section; the same verifier sources are present here and carry the same fixes.
- **The Step-7 confirmation nonce was published and replayable.** `RegistryEntry.confirmationNonce` was serialised verbatim by `registry/awaiting` and `registry/anomalies`, despite the field's own Javadoc claiming controllers stripped it, and it was never cleared on confirm. In the default configuration those endpoints are reachable without a client certificate, so live nonces for every pending verification were readable by anyone. The controller now strips the field per response, and `confirm` clears it, making it single-use as `THREAT_MODEL.md` always claimed. `@JsonIgnore` was deliberately not used: `AppendOnlyFileApprovalRegistry` persists entries to its journal and must be able to replay a pending nonce after a restart.
- **The caller chose the signature algorithm.** `SignatureVerificationService` passed the request's algorithm string straight to `Signature.getInstance`, so a caller could downgrade settlement-time verification to `SHA1withRSA` or `MD5withRSA` and still receive `signatureValid=true`. A whitelist of seven algorithms now applies before the call.
- **`/api/v1/verify` wrote no audit entry.** The settlement-time endpoint is the one that decides whether a payment goes through, and it left no trace: the hash-chained log recorded issuance (`VERIFY`, `BATCH_VERIFY`, `CONFIRM`) and nothing about the decisions taken against those issuances afterwards. A supervisor reading the trail could establish that a certificate had been approved and could not establish that it had ever been used, or how often, or whether the rail had been told to allow or block. `SignatureVerificationService` now appends one entry per call through the same `AuditLog` the rest of the service uses, under the operation label `SETTLEMENT_VERIFY`. The entry carries what the other entries carry and nothing more — sequence number, timestamp, principal, operation, a SHA-256 digest of the canonical request, a SHA-256 digest of the canonical response, and the outcome bit (`signatureValid && compliant`, which is what railgate acts on). No transaction data is written: the request never contained any, and the transaction digest it does contain is hashed again rather than stored. The `verificationId` points at the registry row the answer was read from, so settlement entries and the issuance entry share an identifier; where no registry row matched, the sentinel `NO-REGISTRY-MATCH` is recorded rather than a fabricated UUID. The append is not wrapped in a `try`/`catch`: if the chain cannot be extended the request fails and a default-deny rail blocks the payment, which is the better of the two failure modes. `SignatureVerificationServiceTest` now asserts the entry exists, that its digests differ between two different requests, and — by reading the journal file — that neither the transaction digest, the signature, nor the certificate body appears in it verbatim.
- **Rate limiting covered one path family, and its bucket key was attacker-controlled.** `RateLimitConfig` registered the interceptor on `/v1/attestation/**` only. `/api/v1/verify` (an RSA verification plus an audit fsync per call, in the payment path) and `/v1/audit/**` (including `/v1/audit/export`, which is O(chain length)) were unlimited, and in the reference configuration unauthenticated as well. Separately, the bucket key for unauthenticated callers was the leftmost entry of an unvalidated `X-Forwarded-For`, held in a `ConcurrentHashMap` that was never evicted from — so any client could mint an unlimited number of distinct keys by varying a header it writes itself, which both evaded the limit and grew the map without bound. Both halves are fixed. The interceptor is registered on `/api/v1/**` and `/v1/audit/**` as well, with a settlement bucket sized for payment volume (6000/min by default) and an audit bucket sized like the registry one. `X-Forwarded-For` is now consulted only when the direct peer matches `gatekeeper.ratelimit.trusted-proxies`, which is **empty by default** — out of the box the header is ignored entirely and the peer address is the key. When a proxy is trusted the chain is walked right-to-left and the first entry that is not itself a trusted proxy is taken as the client; entries further left were written outside our trust boundary and are discarded. Values must parse as IP literals, the chain is read at most 20 deep, and a failure of either check falls back to the peer address. Each bucket map is bounded at `max-tracked-keys` (10 000) and sweeps keys idle beyond `key-idle-seconds` (900); at the ceiling, new keys share a single overflow bucket instead of allocating. The trade-off in that last step is deliberate and worth stating: under key flooding, unrecognised callers degrade each other, which is a throttle rather than an out-of-memory. `RateLimitKeyDerivationTest` covers the key derivation directly.
- **Registry queries ignored the `countryCode` path variable.** `VerificationController` read `{countryCode}` on `registry/anomalies` and `registry/awaiting` and then called `findAnomalies()` and `findAwaitingConfirmation()`, which took no argument and returned every jurisdiction's rows. A Swedish supervisor querying the Swedish path received German and French registry entries. Registry contents are supervisory material subject to DORA Article 55 professional secrecy, so this was a disclosure across NCA boundaries, not a cosmetic defect. Both interface methods now take the country code, in both `InMemoryApprovalRegistry` and `AppendOnlyFileApprovalRegistry`; no unfiltered overload was left in place, because an unfiltered overload is how the mistake happens again. A `null` country matches nothing rather than everything, and entries whose own `countryCode` is null belong to no jurisdiction's answer. `ApprovalRegistryCountryScopeTest` runs the same scoping assertions against both implementations — including that an entry registered under `DE` is absent from every `SE` query — because two implementations answering one supervisory question differently would itself be a defect.
- **Nothing bounded the size of a request.** No field on `VerificationRequest`, `SignatureVerificationRequest` or `IssuanceConfirmation` carried a length constraint, `verify/batch` accepted a list of any length, and no configuration capped the request body. One request could therefore occupy a worker thread for as long as the caller wanted, and the per-principal rate limit does not help — it counts requests, not the work inside one. `@Size` now applies to every field, sized from the artefact it bounds with an order of magnitude of headroom (8 KiB for a PEM public key or CSR, 256 KiB for a vendor attestation blob, 16 KiB per certificate, 10 certificates per chain, 256 characters for a SHA-512 digest in hex); the reasoning is in each model's javadoc. `VerificationController.MAX_BATCH_SIZE` caps a batch at 200 and returns 413 before any verification runs — an Article 17(4) sweep of one jurisdiction is tens of entities, and a caller with more can page. Request bodies are capped at `gatekeeper.limits.max-http-request-size` (2 MB) by `RequestSizeLimitFilter`. That is a filter rather than a property because Spring Boot has none that fits: `server.max-http-request-header-size` bounds headers, `spring.servlet.multipart.max-request-size` bounds multipart, and `server.tomcat.max-http-form-post-size` bounds form encoding, while every request this gatekeeper accepts is JSON. The filter rejects a declared `Content-Length` above the cap with a clean 413; for chunked requests, where the size is not known until it has been read, it counts and aborts the stream, and the status in that case is whatever the container makes of a mid-parse `IOException` rather than a clean 413. The guarantee there is the memory bound, not the status code. `VerificationControllerBatchLimitTest` asserts that an oversized batch is refused without any verification being attempted, and that a batch exactly at the ceiling is accepted.

Not closed by any of the above: the reference build still defaults to `EphemeralReceiptSigner`, an in-memory registry, and mTLS off, and the limitations below still stand as written.

## Known limitations and their scope

### `EphemeralReceiptSigner` is not a real signature (Critical for production)

- **Risk.** A receipt signed by an ephemeral self-signed RSA-3072 key has no legal weight. An NCA cannot use it as non-repudiable evidence in a regulatory proceeding.
- **Mitigation in reference.** `EphemeralReceiptSigner` emits WARN logs at class load, on every key generation, and on every signature. The certificate it exposes carries `CN=REFERENCE-EPHEMERAL`. Accidental production use is structurally conspicuous.
- **Close in production.** Switch to `gatekeeper.signing.mode=configured` and point `gatekeeper.signing.keystore-path` at a PKCS#12 containing the NCA's organisation certificate — the certificate the NCA uses for ordinary administrative signing of supervisory acts.

### `ApprovalRegistry` is in-memory (High for production)

- **Risk.** Process restart loses all in-memory `ApprovalRegistry` records. The hash-chained `AppendOnlyFileAuditLog` is the durable side of the picture; the in-memory `ApprovalRegistry` exists for fast read-side state during the lifetime of a verification session.
- **Mitigation in reference.** A verify event and a confirm event, with principal, outcome bit and request and receipt digests, are written to `AppendOnlyFileAuditLog` synchronously on every state change, and the hash chain plus per-entry signature provide tamper-evidence for those entries even if the in-memory map is mutated. Public-key fingerprints, the registry status and the stored certificate are not in the audit log; they are persisted only by `AppendOnlyFileApprovalRegistry`, whose journal is not tamper-evident (`THREAT_MODEL.md`, Tampering). After a restart, supervisory queries served from `/v1/audit/...` reflect the durable state.
- **Close in production.** Replace `ApprovalRegistry` with a PostgreSQL-backed registry that derives state from the audit log on startup; the hash-chained log remains the canonical record.

### Marvell TLV parser is speculative (High)

- **Risk.** Same concern as in the sibling repo — the Azure/Google attestation blob layout is assumed rather than specified.
- **Mitigation in reference.** Fail-closed on parse failure.
- **Close in production.** Replace with a specification-driven parser, shared with the sibling repo.

### Unauthenticated endpoints (High for production)

- **Risk.** The reference default is `gatekeeper.security.mtls.enabled=false`. Anybody with network reach can call `/v1/attestation/{countryCode}/verify`.
- **Mitigation in reference.** Startup emits a WARN log stating mTLS is disabled and the instance "MUST NOT be deployed to production". `SecurityConfig` hot-swaps between a permissive filter chain and a mTLS-enforced filter chain based on the property.
- **Close in production.** Set `gatekeeper.security.mtls.enabled=true`, configure `server.ssl.trust-store` + `server.ssl.client-auth=need`, optionally differentiate supervisory roles per `principal-regex` or the `TODO-NCA` extension point.

### Request size and batch length (Low — was Medium, now bounded)

- **Risk.** `POST /v1/attestation/{countryCode}/verify/batch` accepted an arbitrarily large list and no field carried a length constraint, so a single request could occupy a worker thread indefinitely.
- **Mitigation in reference.** Three layers, all shipped: `@Size` on every request field, `VerificationController.MAX_BATCH_SIZE` (200) rejecting an oversized batch with 413 before any verification runs, and `RequestSizeLimitFilter` capping the body at `gatekeeper.limits.max-http-request-size` (2 MB). `RateLimitInterceptor` continues to bound the per-client request rate on top of that (10 batches/minute vs 600 verifies/minute in the `nca` profile).
- **Residual.** For a chunked request with no `Content-Length`, the body cap is enforced by counting bytes as they are read, so the caller sees a mid-parse failure rather than a clean 413. The memory bound holds; the status code is the container's.
- **Close in production.** Size the caps against the deployment's own traffic, and put an upstream API gateway in front for defence in depth.

### Step-7 confirmation replay (Medium)

- **Risk.** An attacker who knows a `verificationId` can flood the gatekeeper with confirmations.
- **Mitigation in reference.** `VerificationService.confirmIssuance()` requires the submitted issuance certificate to (a) chain to an issuer CA in `IssuerCaValidator`'s trust bundle, and (b) have a public key matching the attested key's fingerprint. Since 1.4.0 the confirmation is also bound to a server-issued single-use nonce, consumed atomically, and — with mTLS enabled — to the principal that performed the verification. A replayed confirmation fails the nonce check and, since 1.5.0, is written to the hash-chained audit log as `ANOMALY_NONCE_MISMATCH`.
- **Residual.** With mTLS disabled there is no principal binding; the nonce still prevents reuse.

### Forward-secure key rotation and RFC 3161 anchoring not implemented (Medium — Article 2 §6.3 scope)

- **Risk.** Article 2 §8.5 calls for a Schneier-Kelsey-style hash chain with forward security and RFC 3161 timestamping. The reference now ships a hash-chained append-only log (`AppendOnlyFileAuditLog`) with per-entry seal signature, but does not yet rotate the signing key forward-securely or anchor batches against an external TSA.
- **Mitigation in reference.** The chain itself is sound: any tampering with a historical entry breaks `verifyChainIntegrity()` at that entry and at every entry that follows. The chain anchor (`/v1/gatekeeper/anchor`) is the operational substitute for an RFC 3161 TSA: a supervisor publishes the anchor periodically (e.g. daily) to a public commitment log, after which any retroactive rewriting of pre-anchor entries is detectable.
- **Close in production.** Add Ma–Tsudik (2008) forward-secure key evolution to the seal key, and integrate the case-study HSM's RFC 3161 capability (HARDWARE_BASELINE.md §3.1 — Primus HSM has RFC 3161 licensed) for an external timestamp anchor on each anchor publication.

---

## Regulatory mapping

| Regulatory source | Code reference |
| ----------------- | -------------- |
| DORA Regulation (EU) 2022/2554 Article 6(10) (verification of compliance) | `VerificationService.verify()` + vendor verifiers' `verifyCertChain()` — core claim of Article 1 |
| DORA Regulation (EU) 2022/2554 Article 17 (incident reporting windows) | Receipt + `ApprovalRegistry` entries carry the `producedAt` timestamp needed to populate DORA Article 17 timelines; the hash-chained audit log preserves the full event stream |
| DORA Regulation (EU) 2022/2554 Article 19 (substantial incident reports) | Article 2 §8.6 uses the signed receipt stream as the evidence substrate; the audit-export endpoint `/v1/audit/export` is the dump format an investigator hands to the supervisor |
| DORA Regulation (EU) 2022/2554 Article 28 (contractual arrangements) | Verification occurs at certificate issuance, not per-transaction — matches Article 1's claim that the financial entity retains full verification responsibility irrespective of outsourcing |
| DORA Regulation (EU) 2022/2554 Article 28(6) (5-year retention with discoverable verifiability) | `AppendOnlyFileAuditLog` provides hash-chained append-only retention and never prunes; `gatekeeper.audit.retention-years` is set to 5 in `application.yaml` but no code reads it, so retention is an operational procedure (`SUPERVISORY_OPERATIONS.md` §5.3); `GET /v1/gatekeeper/keys` and `GET /v1/gatekeeper/anchor` make retroactive verifiability operational |
| DORA Regulation (EU) 2022/2554 Article 29 (concentration risk; "fully monitor outsourced functions") | Supervisory batch endpoint at `/v1/attestation/{countryCode}/verify/batch` aggregates compliance statistics across a population for Article 29 oversight; rate-limiting gap |
| DORA Regulation (EU) 2022/2554 Article 30(2)(c) (data protection provisions) | Article 2 §4.2: contractual HSM requirement without verification does not satisfy Article 30(2)(c); this gatekeeper is the verification mechanism that closes the gap |
| DORA Regulation (EU) 2022/2554 Article 32 (Oversight Forum) | The audit log + anchor publication is the evidence substrate the Oversight Forum consumes when assessing concentration risk and exploring mitigants |
| DORA Regulation (EU) 2022/2554 Article 35 (Lead Overseer powers) | Audit-query endpoints (`/v1/audit/witness`, `/v1/audit/range`, `/v1/audit/entity`, `/v1/audit/export`) are the operational substrate for the supervisory inspection power |
| EBA Regulation (EU) No 1093/2010 Article 17(4)/(6) (breach-of-Union-law procedure) | `VerificationController` exposes `/v1/attestation/{countryCode}/verify` path-variable-scoped per Member State; NCA operates the instance, EBA invokes Article 17 via the API |
| EBA Regulation (EU) No 1093/2010 Article 29 (supervisory convergence) | Wire-format compatibility (locked by `WireFormatGoldenBytesTest`) means cross-Member-State convergence consumes the same byte format from any operating NCA gatekeeper |
| EBA Regulation (EU) No 1093/2010 Article 35(1) (supervisory cooperation; access to records) | The audit-query endpoints are the legal-cooperation substrate; the signed export bundle is what a supervisor obtains for a formal inspection |
| Regulation (EU) 2024/1620 (AMLA) | AML supervisory competence transferred from EBA to AMLA; no AMLA-specific code is present in the reference. Article 1's AML observation (HSM verification is a prerequisite for AML risk assessment under Directive (EU) 2015/849) is an underlying structural point that survives the transfer |
| NIS2 Directive (EU) 2022/2555 Article 21(2)(g)/(h) (cryptographic policies; embed security in acquisition / maintenance) | Verification is the evidence-producing mechanism for the policy per Article 2 §4.4 |
| NIS2 Directive (EU) 2022/2555 Article 23 (incident reporting) | Same evidence substrate as DORA Article 19 |
| Cyber Resilience Act (Regulation (EU) 2024/2847) Annex I (secure-by-design + secure-by-default) | Verification enables continuous demonstration over product support life per Article 2 §4.4; CRA-specific product-lifecycle plumbing is not implemented |
| ISO/IEC 27001:2022 A.5.24–A.5.28 (incident management) | Article 2 §6.5 maps the signed-receipt stream into the ISMS incident playbook |
| ISO/IEC 27001:2022 A.8.15 (logging) | Hash-chained, per-entry-signed audit log; chain integrity verifiable via `verifyChainIntegrity()` |
| ISO/IEC 27001:2022 A.8.17 (clock synchronization) | HARDWARE_BASELINE.md §3.1 time-sync infrastructure (PTP/NTP from GPS PPS) underpins this; the gatekeeper itself trusts the host clock |
| ISO/IEC 27001:2022 A.8.24 (use of cryptography) | Verification is the evidence-producing mechanism for A.8.24 |

---

## How to extend

Obvious extension points:

1. **Real `ReceiptSigner` backed by the NCA's production signing key.** Wire a PKCS#11 provider against the NCA's secure key store — the production baseline is the organisation certificate the NCA uses for ordinary administrative signing of supervisory acts, hosted in an HSM. Implement via `ConfiguredReceiptSigner`-compatible keystore or a new `ReceiptSigner` subclass.
2. **Persistent tamper-evident `ApprovalRegistry`.** Back with PostgreSQL; write a sibling `HashChainedApprovalRegistry` that appends each row with a SHA-256 of `(previous_hash || canonical_row_bytes)`; periodically seal the chain head with the `ReceiptSigner` for forward-secure anchoring.
3. **NCA-role authorisation.** The `SecurityConfig.java` contains a `TODO-NCA` marker. Implement a Spring Security `AccessDecisionVoter` that consults the client certificate's subject or SAN fields against an NCA-role database.
4. **Rate limiting.** Add a Bucket4j / Resilience4j filter ahead of the controllers. Can be principal-aware once mTLS is on.
5. **Step-7 nonce binding.** Implemented: `VerificationService.verify()` returns a 256-bit `confirmationNonce` (SecureRandom, base64url) bound to the `verificationId` in the registry; `confirmIssuance()` requires the FE to echo it back and rejects mismatches with HTTP 400. Extend with a TTL on the bound nonce if deployments need expiry beyond confirm-or-rejected.
6. **RFC 3161 timestamping.** The Primus HSM operated for the case study has RFC 3161 licensed and activated (HARDWARE_BASELINE.md §3.1); integrating a TSA client into the receipt-signing pipeline closes Article 2 §6.3 STR5.
7. **Organisational gatekeeper profile.** Add `application-organisation.yaml` activating an organisational (in-ISMS) configuration — different access control, different consumer of the receipt stream (the organisation's own incident-response desk rather than a supervisory authority). This closes Article 2 §1.3's "two deployment forms" characterisation.
8. **Additional vendor verifier.** Same extension pattern as the sibling repo — implement `HsmAttestationVerifier`, pin the root, anchor `CertPathValidator` at it, add the vendor to `HsmVendor` enum. `TestPki`-based rejection test stays the template.
