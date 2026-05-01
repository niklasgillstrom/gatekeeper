# Peer-review guide — gatekeeper

This document is written for a peer reviewer of Article 1 (Gillström, in preparation; target venue: *Capital Markets Law Journal*) and Article 2 (Gillström, in preparation; target venue: *Computer Law & Security Review*) who wants to reproduce the central gatekeeper-level verification claims these articles make. Companion repos `hsm/` and `railgate/` complete the **triadic system** described in Article 1 §4.2 and Article 2 §9.3:

- **hsm** carries the verifier core (financial-entity side).
- **gatekeeper** (this repo) is the NCA-facing supervisory API that wraps those verifiers for regulatory use, and from v1.2.0 also exposes the settlement-time signature verification endpoint that railgate consumes.
- **railgate** is the central-bank settlement-rail enforcement layer that calls gatekeeper's verification endpoint at settlement time (RIX-INST in Sweden; generalisable to TIPS, FedNow, FPS, NPP).

The three components together operationalise the data-minimised quadruple-triangulation model: only digest, signature, and certificate identifiers traverse the supervisor boundary — no transaction payload content is exposed at any layer.

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

- A production deployment. The receipt signer defaults to `EphemeralReceiptSigner` (self-signed, in-process key pair), which emits `WARN` at startup and on every signature. The `ApprovalRegistry` is `ConcurrentHashMap`-based and lost on restart. There is no rate limiting. mTLS is off by default.
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

**Where the test PKI is built.** `src/test/java/eu/gillstrom/gatekeeper/testsupport/TestPki.java` — a direct sibling of `hsm`'s test PKI helper. Same idea: build a throwaway root + intermediate + leaf, assert the production verifier rejects it because it does not anchor at the pinned vendor root.

### Audit-log integrity guarantees

A reviewer can independently reproduce the following claims about the hash-chained audit log without any external infrastructure beyond `mvn -B test`:

1. **Tamper detection at every row position.** `AppendOnlyFileAuditLogTest` writes a sequence of entries, then mutates one row at a time (first, middle, last) and asserts that `verifyChainIntegrity()` returns `false` in each case. The mutation is targeted at decision-relevant fields (`compliant`, `verificationId`, `requestDigestBase64`) so that a future reviewer can be confident that the chain covers what it claims to cover, not a ceremonial subset.
2. **Persistence across process restart.** The test instantiates a second `AppendOnlyFileAuditLog` against the same file path, asserts that the chain is read back deterministically, and asserts that `verifyChainIntegrity()` returns `true` after restart.
3. **fsync per append.** The append code path uses `FileChannel.force(true)` after every write. The test exercises this by appending, killing the in-process log, and re-reading from disk; the entry is present.
4. **Sequence-number monotonicity.** `AuditEntry`'s record-constructor rejects sequence numbers `< 1`, and the log itself increments strictly monotonically.

These four properties together substantiate the DORA Regulation (EU) 2022/2554 Article 28(6) retention claim — the audit trail kept for 5 years is not merely persisted, it is verifiably untampered.

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
9. **ReceiptCanonicalizerTest.canonicalBytesStartWithVersionPrefix** — every canonical byte sequence begins `v1|`. Protects against silent format migrations.
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
| `gatekeeper.signing.algorithm` | `SHA256withRSA` (common sensible default) | match certificate (`SHA384withECDSA` for EC P-384, etc.) | `ConfiguredReceiptSigner.java` |
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

## Known limitations and their scope

### `EphemeralReceiptSigner` is not a real signature (Critical for production)

- **Risk.** A receipt signed by an ephemeral self-signed RSA-3072 key has no legal weight. An NCA cannot use it as non-repudiable evidence in a regulatory proceeding.
- **Mitigation in reference.** `EphemeralReceiptSigner` emits WARN logs at class load, on every key generation, and on every signature. The certificate it exposes carries `CN=REFERENCE-EPHEMERAL`. Accidental production use is structurally conspicuous.
- **Close in production.** Switch to `gatekeeper.signing.mode=configured` and point `gatekeeper.signing.keystore-path` at a PKCS#12 containing the NCA's organisation certificate — the certificate the NCA uses for ordinary administrative signing of supervisory acts.

### `ApprovalRegistry` is in-memory (High for production)

- **Risk.** Process restart loses all in-memory `ApprovalRegistry` records. The hash-chained `AppendOnlyFileAuditLog` is the durable side of the picture; the in-memory `ApprovalRegistry` exists for fast read-side state during the lifetime of a verification session.
- **Mitigation in reference.** The decision-relevant facts (verify event, confirm event, public key fingerprints, principal) are written to `AppendOnlyFileAuditLog` synchronously on every state change, and the hash chain plus per-entry signature provide tamper-evidence even if the in-memory map is mutated. After a restart, supervisory queries served from `/v1/audit/...` reflect the durable state.
- **Close in production.** Replace `ApprovalRegistry` with a PostgreSQL-backed registry that derives state from the audit log on startup; the hash-chained log remains the canonical record.

### Marvell TLV parser is speculative (High)

- **Risk.** Same concern as in the sibling repo — the Azure/Google attestation blob layout is assumed rather than specified.
- **Mitigation in reference.** Fail-closed on parse failure.
- **Close in production.** Replace with a specification-driven parser, shared with the sibling repo.

### Unauthenticated endpoints (High for production)

- **Risk.** The reference default is `gatekeeper.security.mtls.enabled=false`. Anybody with network reach can call `/v1/attestation/{countryCode}/verify`.
- **Mitigation in reference.** Startup emits a WARN log stating mTLS is disabled and the instance "MUST NOT be deployed to production". `SecurityConfig` hot-swaps between a permissive filter chain and a mTLS-enforced filter chain based on the property.
- **Close in production.** Set `gatekeeper.security.mtls.enabled=true`, configure `server.ssl.trust-store` + `server.ssl.client-auth=need`, optionally differentiate supervisory roles per `principal-regex` or the `TODO-NCA` extension point.

### Unbounded batch endpoint (Medium)

- **Risk.** `POST /v1/attestation/{countryCode}/verify/batch` accepts an arbitrarily large list. A malicious or ignorant client can DoS the gatekeeper.
- **Mitigation in reference.** `RateLimitInterceptor` enforces a per-mTLS-principal token-bucket on the batch path with stricter capacity than the verify path (10 batches/minute vs 600 verifies/minute by default in the `nca` profile). This bounds the per-client request rate but does not bound the per-request payload size.
- **Close in production.** Add a servlet filter that rejects requests with `Content-Length` above a deployment-specific cap, or set Jackson deserialisation limits on the request body. An upstream API gateway provides defence in depth.

### Step-7 confirmation replay (Medium)

- **Risk.** An attacker who knows a `verificationId` can flood the gatekeeper with confirmations.
- **Mitigation in reference.** `VerificationService.confirmIssuance()` requires the submitted issuance certificate to (a) chain to an issuer CA in `IssuerCaValidator`'s trust bundle, and (b) have a public key matching the attested key's fingerprint. This prevents arbitrary-certificate substitution. Replay without certificate possession is still possible.
- **Close in production.** Bind the confirmation to a server-issued nonce (or to the mTLS-authenticated principal) and reject reuse.

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
| DORA Regulation (EU) 2022/2554 Article 28(6) (5-year retention with discoverable verifiability) | `AppendOnlyFileAuditLog` provides hash-chained append-only retention; `gatekeeper.audit.retention-years` defaults to 5; `GET /v1/gatekeeper/keys` and `GET /v1/gatekeeper/anchor` make retroactive verifiability operational |
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
