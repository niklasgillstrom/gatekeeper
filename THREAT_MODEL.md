# Threat model — gatekeeper

**Scope.** Threat model for the supervisory gatekeeper API that sits between an NCA / EBA and HSM vendors' attestation roots. The companion reference libraries (`hsm/` and `railgate/`) have their own threat models covering the verifier core, the BankID-issuance flow, and the settlement-rail enforcement layer respectively. Threat models overlap where verifier behaviour is concerned; this document focuses on what becomes new or different when the verifier is exposed as a REST API operated by a regulator.

**v1.2.0 scope additions.** From v1.1.0 the gatekeeper exposes `POST /api/v1/verify` for settlement-time signature verification consumed by railgate. The settlement-time threats are summarised in the section below before the STRIDE analysis.

**v1.7.0 scope additions.** The settlement verdict is signed (`sv1`); key-lifecycle events (`POST /v1/attestation/{cc}/lifecycle`) move registry entries to `SUPERSEDED`, `REVOKED` or `DECOMMISSIONED`; triangulation inquiries (`/v1/triangulation/**`) take bank and operator reports; audit entries carry inventory fields and a per-key chain (v2); the log-signing key can be held in an HSM and attested at start-up; entries or the chain head can be time-stamped by an RFC 3161 TSA; the audit log can be exported as COSE_Sign1; an organisation-internal profile (`org`) runs the same code inside a regulated organisation; and the verifiers' trust anchors can be replaced through configuration (`gatekeeper.trust-anchors.<key>`), with the active anchors published on `GET /v1/attestation/supported-vendors`. The HSM, attestation and time-stamping paths are off in every shipped profile and have been tested only with test doubles (a test JCA provider, test-PKI evidence, a local TSA).

## Settlement-time verification threats (v1.2.0)

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Forged signing certificate** — caller submits a PEM that is not from a gatekeeper-audited issuance | The registry entry is resolved only through a certificate the gatekeeper itself stored at a Step 7 confirmation that ended in `VERIFIED_AND_ISSUED`, looked up by `(certSerial, issuerDn)`; a supplied PEM must be byte-identical to that stored certificate. No match returns `CERT_NOT_FOUND` — settlement is default-denied. *(Changed 1.6.0.)* Until 1.6.0 a supplied PEM was looked up by public-key fingerprint and never compared with anything: a self-signed certificate for a key that had been verified but never issued settled, and a foreign FE could make another FE's settlements fail by confirming its own verification with the victim's certificate, since the resulting anomaly entry carried the victim's key fingerprint and won the lookup. | Operator must keep the approval registry authoritative (production deployment uses `AppendOnlyFileApprovalRegistry`, not in-memory). |
| **Replayed signature against tampered digest** — caller submits a valid signature with a different digest in an attempt to bind it to a different transaction | SHA-512 collision resistance (256-bit security level) makes it computationally infeasible to find a different payload producing the same digest. Cryptographic verification fails with `SIGNATURE_INVALID`. | Negligible. |
| **Algorithm-downgrade injection** — caller specifies a weak `algorithm` parameter | Explicit allowlist in `SignatureVerificationService` (`PERMITTED_ALGORITHMS`: SHA-256/384/512 with RSA or ECDSA, and `RSASSA-PSS` with fixed SHA-512 parameters), checked before any JCA lookup; anything else returns `ALGORITHM_NOT_SUPPORTED`. Operators MUST NOT register weak algorithms (MD5, SHA-1, RC4) in the JCA provider. | Operational — production deployments should disable weak JCA algorithms via `java.security` policy. |
| **Payload-content leakage to supervisor** — caller submits transaction payload alongside the digest | Endpoint contract does not include a payload field. The verifier never decodes or stores anything beyond `(certSerial, issuerDn, digestHex, signatureBase64, signingCertificatePem, algorithm)`. SHA-512 digest is one-way; the transaction payload cannot be recovered from the digest. | Negligible (cryptographic property). |
| **Compliance-state staleness** — caller relies on a compliance flag that has changed since issuance | Compliance lookup is performed at each verify call against the current registry state, not against a cached snapshot, and it reads both fields that carry the verdict: the Step-3 `compliant` flag *and* the Step-7 `status`. The lookup is by the issued certificate (serial and issuer DN), which Step 7 stores only when it records `VERIFIED_AND_ISSUED` for a compliant entry. A certificate whose confirmation was recorded as `ANOMALY_PUBLIC_KEY_MISMATCH`, `ANOMALY_ISSUED_DESPITE_REJECTION` or `REJECTED_NOT_ISSUED`, or that is still awaiting Step 7, therefore has no stored certificate and is answered `CERT_NOT_FOUND`; the check that a found entry is compliant and `VERIFIED_AND_ISSUED` (`CERT_NON_COMPLIANT` otherwise) remains as a second, defensive condition. Until 1.4.0 only the `compliant` flag was read, so an anomalous confirmation was detected by the Step-7 loop and then ignored by the settlement path. | Operator must maintain the registry's append-only integrity; tampering threats covered under Tampering section below. |
| **Settlement-rail-impersonation** — adversary calls `/api/v1/verify` directly without being a real settlement system | `SecurityConfig` restricts the endpoint to clients holding the `SETTLEMENT_RAIL` or `SUPERVISOR` role. Production deployments use mTLS with NCA-issued client certificates. | Standard mTLS operational risks (certificate management, revocation handling). |
| **Forged or altered verdict on the way to the rail** — an intermediary between gatekeeper and railgate rewrites `signatureValid`/`compliant` *(1.7.0)* | Every response is signed with the receipt key over `sv1`, which covers `verifiedAt`, the request's normalised serial, issuer and digest, the outcome, `auditEntryId` and `auditEntryHashHex`; railgate 1.7.0 verifies it by default under the certificate published at `/v1/gatekeeper/keys` and checks `verifiedAt` against its clock. Requests whose serial, issuer or digest cannot be normalised are answered unsigned. The registry entry is looked up under the request's serial and issuer, and a presented certificate must be the one stored under them *(changed 1.8.0: in 1.7.0 a presented certificate was looked up under its own serial and issuer, so an intermediary that replaced the certificate and the signature in the request with those of another, compliant key obtained a genuine `OK` verdict over the identifiers the rail had sent)*. | `sv1` has no per-call nonce: a genuine verdict for an identical request can be replayed within the relying party's skew window. Whether the rail checks the signature is the rail's configuration. |
| **A revoked or decommissioned certificate keeps settling** *(1.7.0)* | A `REVOKED`, `DECOMMISSIONED` or `ROTATED` lifecycle event moves the entry to a status that settlement answers with `CERT_REVOKED`, `CERT_DECOMMISSIONED` or `CERT_SUPERSEDED` once the signature verifies; with mTLS an `FE` can change only entries it verified itself. An issued certificate is stored on one registry entry only: a confirmation that submits a certificate another entry already stores is refused (`409`, `ANOMALY_CERTIFICATE_ALREADY_REGISTERED`, nothing changed, audited), so neither the client that had it issued nor another client can create a newer entry for settlement and lifecycle events to follow *(changed 1.8.0: in 1.7.0 repeating verification and confirmation with the same evidence and certificate did create one, and the certificate settled again)*. A journal written by 1.7.0 that already holds a certificate on two entries is read with a `SUPERSEDED`, `REVOKED` or `DECOMMISSIONED` entry taking precedence over a later one. | The event must be reported: the gatekeeper does not read CRLs or OCSP. A status change is final for `REVOKED` and `DECOMMISSIONED`; a wrong revocation cannot be undone in the registry. The status follows the certificate, not the key: a new certificate that the issuing CA issues for the same key, verified and confirmed, is a new entry and settles. The first confirmation of a certificate holds it: a client that had the owner's attestation evidence and certificate and confirmed them before the owner did would be the one bound to the certificate's lifecycle, and the owner's own confirmation would be answered `409`. |

---

**Assumptions out of scope.** The host platform (network, OS, JVM, container runtime) is modelled operationally in `HARDWARE_BASELINE.md` §3.1 (locked rack, dual-ISP, UPS, FDE with manual unlock, Wazuh SIEM, gapless HSM audit) for the case-study deployment. The threat model below treats those as sound.

**Framework.** STRIDE.

---

## Spoofing

### Assets at risk

- **Attested signing key identity.** Same as in the sibling repo.
- **NCA / EBA caller identity.** A call to `/v1/attestation/{countryCode}/verify` must be attributable to a known supervisory principal.
- **Step-7 issuance confirmation** — a signing certificate presented via `/confirm` must actually be the certificate the issuer CA produced, not an attacker-substituted one.
- **Receipt signer identity** — the `signature` value on a `VerificationResponse` must be attributable to a specific signing key held by the gatekeeper operator.

### Attack vectors

1. Attacker forges an HSM attestation chain (same as sibling repo).
2. Attacker reaches the unauthenticated endpoint and injects a fabricated verification request, hoping to contaminate the registry or confuse a supervisor.
3. Attacker reaches `/confirm` with a random signing certificate, trying to replay a known `verificationId`.
4. Attacker tampers with a receipt body in transit and expects the (cosmetic) signature to still pass because the "signature" is not cryptographic.

### Mitigations

- **Pinned vendor root CAs + PKIX `CertPathValidator`** — mirrored from the sibling repo. All nine verifiers fail-closed on root-CA load failure.
- **Manufacturer sources and operator-replaceable anchors** *(1.7.0)* — as in the sibling repo: each comment block names the manufacturer's published file where one is known (each anchor is confirmed against the manufacturer's own material), and `gatekeeper.trust-anchors.<key>` replaces a pinned anchor only with a PEM file of the pinned anchor's form, else start-up stops. Start-up logs each override's SHA-256 and a WARN when it differs from the pinned anchor, and `GET /v1/attestation/supported-vendors` publishes every vendor's active anchors (`origin`, `sha256`, `publicKeySha256`, `subjects`, `matchesPinned`), so a relying party can see whether a running gatekeeper verifies against the pinned roots. The `yubico` and `securosys` overrides also govern `SigningKeyAttestation`.
- **mTLS with configurable trust store** — `gatekeeper.security.mtls.enabled=true` activates a Spring Security filter chain that requires a valid client certificate validated against the trust store on the Tomcat connector. Health / OpenAPI endpoints are exempt. When disabled (reference default for sandbox reproduction), a permissive filter chain is active and a startup `WARN` log fires: *"mTLS SecurityFilterChain is DISABLED ... MUST NOT be deployed to production."*
- **Issuer-CA-bound Step 7** — `IssuerCaValidator` loads a configurable bundle (`gatekeeper.confirmation.issuer-ca-bundle-path` or classpath default) of issuer CAs. `VerificationService.confirmIssuance()` requires the submitted certificate to (a) have a PKIX path to one of those issuers, built with `CertPathBuilder` through any intermediates submitted with it or held in the bundle, and (b) expose a public key matching the attested key's fingerprint (constant-time via `MessageDigest.isEqual`). A confirmation reporting issuance without a certificate is an anomaly.
- **Ephemeral receipts are real signatures under a conspicuously marked throwaway key** — `EphemeralReceiptSigner` generates an RSA key pair at startup and signs the canonical bytes with `SHA256withRSA`, so the signature is cryptographically valid; what makes it unusable as evidence is the key, not the format. (Earlier revisions of this document described a `REFERENCE-DIGEST:` prefix on the receipt value. No such prefix exists in the code, and none has: the marker is the certificate, described in the next bullet, plus a WARN on every signature.) `ConfiguredReceiptSigner` loads a PKCS#12 keystore — or, since 1.7.0, any JCA keystore type through a configured provider, so that the key can stay in an HSM — and produces signatures with the algorithm declared in `gatekeeper.signing.algorithm`; production must use it with the NCA's organisation-certificate-backed signing key (the certificate the NCA uses for ordinary administrative signing of supervisory acts). Since 1.7.0 it signs and verifies a probe at start-up and refuses to start when the alias's certificate does not belong to the key, and `SigningKeyAttestation` can verify the HSM's attestation of that key at start-up (`gatekeeper.signing.attestation.*`).
- **`CN=REFERENCE-EPHEMERAL` marker** — the ephemeral signer's self-signed certificate carries this CN. Accidental production use is conspicuous at the certificate level, not just in logs.

### Residual risks

- **Pre-mTLS deployments.** If an operator runs the gatekeeper with `gatekeeper.security.mtls.enabled=false` outside a trusted network, everyone with network reach can forge requests. The WARN log is the mitigation; the deployer is the actor.
- **Vendor root CA compromise.** Same structural residual as in sibling repo.
- **A trust anchor replaced through configuration** *(1.7.0)*. Whoever can set `gatekeeper.trust-anchors.<key>` or write the named file before start-up can make the verifiers, and for `yubico` and `securosys` also the log key's attestation, trust a root of their choosing that has the pinned anchor's form. It is visible: the WARN at start-up and `origin: "override"`, `matchesPinned: false` on `supported-vendors`. An override is not checked for validity (only logged), BasicConstraints, key usage or key size. The endpoint does not publish the file's server path.
- **Step-7 replay.** Closed by server-issued nonce binding: `verify` returns a 256-bit cryptographically random `confirmationNonce` (generated by `SecureRandom`, base64url-encoded) which the gatekeeper binds to the `verificationId` at register time. The FE must echo the exact nonce when calling `confirm`; the registry compares it constant-time and the controller returns HTTP 400 with a structured anomaly body on mismatch. The pubkey-fingerprint comparison continues to run on confirm as a second-line check. The combined effect: an attacker who has obtained a valid issuer-CA-chained certificate and learned a `verificationId` cannot flood the gatekeeper with confirmations because they do not have the nonce. The mismatch is logged at WARN with the verificationId and, from release 1.5.0, appended to the audit log as a `CONFIRM` entry with `compliant=false`, so a supervisor sees attempted replays in the hash-chained record; the 400 body carries `registryStatus=ANOMALY_NONCE_MISMATCH`. Before 1.5.0 the mismatch reached only the application log, and the 400 body was labelled `ANOMALY_PUBLIC_KEY_MISMATCH`.

---

## Tampering

### Assets at risk

- **Attestation evidence** submitted over HTTP.
- **XML-parsed fields** in Securosys evidence.
- **Registry state** — if entries were silently tampered, downstream supervisory reports would be wrong.
- **Receipt canonical bytes** — the signed form of each decision.

### Attack vectors

1. **XXE on Securosys XML input.**
2. **JSON / HTTP body tampering** in transit — TLS handles this at the transport layer; mTLS handles it with client attribution.
3. **Smuggling field boundaries** in receipt canonicalisation — e.g. a `verificationId` containing a literal `|` that collides with the canonicaliser's delimiter.
4. **In-memory registry mutation** by any attacker who achieves code execution — a concern specific to this repo because the registry is in-memory.

### Mitigations

- **XXE-protected `DocumentBuilderFactory`** in `SecurosysVerifier` (same construction as sibling repo).
- **`ReceiptCanonicalizer`** produces `v3|`-prefixed (`v2|` for 1.4.0–1.5.0, `v1|` before), pipe-delimited UTF-8 byte sequences that include every decision-relevant field (verificationId, the customer and supplier, compliant boolean, timestamp, fingerprint, HSM metadata, supplier identifier, key properties, DORA article bits). Pipe characters inside field values are percent-escaped. Test `ReceiptCanonicalizerTest.pipeCharactersInFieldsAreEscaped` is the invariant.
- **`mutatingCompliantFieldChangesCanonicalBytes`** test proves that the signed form covers the compliance decision, not just a ceremonial subset.
- **No JSON deserialisation of signed content** — the receipt is signed over the canonical byte sequence, not over the JSON transport form.
- **Spring `@Valid` + bean validation** on request bodies constrains input shapes at the controller layer.

### Residual risks

- **Registry tamper-evidence.** Two implementations of `ApprovalRegistry` ship with this build, selectable via `gatekeeper.registry.mode`. The default `in-memory` (`InMemoryApprovalRegistry`) is a `ConcurrentHashMap` — fine for the reference flow but loses state on restart and is not tamper-evident. Production deployments use `gatekeeper.registry.mode=file` (`AppendOnlyFileApprovalRegistry`), which writes every `register`/`confirm` operation to an append-only JSONL journal, fsynced before each call returns. The `application-nca.yaml` profile selects the file-backed implementation. The journal is **not** tamper-evident. fsync gives durability and POSIX `0640` restricts access, but neither detects a modification: journal lines carry no hash chain and no signature, so an edited or deleted line changes the registry rebuilt at start-up without anything noticing, and replay skips a line it cannot parse or whose operation it does not recognise with a WARN and a count in the start-up summary rather than refusing to start. What is tamper-evident is the audit log. Until 1.6.0 its `VERIFY` and `CONFIRM` entries recorded that a verification and a confirmation took place and their outcome bit, but not the registry fields that settlement-time compliance reads. Since 1.7.0 the v2 entries carry them: the key fingerprint (`VERIFY`, `BATCH_VERIFY`, `CONFIRM`), the issued certificate's serial and issuer and the registry status (`CONFIRM`, the lifecycle events, `SIGNED`, `SETTLEMENT_VERIFY`), so an edit of those fields in the journal shows as a disagreement with the hash-chained, signed log. No code compares the two — the comparison is a supervisory procedure — and the journal itself still carries no hash chain (`CROSS_REFERENCE.md`, GAP summary). The stored certificate PEM and the submitted evidence are covered by the request digests of the `CONFIRM` and `VERIFY` entries, not stored in the log.
- **Signed confirmation response** *(1.6.0)*. The Step-7 response is signed with the receipt key over `ConfirmationCanonicalizer`'s `c1` form, which covers every field including the anomalies. Before 1.6.0 it was unsigned, and anyone able to answer the confirm call could return `loopClosed=true` with the right `verificationId`; the financial entity's local checks detected a foreign or anomalous response but not a forged one.
- **Canonicaliser version pinning.** `v3|` is the current prefix (1.6.0, which brought the customer's organisation and Swish numbers and the supplier number inside the signed form; `v2` receipts stay verifiable with `canonicalize(receipt, "v2")`, accepted by hsm only for a receipt that carries none of those fields). `v2|` was raised from `v1|` in release 1.4.0 when `confirmationNonce` was brought inside the signed form — under `v1` the nonce was rewritable in transit without invalidating the signature. The migration is not backwards compatible and the `hsm` repository must move in step; `canonicalBytesStartWithVersionPrefix` and the cross-repo golden-bytes test are the guardrails.

---

## Repudiation

### Assets at risk

- **NCA repudiation of a verification decision.** An NCA might later claim a COMPLIANT decision was issued by somebody else, or that a NON-COMPLIANT decision was tampered with.
- **Regulated entity disputing a verification outcome.**

### Attack vectors

1. NCA denies having produced a receipt.
2. An entity denies the receipt's content (e.g. "the gatekeeper said I was compliant").
3. Timestamp is disputed.

### Mitigations

- **`ConfiguredReceiptSigner` in production** — loads the signing key from a PKCS#12 keystore or, since 1.7.0, from an HSM through a JCA keystore type and provider, and produces real signatures over the canonical bytes. A receiver with the signer's public certificate can verify the receipt content cryptographically. Production deployments should host the signing key in an HSM and use the NCA's organisation certificate (the certificate the NCA uses for ordinary administrative signing of supervisory acts) so that the receipts are myndighetshandlingar in the ordinary förvaltningsrättsliga sense; with `gatekeeper.signing.attestation.*` the gatekeeper verifies at start-up that the key is HSM-generated and non-exportable and publishes the evidence on `GET /v1/gatekeeper/keys`.
- **Canonical form covers every decision-relevant field** (see `ReceiptCanonicalizer`). No ambiguity about what was signed.
- **Structured logging via SLF4J** — every verification, every confirmation, every registry mutation produces a log line. In the case-study operational deployment these logs are streamed to a Wazuh SIEM with chain-of-custody controls (HARDWARE_BASELINE.md §3.1).

### Residual risks

- **`EphemeralReceiptSigner` in dev/test.** Ephemeral signatures have no legal weight, which is correct — they are for dev/test. A deployer who forgets to switch to `configured` mode is caught by the startup WARN and the `CN=REFERENCE-EPHEMERAL` marker.
- **Timestamp authority.** The entry `timestamp` is the host clock. Since 1.7.0 an RFC 3161 TSA can add an independent time attribute (`gatekeeper.timestamping.mode=entry` or `anchor`); it is off by default, has been tested only against a local TSA, and the token's `genTime` is not compared with the entry's `timestamp`. A qualified TSA is a matter of configuration (`tsa-url`) and has not been used.
- **Hash-chained log is implemented** — `AppendOnlyFileAuditLog` links every entry to its predecessor via `prevEntryHashHex` and, since 1.7.0, to the previous entry of the same key via `prevKeyEntryHashHex`, and signs each entry's `thisEntryHashHex`, so selective entry deletion breaks the chain at the deletion point and at every entry after it, and `GET /v1/gatekeeper/anchor` publishes the head. Article 2 §8.5 asks for two protections. Against anyone without the key: a log-signing key in an HSM, which cannot be exported (supported since 1.7.0 through a JCA keystore type and provider, with the key's attestation verified at start-up). Against the key holder: external RFC 3161 timestamps of the entries or of the chain head (since 1.7.0). Forward security by key evolution (Ma and Tsudik 2008) is not needed in this design, because a key that cannot be exported cannot be stolen for back-dating, and a rewrite of entries that an external timestamp already covers is detected. Both protections are configuration, off by default: with the default PKCS#12 seal the key is a file, and without time-stamping nothing outside the gatekeeper fixes the chain except the published anchors. The JSON Lines storage is unchanged; `GET /v1/audit/export?format=cose` exports COSE_Sign1. Detection still requires somebody to run the check or reconcile against a published anchor; see the Audit-log tampering section below.

---

## Information disclosure

### Assets at risk

- **Supervisory data.** Which entities have been verified, when, and with what outcome. Pre-disclosure of NON-COMPLIANT decisions could prejudice a supervisory investigation.
- **Cross-Member-State data.** `countryCode` in the URL partitions by jurisdiction; leakage across partitions is a concern.
- **Receipt signer private key.** A leaked key collapses the non-repudiation property.

### Attack vectors

1. Unauthenticated registry query endpoint leaks investigation state.
2. Mis-routing a request across country codes.
3. Exception stack traces returned to clients exposing internals.
4. Receipt signer keystore stored in cleartext or with weak access control.

### Mitigations

- **mTLS-gated endpoints** — when enabled. Registry queries require a valid client certificate.
- **Country-code is path-variable** — `VerificationController` uses `@PathVariable String countryCode` and upper-cases it server-side; separation is at the URL level. No authorisation rule ties a client to a country code (there is no `TODO-NCA` marker in the code for it); production should verify the client cert's subject against the country code in the path.
- **Bounded error surface** — controller returns `VerificationResponse` / `IssuanceConfirmationResponse` with fixed fields; no raw stack traces.
- **Keystore at rest** — `ConfiguredReceiptSigner` expects a PKCS#12 keystore reachable via `gatekeeper.signing.keystore-path`. Production deployments put this behind Spring Cloud Config or a secrets manager; the code does not assume plaintext on disk.
- **No secret in attestation evidence** — attestation evidence is public-verifiable by design.
- **Triangulation inputs** *(1.7.0)* — bank and operator reports name organisation numbers (a sole trader's is a personal identity number) and Swish numbers. `/v1/triangulation/**` is `SUPERVISOR`-only for every method, an inquiry is visible only under its own country code, and inquiries are held in memory only, so a restart discards them; the audit log keeps only digests of the inputs and of the report.

### Residual risks

- **mTLS-off deployments leak freely.** The WARN log is the mitigation. This is a deployer concern.
- **Cross-country authorisation policy** is not implemented. Until it is, any principal holding `SUPERVISOR` can query any country code's registry partition. Production must gate on client-cert subject matching the URL country code.
- **Keystore password management.** Out of scope for the Java code; operational concern. HARDWARE_BASELINE.md §3.1 FDE-with-manual-unlock prevents storage at rest on removed disks in the case study; general deployers vary.

---

## Denial of service

### Assets at risk

- **Availability of the supervisory API.** An NCA needs predictable latency.
- **Registry size** — unbounded growth → memory exhaustion → process death.
- **Batch endpoint** — aggregates N verifications in one call.

### Attack vectors

1. **Unbounded batch endpoint.** `POST /v1/attestation/{countryCode}/verify/batch` with an arbitrarily large list. Each element triggers full PKIX validation.
2. **Unbounded registry growth.** `ConcurrentHashMap` grows with every `verify()`; restart frees memory but a live process can be starved.
3. **Malformed attestation evidence forcing slow path in `CertPathValidator`.**
4. **Flood of confirmation attempts** against a known `verificationId`.

### Mitigations

- **XXE protections** (inherited from sibling repo).
- **PKIX bounds** — path length, validity dates, and linkage checks short-circuit most malformed chains quickly.
- **In-memory registry restart recovery** — the limitation is also a mitigation: restart clears state. Not a production strategy but a reference-code property.
- **Request size.** Spring Boot has no property that bounds a JSON body; `RequestSizeLimitFilter` caps it at `gatekeeper.limits.max-http-request-size` (default 2 MB). Header size and thread count use the Spring Boot defaults.
- **Step-7 certificate validation via `IssuerCaValidator`** — a flood of random certificates is rejected quickly at the issuer-chain check before reaching the registry.

### Residual risks

- **Rate limiting.** A token-bucket rate limiter (`RateLimitInterceptor`, Bucket4j-based) is wired in by default with six buckets — verify (which also carries confirm), batch, registry, settlement, audit (which also carries `/v1/triangulation/**`) and, since 1.7.0, lifecycle — keyed by the mTLS principal, or by the peer address if mTLS is off (`X-Forwarded-For` is believed only from a configured trusted proxy). Per-bucket capacity and refill cadence are configurable via `gatekeeper.ratelimit.{verify,batch,registry,settlement,audit,lifecycle}.{capacity,refill-seconds}`; the `application-nca.yaml` profile sets production-shaped values (verify=600/min, batch=10/min, registry=120/min, settlement=6000/min, audit=120/min, lifecycle=600/min), and `application-org.yaml` the same with lifecycle=6000/min. A settlement now costs one more private-key signature (the signed verdict), and so does each `SIGNED` lifecycle event. The interceptor covers `/v1/attestation/**`, `/api/v1/**`, `/v1/audit/**`, `/v1/gatekeeper/**` and `/v1/triangulation/**`; the only exempt endpoints are `/v1/attestation/health`, `/swagger-ui/**` and `/v3/api-docs/**`. Each bucket map is bounded by `gatekeeper.ratelimit.max-tracked-keys` with idle-key sweeping, so a caller minting keys degrades service for other unrecognised callers rather than exhausting memory. For deployment-wide DoS protection beyond per-principal limits, an upstream API gateway is still recommended.
- **Entry-mode time-stamping latency** *(1.7.0)*. In `entry` mode the TSA request is made while the audit append lock is held, so an unresponsive TSA adds up to `connect-timeout-ms` + `read-timeout-ms` (defaults 5 s + 10 s) to every audited request, serially. A TSA failure never fails the append. `anchor` mode does not have this cost.
- **Triangulation caps** *(1.7.0)*. At most `gatekeeper.triangulation.max-inquiries` (10) inquiries, `max-entries-per-inquiry` (100 000) entries per inquiry and 50 000 entries per submission; the endpoints are `SUPERVISOR`-only and limited under the audit bucket.
- **Registry unboundedness.** The journal-backed `AppendOnlyFileApprovalRegistry` rebuilds the in-memory query index from the journal at startup. Long-running instances accumulate entries until the operator rotates the journal — typical NCA deployments would rotate quarterly or annually. Memory growth is bounded in practice by the rotation cadence; an out-of-memory pressure scenario would require ~O(10⁷) registry entries against the supervisee population, which is not realistic on the DORA Article 28(6) 5-year horizon.
- **Batch endpoint sizing.** Bounded in code: `VerificationController.MAX_BATCH_SIZE` is 200 and an oversized batch is refused with HTTP 413 before any verification runs. The request body itself is capped by `RequestSizeLimitFilter` at `gatekeeper.limits.max-http-request-size` (2 MB by default), and each element's fields carry `@Size` ceilings that, since 1.4.0, are actually enforced for batch elements (the `@Valid` was on the list, not on its type argument, so element constraints were skipped).

---

## Elevation of privilege

### Assets at risk

- **Supervisory decision authority.** Only an authorised NCA or EBA user should be able to cause a COMPLIANT decision to be recorded.
- **Issuance confirmation authority.** Only the legitimate issuer CA (or a party holding a certificate it signed) should be able to confirm issuance.
- **Differentiated supervisory roles.** EBA's Article 17 intervention power differs from an NCA's ordinary oversight; a client cert should not be able to invoke EBA-only endpoints unless it belongs to EBA.

### Attack vectors

1. Unauthenticated actor calls `/verify` (pre-mTLS).
2. Client submits an attacker-controlled certificate to `/confirm` hoping to mark an entry as confirmed (historical weakness).
3. An NCA principal invokes an EBA-scoped endpoint (no role differentiation yet).
4. Receipt-signer keystore is accessible to more principals than intended.

### Mitigations

- **mTLS filter chain** when enabled. `SecurityConfig` permits exactly eight paths without authentication: `/v1/attestation/health`, `/v1/attestation/supported-vendors`, `/v1/gatekeeper/keys`, `/v1/gatekeeper/anchor`, `/v1/gatekeeper/anchor/timestamps` (since 1.7.0), `/swagger-ui/**`, `/swagger-ui.html` and `/v3/api-docs/**`. The three gatekeeper endpoints are public because a relying party must be able to verify a receipt retroactively without holding a client certificate; the rest are liveness and documentation (the three documentation paths exist only in the `dev` profile). Without the mTLS filter chain, which is the default, Spring Boot also served the swagger-ui WebJar under `/webjars/swagger-ui/**` in every profile until 1.7.0; since 1.8.0 static resources are not mapped (`spring.web.resources.add-mappings=false`). `/v1/gatekeeper/health` was in that list until 1.4.0 and is now `SUPERVISOR`-only — it reports operational state, not evidence. `/v1/audit/**`, `/v1/triangulation/**` (since 1.7.0), `/v1/gatekeeper/health` and `/v1/attestation/*/registry/**` require `SUPERVISOR` for every method (until 1.7.0 the last two rules named `GET` only, and a `HEAD` on a registry path, which Spring MVC answers from the `GET` handler without a body, fell through to "requires authentication" and was answered with 200 to any client certificate); `POST` on verify, verify/batch, confirm and, since 1.7.0, lifecycle requires `FE` or `SUPERVISOR`; `POST /api/v1/verify` requires `SETTLEMENT_RAIL` or `SUPERVISOR`; anything else under `/v1/attestation/**` requires authentication, and everything else is denied.
- **Lifecycle changes bound to the verifying principal** *(1.7.0)*. With mTLS, a caller without `SUPERVISOR` may move to `SUPERSEDED`, `REVOKED` or `DECOMMISSIONED` only an entry whose `verificationPrincipal` is its own principal (constant-time comparison); any other entry is answered `CERT_NOT_FOUND`, indistinguishable from an unknown certificate, and logged at WARN. Without mTLS, or for an entry with no bound principal, any caller that reaches the endpoint may change it. `SIGNED` events are not bound, because the signing service may differ from the issuing one.
- **`IssuerCaValidator` gates Step 7** — the submitted certificate must chain to an issuer CA that the gatekeeper operator has explicitly trusted. The bundle is configured via `gatekeeper.confirmation.issuer-ca-bundle-path` (file). Without that setting the validator falls back to the bundled `issuer-ca-bundle.pem` on the classpath and logs at INFO how many anchors it loaded; a deployer missing the configuration therefore trusts the reference bundle, not nothing. A deployer who has set it gets the file it names or no gatekeeper: a path that names no file, or a file without a certificate, stops start-up *(1.8.0; until 1.7.0 such a path fell back to the reference bundle with a WARN, so a mistyped path left the gatekeeper accepting the demonstration issuers)*. Only when no path is set and the reference bundle yields no certificate is every confirmation refused (logged at WARN).
- **Public-key fingerprint match** — `VerificationService.confirmIssuance()` verifies the confirmation certificate's public key against the attested key's fingerprint (constant-time).
- **Placeholder-conspicuous defaults** — `EphemeralReceiptSigner` and `application-nca.yaml` make the "production-ready" posture explicit. Deviations require explicit config and leave log trails.

### Residual risks

- **Role differentiation is implemented.** `RoleMappingProperties` maps client-certificate principals (the exact value of the subject attribute named by `gatekeeper.security.mtls.principal-attribute`) to the roles `SUPERVISOR`, `FE` and `SETTLEMENT_RAIL`, first match wins, with `default-roles: []` meaning deny by default. `SecurityConfig` enforces them per path as listed under Mitigations above, so an `FE` client cannot reach the audit or registry endpoints. What remains deployer-specific is the mapping itself: the patterns shipped in `application-nca.yaml` are illustrative templates and must be replaced with the NCA's real client-certificate conventions. Roles and principals are read from the subject attribute alone, not from the issuing CA: any CA in the client truststore can issue a certificate for any role and any principal, so the truststore may hold only CAs that the NCA operates or whose validation of that attribute it relies on for every client (`DEPLOYMENT.md` §2.3, corrected in 1.8.0). Binding a role to the trust anchor a certificate chains to is not implemented.
- **Step-7 nonce-binding closed.** As of the current build, `verify` returns a single-use `confirmationNonce` and `confirm` rejects on mismatch (HTTP 400). Replay across time with a valid certificate is no longer possible without also possessing the nonce, which is delivered only in the verify response and not stored in the audit log.
- **No audit of configuration mutations** — Spring property changes require a restart; the audit trail is the restart log, not a dedicated config-change log.

---

## Audit-log tampering

### Assets at risk

- **Tamper-evidence of the supervisory record.** Every gatekeeper decision is appended to a hash-chained audit log (`AppendOnlyFileAuditLog`). The integrity of this log is what allows DORA Regulation (EU) 2022/2554 Article 28(6)'s 5-year retention with discoverable verifiability claim to hold.
- **Audit-entry signatures.** Each entry is signed by the gatekeeper's `ReceiptSigner` (in production, the NCA's organisation-certificate-backed signing key — the certificate the NCA uses for ordinary administrative signing of supervisory acts) over the entry's `thisEntryHashHex`.
- **Chain head** — the audit-trail commitment that supervisors use to detect retroactive rewrites.

### Attack vectors (STRIDE: Tampering)

1. An operator or attacker with file-system access to `gatekeeper.audit.path` modifies a historical entry (for example: changes a `compliant=true` row to `compliant=false`, or deletes a row entirely).
2. An attacker with code-execution rebuilds the entire chain from scratch with attacker-chosen content, then re-signs each entry with the seal key (which would require possessing the seal private key).
3. An attacker silently truncates the log to a prior chain head, rolling back recent decisions.
4. An attacker modifies in-memory state (`ApprovalRegistry`) without an audit append.

### Mitigations

- **Hash chain** — every `AuditEntry` carries `prevEntryHashHex`. `AuditLog.verifyChainIntegrity()` walks the entire chain and recomputes each `thisEntryHashHex` from `canonicalBytesForHash(...)`. In `AppendOnlyFileAuditLog` the walk runs over the file as read back from disk and must end at the in-memory head, so file tampering under a running process is caught at the next check rather than at the next restart (before 1.5.0 it walked the in-memory copy). Mutating any entry breaks the chain at that entry and at every entry that follows. The first-row sentinel `0000...0000` (`AuditEntry.SENTINEL_PREV_HASH_HEX`) is a deterministic well-known starting point for the first entry. It does not tell an empty log from one that has been removed: when the file is deleted and the gatekeeper restarted, a new empty log is created, `size` is 0 and `verifyChainIntegrity()` is `true` (this document said until 1.7.0 that the sentinel made the two distinguishable). What shows the removal is outside the file: an anchor published earlier; an RFC 3161 anchor record (with `gatekeeper.timestamping.trusted-certs-path` set the chain check then fails, because the record names an entry the chain does not hold); or a comparison with the approval registry, whose entries then have no audit entries, which the gatekeeper does not make by itself.
- **Per-entry seal signature** — `entrySignatureBase64` is computed over `thisEntryHashHex.getBytes(UTF_8)`. Wholesale re-signing of an alternate chain therefore requires the seal private key. The chain check verifies each signature with the configured `gatekeeper.signing.algorithm` under the active key or any key in `gatekeeper.signing.retired-keys` — so a compromised key must not be listed there (`SUPERVISORY_OPERATIONS.md` §2.3).
- **Per-key chain and inventory fields** *(1.7.0)* — v2 entries bind the key, certificate and registry status into the hash, and `prevKeyEntryHashHex` links the entries of one key, so moving or editing an entry of a key's history breaks both its global and its per-key link (`AuditLogV2ChainTest`). A v1 entry after a v2 entry, or a v1 entry carrying a v2-only field, fails the check, so the version cannot be downgraded to drop fields from the hash.
- **External timestamps** *(1.7.0, when configured)* — in `entry` mode each entry's RFC 3161 token covers its hash; in `anchor` mode the chain head is time-stamped periodically and the record appended to an fsynced file and published on `GET /v1/gatekeeper/anchor/timestamps`. With `trusted-certs-path` set, the chain check validates every token, requires an entry token's `genTime` to be within `entry-token-tolerance-seconds` (default 300) of the entry's own timestamp, and requires every anchor record to name an entry of the chain with that hash and, since 1.8.0, to state the `genTime` its token carries (the record's copy is what `/anchor`, `/anchor/timestamps` and `/health` report, and until 1.7.0 it was never compared with the token), so a rewrite of time-stamped entries — by the seal-key holder too — and a chain truncated below an anchored head are reported (`EntryTimestampingTest`, `EntryTokenTimeTest`, `AnchorTimestampingTest`). The comparison of times was added in 1.8.0: in 1.7.0 the seal-key holder could write the chain again, have every entry time-stamped anew by the same TSA, and pass the check, because the new tokens were valid for the new hashes and nothing compared their time with the entries'. A rewrite within the tolerance of the original writing is not distinguishable by time.
- **fsync per append** — the entry and its newline are written through a `FileChannel` and `force(true)` is called before `append()` returns, so the entry is on the device by then (`JournalAppender`, since 1.8.0, for the audit log, the registry journal and the RFC 3161 anchor file; until 1.7.0 all three used `RandomAccessFile` in `"rwd"` mode with `getFD().sync()`). A crash mid-append leaves a partially written trailing line, which the loader detects, reports and truncates at startup; earlier entries are unaffected.
- **Whole lines only** *(1.8.0)* — until 1.7.0 that held only when the process restarted before the next append. An append that failed part-way in a running process (a full disk, an I/O error) left the same partial line, and the next append continued on it: the two became one unreadable line. The registry skipped it at the next start, so the record the second append had acknowledged, a `STATUS_CHANGE` to `REVOKED` for instance, was lost; the audit log dropped it as an aborted append if it was the last line and otherwise refused to load. Now an append that fails cuts the file back to its length before the append (or, if that fails too, the next append does), and before every append whatever follows the last newline is removed (`JournalAppenderTest`, `ApprovalRegistryTornLineTest`, `AuditLogTornLineTest`, `TimestampAnchorStoreTest`; the I/O failures are simulated). A last line that is a whole record without its newline is kept and given one at start-up.
- **In-memory state derives from durable state** — the file-backed `ApprovalRegistry` journals every `register` and `confirm`, fsynced before the call returns, and replays the journal at startup, so registry state survives restart independently of the audit log.

**Known limitation — the registry write and the audit append are not atomic with respect to each other.** They are two durable writes to two files with no transaction spanning them. A crash between them, or an I/O failure on the second, leaves a registry entry with no audit row or an audit row with no registry entry. Neither file is corrupted and both remain individually verifiable, but a supervisor reconciling the two can find a discrepancy that is a crash rather than tampering, and cannot tell which from the artefacts alone. Reconciliation across the two is therefore an operational procedure (`SUPERVISORY_OPERATIONS.md`), not a property the code guarantees. Closing this needs either a single write-ahead log carrying both records or a two-phase protocol between them; neither ships.
- **Anchor publication endpoint** — `GET /v1/gatekeeper/anchor` returns the current chain head, signed. A supervisor publishes the anchor periodically (for example daily) to a public commitment log; any subsequent retroactive rewriting of pre-anchor entries is detectable by anyone holding the published anchor.

### Residual risks

- **Removal of a token or an anchor record** is not detected by the chain check: both are outside the entry hash and signature. A missing entry token shows as `untimestampedEntries` on health; an anchor record protects against the key holder only once a third party has retrieved it.
- **Detection requires somebody to look.** Retroactive log-fabrication is detectable only by a verifier who actually runs `verifyChainIntegrity()` or reconciles against published anchors. If the NCA does not publish anchors regularly, an internal observer is the only line of defence (see "Anchor publication frequency" below).
- **Pre-publication window.** A change made between the last anchor publication and the next gives the attacker a window in which mutation is detectable only by chain re-validation, not by anchor reconciliation. Daily publication bounds the window to one day.
- **Seal-key compromise** — see "Gatekeeper key compromise" below.
- **Storage-layer corruption** is indistinguishable at the chain level from tampering. The deployer's incident-response runbook must distinguish (typically by checking system / disk logs).

---

## Gatekeeper key compromise

### Assets at risk

- **Cryptographic basis for every receipt and audit-entry signature.** If the gatekeeper's `ReceiptSigner` private key is compromised, an attacker can forge `VerificationResponse` envelopes that trusted relying parties accept and audit entries whose signatures verify under the (compromised) operator certificate.

### Attack vectors

1. Theft of the seal private key (operational compromise at the NCA).
2. Cryptanalytic break of the signature algorithm (`SHA256withRSA` for RSA seals, `SHA384withECDSA` for EC P-384, etc.).
3. Insider misuse — the legitimate signer key is used to seal a receipt that the gatekeeper's decision-making code path did not authorise.

### Mitigations

- **Retired-keys directory.** `GatekeeperKeyDirectory` exposes both the active key and any number of retired keys via `GET /v1/gatekeeper/keys`. Operators rotate by configuring `gatekeeper.signing.retired-keys` (a list of retired PEMs) before flipping the active key. Receipts signed under retired keys remain verifiable for the DORA Regulation (EU) 2022/2554 Article 28(6) 5-year window, and since 1.5.0 the gatekeeper's own audit-chain check accepts entry signatures under them. Where a key is **compromised** (not merely rotated), it is not added to the list (the chain check would otherwise accept entries forged under it); relying parties are notified out-of-band that receipts produced by that key are no longer trustworthy regardless of date.
- **Anchor publication.** A supervisor or relying party that retains the published anchor from before the compromise can determine which entries existed at that anchor time and which did not. Entries signed by the compromised key but absent from the pre-compromise chain-head's reachable set are demonstrably forged.
- **Operational signing key in HSM.** Production deployments host the signing key in an HSM (the case study uses Securosys Primus with RFC 3161 per HARDWARE_BASELINE.md §3.1). Compromise then requires physical compromise of the HSM, which is bounded by the operational controls. Since 1.7.0 the gatekeeper can use such a key through a JCA keystore type and provider and verify its YubiHSM 2 or Securosys attestation at start-up, publishing the result on `GET /v1/gatekeeper/keys`; tested with a test JCA provider and test-PKI evidence only.
- **External timestamps.** Since 1.7.0 an RFC 3161 TSA can time-stamp entries or the chain head (see Audit-log tampering), which fixes the chain outside the gatekeeper against the key holder as well — as far as the tokens are kept where the key holder cannot remove them, and, for entry tokens, with the comparison of the token's time and the entry's that was added in 1.8.0.
- **`CN=REFERENCE-EPHEMERAL` marker** — the ephemeral signer's certificate is marked, so a deployer cannot accidentally treat an ephemeral signature as a production NCA signature.

### Residual risks

- **Receipts already accepted under a compromised key** cannot be invalidated retroactively in a cryptographic sense — what was signed remains signed. The pre-compromise chain head, however, is a commitment that bounds what entries the attacker could have already injected. Relying parties react to a published compromise notice by treating all post-compromise receipts under that key as suspect, regardless of whether or not they appear in the pre-compromise chain.
- **Window between compromise and detection.** Bounded by NCA operational controls (signature counters, alerting, periodic key audit). Out of code scope.
- **Forward security by design rather than by key evolution.** The design Article 2 §6.3 and §8.5 now describe, and the code supports since 1.7.0, is an HSM-bound, non-exportable log key, attested at start-up, plus external RFC 3161 timestamps of entries or of the chain head. Forward security by key evolution (Ma and Tsudik 2008) is not needed in it: the key cannot be exported, so it cannot be stolen to re-sign history, and a rewrite of entries that an external timestamp already covers is detected — by whoever has that timestamp: the chain check itself detects a rewritten entry that kept or renewed its token, not one whose token or anchor record was removed with it (above). The argument holds only as configured: with the default PKCS#12 seal, or without time-stamping, a stolen key file can re-sign everything after the last published anchor. The HSM and TSA paths have been tested only with test doubles.

---

## Anchor publication frequency

### Assets at risk

- **Detectability of internal manipulation.** The hash-chain anchor (`GET /v1/gatekeeper/anchor`) is a commitment to the audit content as of an instant; once published externally, retroactive rewriting of pre-anchor entries is detectable. Publication frequency therefore directly determines the detection window.

### Attack vectors

1. The NCA publishes anchors irregularly or not at all. An internal attacker with chain access then has an unbounded window in which manipulation is detectable only by an internal observer who happens to run `verifyChainIntegrity()`.
2. The NCA publishes anchors but to a forum the attacker also controls. The attacker swaps the published anchor at the same time as rewriting the chain.
3. The published anchor is not signed, so an observer cannot distinguish a real published commitment from an attacker-forged one.

### Mitigations

- **Anchor is signed.** `GET /v1/gatekeeper/anchor` signs the UTF-8 bytes of `headHashHex` with the active seal. A relying party who pins the seal certificate (via `GET /v1/gatekeeper/keys`) can verify that hash independently of the publication channel. The signature covers the hash only: `headSequenceNumber` and `headTimestamp` are bound to it through the head entry, which the relying party needs in order to check them, `totalEntries` is not signed, and the anchor carries no time of its own, so the time of a commitment is that of its publication or of an RFC 3161 anchor record. The anchor of an empty log signs a constant.
- **Recommended cadence in `SUPERVISORY_OPERATIONS.md`.** The operations runbook prescribes daily anchor publication to a forum outside NCA control (transparency log, public web page with timestamped commit, paper-of-record advert). Daily cadence bounds the detection window to one day.
- **Supervisor / relying party retention.** A relying party who retains every published anchor can detect any subsequent rewrite.

### Residual risks

- **NCA passivity.** If the NCA simply stops publishing anchors, the audit trail's external verifiability decays. Internal `verifyChainIntegrity()` checks remain meaningful (they catch storage-layer corruption and unsophisticated tampering), but a sophisticated attacker who controls both the audit file and the seal key can rebuild the chain undetected.
- **Single-channel publication.** A publication forum compromise (NCA web page taken down) defeats reconciliation against that forum specifically. Defence is publication to multiple independent forums.
- **Time-correlation attacks.** An attacker who controls the host clock can backdate the published anchor. Production deployments mitigate via independent time source (GPS-PPS — HARDWARE_BASELINE.md §3.1 — or, since 1.7.0, RFC 3161 anchor mode, whose token carries the TSA's `genTime`).

---

## Summary of residual risks

| Category | Residual risk | Scope |
| -------- | ------------- | ----- |
| Spoofing | Vendor root / issuer CA compromise | Out of code scope; inherent to PKI |
| Spoofing | A pinned anchor that is not the manufacturer's | Every anchor confirmed against the manufacturer's own material; README lists the values and sources (1.7.0) |
| Spoofing | Trust anchor replaced through configuration | Form checked, fail-closed; WARN at start-up; published on `supported-vendors` (1.7.0) |
| Spoofing | Step-7 replay with valid certificate | Closed: `confirmationNonce` server-issued at verify, required-and-validated at confirm |
| Tampering | In-memory `ApprovalRegistry` mutation, or editing the registry journal | Partly mitigated: the hash-chained `AppendOnlyFileAuditLog` records that each verification and confirmation happened and its outcome bit, but not the registry fields, and the registry journal itself is not tamper-evident (see Tampering) |
| Tampering | Audit-log tampering by file-system access | Detected by `verifyChainIntegrity()` and per-entry seal signature; bounded by anchor publication cadence |
| Repudiation | Ephemeral signer is not legally binding | By design; WARN log + `CN=REFERENCE-EPHEMERAL` marker protect against accidental production use |
| Repudiation | Rewriting of the log by the seal-key holder | Since 1.7.0 addressed by an HSM-bound, attested log key plus RFC 3161 timestamps of entries or the chain head (replaces forward-secure key evolution); both off by default and tested only with test doubles (test JCA provider, local TSA). Since 1.8.0 an entry token must be of the entry's time, which closes re-stamping of a rewritten chain; removal of tokens or anchor records is detected only by a party that holds them |
| Repudiation | RFC 3161 token or anchor record removed | Not detected by the chain check (outside the hash); `untimestampedEntries` shows missing entry tokens; anchors protect once retrieved by a third party |
| Settlement | Verdict replay within the skew window | `sv1` has no nonce; bounded by the relying party's clock check |
| Audit-log | Anchor publication frequency | Operational; daily publication recommended in `SUPERVISORY_OPERATIONS.md` |
| Gatekeeper key | Pre-detection compromise window | Bounded by NCA seal-key operational controls |
| Gatekeeper key | Receipts under compromised key cannot be retroactively invalidated | Inherent to digital signatures; bounded by published anchor commitments |
| Information disclosure | Cross-country authorisation | Not implemented; deployer work |
| Information disclosure | Keystore password management | Operational concern |
| DoS | Rate limiting | Implemented: six Bucket4j buckets (verify, batch, registry, settlement, audit, lifecycle) over `/v1/attestation/**`, `/api/v1/**`, `/v1/audit/**`, `/v1/gatekeeper/**`, `/v1/triangulation/**`; upstream gateway still recommended for deployment-wide protection |
| DoS | Entry-mode TSA call under the append lock | Bounded by the TSA timeouts; use `anchor` mode where latency matters |
| Information disclosure | Triangulation reports may contain personal data | `SUPERVISOR`-only, per jurisdiction, in memory only |
| DoS | Batch endpoint size | Bounded: `MAX_BATCH_SIZE` = 200, 413 above it, plus the 2 MB body cap |
| Tampering | Registry write and audit append are not atomic with respect to each other | Known limitation — see Audit-log tampering; reconciliation is an operational procedure |
| Elevation | Role differentiation beyond mTLS | Implemented (`SUPERVISOR`, `FE`, `SETTLEMENT_RAIL`); the CN patterns themselves are deployer-specific |

The **central claim** this gatekeeper sustains for Article 1 §4.2 and Article 2 §6.1 is that attestation verification can be operated as a supervisory API whose results are deterministic, attributable, and independent of the verified entity. The in-library cryptographic construction (pinned roots, PKIX, issuer-CA-bound Step 7, canonicaliser-covered receipt signing) is fully in place; the **operational** controls (mTLS, persistent registry, rate limiting, role differentiation, NCA's production signing certificate) are modular extensions that a deployer activates via configuration or extends in code. None of the residual risks above weaken the central claim — each delimits the scope of what the reference code alone proves vs. what a production deployment adds on top.
