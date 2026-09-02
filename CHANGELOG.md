# Changelog — gatekeeper

This file starts at 1.4.0. Earlier releases are documented in the git history and in `CROSS_REFERENCE.md`.

## 1.4.0

Every item below is a defect that was present in 1.3.0. Where a defect had a reason for surviving review, that reason is stated rather than left out.

### Start-up blocker

- **`application.yaml` had two `audit:` keys** (lines 63–64). SnakeYAML rejects a duplicate mapping key, so 1.3.0 could not start at all under the default profile. The test suite was green throughout, because no test loaded the Spring context: every test used `MockMvcBuilders.standaloneSetup` or constructed its collaborators directly, and neither reads `application.yaml`. The duplicate is removed, and `ApplicationContextLoadsTest` / `NcaProfileContextLoadsTest` now boot the real context from the real configuration files so a configuration error fails in CI instead of on a host. The other two profile files were checked for duplicate keys as well; they had none.

### Wire format — breaking, cross-repo

- **`confirmationNonce` is now inside the signed canonical receipt form, and the canonical version marker moves from `v1` to `v2`.** In 1.3.0 the nonce was excluded on the stated reasoning that it was "operational anti-replay, not a decision-relevant field". That reasoning does not survive contact with the threat it addresses: the nonce decides who may close the Step 7 loop, the receipt is the only place the financial entity receives it, and an unsigned field in a signed document can be rewritten in transit without breaking the signature. An intermediary could substitute a nonce of its own choosing undetectably. The field now sits directly after `verificationId` in the canonical form.

  **The `hsm` repository must be upgraded in lock-step.** It recomputes these bytes to verify receipt signatures and carries the same golden literal in its own `WireFormatGoldenBytesTest`. A gatekeeper on `v2` and a financial entity on `v1` will not agree on any receipt — every signature verification fails, in both directions. The golden literal in this repo's `WireFormatGoldenBytesTest` has been updated accordingly and now pins a non-empty nonce, so the field's position is actually locked rather than nominally present.

### Security

- **Settlement compliance now follows the Step 7 outcome.** `SignatureVerificationService` read only `RegistryEntry.compliant`, which records the Step 3 attestation verdict and is never rewritten. The confirmation outcome lives in `status`. A certificate whose confirmation had been recorded as `ANOMALY_PUBLIC_KEY_MISMATCH` — the issuer produced a certificate over a key that was not the attested one — therefore kept returning `compliant=true` at `POST /api/v1/verify` and kept settling payments. That is precisely the circumvention the Step 7 loop exists to detect, so the loop was detecting it and the settlement path was ignoring the detection. An entry now settles only if it was compliant *and* its status is neither an `ANOMALY_*` value nor `REJECTED_NOT_ISSUED`. An entry still awaiting confirmation (`status == null`) settles, since that is the ordinary state between issuance and confirmation.

- **Step 7 is bound to the jurisdiction in the path.** `POST /v1/attestation/{countryCode}/confirm` took the country code and discarded it: the registry lookup was by `verificationId` alone, so a confirmation posted to `/DE/confirm` could close the loop on a Swedish entry — across a boundary that DORA Article 55 professional secrecy runs along. The 1.3.0 fix to the *registry query* endpoints (which had the same defect) did not extend to confirm. `ApprovalRegistry.lookup(verificationId, countryCode)` is now the lookup used.

- **Step 7 is bound to the client that performed the verification.** Nothing tied a confirmation to a caller: any client holding a `verificationId` and its nonce could confirm another entity's verification. The mTLS principal resolved at verify time is stored on the registry entry and required to match at confirm. When `gatekeeper.security.mtls.enabled=false` there is no authenticated caller to bind to, so the check is skipped and a startup WARN says so, in the same manner as the existing permissive warnings. Entries carrying no bound principal (registered before this release, or under the permissive chain) stay confirmable — failing them closed would make every entry in an upgraded deployment's journal permanently unconfirmable.

- **A jurisdiction or client mismatch is reported as an unknown `verificationId`, with HTTP 404.** Distinct answers would turn the endpoint into an oracle for the existence of entries the caller may not see. This also aligns the endpoint with its own documented contract: 1.3.0 answered an unknown `verificationId` with 200 and an anomaly body while the OpenAPI annotation said 404.

- **The confirmation nonce is now checked and consumed atomically.** `confirm` read the nonce, compared it, and then cleared it, with no lock across the three statements, in both registry implementations. Two confirmations arriving at once with the same nonce both read a non-null value and both succeeded. Single-use is the entire property the nonce provides; "usually single-use" is not a weaker version of it. `InMemoryApprovalRegistry` synchronises the operation; `AppendOnlyFileApprovalRegistry` runs it under the existing write lock, which `appendOp` re-enters.

- **A journal write failure no longer burns the nonce.** `AppendOnlyFileApprovalRegistry` cleared the in-memory nonce *before* the journal append. If the append then failed, the caller received a 5xx telling it to retry, and the retry failed the nonce check against a now-null expected value: the FE could never close the loop for that `verificationId` again. Consumption is ordered after the append. Journal replay clears the nonce too, since a journalled `CONFIRM` is proof it was spent.

- **`GET /v1/gatekeeper/health` requires the `SUPERVISOR` role.** It was in the `permitAll` list next to `/keys` and `/anchor`. Those two are evidence a relying party needs in order to verify a receipt without a client certificate; health is not — it reports chain length, head sequence number and signing mode, i.e. how much supervisory activity the gatekeeper has recorded. Liveness probes use `/v1/attestation/health`, which returns a constant string and stays public.

- **Constant-time fingerprint comparison at Step 7.** `VerificationService.confirmIssuance` compared the submitted certificate's public-key fingerprint to the attested one with `String.equals`. The values are public rather than secret, but the comparison decides whether an issued certificate is accepted as the attested one, and `String.equals` leaks a matching-prefix length that a caller submitting crafted certificates can measure. Now `MessageDigest.isEqual` over UTF-8 bytes, as everywhere else in the codebase.

- **Batch elements are validated.** `POST /v1/attestation/{cc}/verify/batch` declared `@Valid @RequestBody List<VerificationRequest>`. Bean Validation does not descend into container elements from that, so every field constraint on `VerificationRequest` — the `@NotBlank` public key, the `@Size` ceilings on the attestation blobs — was enforced for a single verify and ignored for all 200 elements of a batch. The type argument now carries `@Valid`, which Spring's `HandlerMethodValidator` acts on.

### Availability

- **Chain integrity is no longer recomputed per health request, and no longer under the append lock.** `verifyChainIntegrity()` is O(chain length) with one RSA verification per entry, and it held `appendLock` for the whole walk. `GET /v1/gatekeeper/health` called it on every request, unauthenticated and exempt from rate limiting — so any caller could stall every concurrent verification, at a cost that grows for the whole DORA Article 28(6) five-year retention window. The walk now takes a snapshot under the lock and releases it before verifying, and `AuditLog.cachedIntegrityStatus()` recomputes at most once per `gatekeeper.audit.integrity-check-interval-seconds` (new; default 300). Health returns the cached result together with `chainCheckedAt`, so a monitoring system can see how stale the answer is.

- **`/v1/gatekeeper/**` is rate limited.** The interceptor exempted any path ending in `/health` and was never registered for `/v1/gatekeeper` at all, so `/keys`, `/anchor` (which signs on every call) and `/health` were unlimited. They now use the registry bucket; the deployment still configures exactly five buckets.

### Configuration

- **OpenAPI document and Swagger UI are off unless the `dev` profile is active.** `springdoc.api-docs.enabled` and `springdoc.swagger-ui.enabled` are `false` in every shipped configuration file (`application.yaml`, `application-nca.yaml`, `application-eba.yaml`); the new `application-dev.yaml` turns them on for local use. Neither endpoint has a run-time function in this service, and swagger-ui is a third-party JavaScript application whose vulnerabilities (see Dependencies) would otherwise be part of the deployed surface. The OpenAPI path moves from `/api-docs` to `/v3/api-docs`, which is the path `SecurityConfig` and `RateLimitInterceptor` were already matching — the two had disagreed.

- New key `gatekeeper.audit.integrity-check-interval-seconds` (default 300, env `GATEKEEPER_INTEGRITY_CHECK_INTERVAL_SECONDS`), set in `application.yaml` and `application-nca.yaml`.

### API changes

- `HealthStatus` gains `chainCheckedAt`.
- `RegistryEntry` gains `verificationPrincipal`.
- `ApprovalRegistry.register(...)` takes the verifying principal as a tenth argument; the nine-argument form remains as a default method that binds no principal.
- `ApprovalRegistry.lookup(verificationId, countryCode)` added as a default method.
- `AuditLog.cachedIntegrityStatus()` and `AuditLog.IntegrityStatus` added; the default implementation computes on every call, so existing test doubles keep working.
- `VerificationService.confirmIssuance` takes the country code.
- `POST /v1/attestation/{cc}/confirm` answers 404 where it previously answered 200 with `ANOMALY_UNKNOWN_VERIFICATION`.

### Dependencies

- Spring Boot parent 4.1.1 (Spring Framework 7, Spring Security 7), Lombok 1.18.48, springdoc-openapi 3.1.0, BouncyCastle 1.85 with `bcprov-jdk18on` 1.85.2.
- `org.webjars:swagger-ui` is pinned to 5.32.14. springdoc 3.1.0 ships 5.32.11, which bundles DOMPurify 3.4.12 (CVE-2026-75838). The earlier suppression for DOMPurify 3.3.2 (CVE-2026-41238/41239/41240) no longer matches anything and has been removed from `.owasp-suppressions.xml`; the file is now empty.
- `tomcat.version` is overridden to 11.0.25. Boot 4.1.1 manages 11.0.24, for which OWASP Dependency-Check reports eleven CVEs (CVE-2026-65182, -65183, -65637, -65905, -65927, -66299, -66422, -68525, -68569, -68763, -73180); all are listed as fixed in Tomcat 11.0.25 (2026-08-18). The override is to be removed once the parent manages 11.0.25 or later.
- `dependency-check-maven` stays at 12.2.2. 13.0.0 rejects an absent NVD API key as an invalid key of length 0 (jeremylong/DependencyCheck#8715), and this project is scanned without a key. The `<nvdApiKey>` configuration has been removed for the same reason.

### Documentation

- `PEER_REVIEW_GUIDE.md`, `FORENSIC_INSPECTION.md`, `SUPERVISORY_OPERATIONS.md` and `DEPLOYMENT.md` updated where this release invalidated them: the canonical version marker, the cached integrity result behind `chainIntact`, and `/v1/gatekeeper/health` no longer being a public endpoint.
- `THREAT_MODEL.md`, `CROSS_REFERENCE.md` and `README.md` corrected where they described the code as it was planned rather than as it is: rate limiting listed as a GAP when five buckets ship, the hash chain listed as a GAP when it is implemented, a `REFERENCE-DIGEST:` prefix that does not exist, `FileChannel.force(true)` where the code opens `rwd` and calls `getFD().sync()`, an `O_APPEND` claim for a `seek(length)` write, wrong audit operation labels and response field names, and a stale jar version in the run instructions. The known limitation that registry mutation and audit append are *not* atomic with respect to each other is now written down rather than claimed as a mitigation.
