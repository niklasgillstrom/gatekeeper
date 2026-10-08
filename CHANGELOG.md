# Changelog — gatekeeper

This file starts at 1.4.0. Earlier releases are documented in the git history and in `CROSS_REFERENCE.md`.

## 1.6.0 (2026-10-08)

### Security

- **The attestation evidence is kept.** The registry entry now stores the
  verification request as submitted (`submission`): public key, attestation
  data, signature, chain and parties. Until now only its digest was kept, in
  the audit log, so the supervisor depended on the supervised financial
  entity for the evidence and could not repeat a verification, for instance
  after a verifier was corrected. `VerificationService.requestDigestBase64`
  recomputes the audited digest from a stored submission.
  `SUPERVISORY_OPERATIONS.md` §3.5 step 6 uses it. Tests:
  `PartiesRecordedTest.theAttestationEvidenceIsKeptAndMatchesTheAuditedDigest`,
  `AppendOnlyFileApprovalRegistryJournalTest.theSubmissionIsJournalledAndReplayedWithTheSameDigest`.
- **Customer and technical supplier recorded and signed.** A verification
  request now carries `customerOrganisationNumber` and `customerSwishNumber`
  and, when a technical supplier holds the key, `supplierIdentifier` (its
  organisation number) and the new `supplierNumber` (its 987 number). A
  customer without a technical supplier has no supplier fields. The registry
  stores them (also in the journal), the receipt echoes them, and the
  request digest in the audit log covers them, so the supervisor can compare
  who holds each verified key with the banks' customer registers
  (`SUPERVISORY_OPERATIONS.md` §3.5, new source 5 and step 5). **Breaking:**
  the receipt canonical form is `v3` (customer and supplier fields inside the
  signed form; hsm 1.6.0 moves in step). `v2` receipts stay verifiable with
  `ReceiptCanonicalizer.canonicalize(receipt, "v2")`. Bean Validation: the
  customer's Swish number must be 123…, the supplier number 987…, and a
  supplier number needs a supplier identifier. Tests: `PartiesRecordedTest`
  (4), `AppendOnlyFileApprovalRegistryJournalTest.thePartiesAreJournalledAndReplayed`,
  `WireFormatGoldenBytesTest.thePreviousVersionIsTheFormReleasesBefore160Signed`
  and the v3 golden bytes.
- **The nonce-mismatch refusal of a confirmation was unsigned.** Every
  other confirmation response carries `signature` and `signingCertificate`,
  as this changelog and the README say, but the 400 answer to a replayed
  or wrong `confirmationNonce` was built in the controller without them.
  The service now builds, signs and audits it, and the controller returns
  it with 400. Tests: `ConfirmBindingTest.theNonceMismatchRefusalIsSigned`,
  `VerificationControllerConfirmScopeTest`.
- **Documentation aligned with the code** (a review of every document
  against the code): settlement lookup is by the issued certificate, not by
  fingerprint, so an entry awaiting Step 7 or recorded as an anomaly answers
  `CERT_NOT_FOUND`; under the `nca` profile even the endpoints that need no
  role require a client certificate at the TLS layer; mid-file audit-log
  corruption stops start-up while a chain that does not verify only warns;
  the receipt digest covers the canonical form, not the JSON; the approval
  registry cannot be rebuilt from the audit log; three roles, not two; no
  nonce TTL; the receipt canonical form is `v2`; the issuer-CA validator
  falls back to the bundled reference bundle; the `eba` profile has no
  endpoints of its own; the unused `swish.signatory-rights` block is removed
  from `application-nca.yaml`; the NVD key is passed with
  `-DnvdApiKeyEnvironmentVariable` (the plugin never read `-Dnvd.api.key`);
  stale test names, vendor counts and the `TODO-NCA` marker corrected.

- **Build:** Jackson 3.1.7 and 2.21.7 instead of the 3.1.5 and 2.21.5 that
  Spring Boot 4.1.1 manages (CVE-2026-83557, listed as fixed in 3.1.6 and
  2.21.6); `project.build.outputTimestamp`, so the same commit builds to a
  byte-identical jar (two builds of railgate compared: different hashes
  without it, identical with it); and the OWASP Dependency-Check scan moved
  to the `owasp` profile (`mvn -Powasp verify`), so a build without
  network access or NVD key can run the tests.

- **End-to-end test (`e2e/`) follows the 1.6.0 services.** hsm and railgate
  now refuse to start without TLS, so the local run sets their development
  overrides (`swish.gatekeeper.allow-insecure-http`,
  `railgate.server.allow-insecure-http`); the BankID binding it prints is
  hsm's mandate, `hsm-mandate:v1;org=…;swish=…;count=1`; and its settlement references are
  UETRs (36 characters) instead of `e2e-<uuid>` (40), which railgate now
  refuses. Run against the three 1.6.0 builds: 8 tests pass, and the 6 that
  need a real BankID signature or the HSM's private key are skipped, as
  `e2e/README.md` describes.
- **`SecurosysVerifier.verifyChain` returned true for any input.** It is
  not called by the verification flow, but it is the interface's chain
  check; it now runs the same PKIX validation under the pinned root
  (`SecurosysVerifierTest.verifyChainValidatesAgainstThePinnedRoot`).
- **`RequestSizeLimitFilter` had no tests.** It now has four
  (`RequestSizeLimitFilterTest`): a declared length above the cap is 413
  before the body is read, a length at the cap passes, a chunked body is
  counted while read, and a non-positive cap is refused at start-up. Four of
  five guard mutants are killed; the fifth (`declared >= 0` to `>= 1`) only
  routes an empty body through the counting wrapper and is equivalent.

- **Settlement resolves the registry entry through the issued certificate.**
  `SignatureVerificationService` looked the entry up by public-key
  fingerprint and, when the request carried a certificate PEM, never compared
  that PEM with anything. Two consequences, both reproduced by tests that
  fail against 1.5.0:
  - Any FE could make another FE's settlements fail. It confirmed its own
    verification with the victim's public certificate; the resulting
    `ANOMALY_PUBLIC_KEY_MISMATCH` entry carried the victim's key fingerprint,
    was the newest match, and every later settlement of the victim returned
    `CERT_NON_COMPLIANT` with the attacker's `auditEntryId`.
  - A key that was verified but never issued settled with a self-signed
    certificate, because an entry awaiting Step 7 (`status == null`) or
    confirmed `VERIFIED_NOT_ISSUED` counted as settlement-compliant.

  The entry is now resolved by `(serial, issuer)` among certificates stored at
  a confirmation that ended in `VERIFIED_AND_ISSUED`, a supplied PEM must be
  byte-identical to that stored certificate, and only `VERIFIED_AND_ISSUED`
  settles. This reverses the 1.5.0 decision that an entry awaiting Step 7
  keeps settling; hsm's `INTEGRATION_GUIDE.md` already requires that a
  certificate is not delivered before its confirmation completes.
- **Certificate validity at settlement.** No validity period was checked;
  an expired certificate settled. The stored certificate must now be within
  its validity period at the time of the call; otherwise the answer is the new
  reason `CERT_EXPIRED` (railgate maps an unknown reason to
  `CERT_NON_COMPLIANT`, so it denies either way).
- **Order of checks.** Malformed digest or signature input is reported as
  `MALFORMED_INPUT` first; the certificate is then resolved before the
  signature is checked, so `CERT_NOT_FOUND` now comes with
  `signatureValid=false`.
- Tests: `SettlementLookupTest` (5, against the real
  `InMemoryApprovalRegistry`, all failing against 1.5.0). The fake registries
  in `SignatureVerificationServiceTest` and
  `SignatureVerificationControllerTest` now look entries up by issued
  certificate, as the real ones do;
  `allowsSettlementWhileStillAwaitingConfirmation` became
  `deniesSettlementWhileStillAwaitingConfirmation`, and
  `looksUpByActualPublicKeyFingerprintWhenPrimaryFingerprintDiffers` became
  `looksUpByIssuedCertificateNotByFingerprint`.
- **mTLS principal is read from the encoded subject.** The principal was
  taken with a regular expression (`principal-regex`, default
  `CN=(.*?)(?:,|$)`) over the RFC 2253 string. It stopped at an escaped
  comma, so `CN=Acme AB\, Stockholm` and `CN=Acme AB\, Malmo` both became
  `Acme AB\` and shared one identity for confirm binding, rate limiting and
  the audit log; it fell back to the whole DN when the attribute was missing,
  so role patterns were matched against a DN; and the documented
  `SERIALNUMBER=(.*?)` never matched, because `X500Principal.getName()`
  renders that attribute as `2.5.4.5=#13..` hex. The new
  `gatekeeper.security.mtls.principal-attribute` (default `CN`; `SERIALNUMBER`
  or a dotted OID also work) names the attribute; its exact value is the
  principal, and a subject in which it is missing or repeated is not
  authenticated. `principal-regex` was removed; setting it fails start-up so
  that a SERIALNUMBER deployment cannot silently fall back to CN. Tests:
  `SubjectAttributePrincipalExtractorTest` (5).
- **Yubico: missing or critical capabilities extension.** The fix hsm made
  in 1.4.0 had not been ported. `YubicoVerifier` read only non-critical
  extensions and did not notice a missing capabilities extension
  (1.3.6.1.4.1.41482.4.5), so an attestation without it reported the key as
  not exportable although nothing had been parsed. Both critical and
  non-critical extensions are now read, and a missing capabilities extension
  adds `YUBICO_CAPABILITIES_MISSING`. Tests:
  `YubicoVerifierTest.missingCapabilitiesExtensionIsRejected` and
  `attestationExtensionsMarkedCriticalAreRead`, both failing before.
- **Signed confirmation response.** The Step-7 response
  (`IssuanceConfirmationResponse`) was unsigned: anyone able to answer the
  confirm call (a TLS-terminating proxy, a wrong host) could return
  `loopClosed=true` with the right `verificationId`, and hsm recorded the
  supervisory loop as closed. Every confirmation response, including the
  unknown-verification anomaly, now carries `signature` and
  `signingCertificate`, made with the receipt key over the new
  `ConfirmationCanonicalizer` form `c1`. hsm 1.6.0 verifies it; hsm 1.5.0
  ignores the two fields. Tests: `ConfirmationCanonicalizerGoldenBytesTest`
  (2; the literal is identical in hsm) and
  `IssuanceConfirmationCertificateTest.confirmationResponseIsSignedOverItsCanonicalBytes`.
- **Securosys key origin is read from the attestation.** `SecurosysVerifier`
  never read `<private_key creation="...">`, and `VerificationService` set
  `generatedOnDevice` from `never_extractable` and `always_sensitive`, which
  are not origin attributes. The root element must now be `private_key` with
  `creation="generated"` (`SECUROSYS_KEY_NOT_GENERATED` otherwise), and
  `generatedOnDevice` is taken from that attribute. The verifier is again
  identical to hsm's. Tests: three in `SecurosysVerifierTest`, the two
  rejections failing before the change. PSS-signed Securosys attestations
  remain unsupported and are rejected.
- **Azure and Google: Marvell parser rebuilt from the vendors' tools.** The
  verifiers parsed a format of their own that matches neither vendor's tool,
  and `AzureHsmVerifier` took the public key from the unsigned JWK in the
  JSON. `MarvellAttestation`, identical to hsm's, ports Microsoft's
  MIT-licensed parser and validator and Google's owner-chain check; the key is
  bound only through the modulus or EKCV in the signed blob (Marvell's
  published attestation page and `verify_pubkey.py`), and
  EXTRACTABLE=false, NEVER_EXTRACTABLE=true and LOCAL=true are required. The
  Marvell roots are the two in Microsoft's validator (the 2015 root expired
  2025-11-16). No real attestation has been run through it, so both verifiers
  add `MARVELL_FORMAT_UNCONFIRMED` and neither vendor reaches COMPLIANT, as
  before. Tests: `MarvellAttestationTest` (12), `AzureHsmVerifierTest` (6,
  replacing 2), `GoogleCloudHsmVerifierTest` (8, replacing 3).
- **Physical Marvell LiquidSecurity HSMs as a fifth vendor (`MARVELL`).**
  The hardware behind Azure and Google signs its own key attestation when a
  key is generated. `MarvellHsmVerifier` checks the manufacturer chain
  (pinned Marvell roots → card → partition), the signature and the same key
  evidence as the cloud verifiers. Never valid until a real attestation
  confirms the format (`MARVELL_FORMAT_UNCONFIRMED`). Tests:
  `MarvellHsmVerifierTest` (5).
- **Thales Luna as a sixth vendor (`THALES`).** A Luna HSM issues a Public
  Key Confirmation (PKC) only for keys it generated and that cannot leave a
  Luna HSM (Thales documentation). `ThalesLunaVerifier` checks the PKC chain
  as Thales's MIT-licensed `luna-pkc-validator` does (signature, issuer, EKU
  per position, CA flag, validity) under the pinned Chrysalis-ITS Root key,
  and that the Proof of Origin key is the CSR key. Two published copies of
  the root (serials 804500000007 and 80450000000D) carry that key. Thales's
  own PKC and CSR test vector verifies, so this vendor is not behind a
  format gate. Tests: `ThalesLunaVerifierTest` (8; all five guard mutants
  are killed).
  `AttestationSignatureValidityTest.genuineThalesLunaPkcSetsEveryArticleBit`
  shows the test vector reaching COMPLIANT.
- **Crypto4A QASM as a seventh vendor (`CRYPTO4A`).** `Crypto4AVerifier`
  follows Crypto4A's attestation specification (C4A-302-0043): every
  signature block (ECDSA P-384 and HSS/LMS) must verify over the DER claims,
  carry the attestation EKU and chain to the pinned C4A_RCA key, as
  `spa-attest verify` checks them. The key's `key-spki` must be the CSR key
  and the same object must carry private-key class, `key-is-confined`,
  `key-is-hardware-generated` and `key-never-extracted`, plus
  `qasm-certified-production` and `attestation-keys-are-unique`. The PKI
  Consortium's published QASM message verifies, both signatures included.
  Its OIDs (`1.3.6.1.4.1.39901.6.2.x`) match Crypto4A's specification; the
  PKI Consortium page lists them one level too deep. Tests:
  `Crypto4AVerifierTest` (10; all eleven guard mutants are killed).
  `AttestationSignatureValidityTest.genuineCrypto4AMessageSetsEveryArticleBit`
  shows the message reaching COMPLIANT.
- **Fortanix DSM as an eighth vendor (`FORTANIX`).** `FortanixVerifier`
  follows Fortanix's "Verifying Key Attestation Statements": the Key
  Attestation Authority certificate by PKIX with Fortanix's attestation
  policy to the pinned Fortanix root, its EKU and Key Usage; the statement
  signed by the authority, naming it as issuer, with no unknown critical
  extension and a signing time within the authority's validity and not in
  the future; the statement's key must be the CSR key and carry
  `fortanixKeyGeneratedInDSM` and `fortanixKeyNeverExportable`. Validation
  happens at the signing time, as Fortanix prescribes for its one-month
  authority certificates. The sample in Fortanix's documentation verifies.
  Tests: `FortanixVerifierTest` (7; all twelve guard mutants are killed).
  `AttestationSignatureValidityTest.genuineFortanixStatementSetsEveryArticleBit`
  shows the sample reaching COMPLIANT.
- **Key policy: RSA-4096 only by default.** Gatekeeper did not check the key
  itself, so any key with a valid attestation was COMPLIANT, including the
  RSA-2048 and EC P-256 keys of the Thales, Crypto4A and Fortanix samples.
  Swish signing keys are RSA-4096, which hsm already enforces at the CSR.
  `KeyPolicy` (`gatekeeper.key-policy.allowed-keys`, default `RSA-4096`) now
  makes any other key NON-COMPLIANT with `KEY_NOT_ALLOWED`; the attestation
  is still verified and reported, the article bits describe it, and Article
  28(1)(a) and the summary follow the overall finding. Tests: `KeyPolicyTest`,
  `AttestationSignatureValidityTest.defaultPolicyRefusesEveryKeyButRsa4096`
  (the three samples, each refused with only the key error) and
  `keyPolicyFailureIsListedWithAttestationFailures`; the sample tests now run
  under a policy that also allows the samples' keys.
- **Entrust nShield as a ninth vendor (`ENTRUST`).** `NShieldVerifier`, the
  same as hsm's: warrant from the pinned KWARN-1 key, module state, world
  binding and key generation certificates, and the generation-time ACL; a
  key the Administrator Card Set can recover is refused under Art. 9(3)(d).
  Only `ModuleInformation` warrants are accepted: Entrust states that
  `FieldUpgradeModuleInformation` certificates depend on legacy DSA-1024
  signatures, which NIST SP 800-131A no longer allows to be made. Tests:
  `NShieldVerifierTest` (25; all 75 guard mutants are killed in hsm) and
  `AttestationSignatureValidityTest.entrustsFieldUpgradeBundlesSetNoArticleBit`
  (Entrust's two examples carry such warrants and set no article bit).

### Tests

- **Mutation testing.** A `pit` profile (`mvn -Ppit test-compile
  org.pitest:pitest-maven:mutationCoverage`, PIT 1.30.0, `-Dpit.threads=N`)
  runs over every production class and fails below 100 %. First run 1,682
  of 2,278 detected; now 2,203 of 2,203 (2,194 killed, 9 timed out). New
  tests cover the rate limiter per request and its sweep on a controllable
  clock, a registry contract run against both implementations, every vendor
  branch of `VerificationService`, the audit log's locking, loading,
  permissions and integrity cache, the controllers, the mTLS role matrix of
  the `nca` profile, and mutation tests for all nine verifiers. Redundant
  constructs whose mutants no test could kill were removed, not suppressed
  (see `PEER_REVIEW_GUIDE.md`, Mutation testing). `java.io.FileDescriptor`
  is in `avoidCallsTo`: a removed fsync is observable only by a power cut.
- **`application-nca.yaml`** gains an illustrative `SETTLEMENT_RAIL` role
  mapping (`^RAIL-.*$|^railgate-.*$`). The profile mapped no principal to
  `SETTLEMENT_RAIL`, so railgate could not reach `/api/v1/verify` under it.

## 1.5.0

Every item below is a defect that was present in 1.4.0. As before, where a defect had a reason for surviving review, that reason is stated. The test suite now runs 160 test executions (each parameterised test counted once per registry implementation), 7 of them from the documentation-versus-code review whose findings are folded into the sections below, all green under `mvn verify`; the regression test for each defect fails against the 1.4.0 code, either on its assertions or, where it calls a method this release adds, at compilation. A few controls next to them pass on 1.4.0 by design — the unmodified Securosys attestation in `AttestationSignatureValidityTest`, the missing-intermediate case in `IssuanceConfirmationCertificateTest` — to show that a fix did not simply turn everything off.

### Deployment — breaking, cross-repo

- **gatekeeper 1.5.0 must be deployed together with hsm 1.5.0 and railgate 1.5.0.** The settlement contract between railgate and `POST /api/v1/verify` changed (next section). A gatekeeper older than 1.5.0 answers every railgate request `MALFORMED_INPUT`.

### Settlement

- **railgate's settlement requests could never succeed.** railgate sends exactly four fields — `certSerial`, `issuerDn`, `digestHex`, `signatureBase64`. `SignatureVerificationService` required `signingCertificatePem` and answered `MALFORMED_INPUT` without it, so every real settlement was default-denied. The `SignatureVerificationRequest` javadoc described a lookup "under `(certSerial, issuerDn)`" of "the certificate stored at Step-7 confirmation", but nothing stored a certificate at Step 7 and nothing looked one up. It survived review because each side was tested against its own picture of the other: gatekeeper's tests always supplied the PEM — one of them, `deniesWhenSigningCertificatePemIsMissing`, asserted the defect as the expected behaviour — and railgate's tests stub the gatekeeper. Now a Step 7 confirmation that ends in `VERIFIED_AND_ISSUED` stores the issued certificate, its serial number and its issuer DN on the registry entry; `AppendOnlyFileApprovalRegistry` writes them into the `CONFIRM` journal line, and replays lines without them as before. A request without a PEM but with `certSerial` and `issuerDn` is resolved against the stored certificates: `certSerial` is hexadecimal, case-insensitive, optional `0x`, compared as `new BigInteger(hex, 16)` against the certificate's serial; `issuerDn` is compared with `X500Principal.equals`. No match is `CERT_NOT_FOUND` (which railgate passes through); an unparseable serial or DN is `MALFORMED_INPUT`. A supplied PEM is used as before. One consequence to be aware of: a four-field request for a certificate whose Step 7 confirmation has not yet arrived is `CERT_NOT_FOUND`, whereas the PEM form settles in that state. Tests: `SettlementCertificateLookupTest` (Step 7 stores the certificate; four-field request verifies end to end including the `SETTLEMENT_VERIFY` audit entry; unknown serial and issuer mismatch give `CERT_NOT_FOUND`; the file-backed registry keeps the certificate across replay; 1.4.0-format `CONFIRM` lines still replay). The old `deniesWhenSigningCertificatePemIsMissing` is replaced by a `MALFORMED_INPUT` case without serial and issuer and a `CERT_NOT_FOUND` case with them.

- **Journal replay of `REGISTER` lines.** `RegistryEntry` had only the package-private all-args constructor Lombok's `@Builder` generates, and `AppendOnlyFileApprovalRegistry` deserialises it with a plain Jackson 2 `ObjectMapper`, which cannot use that constructor without the parameter-names module. As far as can be read from the code, every `REGISTER` line would therefore have been skipped as malformed on restart, and every `CONFIRM` after it as referring to an unknown entry. This was found while writing the replay test above and was not reproduced by running 1.4.0; no earlier test replayed a journal. `RegistryEntry` now also has `@NoArgsConstructor` and `@AllArgsConstructor`, and replay is covered by the two tests above.

- **`RSASSA-PSS` was accepted but could not verify anything.** It is on the algorithm whitelist, but the JCA `RSASSA-PSS` signature refuses to verify until its parameters are set, and they never were, so every PSS signature came back `SIGNATURE_INVALID`. The README described PSS as supported. Nothing tested a PSS signature. The endpoint now sets one fixed parameter set — SHA-512, MGF1 with SHA-512, a 64-byte salt, trailer field 1 — and a PSS signature made with other parameters still does not verify. Swish Utbetalning does not use PSS: payouts are signed with RSA PKCS#1 v1.5 over the SHA-512 digest of the payload, which is the default `SHA512withRSA`, so the settlement path from railgate is unaffected by the PSS parameter choice. Test: `SignatureVerificationServiceTest.rsassaPssSignatureVerifiesWithSha512Mgf1AndA64ByteSalt`.

- **`auditEntryId` did not identify the audit entry of a settlement decision.** The name, railgate's `THREAT_MODEL.md` ("references the gatekeeper audit entry") and `SUPERVISORY_OPERATIONS.md` §3.6 (reconcile the rail's decisions "with the gatekeeper audit-entry references returned in the `auditEntryId` field") all treated it as a reference to the settlement's own audit entry. It is the registry `verificationId` the verdict was read from: shared by every settlement against the same certificate and by the issuance's `VERIFY` and `CONFIRM` entries, and `null` on `CERT_NOT_FOUND`, which is the settlement a supervisor most wants to trace. The response now also carries `auditEntryHashHex`, the `thisEntryHashHex` of the `SETTLEMENT_VERIFY` entry written for the call, on every `200` response including `CERT_NOT_FOUND`. `auditEntryId` is unchanged, so the contract is backward-compatible; the new field is set after the append and is therefore not covered by the entry's `receiptDigestBase64`. railgate 1.5.0 stores it. Test: `SignatureVerificationServiceTest.responseCarriesTheHashOfItsOwnSettlementAuditEntry`.

### Attestation verification

- **YubiHSM capabilities were read in the wrong byte order.** The capabilities extension (`1.3.6.1.4.1.41482.4.5`) was folded little-endian. Yubico's reference implementation reads it big-endian (python-yubihsm `objects.py`, `int.from_bytes(..., "big")`), and the two export bits the verifier checks — `exportable-under-wrap` (bit 16) and `export-wrapped` (bit 12) — therefore landed at bits 40 and 52 of the misread value. A key that could be exported under wrap was reported non-exportable and accepted. It survived because the only real device data, the reference YubiHSM 2, has capabilities `00 00 00 04 00 00 06 60`, which sets neither bit in either byte order, and no test put a byte sequence through the parser where the order mattered. The fold is now big-endian, in the package-private `YubicoVerifier.parseCapabilities`. Tests: `YubicoVerifierTest.capabilitiesByteOrder*` (the reference-device bytes, bit 16 and bit 12, directly and inside an attestation certificate) and `realYubiHsm2AttestationIsValidGeneratedAndNotExportable`, which runs the real attestation from `hsm/examples/yubico` (copied to `src/test/resources/fixtures/yubico`).

- **A YubiHSM key that had been exported and imported again was accepted as generated on the device.** Origin was parsed as three independent flags, and validity required only `generated`. Yubico defines `IMPORTED_WRAPPED` (`0x10`) as set in combination with `GENERATED` or `IMPORTED`, so origin `0x11` is a key generated on some device, exported under wrap and re-imported — it has existed outside this HSM's boundary. `getKeyOrigin()` also checked `generated` first and reported `0x11` as `generated`. It survived because no test or fixture carried an origin other than `0x01`. Origin is now rejected when `imported` or `imported_wrapped` is set, and `keyOrigin` reports `imported_wrapped` / `imported` ahead of `generated`. Tests: `YubicoVerifierTest.originGeneratedIsAccepted`, `originGeneratedAndImportedWrappedIsRejected`, `originGeneratedAndImportedWrappedInAnAttestationCertificateIsRejected`.

- **The DORA article bits in a signed receipt ignored whether the attestation signature verified.** `buildDoraCompliance` derived Articles 5(2)(b), 9(3)(c) and the others from chain validity, key match and exportability only, and `generatedOnDevice` was hard-coded `true` for Securosys. A genuine Securosys chain with an XML whose signature did not verify — attributes an attacker can write freely — therefore produced a receipt, signed by the NCA, asserting five of the six article bits. `compliant` was `false`, because the verifier's error list was non-empty, and that is what the tests looked at; no test read the article bits of a failed verification. Every article bit and `compliant` now require a valid attestation signature (the XML signature for Securosys, the signature over the attestation data for Azure and Google, the PKIX-validated attestation certificate for Yubico), and Securosys `generatedOnDevice` is derived from the verified `never_extractable` and `always_sensitive` attributes, only when the signature is valid. Tests: `AttestationSignatureValidityTest`, which runs the real Securosys attestation from `hsm/examples/securosys` (copied to `src/test/resources/fixtures/securosys`) once as issued and once with one character of the XML changed.

- **A non-extractable Google Cloud HSM key was reported as generated on the device.** `GoogleCloudHsmVerifier` set `keyOrigin="generated"` whenever the extractability attribute was present and false. Non-extractability says nothing about origin — a key imported into the HSM can be non-extractable — and the TLV parser reads no origin attribute, so an imported key satisfied `generatedOnDevice`. It survived because no Google test carried an extractability attribute. Origin is now always `unverified`, and an error is always added — `GOOGLE_KEY_ORIGIN_UNVERIFIED`, or as before `GOOGLE_ATTRIBUTES_UNVERIFIED` when the extractability attribute is missing — so a Google attestation cannot end in COMPLIANT, as an Azure one already could not. The same inference remains in hsm's copy of the verifier, where `keyOrigin` is reported but does not decide validity. Test: `GoogleCloudHsmVerifierTest.nonExtractableKeyIsNotReportedAsGeneratedOnDevice`.

### Step 7 confirmation

- **A confirmation reporting issuance without a certificate closed the loop.** `issued=true` with no `signingCertificatePem` skipped the certificate checks, added no anomaly, and returned `loopClosed=true` next to `registryStatus=ANOMALY_PUBLIC_KEY_MISMATCH`. It survived because every Step 7 test used either a non-issuance notice or a certificate. It is now an anomaly, so the loop stays open and the status and `loopClosed` agree. Tests: `IssuanceConfirmationCertificateTest.issuedWithoutCertificateIsAnAnomalyAndLeavesTheLoopOpen` and `issuedWithBlankCertificateIsAnAnomalyAndLeavesTheLoopOpen`.

- **Issuer-CA validation could not use intermediates, so a real Swish certificate could never confirm.** `IssuerCaValidator.validate` built a `CertPath` of the leaf alone, and `VerificationService` parsed only the first certificate of the submitted PEM. The shipped bundle holds Getswish Root CA v2 for Swish; Swish signing certificates are issued by Swish Customer CA1 v2 for Swish, an intermediate under it. With the shipped bundle, every real Swish Step 7 confirmation was therefore an anomaly, and a deployment could avoid that only by listing the intermediate itself as a trust anchor. It survived because the validator's tests only exercised rejection, with throwaway certificates, and no test ever validated a certificate issued below an intermediate. The validator now builds the path with `CertPathBuilder` (`PKIXBuilderParameters` plus a `CertStore` of the submitted intermediates and of bundle certificates issued by another bundle certificate), with the remaining bundle certificates as trust anchors; `VerificationService` parses every certificate in `signingCertificatePem`. The Swish Customer CA1 v2 for Swish certificate is added to `issuer-ca-bundle.pem` as an intermediate. Tests: `IssuanceConfirmationCertificateTest.certificateIssuedUnderAnIntermediateValidatesWhenTheIntermediateIsSubmitted` / `...IsAnAnomalyWhenTheIntermediateIsMissing`, and in `IssuerCaValidatorTest` root → intermediate → leaf with only the root as anchor.

- **A nonce mismatch never reached the audit log, and its 400 said public-key mismatch.** `ApprovalRegistry.confirm` throws `NonceMismatchException` before `confirmIssuance` appends its `CONFIRM` entry, so a replayed or forged confirmation was recorded only as a WARN in the application log, although `THREAT_MODEL.md` presents attempted replays as something a supervisor sees. `VerificationController` answered it with `registryStatus=ANOMALY_PUBLIC_KEY_MISMATCH`, a status that describes a certificate whose key differs from the attested one. It survived because the only mismatch test stubbed the service and asserted the status code. `confirmIssuance` now appends a `CONFIRM` entry with `compliant=false` before rethrowing, and the 400 body carries the new `ANOMALY_NONCE_MISMATCH`; the registry entry is unchanged, as before. Tests: `ConfirmBindingTest.nonceMismatchIsWrittenToTheAuditLog`, `VerificationControllerConfirmScopeTest.nonceMismatchIsLabelledAsANonceMismatch`.

### Registry

- **"Most recent compliant entry wins" was `findFirst` over a `ConcurrentHashMap`.** The javadoc of `findByPublicKeyFingerprint` promised the most recent entry when one key has several (certificate renewal is the ordinary case); both implementations returned whichever entry the map's hash order produced first, and settlement compliance was read from that entry. It survived because every test had one entry per key. Both implementations now choose by `verificationTimestamp`, then `confirmationTimestamp`. Tests: `ApprovalRegistryRecencyTest`, against both implementations, with identifiers chosen so that the hash order yields the older entry first.

- **A failed journal write left an unrecorded confirmation in the registry.** `AppendOnlyFileApprovalRegistry.confirm` applied the transition to the in-memory entry and then appended the `CONFIRM` line. When the append failed the caller got a 5xx and was told to retry, but registry queries and settlement-time compliance already saw the confirmed status, with no journal line and no audit entry behind it; a restart then silently reverted it. It survived because the journal-failure test, `ApprovalRegistryNonceConcurrencyTest.nonceSurvivesAJournalWriteFailure`, checked only that the nonce was still spendable. The journal line is now written first and the entry changed only after it has returned. Test: `AppendOnlyFileApprovalRegistryJournalTest.failedJournalWriteLeavesTheEntryAwaitingConfirmation`, which fails the write the same way (the journal replaced by a directory).

- **Replay re-dated every confirmation to the restart.** `CONFIRM` journal lines carried no timestamp, and replay set `confirmationTimestamp` to `Instant.now()`, so after each restart every confirmed entry claimed to have been confirmed at start-up — and `recency()`, which breaks ties on that field, compared start-up times. The line now carries `confirmationTimestamp` and replay uses it; a line written before this fix has none and replays with `null`, which is what is actually known. Tests: `AppendOnlyFileApprovalRegistryJournalTest.confirmationTimestampIsJournalledAndReplayed`, `confirmLinesWithoutATimestampReplayWithoutOne`.

### Audit log

- **The health check verified the in-memory copy of the chain, not the file.** `verifyChainIntegrity()` — and the cached status behind `GET /v1/gatekeeper/health` — walked `snapshot()`, the list loaded at start-up. Editing or truncating the file under a running gatekeeper was therefore never reported until the next restart. It survived because the tamper tests reloaded a fresh instance before checking, which re-reads the file and so cannot tell the two apart. The walk now reads the file back, re-parses it with the parser used at start-up, requires it to end at the in-memory head, and verifies what is on disk; the cache is unchanged. Tests: `AppendOnlyFileAuditLogTest.verifyChainIntegrityDetectsTamperingOfTheFileWhileRunning`, `...DetectsTruncationOfTheFileWhileRunning`, `cachedIntegrityStatusDetectsTamperingOfTheFileWhileRunning`.

- **The integrity check assumed SHA-256 and the active key.** Entry signatures were verified with a hard-coded `SHA256withRSA` / `SHA256withECDSA` and only against the active certificate. A deployment configured with `gatekeeper.signing.algorithm=SHA384withECDSA` — the configuration the documentation recommends for EC seals — reported a broken chain from its first entry, and every deployment reported a broken chain after its first key rotation. The javadoc acknowledged the rotation case and said rotation "triggers a clean re-anchor of the chain"; no code does that. It survived because every test used `EphemeralReceiptSigner`, whose `SHA256withRSA` over an RSA key is the one configuration the hard-coding gets right. `ReceiptSigner.getSignatureAlgorithm()` now reports the algorithm the signer uses, and the check verifies each entry under the active certificate or any certificate in `gatekeeper.signing.retired-keys`, taken from `GatekeeperKeyDirectory` — the source behind `GET /v1/gatekeeper/keys`. A rotation that also changes the algorithm is not covered: all entries are verified with the current one. Tests: `AppendOnlyFileAuditLogTest.chainSignedWithSha384WithEcdsaIsIntact` (a real `ConfiguredReceiptSigner` over a P-384 PKCS#12 keystore), `chainStaysIntactAfterKeyRotationWithTheOldCertificateRetired`, `chainSignedUnderAKeyThatIsNeitherActiveNorRetiredIsNotIntact`.

### API changes

- `ApprovalRegistry.confirm(...)` takes an `IssuedCertificate` as a sixth argument; the five-argument form remains as a default method that stores no certificate. New: `ApprovalRegistry.findByIssuedCertificate(BigInteger, X500Principal)` (default: empty), the `ApprovalRegistry.IssuedCertificate` record, and the static helpers `recency()` and `issuedCertificateMatches(...)`.
- `RegistryEntry` gains `issuedCertificatePem`, `issuedCertificateSerial` (lower-case hex) and `issuedCertificateIssuerDn` (RFC 2253), and public no-argument and all-argument constructors. `CONFIRM` journal lines carry the three new fields when a certificate is stored.
- `ReceiptSigner.getSignatureAlgorithm()` added — abstract, so an implementation outside this repository must add it.
- `AppendOnlyFileAuditLog` gains a constructor taking `GatekeeperKeyDirectory`, which is now the Spring-injected one; the two- and three-argument constructors remain and verify against the active key only.
- `IssuerCaValidator.validateChain(List<X509Certificate>)` added; `validate(X509Certificate)` delegates to it.
- `IssuanceConfirmationResponse.RegistryStatus.ANOMALY_NONCE_MISMATCH` added. It appears only in the `400` body; no registry entry is given this status.
- `SignatureVerificationResponse.auditEntryHashHex` added.
- `CONFIRM` journal lines carry `confirmationTimestamp`.

### Dependencies

- BouncyCastle `bcprov-jdk18on` and `bcpkix-jdk18on` 1.86; springdoc-openapi 3.1.1; `org.webjars:swagger-ui` 5.32.15 (springdoc 3.1.1 declares 5.32.14); bucket4j 8.20.0.
- `tomcat.version` 11.0.26 (2026-09-15), which fixes twelve CVEs on top of 11.0.25 (CVE-2026-73581, -75973, -76183, -77756, -77762, -77791, -78383, -78437, -79677, -86248, -86350, -87022). The parent still manages 11.0.24.
- Unchanged: Spring Boot parent 4.1.1, Lombok 1.18.48, maven-enforcer-plugin 3.6.3; `maven-compiler-plugin` is not pinned and comes from the parent.
- `dependency-check-maven` stays at 12.2.2. 13.0.0 is still the latest release, and it is the version jeremylong/DependencyCheck#8715 was reported against: it rejects an absent NVD API key, and the `check` goal runs in `verify`, so moving to it would fail every build run without a key.

### Documentation

- `FORENSIC_INSPECTION.md` §2.3 and §4 named the export fields `from`, `to`, `chainHeadHashHex` and `bundleSignatureBase64`; `AuditExport` has `rangeFrom`, `rangeTo`, `chainHeadHashAtExport` and `exportSignatureBase64`, and `signingKeyFingerprintHex` is the fingerprint of the public key, not of the certificate. The description of the export's signed input omitted the chain head and had the fields out of order.
- `SUPERVISORY_OPERATIONS.md` §2.2 named the anchor's key field `activeSigningKeyFingerprintHex`; `AuditAnchor` has `signingKeyFingerprintHex` (and `totalEntries`, which was not listed).
- `gatekeeper.audit.retention-years` was described as defaulting to 7 (`SUPERVISORY_OPERATIONS.md` §5.3) and as the setting through which the gatekeeper exposes retention. It is set to 5 in both configuration files and no code reads it; the gatekeeper never prunes the log. §5.3, `PEER_REVIEW_GUIDE.md` and the README say so now.
- `DEPLOYMENT.md` §9 told operators to add a compromised signing certificate to `GATEKEEPER_RETIRED_KEYS`, contradicting `SUPERVISORY_OPERATIONS.md` §2.3. With retired keys now accepted by the chain check that advice would let forged entries pass; it is reversed.
- `ConfiguredReceiptSigner` and `application-nca.yaml` offered `SHA256withRSAandMGF1` for PSS seals. That is a BouncyCastle algorithm name, BouncyCastle is not registered as a JCA provider, and the JDK has no algorithm of that name, so the first signature would have failed. Removed.
- `THREAT_MODEL.md` described the settlement algorithm allowlist as "enforced via JCA provider lookup"; it is an explicit set checked before any lookup.
- A documentation-versus-code review found further claims the code did not bear out. `SUPERVISORY_OPERATIONS.md` §3.5 had the audit log carry the key fingerprint and the certificate serial for triangulation; an `AuditEntry` holds digests only, and the two values are in the approval registry, which no endpoint lists for confirmed entries — the procedure now joins the registry journal to the audit log on `verificationId`. §3.2 read identical `requestDigestBase64` values as evidence reused for distinct keys, which the digest cannot show because it covers the public key. §3.2, §6.1, the README and `AuditController` described the recorded principal as the certificate DN; it is what `principal-regex` captures, by default the CN value. §6.2 described an erasure "deletion record" that does not exist. `THREAT_MODEL.md` and `CROSS_REFERENCE.md` called the registry journal integrity-protected and tamper-evident; it has neither a hash chain nor a signature. The README and `CROSS_REFERENCE.md` listed Azure as supported without saying it can never be COMPLIANT. `AuditLog.findByVerificationId` claimed a one-to-one relation between `verificationId` and `VERIFY`/`CONFIRM` entries; `/v1/audit/witness` returns the earliest entry, and `CONFIRM` and `SETTLEMENT_VERIFY` entries share the identifier. `SUPERVISORY_OPERATIONS.md` §3.3 called a calendar quarter exactly the 90-day `range` limit, which holds only for January–March of a non-leap year, and §3.5 passed `inspectionId` to `/range`, which takes none. `FORENSIC_INSPECTION.md` §3.2 filtered on `operation=confirm` and `loopClosed`; the value is `CONFIRM` and the audit entry has no `loopClosed`. `THREAT_MODEL.md` pointed to `TODO-NCA` hook points for cross-country authorisation; there is no such marker in the code, and the policy is simply not implemented. `CROSS_REFERENCE.md` also said it is shipped identically in the three repositories; the copies differ, and the statement is replaced by railgate's. The `AuditExport` field names, `signingKeyFingerprintHex` and the `retention-years` statements corrected above were re-checked against the code and stand.
- The settlement lookup, the PSS parameters, path building through intermediates, the disk-based chain check and the retired-key verification are documented in the README, `DEPLOYMENT.md`, `SUPERVISORY_OPERATIONS.md`, `FORENSIC_INSPECTION.md` and `THREAT_MODEL.md`; `CROSS_REFERENCE.md` test counts are updated.

### End-to-end test

- **New `e2e/`: a local end-to-end test of gatekeeper, hsm and railgate.** Until now each repository tested its side of the contracts in isolation, with mocks for the others, and that is how the settlement contract defect above survived: railgate's tests mocked gatekeeper and gatekeeper's tests never sent railgate's request. `e2e/` starts the three built jars on loopback ports and drives Steps 2–7 with the real Yubico and Securosys attestation fixtures, then settlement directly against gatekeeper and through railgate (8 tests; 6 more run only with material that cannot be produced locally — a BankID signature for the hsm issuance path, and a signature from the attested HSM key for an allowed settlement). It is a separate Maven project and is not run by `mvn verify` here. See `e2e/README.md`.

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
