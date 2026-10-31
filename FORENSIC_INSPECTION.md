# Forensic inspection procedures — gatekeeper

This document describes how to extract, package, and verify cryptographic evidence from a deployed gatekeeper instance for use in formal proceedings. It is a companion to `SUPERVISORY_OPERATIONS.md`: that document describes day-to-day operations and the routine inspection workflow; the present document describes the more rigorous procedures that apply when the evidence may be challenged before a court, an arbitration panel, EBA's investigation team, or a Member State's prosecutorial authority.

## 1. Scope

This document applies in three settings:

1. **Court proceedings** — administrative, civil, or criminal — in which a gatekeeper-recorded fact is at issue. Examples: a supervisee disputes a non-compliance finding; a third party sues an NCA for negligent supervision; a prosecutor charges a TL with fraudulent issuance of a payment-signing certificate.
2. **Internal investigations** — by NCA staff, by an outside auditor commissioned by the NCA, or by EBA under EBA Regulation (EU) No 1093/2010 Article 17 — where the standard of evidence must withstand independent scrutiny.
3. **Supervisory inspections under DORA Regulation (EU) 2022/2554 Article 6(10)** in which a supervisor inspects a financial entity's HSM-attestation compliance and the gatekeeper's record is the primary evidence base.

The procedures below assume a deployed gatekeeper running with `gatekeeper.signing.mode=configured` against the NCA's production signing key — the organisation certificate the NCA uses for ordinary administrative signing of supervisory acts. The receipts and audit entries are myndighetshandlingar issued in the course of ICT supervision under DORA Regulation (EU) 2022/2554 Article 50; their evidential weight in a Swedish administrative or judicial proceeding follows from the ordinary rules of förvaltningsprocesslagen (1971:291) and offentlighets- och sekretesslagen (2009:400), supported substantively by the canonical-bytes contract, the per-entry signature, and the hash chain (any of which a counterparty can independently re-verify against the published `GET /v1/gatekeeper/keys` directory and `GET /v1/gatekeeper/anchor`). A gatekeeper running in `ephemeral` mode produces evidence whose signature carries no organisation-certificate backing and is therefore not a myndighetshandling in any normal sense; the underlying canonical bytes and hash chain still remain probative on substance.

## 2. Evidence types and how to obtain them

### 2.1 Audit entry for a specific verification

Each `AuditEntry` is a record of one gatekeeper decision or event: `VERIFY`, `BATCH_VERIFY`, `CONFIRM`, `SETTLEMENT_VERIFY` and, since 1.7.0, the key-lifecycle events `SIGNED`, `ROTATED`, `REVOKED`, `DECOMMISSIONED` and the triangulation report `TRIANGULATION`. To obtain the entry of a verification:

```bash
curl --cert client.pem --key client.key \
     -H "Accept: application/json" \
     "https://dora-api.fi.se/v1/audit/witness/${verificationId}"
```

The response is the earliest entry with that `verificationId`, which for an issuance is its `VERIFY` or `BATCH_VERIFY` entry. `CONFIRM` entries (one per confirmation attempt, rejected ones included) and `SETTLEMENT_VERIFY` entries carry the same `verificationId` and are not returned by this call; obtain them from the signed export (Section 2.3). The response carries the entry's `sequenceNumber`, `timestamp`, `mtlsClientPrincipal`, `operation`, `verificationId`, `requestDigestBase64`, `receiptDigestBase64`, `compliant`, `prevEntryHashHex`, `thisEntryHashHex`, and `entrySignatureBase64`, and since 1.7.0 `canonicalVersion`, the inventory fields `keyFingerprintHex`, `certSerialHex`, `certIssuerDn`, `hsmVendor`, `hsmSerial`, `registryStatus`, `hsmFirmwareVersion`, `hsmFipsApprovedMode`, the per-key link `prevKeyEntryHashHex` and, in time-stamping entry mode, `timestampTokenBase64` (each `null` where it does not apply; entries written before 1.7.0 have `canonicalVersion: null` and no inventory). Save the response verbatim — including HTTP headers, in particular the `Date` header, so the time of extraction is in the record.

### 2.2 Chain integrity proof

The chain integrity proof binds every audit entry to every other audit entry. Two complementary primitives are available:

- **`verifyChainIntegrity()` over the file on disk.** Run by the gatekeeper's own code path behind `GET /v1/gatekeeper/health`. From release 1.5.0 the walk reads the audit file back from disk, re-parses it with the parser used at start-up, and requires it to end at the in-memory head; before that it walked the in-memory copy, so a change made to the file while the gatekeeper was running was not reported until the next restart. Entry signatures are verified with the configured `gatekeeper.signing.algorithm` under the active or a retired signing certificate. From release 1.4.0 the result is cached and recomputed at most once per `gatekeeper.audit.integrity-check-interval-seconds`, so `chainIntact` is proof that the chain was intact at the instant reported in `chainCheckedAt`, not necessarily at the instant of the call — for an inspection record, cite the pair. For court use, additionally export the chain (Section 2.3) and rerun `verifyChainIntegrity()` independently against the exported bytes — a court-appointed expert must be able to do this without trusting the NCA's tooling.
- **Anchor reconciliation.** Pair the chain head observed at time t1 with a previously published anchor at time t0 < t1. If the t0 anchor is reachable by walking back the chain from the t1 head, no entry pre-existing at t0 has been rewritten in the interval [t0, t1]. The t0 anchor, being a published commitment, is independent of the NCA's current state.
- **Since 1.7.0** the walk also checks, for each v2 entry, the per-key link (`prevKeyEntryHashHex` equals the hash of the previous entry with the same `keyFingerprintHex`, or 64 zeros for the key's first entry, and is `null` exactly when there is no fingerprint); refuses a v1 entry after a v2 entry, a v1 entry carrying a v2-only field or a token, and an unknown `canonicalVersion`; and, when `gatekeeper.timestamping.trusted-certs-path` is configured, validates every stored RFC 3161 token over its entry and requires every anchor record to name an entry of the chain with that hash. Without trusted TSA certificates stored tokens are not validated, and the log says how many there are.

### 2.3 Signed export for an interval

The signed export bundles a window of audit entries together with the chain head and the active key fingerprint, all sealed under the gatekeeper's signing key:

```bash
curl --cert client.pem --key client.key \
     -H "Accept: application/json" \
     "https://dora-api.fi.se/v1/audit/export?from=2026-01-01T00:00:00Z&to=2026-04-01T00:00:00Z&inspectionId=FI-2026-001"
```

The response is an `AuditExport` JSON object with these fields:

- `inspectionId` — caller-supplied or gatekeeper-generated UUID.
- `generatedAt` — instant of export at the gatekeeper.
- `rangeFrom`, `rangeTo` — the window.
- `entryCount` — `entries.size()`; included so that a missing entry is detectable independently of `entries.length`.
- `entries` — the list of `AuditEntry` records.
- `chainHeadHashAtExport` — the chain head's `thisEntryHashHex` as of `generatedAt`.
- `exportSignatureBase64` — gatekeeper signature over `AuditExport.canonicalBytesForSignature(...)`.
- `signingKeyFingerprintHex` — lower-case hex SHA-256 of the active signing key's DER-encoded public key, as listed by `GET /v1/gatekeeper/keys`.

Save the entire response verbatim. The export is self-contained and self-verifying. Since 1.7.0 each entry in `entries` carries the v2 fields listed in §2.1, and the export signature covers each entry's `thisEntryHashHex`, hence its inventory fields; it does not cover `timestampTokenBase64`, which is outside the hash and authenticated by the TSA's own signature.

### 2.4 Historical anchor publications

The supervisor or a relying party retains every published anchor (Section 2.2 of `SUPERVISORY_OPERATIONS.md`). For evidence purposes:

- Identify the anchor period that brackets the events under investigation.
- Retrieve the signed anchor JSON from the publication forum (transparency log entry, archived web page, archived newspaper advertisement, etc.).
- Retrieve the operator certificate that was active at the anchor time (from `GET /v1/gatekeeper/keys`, including retired keys).

The anchor is a fixed-point commitment that bounds what the NCA could have rewritten in the interval `[anchor_time, present]`.

In time-stamping anchor mode *(since 1.7.0)* the gatekeeper itself obtains an RFC 3161 token over the chain head periodically. `GET /v1/gatekeeper/anchor/timestamps?offset=&limit=` (public) lists every record `{headSequenceNumber, headHashHex, tokenBase64, genTime}`, oldest first; the latest also appears as `latestTimestamp` on `GET /v1/gatekeeper/anchor`. Retrieve and retain them outside the NCA: a record kept only on the gatekeeper host protects against the seal-key holder only once someone else holds a copy, because the record file is outside the hash chain and a deleted record is not detected by the chain check.

### 2.5 COSE_Sign1 export *(since 1.7.0)*

```bash
curl --cert client.pem --key client.key \
     "https://dora-api.fi.se/v1/audit/export?from=2026-01-01T00:00:00Z&to=2026-04-01T00:00:00Z&format=cose" \
     -o export.cbor-seq
```

The body (`Content-Type: application/cbor-seq`, RFC 8742) is a concatenation of one COSE_Sign1 (RFC 9052, CBOR tag 18) per entry in `[from, to)`, in sequence order: `[protected, {}, payload, signature]`.

- `protected` is the deterministic CBOR map `{1: alg, 4: kid}`. `kid` is the 32 bytes of SHA-256 over the active signing certificate's SubjectPublicKeyInfo — hex-decoded, the `publicKeyFingerprintHex` of `GET /v1/gatekeeper/keys`. `alg`: −257, −258, −259 for `SHA256/384/512withRSA` (PKCS#1 v1.5), −7, −35, −36 for `SHA256/384/512withECDSA`.
- `payload` is a deterministic CBOR map with text keys, a key being absent when the entry's value is `null`: `eventType` (the operation), `sequence`, `timestamp`, `principal`, `verificationId`, `requestDigest`, `receiptDigest`, `compliant`, `canonicalVersion` (`"v1"` for entries without one), `keyFingerprint`, `certSerial`, `certIssuerDn`, `hsmVendor`, `hsmSerial`, `registryStatus`, `hsmFirmwareVersion`, `hsmFipsApprovedMode`, `prevEntryHash`, `prevKeyEntryHash`, `thisEntryHash` (text, in the form that was hashed), `entrySignature` (bytes, the original entry signature) and `timestampToken` (bytes, DER, when present).
- `signature` is the active signer's signature over the deterministic CBOR of `["Signature1", protected, h'', payload]`; for ECDSA the JCA DER signature is converted to `r‖s` of fixed length (P-256: 64 bytes, P-384: 96, P-521: 132).

The COSE signature is an **export seal**: it says that this gatekeeper, under its active key, exported these fields now. It is not the entry's evidence; that is the entry's own signature, its hashes and its token, all inside the payload. The COSE form has no envelope: no `inspectionId` (the parameter is ignored), no chain head at export, no generation time and no export-level signature, so a missing entry within the window is detectable only through the hash links between consecutive exported entries. Use the JSON export (§2.3) when the window must be bound to an inspection record and a chain head, and the COSE export when the recipient's tools consume COSE; both can be taken for the same window. A signer algorithm outside the list above answers 501.

### 2.6 RFC 3161 tokens of entries *(since 1.7.0)*

In time-stamping entry mode each entry's `timestampTokenBase64` is an RFC 3161 `TimeStampToken` whose message imprint is SHA-256 over the UTF-8 bytes of the entry's `thisEntryHashHex` — the same bytes the entry signature is over. It is stored on the entry but outside its hash, so it can be added without changing the chain, and a token moved to another entry, or damaged, fails the chain check when trusted TSA certificates are configured. An entry without a token was written while the TSA was unavailable, before entry mode was enabled, or had its token removed; the chain check cannot tell these apart, and `GET /v1/gatekeeper/health` reports the count as `untimestampedEntries`. Record which TSA the deployment uses and keep its certificate chain with the evidence.

### 2.7 Attestation of the gatekeeper's own signing key *(since 1.7.0, when configured)*

When the seal is held in an HSM and its attestation is configured, `GET /v1/gatekeeper/keys` carries, on the active entry, `attestation`: the verification result (`valid`, `chainValid`, `publicKeyMatch`, `keyOrigin`, `exportable`, `verifiedAgainstRootSha256Hex`, `verifiedAt`, `errors`) and the `evidence` itself (the certificate chain, and for Securosys the XML and its signature). Save it with the `keys` snapshot: it lets a court-appointed expert repeat, against the vendor root, the check that the key which signed the evidence was generated in the HSM and cannot be exported. The attestation is checked once, at start-up, and only for the active key; retired keys carry none.

## 3. Step-by-step procedure for reconstructing a single event

Scenario: a financial entity has produced a signing certificate. The supervisor must determine whether the gatekeeper authorised the issuance, and whether the certificate was bound to a genuine HSM-protected key.

### 3.1 Given a receipt the financial entity holds

1. The financial entity hands over the `VerificationResponse` JSON (the receipt) and the issued certificate's PEM.
2. The supervisor extracts `verificationId` from the receipt.
3. Fetch the audit entry: `GET /v1/audit/witness/{verificationId}`.
4. Recompute SHA-256 over the receipt JSON's canonical bytes (`ReceiptCanonicalizer.canonicalize(...)` produces the same bytes the gatekeeper signed). Confirm the digest matches `receiptDigestBase64` in the audit entry.
5. Verify the receipt's `signature` against the operator certificate carried in `signingCertificate`. The certificate must be present in `GET /v1/gatekeeper/keys` (active or retired), and the signature must verify under the receipt's canonical bytes.
6. Verify the audit entry's signature: `entrySignatureBase64` is computed over `thisEntryHashHex.getBytes(UTF_8)`. Recompute `thisEntryHashHex` from the entry's other fields via `AuditEntry.canonicalBytesForHash(...)`, then verify the signature against the operator certificate.
7. If steps 4, 5, and 6 all succeed, the receipt is genuine and the audit trail confirms it.

### 3.2 Given a certificate the supervisor wants to verify

Scenario: the supervisor has a signing certificate of unknown provenance and wants to determine whether the gatekeeper authorised its issuance.

1. Compute the SHA-256 fingerprint of the certificate's `SubjectPublicKeyInfo`. This is the same fingerprint the gatekeeper records in `VerificationResponse.publicKeyFingerprint` and binds in the Step-7 confirm (lower-case, colon-separated hex).
2. Run `GET /v1/audit/range?from=<earliest plausible>&to=<latest plausible>` over a window that covers the certificate's notBefore date.
3. Filter the returned entries to `operation` = `CONFIRM`. Since 1.7.0 a v2 `CONFIRM` entry carries `keyFingerprintHex` (the attested key of the registry entry the confirmation resolved to) and, once the submitted certificate passed issuer-CA validation, its `certSerialHex` and `certIssuerDn`, inside the entry's hash: match the certificate's fingerprint, serial (lower-case hex) and issuer (RFC 2253) against them directly. For entries written before 1.7.0, which carry neither, re-fetch the corresponding `VerificationResponse` (operationally retained at the financial-entity side) and compare its `publicKeyFingerprint` against the certificate's, or read the approval-registry journal (`gatekeeper.registry.path`), whose `CONFIRM` line for the same `verificationId` carries the issued certificate's serial and issuer DN when the confirmation ended in `VERIFIED_AND_ISSUED` (from release 1.5.0).
4. If a matching `CONFIRM` entry exists with `compliant=true` — set only when the loop closed with no anomaly; the audit entry has no `loopClosed` field, but since 1.7.0 its `registryStatus` is `VERIFIED_AND_ISSUED` — the certificate's issuance was authorised. If no matching entry exists, the certificate either was not authorised or was issued via a path that bypassed the gatekeeper — the latter being the qualitatively more serious finding flagged in `README.md` Section "Secondary control — registry reconciliation".

### 3.3 Reconstructing the history of one key *(entries since 1.7.0)*

Scenario: the supervisor must establish everything the gatekeeper recorded about one signing key — verification, issuance, settlements, signing reports, rotation, revocation, decommissioning.

1. Take an export (JSON or COSE) of a window that covers the key's life, or several consecutive ones.
2. Select the entries whose `keyFingerprintHex` is the key's fingerprint. In time order they are `VERIFY`/`BATCH_VERIFY`, `CONFIRM`, then any `SETTLEMENT_VERIFY`, `SIGNED`, `ROTATED`, `REVOKED`, `DECOMMISSIONED`; a renewal adds another `VERIFY` and `CONFIRM` for the same key.
3. Check the per-key chain: the first selected entry has `prevKeyEntryHashHex` of 64 zeros, and every later one names the `thisEntryHashHex` of the one before. A break means an entry of that key is missing from the selection (outside the window) or was altered.
4. Read the status from the entries: `registryStatus` after each `CONFIRM` and lifecycle event; `CERT_REVOKED` and similar reasons are in the settlement responses (the entry's `receiptDigestBase64` covers them).

Lifecycle events that resolved to no registry entry, and `TRIANGULATION` entries, carry no fingerprint and are not part of any per-key chain.

## 4. Cryptographic verification primitives

A forensic verifier must be able to recompute every digest and verify every signature using only standard primitives. The conventions are:

### 4.1 Hashing

- **Algorithm:** SHA-256.
- **Input encoding:** UTF-8 bytes of the canonical-form string for receipts (`ReceiptCanonicalizer`) and audit entries (`AuditEntry.canonicalBytesForHash`). An audit entry is hashed in the form its `canonicalVersion` names. v1 (entries without `canonicalVersion`): `v1|sequenceNumber|timestamp|principal|operation|verificationId|requestDigestBase64|receiptDigestBase64-or-<no-receipt>|compliant|prevEntryHashHex`. v2 (since 1.7.0): `v2|sequenceNumber|timestamp|principal|operation|verificationId|requestDigestBase64|receiptDigestBase64|compliant|prevEntryHashHex|keyFingerprintHex|certSerialHex|certIssuerDn|hsmVendor|hsmSerial|registryStatus|hsmFirmwareVersion|hsmFipsApprovedMode|prevKeyEntryHashHex`. In both, `sequenceNumber` is decimal, `timestamp` is `Instant.toString()`, `compliant` is `true`/`false`, and every other value has `%` replaced by `%25` and then `|` by `%7C`; in v2 every `null` is written as `%N`. `timestampTokenBase64` and `entrySignatureBase64` are outside the hash.
- **Output encoding:** hex (lower-case) for chain-internal hashes (`thisEntryHashHex`, `prevEntryHashHex`, `chainHeadHashAtExport`); standard Base64 with `=` padding for `requestDigestBase64` and `receiptDigestBase64`.

### 4.2 Signing

- **Algorithm:** as configured via `gatekeeper.signing.algorithm`. The reference default is `SHA256withRSA` for RSA seals; production NCA deployments using EC seals select `SHA384withECDSA` or per the seal's certified algorithm.
- **Signature encoding:** standard Base64 with `=` padding.
- **Signed input for receipts:** `ReceiptCanonicalizer.canonicalize(VerificationResponse)` — a UTF-8 byte sequence beginning with `v3|`. A receipt issued under 1.4.0–1.5.0 is re-verified with `ReceiptCanonicalizer.canonicalize(receipt, "v2")`, the form without the customer fields and the supplier number. The code no longer produces `v1` (before 1.4.0); such a receipt needs the 1.3 canonicaliser from the repository history.
- **Signed input for audit entries:** `thisEntryHashHex.getBytes(UTF_8)`. Signing the hex form of the chain hash, rather than the raw 32-byte digest, keeps the signature input identical to what is published in the JSON Lines storage form, which simplifies retroactive verification.
- **Signed input for export bundles:** `AuditExport.canonicalBytesForSignature(...)` — the pipe-separated UTF-8 string `v1|inspectionId|generatedAt|rangeFrom|rangeTo|entryCount|chainHeadHashAtExport|signingKeyFingerprintHex`, followed by `|thisEntryHashHex` for each entry in the window; `%` and `|` inside string fields are escaped as `%25` and `%7C`, and instants are rendered by `Instant.toString()`.
- **Signed input for COSE export items** *(1.7.0)*: the deterministic CBOR of `["Signature1", protected, h'', payload]` (§2.5).
- **Signed input for settlement verdicts** *(1.7.0)*: `SettlementVerdictCanonicalizer`'s `sv1|verifiedAt|certSerialHex|issuerDn|digestHex|signatureValid|compliant|reason|auditEntryId|auditEntryHashHex` (README, `POST /api/v1/verify`). The same applies to the `SIGNED` lifecycle response.
- **Signed input for triangulation reports** *(1.7.0)*: the `tr1` form of `TriangulationCanonicalizer`, one LF-terminated line per header, input digest, discrepancy and total.
- **RFC 3161 tokens** *(1.7.0)*: the TSA's CMS signature over its `TSTInfo`, whose message imprint is SHA-256 of the UTF-8 bytes of `thisEntryHashHex` (entry mode) or of the anchored `headHashHex` (anchor mode).

### 4.3 Certificate handling

- **Format:** PEM (`-----BEGIN CERTIFICATE-----` ... `-----END CERTIFICATE-----`), one certificate per blob. The signing certificate is published with its issuer chain via `GET /v1/gatekeeper/keys`.
- **Issuer:** the operator certificate is the NCA's organisation certificate, issued by the CA that the NCA uses for ordinary administrative signing of supervisory acts (typically a domestic CA or eID infrastructure provider). The verifier validates the chain to that issuer using PKIX `CertPathValidator`.
- **Validity:** a forensic verifier checks both `notBefore` / `notAfter` and revocation status at the time of the original signature, not at the time of verification. Swish signing certificates carry no CRL distribution point and no OCSP address (checked on a certificate issued by `SEB Customer CA1 v2 for Swish`), so the revocation status has to be requested from the issuing CA, the bank, under DORA Article 50(1)(a). The gatekeeper does not read CRLs or OCSP. Since 1.7.0 it records the revocations, rotations and decommissionings reported to it as lifecycle events (`REVOKED`, `ROTATED`, `DECOMMISSIONED`, each with its time and reason in the registry entry and an audit entry in the key's per-key chain), and settlement after such an event answers `CERT_REVOKED`, `CERT_SUPERSEDED` or `CERT_DECOMMISSIONED`; a revocation that was never reported to it is not known to it. A certificate that was valid at signing time and has since expired or been revoked still produces a valid signature.

### 4.4 Cross-repo wire-format compatibility

The financial entity repository (`hsm`) and the gatekeeper repository carry byte-identical canonicalisation logic. This is enforced by the `WireFormatGoldenBytesTest` in each repository, asserting against a literal golden string. A forensic verifier who reproduces the gatekeeper's canonical bytes on their own system must obtain the same bytes the financial entity computed locally — any drift indicates a code-base inconsistency that itself is forensically relevant.

### 4.5 Verifying an export offline

An expert who holds an export and the `GET /v1/gatekeeper/keys` snapshot taken with it can check, without contacting the gatekeeper:

1. **The seal.** JSON: `exportSignatureBase64` over `AuditExport.canonicalBytesForSignature(...)` under the certificate whose `publicKeyFingerprintHex` equals `signingKeyFingerprintHex`. COSE: each item's signature over its `Sig_structure` under the certificate whose `publicKeyFingerprintHex` is the hex of `kid`, with the algorithm `alg` names (ECDSA as `r‖s`, e.g. `SHA256withECDSAinP1363Format` in Java).
2. **Each entry's hash.** Recompute `thisEntryHashHex` in the form `canonicalVersion` names (§4.1) from the entry's fields — in the COSE payload every hashed field is present in the string form that was hashed — and compare.
3. **Each entry's own signature.** `entrySignatureBase64` (COSE: `entrySignature`) over the UTF-8 bytes of `thisEntryHashHex`, under the active certificate or a retired one from `/keys` (the export does not say which key signed an entry; try each).
4. **The links.** Each entry's `prevEntryHashHex` is the previous entry's `thisEntryHashHex`, and for v2 entries `prevKeyEntryHashHex` is the previous same-key entry's hash (§3.3). A gap in `sequence` or a broken link inside the window is an omission or an alteration.
5. **The tokens.** Each `timestampToken` is a valid RFC 3161 token from the deployment's TSA whose imprint is SHA-256 of the UTF-8 bytes of `thisEntryHashHex`; each retained anchor record's token covers its `headHashHex`, which must be the hash of the entry at `headSequenceNumber`.
6. **The anchors.** Reconcile with published chain anchors as in §2.2.

`AuditCoseExportTest` in the repository performs steps 1–3 for COSE exports, building the `Sig_structure` with code independent of the production encoder and verifying with `java.security.Signature`.

## 5. Chain-of-custody requirements

Every forensic extraction generates a chain-of-custody record that travels with the evidence. The minimum content of the record:

### 5.1 Sealing the export at extraction time

1. Compute SHA-256 of the extracted bundle bytes (the JSON returned by `/v1/audit/export`, exactly as received including whitespace).
2. Record the digest, the time of extraction, and the operator's identity. Sign the chain-of-custody record under the NCA's own organisation-certificate-backed signing key (separate from the gatekeeper's signing key).
3. Move the bundle and its custody record to write-once media. The case-study deployment uses HSM-backed FDE volumes with manual unlock and an off-line cold-storage tier; deployers vary.
4. Record the storage location and accessibility constraints.

### 5.2 Onward custody log

Each subsequent action — transfer to another custodian, decryption, copy for opposing counsel, signature for transmission — appends a line to the custody log. The log is itself signed by the NCA's organisation-certificate-backed signing key at every append, so the log is hash-chained on its own (the same construction as the audit log it documents).

A typical custody-log line:

```text
2026-04-15T09:32:11Z  TRANSFER  from=Inspector A (FI-12345)  to=Inspector B (FI-67890)
                      bundle-sha256=<hex>  reason="case FI-2026-001 review"
                      sealed-by=<FI seal fingerprint>  signature=<base64>
```

### 5.3 Documenting verification activity

Every time the bundle is verified — by NCA staff, by a court-appointed expert, by opposing counsel — the verification is recorded. The record states what was verified (each digest match, each signature verification, each anchor reconciliation), the tooling used (a court-appointed expert may use independent code; the NCA must support that), and the outcome.

A verification that does not match — a digest mismatch, a signature failure, an anchor that does not chain back — must be recorded as such, with full diagnostic detail. Suppression of a non-matching result, or selective re-verification until a match is found, defeats the purpose of the chain of custody and can itself become evidence of misconduct.

## 6. What this document does not cover

The following remain the responsibility of the case-handling supervisor or prosecutor and are not addressed here:

- **Substantive analysis** of whether a particular HSM-attestation evidence in fact justifies the COMPLIANT determination — for that, see the vendor verifiers under `src/main/java/.../verification/`.
- **Personal data handling** for natural-person mTLS principals — see `SUPERVISORY_OPERATIONS.md` Section 6.
- **Supervisory escalation paths** under EBA Regulation (EU) No 1093/2010 Articles 17, 18, and 29 — see the same.
- **Cross-border admissibility** of the evidence in non-Swedish or non-EU forums — coordinate with the receiving jurisdiction's procedural law.

The cryptographic record produced by the procedures above is forensically sound by construction. The remaining links — chain of custody, organisational integrity, procedural law — are organisational obligations that this code base cannot guarantee on its own and that the operating NCA must implement.
