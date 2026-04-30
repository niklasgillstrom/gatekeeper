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

Each `AuditEntry` is a record of one gatekeeper decision (verify, verify-batch, or confirm). To obtain:

```bash
curl --cert client.pem --key client.key \
     -H "Accept: application/json" \
     "https://dora-api.fi.se/v1/audit/witness/${verificationId}"
```

The response carries the entry's `sequenceNumber`, `timestamp`, `mtlsClientPrincipal`, `operation`, `verificationId`, `requestDigestBase64`, `receiptDigestBase64`, `compliant`, `prevEntryHashHex`, `thisEntryHashHex`, and `entrySignatureBase64`. Save the response verbatim — including HTTP headers, in particular the `Date` header, so the time of extraction is in the record.

### 2.2 Chain integrity proof

The chain integrity proof binds every audit entry to every other audit entry. Two complementary primitives are available:

- **`verifyChainIntegrity()` over a snapshot.** Run by the gatekeeper's own code path during `GET /v1/gatekeeper/health`. The boolean `chainIntact` in the health response is the proof for the operator that the chain is intact at the moment of the call. For court use, additionally export the chain (Section 2.3) and rerun `verifyChainIntegrity()` independently against the exported bytes — a court-appointed expert must be able to do this without trusting the NCA's tooling.
- **Anchor reconciliation.** Pair the chain head observed at time t1 with a previously published anchor at time t0 < t1. If the t0 anchor is reachable by walking back the chain from the t1 head, no entry pre-existing at t0 has been rewritten in the interval [t0, t1]. The t0 anchor, being a published commitment, is independent of the NCA's current state.

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
- `from`, `to` — the window.
- `entryCount` — `entries.size()`; included so that a missing entry is detectable independently of `entries.length`.
- `entries` — the list of `AuditEntry` records.
- `chainHeadHashHex` — the chain head as of `generatedAt`.
- `bundleSignatureBase64` — gatekeeper signature over `AuditExport.canonicalBytesForSignature(...)`.
- `signingKeyFingerprintHex` — fingerprint of the active operator certificate.

Save the entire response verbatim. The export is self-contained and self-verifying.

### 2.4 Historical anchor publications

The supervisor or a relying party retains every published anchor (Section 2.2 of `SUPERVISORY_OPERATIONS.md`). For evidence purposes:

- Identify the anchor period that brackets the events under investigation.
- Retrieve the signed anchor JSON from the publication forum (transparency log entry, archived web page, archived newspaper advertisement, etc.).
- Retrieve the operator certificate that was active at the anchor time (from `GET /v1/gatekeeper/keys`, including retired keys).

The anchor is a fixed-point commitment that bounds what the NCA could have rewritten in the interval `[anchor_time, present]`.

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

1. Compute the SHA-256 fingerprint of the certificate's `SubjectPublicKeyInfo`. This is the same fingerprint the gatekeeper records in `VerificationResponse.publicKeyFingerprint` and binds in the Step-7 confirm.
2. Run `GET /v1/audit/range?from=<earliest plausible>&to=<latest plausible>` over a window that covers the certificate's notBefore date.
3. Filter the returned entries to `operation=confirm`. For each candidate, re-fetch the corresponding `VerificationResponse` (operationally retained at the financial-entity side) and compare its `publicKeyFingerprint` against the certificate's.
4. If a matching entry exists with `compliant=true` and `loopClosed=true`, the certificate's issuance was authorised. If no matching entry exists, the certificate either was not authorised or was issued via a path that bypassed the gatekeeper — the latter being the qualitatively more serious finding flagged in `README.md` Section "Secondary control — registry reconciliation".

## 4. Cryptographic verification primitives

A forensic verifier must be able to recompute every digest and verify every signature using only standard primitives. The conventions are:

### 4.1 Hashing

- **Algorithm:** SHA-256.
- **Input encoding:** UTF-8 bytes of the canonical-form string for receipts (`ReceiptCanonicalizer`) and audit entries (`AuditEntry.canonicalBytesForHash`).
- **Output encoding:** hex (lower-case) for chain-internal hashes (`thisEntryHashHex`, `prevEntryHashHex`, `chainHeadHashHex`); standard Base64 with `=` padding for `requestDigestBase64` and `receiptDigestBase64`.

### 4.2 Signing

- **Algorithm:** as configured via `gatekeeper.signing.algorithm`. The reference default is `SHA256withRSA` for RSA seals; production NCA deployments using EC seals select `SHA384withECDSA` or per the seal's certified algorithm.
- **Signature encoding:** standard Base64 with `=` padding.
- **Signed input for receipts:** `ReceiptCanonicalizer.canonicalize(VerificationResponse)` — a UTF-8 byte sequence beginning with `v1|`.
- **Signed input for audit entries:** `thisEntryHashHex.getBytes(UTF_8)`. Signing the hex form of the chain hash, rather than the raw 32-byte digest, keeps the signature input identical to what is published in the JSON Lines storage form, which simplifies retroactive verification.
- **Signed input for export bundles:** `AuditExport.canonicalBytesForSignature(...)` — combines `inspectionId`, `generatedAt`, `from`, `to`, `entryCount`, the entries' chain hashes, and the active key fingerprint.

### 4.3 Certificate handling

- **Format:** PEM (`-----BEGIN CERTIFICATE-----` ... `-----END CERTIFICATE-----`), one certificate per blob. The signing certificate is published with its issuer chain via `GET /v1/gatekeeper/keys`.
- **Issuer:** the operator certificate is the NCA's organisation certificate, issued by the CA that the NCA uses for ordinary administrative signing of supervisory acts (typically a domestic CA or eID infrastructure provider). The verifier validates the chain to that issuer using PKIX `CertPathValidator`.
- **Validity:** a forensic verifier checks both `notBefore` / `notAfter` and revocation status (CRL / OCSP) at the time of the original signature, not at the time of verification. A certificate that was valid at signing time and has since expired or been revoked still produces a valid signature.

### 4.4 Cross-repo wire-format compatibility

The financial entity repository (`hsm`) and the gatekeeper repository carry byte-identical canonicalisation logic. This is enforced by the `WireFormatGoldenBytesTest` in each repository, asserting against a literal golden string. A forensic verifier who reproduces the gatekeeper's canonical bytes on their own system must obtain the same bytes the financial entity computed locally — any drift indicates a code-base inconsistency that itself is forensically relevant.

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
