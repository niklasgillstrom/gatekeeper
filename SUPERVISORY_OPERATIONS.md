# Supervisory operations runbook — gatekeeper

This document is written for operational and inspection staff at the National Competent Authority (NCA) that hosts the gatekeeper. In Sweden the NCA is Finansinspektionen (FI), exercising powers conferred by DORA Regulation (EU) 2022/2554 in conjunction with EBA Regulation (EU) No 1093/2010 Articles 17 and 29. The same procedures apply, with terminology adjustments, to any Member State NCA that operates this gatekeeper, and to EBA itself during the transitional phase described in `README.md` "Transitional architecture — EBA to NCA".

This is **not** a developer guide. Developer-facing documentation lives in `README.md`, `PEER_REVIEW_GUIDE.md`, `THREAT_MODEL.md`, and `CROSS_REFERENCE.md`. The audience for the present document is the supervisor who is operating, inspecting, or relying on a deployed gatekeeper instance.

## 1. Purpose

The gatekeeper is the supervisory cross-check that closes the verification gap identified in DORA Regulation (EU) 2022/2554 Article 6(10): a financial entity's local self-attestation does not satisfy the verification obligation, because it is the entity itself certifying its own compliance. The gatekeeper, operated by an authority structurally independent of the supervisee, re-runs the cryptographic checks against the same attestation evidence and signs a receipt that the supervisee retains as falsifiable proof of supervisory acceptance.

This runbook documents the operational responsibilities that come with hosting the gatekeeper:

- Day-to-day operations — making sure the audit log is intact, the seal key is healthy, and the chain anchor is published.
- Inspection procedures — using the supervisory query API to investigate specific cases.
- Forensic procedures — extracting evidence that holds up in legal proceedings.
- Retention policy — how long records are kept and why.
- GDPR considerations — how the audit log interacts with Regulation (EU) 2016/679.
- Legal basis summary — the EU and Swedish provisions that anchor each obligation in this document.

The gatekeeper does not replace any existing supervisory process; it provides cryptographic primitives that those processes can build on. Decisions about when to open an investigation, when to issue a remediation order, and when to escalate to EBA under EBA Regulation (EU) No 1093/2010 Article 17 remain with NCA staff.

### 1.1 Enforcement model — preventive through detection certainty

The classical security-architecture taxonomy (preventive / detective / corrective / deterrent) is a useful first approximation but is too coarse for what the gatekeeper actually does. The architecture operates on three layers simultaneously:

- **Technically, the gatekeeper is detective.** It does not physically block a financial entity (FE) from issuing a certificate without first calling `gatekeeper.verify` and `gatekeeper.confirm`. The FE retains operational control over its own issuing CA, and the gatekeeper has no technical channel into that CA's signing path.
- **Operationally, the gatekeeper is preventive.** The combination of (i) a cryptographically anchored, hash-chained audit log, (ii) cross-source data triangulation against the FE's own issuance register, the technical provider's transaction logs, and the issuing CA's CRL/OCSP, (iii) periodic and unannounced ad-hoc supervisory inspection, and (iv) DORA's sanction architecture (Article 35(6)–(11) periodic penalty payments capped at 1% of average daily worldwide turnover, Article 51 sanktionsavgift up to a percentage of annual turnover under national finance law, license withdrawal under Lag (2004:297) 15 kap. 12 § and Lag (2010:751) 8 kap. 11 §, Article 54 publication) makes the *expected cost* of deviation exceed the *expected benefit* by a margin large enough that rational FE behaviour collapses into compliance. This is preventive at the behavioural and population level: an FE that wishes to remain solvent will not deviate, even though it could.
- **The detection window** is bounded by the inspection cadence. Between two periodic triangulation cycles, an FE *could* in principle issue out-of-protocol certificates that are not yet flagged. Section 3.5 operationalises monthly or quarterly periodic triangulation, complemented by unannounced ad-hoc inspection, to keep this window short and unpredictable.

This is consistent with how DORA's enforcement architecture is constructed:

- **Article 6(10) and Article 28(1)(a)** place the substantive verification duty on the FE, irrespective of outsourcing. Compliance is the FE's obligation; the gatekeeper's role is to make compliance evidenceable.
- **Article 28(6)** mandates a 5-year retention of records that makes non-compliance discoverable for the full window in which sanctions can attach.
- **Articles 50, 51 and 54** confer the supervisor's investigative, sanctioning and publication powers.
- **Article 35(6)–(11)** enables periodic penalty payments that accumulate daily from the date the breach is detected — meaning a breach undetected for six months attracts six months of accumulated penalty once detected, multiplying the cost of any deviation that might briefly escape detection.

A peer reviewer who reduces this to "the gatekeeper does not technically prevent issuance, therefore it is not preventive" is making a category error. The classical taxonomy assumes a single layer of control; here the preventive effect is *emergent* from the combination of cryptographic detection certainty plus sanction severity plus inspection frequency. The same logic underlies, for example, traffic enforcement by camera (technically detective, operationally preventive in the population), market-abuse surveillance under MAR (technically detective, operationally preventive in trading behaviour), and AML transaction monitoring under AMLD6 (same pattern). The gatekeeper applies the same enforcement-architecture pattern to the cryptographic-key compliance domain DORA opens up.

## 2. Daily operations

### 2.1 Monitor audit-log integrity

The gatekeeper exposes `GET /v1/gatekeeper/health`. The response carries a JSON body with three load-bearing fields:

- `auditLogReadable` — `true` iff the gatekeeper can read the audit-log file without I/O error.
- `chainIntact` — `true` iff `AuditLog.verifyChainIntegrity()` walked the entire chain successfully (every entry's `prevEntryHashHex` matched the previous entry's `thisEntryHashHex`, and every `thisEntryHashHex` matched the SHA-256 over the canonical bytes).
- `signingMode` — `configured` for production (real seal certificate from a PKCS#12 keystore) or `ephemeral` for reference deployments (throwaway in-process key, marked `CN=REFERENCE-EPHEMERAL`).

Operational requirements:

- A monitoring pipeline polls `/v1/gatekeeper/health` at least every five minutes. The pipeline raises an alert if `chainIntact=false` or `auditLogReadable=false`.
- If `signingMode=ephemeral` is observed in a production environment, the pipeline raises a P1 alert immediately. A real production deployment must run with `gatekeeper.signing.mode=configured`.
- The alerting destination is whichever incident-response queue the NCA's ICT operations team uses. Finansinspektionen's deployments route to the same on-call queue that handles other regulated supervisory APIs.

### 2.2 Publish the chain anchor

The chain anchor is the gatekeeper's commitment to the audit content as of an instant in time. Publishing the anchor outside NCA-controlled infrastructure makes any subsequent retroactive rewriting of pre-anchor audit entries detectable by anyone who retained the published anchor.

Recommended cadence: **daily**, executed by a cron-driven job at a fixed UTC time. Daily cadence bounds the detection window for retroactive rewriting to one day.

Recommended procedure:

1. The cron job calls `GET /v1/gatekeeper/anchor` against the gatekeeper. The response is a JSON object containing `headSequenceNumber`, `headHashHex`, `headTimestamp`, `headSignatureBase64`, and `activeSigningKeyFingerprintHex`.
2. The job posts the anchor to one or more **independent** publication forums — for instance:
   - A timestamped commit to a transparency log such as Sigstore's Rekor or a privately-operated transparency service.
   - A signed publication to the NCA's public web site, dated and tagged with the inspection identifier.
   - An advert in a newspaper of record on a fixed schedule (this approach has historical precedent; in practice a daily web publication suffices).
3. The job retains the published anchor in a long-term archive that survives media-rotation.

The objective is that an attacker would need to compromise both the gatekeeper's audit file and every publication forum simultaneously in order to rewrite history undetected.

The anchor is signed under the active seal key. Relying parties verify the anchor independently by fetching the active certificate from `GET /v1/gatekeeper/keys` and checking the signature. When the seal key is rotated (Section 2.3), retain the retired certificate so that historical anchor signatures remain verifiable.

### 2.3 Rotate the signing key

Routine rotation, on a documented cadence (annually or per the NCA's signing-certificate lifecycle):

1. Provision the new key pair in the secure key store (HSM where deployed). Issue the new operator certificate from the CA the NCA uses for organisation certificates per its ordinary administrative signing practice (typically a domestic CA or eID infrastructure provider).
2. Add the new keystore path / alias / password to the deployer's secrets-management system.
3. Append the **previous** active certificate's PEM to the `gatekeeper.signing.retired-keys` configuration. This preserves verifiability of receipts and audit entries that were signed under the previous key during the DORA Regulation (EU) 2022/2554 Article 28(6) 5-year retention window.
4. Switch `gatekeeper.signing.keystore-path` and `gatekeeper.signing.key-alias` to the new key. Restart.
5. Verify by issuing a synthetic verify call from a test client and confirming that the receipt is signed under the new key.
6. Publish the new active certificate via the channel the NCA uses to announce supervisory key changes (web page, regulated mailing list, supervisor-portal notice).

Compromise rotation, on the day a compromise is detected:

1. Take the gatekeeper out of service immediately. Do not produce further signatures with the compromised key.
2. Provision a fresh key pair and operator certificate as in routine rotation.
3. **Do not** add the compromised certificate to `gatekeeper.signing.retired-keys` for purposes of trust — the retired-keys list is for historical verifiability of legitimate receipts, not for continued trust of compromised ones. Instead, publish a compromise notice naming the compromised certificate fingerprint and the date from which receipts under that fingerprint must be treated as suspect.
4. Restart the gatekeeper with the new key.
5. Coordinate with relying parties (financial entities holding receipts; supervisors holding exports) to update their trust stores and to flag any receipts under the compromised fingerprint pending re-verification.

The pre-compromise published chain anchors remain meaningful: any audit entry not reachable from a pre-compromise anchor is demonstrably attacker-injected, and any audit entry that is reachable from a pre-compromise anchor is genuine.

## 3. Inspection procedures

### 3.1 A financial entity asserts its receipt is legitimate

Scenario: a financial entity, when challenged about its HSM compliance, presents a gatekeeper-signed `VerificationResponse` and claims the gatekeeper authorised its issuance. The supervisor's task is to verify that claim independently.

Procedure:

1. Obtain the receipt from the financial entity in its original signed form. Record the receipt's `verificationId`.
2. Call `GET /v1/audit/witness/{verificationId}` against the gatekeeper. The response is the `AuditEntry` for that decision (`requestDigestBase64`, `receiptDigestBase64`, `compliant`, `mtlsClientPrincipal`, etc.) or a `404` if no such entry exists.
3. If the audit entry is absent, the receipt is forged or the verification ID is wrong. Do not trust the receipt; treat the situation as either an investigation lead (a forged receipt was presented as legitimate) or a clerical error.
4. If the audit entry is present, recompute SHA-256 over the receipt body the financial entity presented. Compare the digest to `receiptDigestBase64` in the audit entry. They must match.
5. Verify the receipt's `signature` against the operator certificate. Fetch the operator certificate via `GET /v1/gatekeeper/keys` (use the certificate matching the receipt's `signingCertificate` fingerprint, including retired keys). The signature must verify under the receipt's canonical bytes.
6. If steps 4 and 5 both succeed, the receipt is genuine and matches the supervisory record. The supervisor's substantive question — whether the underlying HSM evidence in fact justifies the COMPLIANT determination — is a separate matter, but the cryptographic chain of evidence is sound.

### 3.2 Suspected systemic problem with a technical supplier

Scenario: a Swish technical supplier (TL) is suspected of issuing certificates without proper attestation, or of forwarding the same attestation evidence for multiple distinct keys.

Procedure:

1. Identify the supplier's mTLS principal (the DN of the client certificate they use to call the gatekeeper). For a Swedish TL this is typically `CN=<TL legal name>,O=<TL legal name>,SERIALNUMBER=<TL org number>`.
2. URL-encode the principal. Call `GET /v1/audit/entity/{principal}` against the gatekeeper. The response is the full chronological sequence of audit entries attributable to that principal.
3. Inspect the entries. Anomalies to look for:
   - Repeated identical `requestDigestBase64` across different `verificationId` values — the same attestation evidence reused for distinct keys.
   - Sudden bursts of NON-COMPLIANT decisions followed by COMPLIANT decisions in the same window — possible attempts to game the verifier.
   - Large gaps in timestamp followed by clustered activity — possible after-hours batch issuance.
4. Cross-reference with the financial entity's records via the Phase 1 / Phase 2 / Phase 3 reconciliation procedure described in `README.md` Section 4.1.
5. If sufficient grounds exist, escalate to the formal investigation track under DORA Regulation (EU) 2022/2554 Article 50 and, where appropriate, EBA Regulation (EU) No 1093/2010 Article 17.

### 3.3 Period inspection

Scenario: the NCA's annual supervisory plan calls for a full review of all gatekeeper decisions in a calendar quarter.

Procedure:

1. Compute the inspection's calendar window in UTC (for example, `2026-01-01T00:00:00Z` to `2026-04-01T00:00:00Z`).
2. The audit-query API caps a single `range` query at 90 days; for a calendar quarter this is exactly the limit. For longer windows, issue multiple successive queries.
3. Call `GET /v1/audit/export?from=...&to=...&inspectionId=<NCA case id>` against the gatekeeper. The supervisor passes the NCA's own case identifier (for example `FI-2026-001`) so that the export bundle is bound to the inspection record.
4. Retain the response body as inspection evidence. The `AuditExport` JSON contains the full list of audit entries in the window, the chain-head hash at the moment of export, the active signing key fingerprint, and the gatekeeper's signature over the canonical bytes of the export.
5. To verify the export later: recompute the canonical bytes via `AuditExport.canonicalBytesForSignature(...)` and verify the signature against the active certificate (obtained from `GET /v1/gatekeeper/keys` at the time of export, retained as part of the inspection record).

### 3.4 EBA Article 17 investigation

Scenario: EBA invokes the breach-of-Union-law procedure under EBA Regulation (EU) No 1093/2010 Article 17(2), and requires NCA-held records to determine whether and how the supervisory failure occurred.

Procedure:

1. Coordinate the request with EBA's investigating team. Establish the scope: time window, jurisdictions, supervisees in scope.
2. For each supervisee, run the Section 3.2 procedure (per-entity history). For each time window, run the Section 3.3 procedure (signed export).
3. Bundle all signed exports plus the corresponding `GET /v1/gatekeeper/keys` snapshots into a forensic evidence package per `FORENSIC_INSPECTION.md`.
4. Sign the forensic package under the NCA's own organisation-certificate-backed signing key, separately from the gatekeeper's seal — the supervisor's signature commits the supervisor to the package's contents; the gatekeeper's signature commits the gatekeeper to the audit-export's contents.
5. Submit to EBA via the supervisor-cooperation channel established under EBA Regulation (EU) No 1093/2010 Article 35(1).

### 3.5 Periodic data triangulation

Scenario: the NCA's supervisory plan calls for routine cross-source verification that every certificate issued by every supervisee carries a matching gatekeeper receipt. This is the principal procedure for detecting Article 6(10) breaches — FEs that fail to call `verify`/`confirm` before issuance — and is the operational realisation of the detective-enforcement model set out in Section 1.1.

**Cadence:**

- **Baseline triangulation:** monthly recommended, quarterly minimum. Automate the cross-source query so the supervisor does not have to recompose it manually each cycle. The supervisor's case-management system records each cycle's run, hash of the input data, and the outcome (no candidates / N candidates / breaches confirmed) so that the periodic activity itself is auditable.
- **Ad-hoc direct inspection:** at any time, on any subset of supervisees, without notice. The unpredictability of ad-hoc inspection is the deterrent that makes the periodic baseline credible — an FE that times its non-compliance to the periodic cycle gains nothing if a direct inspection can land mid-cycle.

Specific cadence is a supervisory-policy decision under DORA Article 50, not a regulatory minimum. Member State practice will likely converge on monthly or quarterly once Article 41 RTS supplements the basic provisions.

**Data sources to triangulate:**

1. **Gatekeeper audit log.** Run `GET /v1/audit/range?from=...&to=...&inspectionId=...` to extract every `verify` and `confirm` entry in the period. Each entry includes the attestation key fingerprint and (for `confirm`) the issued cert serial number.
2. **FE's own issuance register** (DORA Article 28(6) plus Bokföringslagen (1999:1078) 7 kap.). Request from the FE under DORA Article 50(1)(a): list of every cert the FE issued in the period, including key fingerprint, cert serial number, and issuance timestamp.
3. **Technical provider's transaction logs** (where applicable; in the Swish architecture this is GetSwish AB's payment-transaction record). For each cert serial, the technical provider produces the list of payment transactions signed under it. Used for proportionality assessment under Article 51(2), not for breach detection itself.
4. **CRL/OCSP data from the issuing CA.** Independent record of which cert serial numbers were actually issued.

**Triangulation procedure:**

1. From source (2), enumerate every certificate the FE claims to have issued in the period.
2. For each cert, look up the matching `verify`+`confirm` pair in source (1) by key fingerprint and cert serial.
3. Flag every cert in source (2) without a matching pair in source (1). These are the candidate breaches.
4. Cross-check candidates against source (4): does the issuing CA's CRL/OCSP confirm the cert was actually issued? If yes, the breach is confirmed.
5. For each confirmed breach, optionally consult source (3) to determine whether the breaching cert was used to sign payment transactions. This goes to proportionality of sanction under Article 51(2), not to whether a breach occurred.

**Action on confirmed breach (sanction trappstegen):**

| Severity trigger | Instrument | Legal basis |
| --- | --- | --- |
| Single occurrence, not used in production traffic | Anmärkning + remediation order with deadline | DORA Article 50(1)(c); Förvaltningslag (2017:900) |
| Systematic or repeated breach | Sanktionsavgift (administrative penalty) | DORA Article 51; Lag (2010:751) 8 kap.; Lag (2004:297) 15 kap.; Lag (2007:528) 23 kap. |
| Continuing non-compliance after remediation order | Periodic penalty payments accumulating daily from breach detection (max 1% of average daily worldwide turnover per day) | DORA Article 35(6)–(11) |
| Severe systemic breach | License withdrawal | Lag (2004:297) 15 kap. 12 §; Lag (2010:751) 8 kap. 11 § |
| Any sanction imposed | Publication on supervisor's website | DORA Article 54 |

The trigger thresholds for moving up the trappa (e.g. ≥ 3 unmatched certs in one quarter, ≥ 1 unmatched cert with confirmed payment usage) are supervisory-policy decisions and should be documented in the NCA's internal sanctions-policy guidance separately from this runbook.

### 3.6 Settlement-time signature verification (since v1.2.0)

Scenario: the central-bank settlement-rail operator (Sveriges Riksbank for RIX-INST) deploys the railgate companion artefact in front of the settlement pipeline. For every regulated payment, railgate retrieves the SHA-512 digest, signature, and certificate identifiers from the payment-network operator (Getswish AB in the Swedish reference deployment) and submits them to the gatekeeper's `POST /api/v1/verify` endpoint at settlement time.

**Operational responsibilities of the NCA:**

- **Provision a `SETTLEMENT_RAIL`-role mTLS certificate** to the settlement-rail operator (typically the central bank) following the role-mapping convention in `DEPLOYMENT.md` §4. This certificate authorises the settlement-rail clients to call `/api/v1/verify`.
- **Monitor the rate of `CERT_NOT_FOUND` and `SIGNATURE_INVALID` decisions.** A sudden rise indicates either (a) an issuance flow that is bypassing gatekeeper (a breach detection signal), or (b) a settlement-rail integration regression. Either case warrants supervisory follow-up.
- **Reconcile the gatekeeper audit log against the settlement-rail logs.** The settlement-rail operator's logs of allowed/denied settlements must reconcile with the gatekeeper audit-entry references returned in the `auditEntryId` field. Discrepancies indicate either log-tampering or mTLS-replay incidents.
- **Coordinate with the central bank under DORA Article 32 (oversight forum).** Settlement-time enforcement is a joint operational responsibility; the gatekeeper holds the compliance state, the settlement rail holds the enforcement chokepoint.

**Data minimisation envelope.** The supervisor never receives transaction payload content via `/api/v1/verify`. The endpoint contract is intentionally limited to cryptographic artefacts. The supervisor's ICT-third-party-data-processing register under DORA Article 28(3) should reflect this scope explicitly: for the settlement-time verification function, only digests, signatures, and certificate identifiers are processed.

**Latency expectations.** `POST /api/v1/verify` must return well within the settlement deadline of the underlying rail (RIX-INST: sub-second; TIPS: typically under 10 seconds end-to-end). The reference implementation completes the verification in single-digit milliseconds against an in-memory registry; production deployments using the file-backed `AppendOnlyFileApprovalRegistry` should benchmark before SLA commitments.

## 4. Forensic procedures

For full procedural detail, see `FORENSIC_INSPECTION.md`. This section summarises the operational entry points.

### 4.1 Extract court-admissible evidence

When evidence is required for a court proceeding (administrative, civil, or criminal):

1. Identify the verification IDs in scope.
2. Pull each `AuditEntry` via `GET /v1/audit/witness/{verificationId}`.
3. Pull the chain-anchor at the moment of extraction via `GET /v1/gatekeeper/anchor`. This commits the gatekeeper to the state of the audit log at the extraction instant — even if subsequent audit entries are added, the anchor pins the present.
4. Pull `GET /v1/gatekeeper/keys` to record the certificates needed to verify the entry signatures and the anchor signature.
5. Bundle into a forensic package and seal it under the NCA's own organisation-certificate-backed signing key as in Section 3.4.

### 4.2 Cryptographic primitives bound into the evidence

The forensic package must, for each piece of cryptographic content, also bundle the verification primitives:

- `SHA256withRSA` (or whichever algorithm `gatekeeper.signing.algorithm` is set to) — the operator certificate's signature scheme.
- The operator certificate as a PEM blob, with its issuer chain.
- The hash-chain SHA-256 over the canonical bytes (`AuditEntry.canonicalBytesForHash`).
- The hex / Base64 encoding conventions used in the API (hex lower-case 64-char hashes, standard Base64 with `=` padding for signatures).

A court expert or opposing counsel must be able to recompute every digest and verify every signature independently of the NCA's tooling. For that reason the forensic package is plain JSON and PEM, never NCA-proprietary serialisation.

### 4.3 Sample chain of custody

Each forensic extraction must record:

- Time of extraction (UTC).
- Identity of the operator who performed the extraction (NCA staff member, role, employee identifier).
- Source: gatekeeper hostname, deployment environment (production / staging / test).
- Hash of the extracted bundle (SHA-256 hex of the bundle bytes).
- Storage location (write-once media, archival vault) with custody record.
- Onward custody log: every transfer, every decryption, every signature, with operator + timestamp.

The chain-of-custody record is itself signed by the NCA's organisation-certificate-backed signing key at sealing time and at every onward transfer.

## 5. Retention policy

The retention policy is **layered**: a statutory minimum from DORA, a statutory maximum from DORA itself for personal-data fields, and a practical band between them set by Swedish administrative law and the criminal statute of limitations.

### 5.1 Statutory minimum — 5 years

DORA Regulation (EU) 2022/2554 Article 28(6) requires retention of records relating to ICT third-party service providers for at least **5 years**. Gatekeeper receipts and the corresponding audit-trail entries are precisely such records — they document the supervisory verification of an ICT service that supports critical or important functions. Operators must not reduce retention below 5 years.

### 5.2 Statutory maximum — 15 years for personal data

DORA Regulation (EU) 2022/2554 Article 56(2) caps the retention of personal data held by competent authorities (and by entities acting under their supervisory mandate) at **15 years** unless ongoing judicial proceedings require further retention. Audit-log entries that contain personal data — see Section 6 for the field-by-field analysis — must therefore be either deleted, anonymised or migrated to litigation-hold storage at the 15-year mark.

### 5.3 Practical retention band

Within the 5–15-year window the gatekeeper applies a layered policy to the audit log:

- **Layer A — entries with no personal-data fields** (the typical case: audit entries whose `mtlsClientPrincipal` is an organisational DN with no personal name, and which carry only request and receipt digests). These are governed only by DORA Article 28(6) and parallel domestic obligations. The recommended retention is **7 years**, set in `gatekeeper.audit.retention-years`. Rationale: aligns with the Bokföringslag (1999:1078) 7-year requirement for business records, and covers the most common bands of Brottsbalken (1962:700) preskriptionstid for relevant economic crimes (5–10 years for most relevant categories).
- **Layer B — entries that contain personal data** (audit entries whose `mtlsClientPrincipal` includes a natural-person name, or any entry that legitimately carries other personal data). These are governed by both DORA Article 28(6) (≥ 5 years) and DORA Article 56(2) (≤ 15 years). The retention window therefore is **5–15 years**, with the actual value set by the deployer based on the type of supervisory case the entry might support. A deployer may default to 7 years for parity with Layer A and extend on a case-by-case basis when an active proceeding requires it.
- **Layer C — entries under an active litigation hold or under an active supervisory investigation** are exempt from the upper bound and retained until the proceeding closes. After the proceeding closes, entries return to either Layer A or Layer B depending on their personal-data status.

The gatekeeper exposes the default retention via `gatekeeper.audit.retention-years` (default 7). The operator must additionally implement Layer-B and Layer-C overrides through operational procedure, since the gatekeeper does not by itself classify entries as containing personal data.

### 5.4 Retention versus storage limitation

GDPR Regulation (EU) 2016/679 Article 5(1)(e) requires that personal data not be kept longer than necessary. DORA Article 28(6) provides the lawful basis for retention up to its 5-year minimum and the practical 7-year band; DORA Article 56(2) provides the lawful basis for retention beyond that, up to 15 years, where supervisory necessity persists. Where a data subject invokes GDPR Article 17, the supervisory retention exception in Article 17(3)(b) ("compliance with a legal obligation") applies for the period during which the DORA retention is itself a legal obligation. Article 23 GDPR additionally permits Member State law to restrict GDPR rights for supervisory purposes; Sweden has activated this restriction through the Cybersäkerhetslag (2025:1506) and the broader financial-supervisory framework.

The position adopted by this runbook is that the layered DORA Article 28(6) / Article 56(2) policy described above is itself the operationalisation of GDPR Article 5(1)(e) for this gatekeeper. The deployer's data-protection officer must verify this position against the DPIA conducted before deployment, with particular attention to whether the deployer's actual mTLS-principal namespace ever produces Layer-B entries.

## 6. GDPR considerations

### 6.1 What personal data may appear in the audit log

The `AuditEntry` record carries the following potentially-personal fields:

- `mtlsClientPrincipal` — the DN of the mTLS client certificate. For organisational certificates this is normally not personal data (legal-person attributes only). For natural-person certificates it can be personal data.
- `verificationId` — a UUID. Not personal data on its own; can become personal in combination with other records.
- `requestDigestBase64`, `receiptDigestBase64` — SHA-256 digests. Not personal data; they are one-way functions of input.
- `compliant` — a Boolean. Not personal data on its own.

Personal numbers (Swedish personnummer) are **never** stored in the audit log. The financial-entity-side flow does carry personal numbers (BankID is keyed on personal number), but those are masked at the boundary (`maskPersonalNumber()` in the sibling repo) and are never forwarded to the gatekeeper.

Operators must verify, on every change to the gatekeeper's data flow, that the audit log does not begin to receive personal numbers. This is a structural property guarded by code review and by the audit-entry record's typed fields, but it warrants periodic confirmation.

### 6.2 The right to erasure versus DORA retention

A data subject may invoke GDPR Article 17 (right to erasure). The gatekeeper's response, coordinated with the NCA's data-protection officer:

- Identify which audit entries (if any) carry personal data attributable to the data subject.
- For each entry, determine whether the supervisory retention exception (GDPR Article 17(3)(b)) applies. For DORA-recorded events the answer is normally yes for the duration of the retention window.
- Where the supervisory exception applies, document the position and notify the data subject of the lawful basis.
- Where it does not (e.g. an entry was created in error and the retention obligation does not attach), erase the entry. Because the audit log is hash-chained, "erasure" in the cryptographic sense is not possible — a deletion record is appended that voids the original entry, and the chain head moves forward. The original `thisEntryHashHex` remains a fixed point in the chain so that prior anchors remain valid; the deletion record is the supervisory acknowledgement that the content is no longer to be relied upon.

### 6.3 Cross-border data transfer

Where the gatekeeper is consulted from another Member State (under EBA Regulation (EU) No 1093/2010 Article 35(1) supervisory cooperation), the cross-border transfer is intra-EU and GDPR Chapter V transfer rules do not engage. Transfers to third countries (for example, where a Swedish supervisee's TL is established outside the EEA) require either an adequacy decision under GDPR Article 45 or appropriate safeguards under Article 46.

## 7. Legal basis summary

The following EU and Swedish provisions anchor the obligations and powers exercised through this gatekeeper. Operators must reference the consolidated text in force at the time of any specific supervisory action; this list is for orientation, not for citation in formal decisions.

### 7.1 EU primary and secondary law

- **DORA — Regulation (EU) 2022/2554 of the European Parliament and of the Council of 14 December 2022** on digital operational resilience for the financial sector. Operative provisions for this gatekeeper:
  - Article 5(2)(b) — management body responsibility for authenticity and integrity standards.
  - Article 6(1) — sound, comprehensive ICT risk management framework.
  - Article 6(10) — financial entity remains fully responsible for verification of compliance.
  - Article 9(3)(c) and 9(3)(d) — prevent impairment of authenticity and integrity; protection from poor administration.
  - Article 9(4)(d) — strong authentication mechanisms; dedicated control systems.
  - Article 17 — incident reporting windows.
  - Article 19 — substantial incident reports.
  - Article 28(1)(a) — full responsibility irrespective of outsourcing.
  - Article 28(6) — 5-year retention with discoverable verifiability.
  - Article 29 — concentration risk; full monitoring of outsourced functions.
  - Article 30(2)(c) — contractual provisions on authenticity, integrity, confidentiality of data.
  - Article 32 — Oversight Forum functions.
  - Article 35 — Lead Overseer powers.
  - Article 46 — competent-authority monitoring obligation.
  - Article 50 — competent-authority remediation powers.
- **EBA Regulation — Regulation (EU) No 1093/2010 of the European Parliament and of the Council of 24 November 2010**:
  - Article 1(2) — EBA's mandate to ensure consistent application of Union law in the financial sector.
  - Article 16 — guidelines and recommendations (comply or explain).
  - Article 17 — breach-of-Union-law procedure (paragraphs 1 through 6).
  - Article 18 — crisis mechanism.
  - Article 29 — supervisory convergence.
  - Article 35(1) — supervisory cooperation; access to records.
  - Article 61(3) — passivity remedy before the Court of Justice (TFEU Article 265).
- **GDPR — Regulation (EU) 2016/679 of the European Parliament and of the Council of 27 April 2016**:
  - Article 5(1)(e) — storage limitation principle.
  - Article 17 — right to erasure.
  - Article 17(3)(b) — supervisory-purpose exception to erasure.
  - Article 23 — Member State restrictions.
  - Articles 45 and 46 — cross-border transfer rules.
- **NIS2 — Directive (EU) 2022/2555 of the European Parliament and of the Council of 14 December 2022** — Article 21(2)(g) and 21(2)(h) (cryptographic policies), Article 23 (incident reporting). Note that NIS2 is a directive transposed into Member State law; the Swedish transposition is the Cybersäkerhetslag (2025:1506).
- **CRA — Regulation (EU) 2024/2847 of the European Parliament and of the Council of 23 October 2024** on horizontal cybersecurity requirements for products with digital elements, Annex I (secure-by-design + secure-by-default).
- **AMLA Regulation — Regulation (EU) 2024/1620 of the European Parliament and of the Council of 31 May 2024** transferring AML supervisory competence to the Anti-Money Laundering Authority. The audit-log evidence base supports both the DORA and AML supervisory tracks.

### 7.2 Swedish law

- **Cybersäkerhetslag (2025:1506)** — the Swedish transposition of NIS2. Establishes Swedish supervisory powers and the procedural framework for the NCA's intervention.
- **Förvaltningslag (2017:900)** — the general administrative-law framework that governs how Finansinspektionen conducts supervisory proceedings, including the procedural rights of supervisees.
- **Offentlighets- och sekretesslag (2009:400)** — the Public Access to Information and Secrecy Act. Determines how supervisory records are classified and how access requests under the principle of public access to official documents are handled.
- **Lag (2004:297) om bank- och finansieringsrörelse** and adjacent banking-supervision statutes — substantive grounds on which supervisory decisions about Swish-issuing banks rely.

### 7.3 Treaty law

- **Article 4(3) TEU** — sincere cooperation; Member States ensure fulfilment of Union law obligations.
- **Article 258 TFEU** — Commission infringement proceedings.
- **Article 265 TFEU** — failure-to-act proceedings, available against EBA via EBA Regulation Article 61(3).
- **Article 288 TFEU** — direct applicability of regulations; DORA Regulation (EU) 2022/2554 applies directly without national transposition.

---

The gatekeeper's purpose, ultimately, is to make the supervisory verification obligation in DORA Regulation (EU) 2022/2554 Article 6(10) cryptographically falsifiable. Every operational, inspection, forensic, retention, and legal step in this runbook exists to keep that property intact end-to-end: from the moment a financial entity submits attestation evidence to the moment a supervisor demonstrates, in a court of law, that the supervisory record is what it claims to be. Operators of this gatekeeper bear that responsibility; this document is the procedural map.
