# NCA / EBA HSM Attestation Verification Gatekeeper

Independent verification tool for cryptographically verifying whether financial entities comply with DORA requirements for HSM-based key protection — without requiring the entity's cooperation.

**Operator model.** The primary operator is the National Competent Authority (NCA); in Sweden this is Finansinspektionen (FI). EBA does not operate the gatekeeper itself under a stable equilibrium: EBA's DORA-relevant powers under Regulation (EU) No 1093/2010 are supervisory convergence (Article 29) and investigation of breach of Union law (Article 17). EBA receives read-only access to the NCA's approval registry under those provisions. A transitional EBA-operated phase is provided for in Section "Transitional architecture — EBA to NCA" below, activated when an NCA's supervisory failure makes direct EBA action under Article 17(6) necessary, and reverted when the NCA has demonstrated equivalent verification capability.

**Academic foundation:** Gillström, N., *Verifieringsansvar för kryptografiska nycklar i betalinfrastruktur — En rättsdogmatisk fallstudie av kontraktuell riskallokering och DORA-förordningens krav på IKT-riskhantering*, bachelor's thesis in Commercial Law (*examensarbete i handelsrätt C*, 15 ECTS), Department of Law, Uppsala University, Spring 2026. Supervised by a Docent (Associate Professor) and former Senior Adviser (*ämnesråd*) at the Financial Markets Division of the Swedish Ministry of Finance, whose assessment stated that the conclusions are *befogade* — a Swedish legal term denoting that the conclusions are justified on the merits of the legal analysis. The thesis demonstrates through systematic legal analysis that contractual HSM requirements without verification mechanisms do not satisfy DORA. The legal definition below follows the thesis's argument structure.

---

## Documentation map

| Document | Audience | Purpose |
| --- | --- | --- |
| `README.md` (this file) | Everyone | Legal definition, architectural overview, transitional EBA→NCA framing |
| `DEPLOYMENT.md` | NCA systems engineer | Single deployment checklist: prerequisites, keystores to provision, environment variables, bring-up sequence, role-mapping override, pre-production checklist |
| `SUPERVISORY_OPERATIONS.md` | NCA / FI inspection staff | Daily ops, periodic data triangulation, inspection procedures, retention policy, GDPR considerations, legal-basis summary |
| `FORENSIC_INSPECTION.md` | Forensic / inspection officer | Court-admissible evidence extraction, chain-of-custody, signed-export workflow |
| `THREAT_MODEL.md` | Security reviewer, peer reviewer | Adversary model, mitigations, residual risks, enforcement model |
| `PEER_REVIEW_GUIDE.md` | Academic peer reviewer | What the repo is and isn't, build-and-test, reproducible assertions, known limitations |
| `CROSS_REFERENCE.md` | Peer reviewer, deployer | Article-claim ↔ code-path mapping; honest GAP flags for what is and is not yet executable |
| `e2e/README.md` | Peer reviewer, NCA | Local end-to-end test that starts gatekeeper, hsm and railgate and drives the real flow between them |

---

## Legal Definition

### 1. The Verification Gap in DORA's Contractual Framework

DORA and its delegated regulation (EU) 2024/1773, Article 3(6)(b), require that contractual arrangements for ICT services supporting critical functions include provisions on cryptographic controls. The deficiency is not the absence of contractual requirements — which DORA mandates — but the absence of verification that those requirements are met. This distinction is not specific to the case study below: any financial entity in the EU that includes contractual cryptographic security requirements, as DORA requires, but does not verify compliance faces the same structural deficiency.

**Case study: Swish Utbetalning.** Six Swedish major banks collectively own GetSwish AB, which provides infrastructure for digitally signed payment instructions. The banks' contractual terms require that signing keys are managed in Hardware Security Modules (HSM), whether handled by the corporate customer directly or by their technical supplier, satisfying the formal contractual requirement under DORA. No mechanism exists to verify that any party in the chain complies. However:

- **No verification has ever occurred.** Neither the banks nor GetSwish AB have verified HSM usage for any customer or technical supplier in the years the service has been operational. The system does not distinguish between signing and transport certificates at issuance — a customer can create multiple signing certificates and switch between them without restriction. Verification at each certificate issuance, which is what DORA requires, is not implemented and cannot be performed within the current system architecture. GetSwish AB has confirmed in writing that it does not use the open source reference implementation for HSM attestation verification — and since no alternative verification mechanism exists, no verification of any kind occurs.
- **The digital signature is immediately binding.** A signed payment order is irrevocable — there is no secondary verification, no manual approval process, and no possibility of intervention after signing.
- **The signing key is the sole security barrier.** A compromised key gives immediate, irrevocable access to the customer's funds up to the daily transaction limit.
- **At least one actor complies — but is not verified.** At least one technical supplier in the Swish ecosystem uses HSM in accordance with DORA's requirements and can provide independently verifiable cryptographic attestation proof. This attestation can be verified by EBA without the actor's cooperation. Yet neither the banks, GetSwish AB, nor the NCA (Finansinspektionen) have ever requested or verified this proof. This establishes that compliance is achievable, that the verification mechanism functions, and that the supervisory failure is complete — even compliant actors are not verified.

### 2. The Supervisory Method Gap

A principles-based supervisory method that examines whether contractual requirements exist — but not whether they are met — cannot detect non-compliance in cases where the only independently verifiable proof of compliance is cryptographic. DORA requires financial entities to ensure authenticity and integrity, not merely to contractually require it.

### 3. Regulatory Basis — Systematic Interpretation of DORA

The thesis applies EU legal methodology — examining wording, context, and objectives — to construct the applicable law. The following provisions form a coherent system that presupposes actual control mechanisms, not merely formal contractual requirements:

#### 3.1 Governance and Ultimate Responsibility

| DORA Provision | Requirement | Significance for Verification |
|---|---|---|
| **Article 5(2)(a)** | The management body shall bear the **ultimate responsibility** for managing the financial entity's ICT risk. | The management body bears ultimate responsibility for ICT risk management, which includes verifying that security requirements the bank itself has imposed — such as HSM usage — are actually met. This responsibility cannot be discharged by placing the requirement in a contract and relying on the customer's compliance without verification. |
| **Article 5(2)(b)** | The management body shall put in place policies that aim to ensure the maintenance of **high standards of availability, authenticity, integrity and confidentiality, of data**. | DORA requires that contractual arrangements include provisions on cryptographic controls — the banks' HSM requirement satisfies this obligation. However, maintaining "high standards" of authenticity and integrity requires both the contractual requirement and verification of its implementation. Without attestation verification, the infrastructure cannot distinguish between a signing key protected inside an HSM — which by design cannot be copied — and a software-generated key that may have been compromised. |
| **Article 5(3)** | Financial entities, other than microenterprises, shall establish a role in order to monitor the arrangements concluded with ICT third-party service providers on the use of ICT services, or shall designate a member of senior management as responsible for overseeing the related risk exposure and relevant documentation. | Monitoring presupposes that there is something to monitor — an actual control mechanism. A contractual requirement without follow-up does not satisfy this. Article 9(4)(a) confirms that this obligation extends to customers where applicable — and where the bank's own contractual terms require HSM usage, it is applicable. |

#### 3.2 The ICT Risk Management Framework — Verification Obligation

| DORA Provision | Requirement | Significance for Verification |
|---|---|---|
| **Article 6(1)** | Financial entities shall have a sound, comprehensive and well-documented ICT risk management framework as part of their overall risk management system, which enables them to address ICT risk quickly, efficiently and comprehensively and to ensure a high level of digital operational resilience. | The framework must be substantive, not formal. Recital 21 confirms this: "comprehensive capacity enabling a **robust and efficient** ICT risk management." |
| **Article 6(2)** | The ICT risk management framework shall include the strategies, policies, procedures, ICT protocols and tools that are necessary to duly and adequately protect all information assets and ICT assets [...] in order to ensure that all information assets and ICT assets are adequately protected from risks including damage and **unauthorised access or use**. | A compromised signing key enables precisely the unauthorised access or use this provision targets. |
| **Article 6(10)** | Financial entities may, in accordance with Union and national sectoral law, outsource the tasks of verifying compliance with ICT risk management requirements to intra-group or external undertakings. In case of such outsourcing, **the financial entity remains fully responsible for the verification of compliance with the ICT risk management requirements**. | The grammatical construction — "the verification" in the definite form, not "any verification" — presupposes linguistically that verification takes place. The provision regulates **who** bears responsibility for a verification that is presupposed to occur. The same construction is present across three equally authentic language versions: English ("the verification of compliance"), French ("la vérification du respect"), Swedish ("kontrollen av efterlevnaden"). The convergence excludes that the definite form is a translation artefact. It is further legally significant that the Swedish version uses "kontroll" where the English and French versions use "verification" / "vérification": the translation choice places the provision within the Swedish legislative tradition concerning supervisory and control responsibility, where "kontroll" carries implications of continuous review activity rather than one-off ascertainment. |

#### 3.3 Protection and Prevention — Strong Authentication Mechanisms

| DORA Provision | Requirement | Significance for Verification |
|---|---|---|
| **Article 9(2)** | Financial entities shall design, procure and implement ICT security policies, procedures, protocols and tools that aim to ensure the resilience, continuity and availability of ICT systems, in particular for those supporting critical or important functions, and to maintain high standards of availability, authenticity, integrity and confidentiality of data, whether at rest, in use or in transit. | Sets the standard against which Articles 9(3) and 9(4) must be assessed. |
| **Article 9(3)** | In order to achieve the objectives referred to in paragraph 2, financial entities shall use ICT solutions and processes that are appropriate **in accordance with Article 4**. | The proportionality assessment under Article 4 is incorporated directly into Article 9(3). This means that the choice of ICT solution must satisfy proportionality **before** being assessed against 9(3)(a)-(d). |
| **Article 9(3)(b)** | Minimise the risk of corruption or loss of data, unauthorised access and technical flaws that may hinder business activity. | A manual process does the opposite — it introduces the risks it should minimise. |
| **Article 9(3)(c)** | **Prevent** the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data. | The verb is "prevent" — not "minimise," not "manage." An entity that chooses a manual process over an automated solution does not *prevent* the impairment of authenticity and integrity — it *permits* it by deliberately choosing a method with inherent weaknesses. |
| **Article 9(3)(d)** | Ensure that data is protected from risks arising from data management, **including poor administration, processing-related risks and human error**. | An entity that identifies a risk, formulates a countermeasure (HSM requirement), but fails to verify compliance exhibits poor administration. Choosing a manual process over an automated one introduces all three listed risk categories simultaneously. |
| **Article 9(4)(a)** | Develop and document an information security policy defining rules to protect the availability, authenticity, integrity and confidentiality of data, information assets and ICT assets, **including those of their customers, where applicable**. | The legislature explicitly anticipated situations where the bank's obligations extend to the customer's technical environment. This excludes the interpretation that the bank's obligations under Article 9 are limited to internal matters. |
| **Article 9(4)(d)** | Implement **policies and protocols for strong authentication mechanisms**, based on relevant standards and **dedicated control systems**, and protection measures of cryptographic keys whereby data is encrypted based on results of approved data classification and ICT risk assessment processes. | Digital signing is an authentication mechanism. The requirement that it be "strong" means it must actually provide authenticity, not merely give the appearance of it. The requirement for "dedicated control systems" means there must be mechanisms to verify that the authenticity guarantee is maintained. The explicit reference to "protection measures of cryptographic keys" directly addresses the HSM verification question. |

#### 3.4 The Reversed Proportionality Argument

The proportionality principle (Article 4, incorporated via Article 9(3)) can be applied in reverse: since Article 9(3) expressly prescribes that the ICT solutions applied shall be appropriate in accordance with Article 4, a proportionality assessment means that an entity that chooses a manual process with inherent error risk over an available automated solution neither prevents the impairment of authenticity and integrity within the meaning of Article 9(3)(c), nor ensures the protection from poor administration, processing-related risks and human error required by Article 9(3)(d).

The proportionality assessment for HSM attestation verification:

- **Appropriateness:** HSM attestation directly verifies the security requirement — it is suited to achieve the goal.
- **Necessity:** No less intrusive alternative provides equivalent independently verifiable assurance (physical inspection is disproportionate, self-declaration lacks independence, third-party audit provides only point-in-time assurance, software attestation can be modified by the entity being verified and lacks the independently verifiable guarantees of a certified HSM).
- **Proportionality in the strict sense:** The service is critical, the risk at compromise is high (immediate irrevocable access to funds), and the verification cost is negligible (attestation is built into the HSMs the contractual terms already presuppose). Attestation capability is specified as a requirement in FIPS 140-2 Level 3, FIPS 140-3 Level 3 and Common Criteria EAL 4+, independently verifiable via NIST CMVP and certified evaluation reports.

An entity cannot claim that verification is disproportionate when the attestation functionality is built into the hardware the entity's own contractual terms require, the verification is a single check at certificate issuance, and the alternative (no verification) means the entity does not know whether its own security mechanism functions. Furthermore, without verification, the entity cannot fulfil its obligation under Article 19 to detect and report ICT-related incidents — a compromised signing key that was never HSM-protected is an incident the entity has no means of discovering. With HSM attestation verification at certificate issuance, a single check provides a cryptographic proof that remains valid for the lifetime of the certificate — the mathematical guarantee requires no ongoing monitoring.

#### 3.5 Full Responsibility in Contractual Arrangements

| DORA Provision | Requirement | Significance for Verification |
|---|---|---|
| **Article 28(1)(a)** | Financial entities that have in place contractual arrangements for the use of ICT services to run their business operations shall, **at all times**, remain **fully responsible** for compliance with, and the discharge of, all obligations under this Regulation and applicable financial services law. | The formulations are absolute. "At all times" and "fully responsible" leave limited semantic space for the qualifications that a permissive interpretation would require. A contractual risk allocation cannot relieve the bank of its regulatory obligations. |
| **Article 28(1)(b)** | Financial entities' management of ICT third-party risk shall be implemented in light of the **principle of proportionality**, taking into account the nature, scale, complexity and importance of ICT-related dependencies, and the risks arising from contractual arrangements, taking into account the **criticality or importance** of the respective service and **the potential impact on the continuity and availability** of financial services. | See Section 3.4 above — proportionality favours stricter control when the service is critical, risk is high, and verification cost is negligible. |
| **Article 28(5)** | Financial entities shall only enter into contractual arrangements with providers that comply with appropriate information security standards. | Presupposes that the financial entity **can assess** whether the provider complies — which in turn presupposes some form of control. |
| **Article 29(1)-(2)** | Financial entities shall take into account whether the envisaged contractual arrangement would lead to (a) contracting an ICT third-party service provider that is **not easily substitutable**, or (b) having in place **multiple contractual arrangements** with the same ICT third-party service provider. Financial entities shall assess whether arrangements may impact their ability to **fully monitor the contracted functions**. | Both criteria are met: GetSwish AB is the sole provider (not substitutable) and all six banks have contractual arrangements with the same provider. A bank without a mechanism to verify HSM management does not monitor the contracted function at all. |
| **Article 30(2)(c)** | Provisions on availability, authenticity, integrity and confidentiality in relation to the **protection of data**, including personal data. | A contractual requirement for HSM management without verification is not a provision on protection — it is a provision on what the customer shall do, without any mechanism that actually protects the signing key. |

#### 3.6 ICT Concentration Risk — EBA's Own Oversight Mandate

DORA establishes ICT concentration risk as a systemic concern with dedicated institutional mechanisms. The case study presents the precise scenario the legislature intended these mechanisms to address.

**Definition.** Article 3(29) defines ICT concentration risk as "an exposure to individual or multiple related critical ICT third-party service providers creating a degree of dependency on such providers so that the unavailability, failure or other type of shortfall of such provider may potentially endanger the ability of a financial entity to deliver critical or important functions, or cause it to suffer other types of adverse effects, including large losses, or endanger the financial stability of the Union as a whole." In the present case, six major Swedish banks depend on a single collectively owned provider (GetSwish AB) for payment signing infrastructure. The provider is not substitutable. The dependency is total.

**Obligation to assess.** Article 28(4)(c) requires financial entities, before entering into contractual arrangements, to "identify and assess all relevant risks in relation to the contractual arrangement, including the possibility that such contractual arrangement may contribute to reinforcing ICT concentration risk as referred to in Article 29." Article 29(1) specifies two criteria: (a) contracting a provider that is not easily substitutable, or (b) having multiple contractual arrangements with the same provider. Both criteria are met.

**Oversight Forum.** Article 32(2) requires the Oversight Forum to "undertake a collective assessment of the results and findings of the oversight activities conducted for all critical ICT third-party service providers and promote coordination measures to increase the digital operational resilience of financial entities, foster best practices on addressing ICT concentration risk and **explore mitigants** for cross-sector risk transfers." The open source reference implementation for HSM attestation verification constitutes precisely such a mitigant — it reduces concentration risk by providing an independently verifiable control mechanism that is not dependent on the concentrated provider's own systems or cooperation.

**Lead Overseer powers.** Article 35(1)(d)(ii) grants the Lead Overseer authority to examine "the use of conditions and terms, including their technical implementation, under which the critical ICT third-party service providers provide ICT services to financial entities, which the Lead Overseer deems relevant for preventing the generation of single points of failure, the amplification thereof, or for minimising the possible systemic impact across the Union's financial sector in the event of ICT concentration risk." A payment infrastructure where signing key integrity is neither verified nor verifiable constitutes a single point of failure. HSM attestation verification eliminates this single point of failure.

**Legislative intent.** The recitals confirm that the concentration risk framework was established because existing national mechanisms were insufficient. Recital 30 states that "the broader issue of counteracting systemic risk which may be triggered by the financial sector's exposure to a limited number of critical ICT third-party service providers is not sufficiently addressed by Union law." Recital 31 adds that intra-group provision of ICT services "should not be automatically considered less risky" — directly applicable to GetSwish AB's ownership structure. Recital 88 states that the Lead Overseer's powers should "enable the Lead Overseer to acquire real insight into the type, dimension and impact of the ICT third-party risk posed to financial entities and ultimately to the Union's financial system."

The concentration risk framework provides EBA with an additional, independent legal basis — beyond the Article 17 breach-of-Union-law procedure — to address the verification gap. The tools already exist in the regulation. The mitigant already exists as open source, supporting multiple HSM vendors, with independently auditable code. Any alternative implementation must meet the same functional standard — multi-vendor attestation verification, key origin and exportability checks, and DORA article compliance mapping — or fail the proportionality assessment under Article 9(3), since a less capable solution cannot be justified when a more complete one is freely available. Compliance of any alternative implementation is independently testable: cryptographic chain validation is mathematically deterministic, meaning the same attestation input must produce the same verification result — EBA can run both implementations against the same signing certificate attestation evidence and compare, leaving no room for interpretive divergence. The critical requirement for independent verification is that EBA or the national competent authority obtains the HSM manufacturers' root certificates directly from the manufacturers — Securosys, Yubico, Thales (Chrysalis-ITS root), Crypto4A, Fortanix, Entrust (KWARN-1 key), Marvell, whose LiquidSecurity roots also anchor Azure Managed HSM and Google Cloud HSM attestations, and Google for its owner root (no Microsoft root is pinned) — not from any party in the chain being verified. The fingerprints of the anchors this implementation pins are listed under "Pinned trust anchors" below and asserted by `TrustAnchorPinningTest`, together with the manufacturer source each anchor's comment block records; every anchor is confirmed against the manufacturer's own material. Since 1.7.0 the authority can also run the gatekeeper on the roots it obtained itself, instead of the pinned ones (`gatekeeper.trust-anchors.<key>`, see "Replacing a trust anchor" below). This ensures that the verification is independent of all parties: the bank, GetSwish AB, the technical supplier, and the reference implementation provider alike.

#### 3.7 The Contractual Requirement as De Facto Liability Limitation

The contractual structure can be summarised in three steps: the bank imposes a security requirement, establishes that the signature is binding, but implements no mechanism to verify that the security requirement is met. The contractual term functions in practice as a **liability limitation** vis-à-vis the customer rather than the **security measure** the regulation requires. The absence of verification is not the result of a lack of bargaining position but an active choice not to use a control mechanism the banks, through their ownership of GetSwish AB, have full legal and factual ability to implement (cf. Recital 31: intra-group providers shall not automatically be considered less risky).

#### 3.8 Effet Utile

If formal contractual requirements without verification were accepted as sufficient, every DORA obligation could be fulfilled through documentation alone, which would reduce Articles 5, 6, 9 and 28-30 to requirements without independent normative content — in conflict with the principle that every provision shall be given effective application. DORA's purpose is preventive digital operational resilience — Article 9(3)(c) requires financial entities to *prevent* the impairment of authenticity and integrity, not to detect it after the fact. This preventive requirement can only be satisfied by verification at the point of certificate issuance: either valid HSM attestation evidence is presented and the signing certificate is issued, or it is not and the certificate is refused. Any verification that occurs after issuance — periodic audits, supervisory reviews, incident investigations — is by definition reactive, not preventive, and cannot satisfy this standard.

### 4. The Supervisory Authority's Responsibility

| Source | Obligation | Significance |
|---|---|---|
| **DORA Article 46** | Competent authorities shall monitor financial entities' compliance. | The national competent authority (NCA) — in the Swedish case, Finansinspektionen — has an obligation, not merely a power, to supervise compliance. |
| **DORA Article 50(2)** | Competent authorities shall have the power to require that measures be taken. | The NCA has the legal tools to order banks to implement verification mechanisms. That such tools exist and have not been used underscores the question of supervisory passivity. |
| **Article 4(3) TEU** | The loyalty principle: Member States shall take all appropriate measures to ensure fulfilment of obligations arising from Union law. | A supervisory authority that fails to act despite knowledge of systematic breaches of a directly applicable regulation raises the question of compatibility with the loyalty principle. |
| **Article 258 TFEU** | The Commission may bring infringement proceedings against a Member State. | A systematic failure to supervise constitutes a potential Treaty infringement. |

A supervisory authority's failure to intervene does not constitute a legal source. The regulation is directly applicable under Article 288 TFEU. A supervisory authority's inaction does not change the legal position — it only means that the breach has not been sanctioned. An authority's failure to express a view on a question it has not examined cannot be interpreted as a position on that question.

In a system with automated reporting at certificate issuance, the absence of reported data would itself constitute verifiable evidence of non-compliance, transforming supervision from reactive review to proactive anomaly detection.

#### 4.1 Verification Procedure — Triangulation From Independent Sources

To prevent selective reporting and ensure complete coverage, the verification procedure should use three independent data sources: the banks, GetSwish AB, and the HSM manufacturers' root certificates. No single party can manipulate the result without another party's data revealing the discrepancy.

**Phase 1 — Banks report first.** EBA or the NCA requests each owning bank to provide a complete list of all active customer agreements for Swish Utbetalning, including the associated Swish numbers and signing certificate identifiers. Since a representative from each owning bank sits on GetSwish AB's board, requesting the banks first prevents coordination of responses. During this phase, all banks are prohibited from onboarding new customers to Swish Utbetalning — ensuring the dataset is frozen at the point of inquiry. This freeze should be achievable within one business day; a period of up to one week is reasonable.

**Phase 2 — GetSwish AB reports.** Once all banks have submitted their data, EBA or the NCA requests GetSwish AB to provide all active Swish numbers with their associated certificates and any available attestation evidence. Critically, GetSwish AB's current system does not distinguish between signing and transport use — the certificates are identical duplicates, and any of them can be used for payment signing. This means that for every Swish number with a Swish Utbetalning agreement (identified via bank data in Phase 1), either all associated certificates must have valid HSM attestation — since any certificate may be used to authorise payments — or GetSwish AB must implement a separation between signing and transport certificates so that only HSM-attested certificates can be used for payment signing. In the absence of such separation, the only way to ensure that signing operations are HSM-protected is through a technical supplier that can distinguish certificate purposes via HSM attestation evidence — a capability that neither the banks nor GetSwish AB currently possess. Either path leads to the same requirement: HSM attestation verification must be implemented. In the Swish architecture, technical suppliers operate under a separate TL-number (987 prefix) linked to the customer's Swish number (123 prefix). A technical supplier has one transport certificate (for mTLS to the Swish API) and separate signing certificates for each customer's Swish number — each with its own private key, and often multiple signing certificates per Swish number for redundancy. Transport and signing certificates serve different purposes — transport certificates secure the mTLS channel to the Swish API, while signing certificates authorise payments. All signing certificate private keys must be generated and stored inside an HSM. The same HSM-protected signing key may be used across multiple customers, which further simplifies the verification: a single HSM attestation evidence for one private key can cover all signing certificates using that key. A technical supplier that uses HSM can produce valid attestation evidence for each individual signing certificate issued under its TL-number, proving that every signing key was generated and is stored inside a certified HSM. This makes the verification operationally scalable: one technical supplier's HSM infrastructure covers all of its customers' signing certificates, and the attestation evidence is produced per certificate at the point of issuance. This architectural deficiency — the inability to enforce different security levels for different certificate purposes — is itself a failure of ICT risk management. The cross-reference between bank data (Phase 1) and GetSwish AB data (Phase 2) must produce a matching set. Any discrepancy — a Swish number reported by a bank but absent from GetSwish AB's list, or vice versa — is immediately identifiable and requires explanation.

**Phase 3 — Independent attestation verification.** For each signing certificate reported, EBA or the NCA verifies the attestation evidence against the HSM manufacturers' root certificates obtained directly from the manufacturers. The result is binary for each certificate: valid HSM attestation exists, or it does not. This step requires no cooperation from any party in the chain — the mathematical proof is independently verifiable.

**Phase 4 — Remediation.** Signing certificates that lack valid HSM attestation evidence must be revoked. The affected entities must demonstrate that a verification mechanism — capable of validating HSM attestation at certificate issuance — is operational before new signing certificates may be issued. The freeze on new certificate issuance for non-compliant entities remains in effect until this capability is verified by the competent authority.

The procedure is designed so that no party can conceal non-compliance. The banks cannot underreport because GetSwish AB's operational data will reveal the gap. GetSwish AB cannot underreport because the banks' data will reveal the gap. Neither can falsify attestation evidence because the verification is performed against HSM manufacturers' root certificates held by the supervisory authority itself. The only way to conceal non-compliance would require the independent HSM manufacturer to participate — which is structurally excluded.

**In code (since 1.7.0).** Phases 1–3 run as a triangulation inquiry under `/v1/triangulation/{countryCode}/inquiries` (`SUPERVISOR` only; see "Data triangulation" under API Endpoint). The banks submit their reports first; once the payment-network operator (GetSwish AB) has submitted its report, further bank reports are refused, and only one operator may report per inquiry. The discrepancy report compares both with the registry entries of the jurisdiction that hold a certificate stored at a Step 7 confirmation ending in `VERIFIED_AND_ISSUED` — Phase 3, because an entry gets there only after its attestation verified against the manufacturer roots in use (the pinned ones unless the operator replaced them). The report is signed with the receipt key and recorded in the audit log. What the code does not do: freeze onboarding (Phase 1's freeze is an order to the banks), compare the certificate fields the banks report (they are kept and digested only), or keep inquiries across a restart (they are held in memory). No bank or operator submits reports to it yet. For Phase 4, the gatekeeper records a revocation as a `REVOKED` key-lifecycle event (`POST /v1/attestation/{countryCode}/lifecycle`), after which `POST /api/v1/verify` denies the certificate with `CERT_REVOKED`; revoking the certificate itself remains the issuing CA's act.

#### 4.2 Two Distinct Structural Problems

The Swish Utbetalning case presents two separate problems that must not be conflated, as they have different causes and different solutions.

**Problem 1 — Certificate type separation (architectural).** GetSwish AB's current system does not distinguish between transport certificates and signing certificates — they are identical duplicates, and any certificate can be used for payment signing. This is an architectural deficiency in GetSwish AB's infrastructure. It could be resolved by GetSwish AB introducing separate number ranges (e.g. 456-prefix) or other mechanisms to enforce the distinction between certificate types. This is an internal design decision for GetSwish AB and does not in itself raise DORA independence concerns. However, solving Problem 1 alone does not resolve Problem 2.

**Problem 2 — Independence of the signing key provider (regulatory).** Regardless of how certificate type separation is implemented, DORA's independence requirements determine who may provide the HSM-protected signing key and attestation evidence. This is the core DORA compliance problem.

Article 6(4) requires "appropriate segregation and independence of ICT risk management functions, control functions, and internal audit functions, according to the three lines of defence model." Article 5(4) requires members of the management body to actively maintain sufficient knowledge and skills, and the governance framework must ensure "effective and prudent management of ICT risk."

A bank that simultaneously acts as the contractual party imposing the HSM requirement on the customer, an owner of GetSwish AB which issues the certificates, and a technical supplier providing the HSM solution to the customer, occupies three roles that cannot be reconciled with the independence and segregation requirements in Articles 5 and 6. The entity setting the security requirement cannot simultaneously be the entity selling the solution to meet that requirement and the entity verifying compliance — this collapses all three lines of defence into one.

The consequence is that DORA's own independence requirements effectively prohibit the following parties from acting as technical suppliers for Swish Utbetalning signing services: the owning banks (direct conflict of interest across all three lines of defence), any indirect participant acting under a bank's mandate (the mandate creates the same structural dependency as direct participation — the entity acts as an extension of the bank and therefore inherits the same independence disqualification), and GetSwish AB itself (as the certificate issuer, it cannot simultaneously be the party providing the keys to be certified — the verifier and the verified cannot be the same entity). This prohibition follows directly from Articles 5 and 6 of DORA, not from competition law. It should be noted that both banks and GetSwish AB may have the capability to issue certificates, and could argue that decentralised certificate issuance reduces concentration risk under Article 29. However, concentration risk and structural independence are separate requirements that must both be satisfied simultaneously. Decentralising certificate issuance may address concentration risk but does not resolve the independence conflict: regardless of where the certificate is issued, the party providing the HSM-protected signing key and attestation evidence must be independent of the party setting the requirement and the party verifying compliance. The certificate issuer and the signing key provider serve different functions — and it is the signing key provider that must be an independent technical supplier.

A further variant of this argument must be addressed. An owning bank might claim to resolve the independence conflict by issuing signing certificates itself rather than through GetSwish AB, while continuing to use GetSwish AB's infrastructure to process the signed payment instructions. This does not resolve the conflict. The signing key's validity is ultimately relied upon by GetSwish AB's system to authorise payments — and the bank is a co-owner of that system. The bank would simultaneously impose the HSM requirement (contractual party), issue the certificate (certificate authority), and co-own the infrastructure that relies on the certificate's integrity (GetSwish AB shareholder). The independence conflict is not reduced by moving the certificate issuance step; it is reproduced. The same analysis applies to all six owning banks, since each bank's board representation in GetSwish AB creates the same structural dependency. A bank cannot claim independence from an infrastructure it co-owns and co-governs. Recital 63 explicitly provides that entities "collectively owned by financial entities" shall be considered third-party providers, and Recital 31 confirms that such arrangements "should not be automatically considered less risky than the provision of ICT services by providers outside of a financial group." GetSwish AB is not a subsidiary of any single bank — it is collectively owned by all six owning banks, which is precisely the ownership structure these recitals address. A potential counterargument arises from the second sentence of Recital 31, which states that "when ICT services are provided from within the same financial group, financial entities might have a higher level of control over intra-group providers, which ought to be taken into account in the overall risk assessment." However, this provision strengthens rather than weakens the case for a verification obligation. If the owning banks have a higher level of control over GetSwish AB — which they demonstrably do through board representation and ownership — they have correspondingly less justification for not having implemented HSM attestation verification. The banks could have mandated verification through an ownership directive at any time. The "higher level of control" has not been exercised to manage the risk; it has been left unused. Having the control but not using it is precisely the poor administration that Article 9(3)(d) requires protection against.

**The relationship between the two problems.** Problem 1 (certificate type separation) is an architectural prerequisite that GetSwish AB must resolve regardless. Problem 2 (independence of the signing key provider) is a DORA compliance requirement that persists regardless of how Problem 1 is solved. Even if GetSwish AB implements perfect certificate type separation, the signing keys must still be provided by an independent party with HSM attestation evidence, and verification must still pass through EBA's gatekeeper. Solving Problem 1 without solving Problem 2 achieves nothing — the signing certificates would be correctly categorised but still unverified.

All customers must therefore use an independent technical supplier operating under a separate TL-number (987 prefix) with its own HSM infrastructure and attestation capability, or register as a technical supplier themselves with their own TL-number and HSM infrastructure. For enterprise customers with sufficient technical capacity, becoming a TL is a viable path that preserves full control over their signing keys while satisfying the independence requirement — their attestation evidence is verified through EBA's gatekeeper identically to any other TL.

The TL model also provides a significant risk reduction advantage: requiring more than 22,000 corporate customers to individually maintain HSM competence — including correct configuration with non-exportable keys, firmware management, and the ability to produce valid attestation evidence — constitutes an unnecessary risk exposure under Article 9(3)(d) when specialised technical suppliers can handle it on their behalf. The automated verification at EBA's gatekeeper handles any volume of attestation checks equally; the issue is not the number of verifications but the number of entities that must independently maintain cryptographic competence.

The proportionality argument is further reinforced: since the verification mechanism must be implemented at the GetSwish AB infrastructure level regardless — because that is where certificates are issued — the marginal cost of verification for each additional customer or technical supplier approaches zero.

A further obligation follows from the combination of Articles 5(2)(b), 9(3)(d) and 9(4)(a). Banks that impose a contractual HSM requirement on customers and know — through the verification procedure described in Section 4.1 — which technical suppliers have valid HSM attestation, are obligated under DORA to make that information available to their customers. To impose a requirement without informing the customer how it can be met constitutes poor administration within the meaning of Article 9(3)(d). The bank's obligation under Article 9(4)(a) to protect data "including those of their customers, where applicable" extends to ensuring that customers have the information necessary to comply with the security requirements the bank itself has imposed. In practice, this means banks must provide customers seeking Swish Utbetalning with a list of technical suppliers whose HSM attestation has been verified. This is not a commercial recommendation — it is a factual record of compliance status, comparable to publishing which auditing firms hold a valid licence from the supervisory authority.

Should the initial list of verified technical suppliers contain only a single provider, this does not constitute ICT concentration risk within the meaning of Article 3(29). The reference implementation is published as open source, supporting multiple HSM vendors (Crypto4A, Entrust nShield, Fortanix, Securosys, Thales Luna and Yubico end to end; Azure, Google Cloud and Marvell are accepted and checked but cannot yet end in COMPLIANT — see "Supported HSM Vendors"), with no vendor lock-in. The barrier to becoming a compliant technical supplier is low: acquire a certified HSM, implement attestation verification, and register a TL-number. A market with a single initial provider due to first-mover advantage — where the technology is open, the standards are published, and the entry barrier is minimal — is structurally different from the concentration risk DORA addresses, which concerns dependency on providers that are not easily substitutable. Any technical supplier with a certified HSM can replicate the capability.

A separate consideration arises from the fact that representatives of all six owning banks sit on GetSwish AB's board. Any coordination between banks regarding which technical suppliers to use, avoid, or favour would constitute a potentially anti-competitive agreement under Article 101 TFEU and applicable national competition law. The obligation to publish a factual list of verified technical suppliers resolves this: banks share compliance status, not commercial preferences. Each customer selects independently from the list of compliant providers.

## 5. EBA's Supervisory Mechanisms — The Escalation Ladder

The following table sets out the sequential procedural steps available under Regulation (EU) No 1093/2010, verified against the consolidated text (version of 30 December 2024). The steps are mandatory and sequential — each step references the preceding step as a precondition.

| Step | Mechanism | Legal basis | Character | Timeline |
|------|-----------|-------------|-----------|----------|
| 1 | EBA issues guidelines with "comply or explain." Competent authorities shall endeavour to follow them. If they do not, they must explain why. EBA may publish the reasons. | Article 16, Regulation 1093/2010 | Voluntary. Insufficient for a documented systemic deficiency. | No fixed deadline. |
| 2 | EBA investigates alleged breach of Union law by a competent authority. EBA may, before issuing a recommendation, engage with the competent authority "if it considers such engagement appropriate." This is discretionary — not mandatory. | Article 17(2) and 17(2a), Regulation 1093/2010 | Discretionary engagement; mandatory investigation when conditions in 17(1) are met. | Investigation: up to two months. |
| 3 | EBA issues a recommendation to the competent authority setting out the action necessary to comply with Union law. The competent authority shall within ten working days inform EBA of measures taken or intended. | Article 17(3), Regulation 1093/2010 | Binding recommendation. | Ten working days (information). One month (compliance). |
| 4 | If the competent authority has not complied with Union law within one month from receipt of the recommendation, **the Commission may** issue a formal opinion requiring the competent authority to take the action necessary to comply. The Commission's formal opinion shall take into account EBA's recommendation. | Article 17(4), Regulation 1093/2010 | **Discretionary** — "may," not "shall." The Commission has a veto position: without its formal opinion, Article 17(6) cannot be activated. | Commission shall issue the opinion within three months of the recommendation (extendable by one month). |
| 5 | The competent authority shall inform the Commission and EBA of the steps it has taken or intends to take to comply with the formal opinion. | Article 17(5), Regulation 1093/2010 | Mandatory information duty. | Ten working days from receipt of the formal opinion. |
| 6 | If the competent authority does not comply with the formal opinion referred to in paragraph 4, and where it is necessary to remedy the non-compliance to maintain or restore neutral conditions of competition or ensure the orderly functioning and integrity of the financial system, **EBA may** adopt an individual decision addressed to a financial institution requiring compliance with Union law. The decision **shall be in conformity with** the Commission's formal opinion under paragraph 4. | Article 17(6) first paragraph, Regulation 1093/2010 | Binding decision addressed directly to financial institutions, bypassing the competent authority. Requires the Commission's formal opinion as a precondition. | No fixed deadline once preconditions are met. |

### 5.1 The Commission's Discretionary Role — A Structural Bottleneck

Article 17(4) uses the permissive "may" ("får" in Swedish) — not the mandatory "shall." If the Commission chooses not to issue a formal opinion, Article 17(6) cannot be activated, because 17(6) explicitly requires "the formal opinion referred to in paragraph 4" as a precondition and prescribes that EBA's decision "shall be in conformity with" that opinion. This creates a structural bottleneck: the Commission holds an effective veto over EBA's ability to address decisions directly to financial institutions under the breach-of-Union-law procedure.

However, the Commission's discretion is not unconstrained. Article 1(4) of Regulation 1093/2010 preserves the Commission's powers under Article 258 TFEU — the infringement procedure. If the Commission is informed by EBA of a competent authority's failure to comply and chooses not to issue a formal opinion under Article 17(4), the question arises whether the Commission itself has an obligation to act under Article 258 TFEU. A Commission that is informed of a documented breach and chooses neither to issue a formal opinion under 17(4) nor to initiate infringement proceedings under 258 TFEU faces the question of whether it fulfils its own Treaty obligation to ensure that Union law is applied.

### 5.2 The Anti-Money-Laundering Dimension — AMLA Takeover

The absence of HSM verification creates a structural anti-money-laundering vulnerability. Without attestation evidence, no institution in the chain — banks, GetSwish AB, or the competent authority — can determine whether a signing key has been compromised. A compromised signing key enables an unauthorised party to sign payment instructions that are immediately binding and irrevocable — and that are indistinguishable from legitimate transactions in monitoring systems. The risk is not that money laundering has occurred but that no institution can know whether it has, because the verification that would make such a determination possible has never been implemented. The risk is not quantified as low — it is unquantifiable. This renders the financial institutions' obligation under Directive (EU) 2015/849 to conduct a risk assessment of this channel structurally impossible to fulfil.

Regulation (EU) 2024/1620 has transferred AML supervision to the newly established Anti-Money-Laundering Authority (AMLA). EBA's earlier enhanced AML enforcement powers under Regulation (EU) No 1093/2010 — in particular the Article 17(6) second paragraph added by Regulation (EU) 2019/2175 — have been superseded in the process. For the case study treated here, however, the relevant dimension is not an AML-specific procedural track but the underlying DORA obligation: the documented deficiency relates to requirements of Regulation (EU) 2022/2554 that are directly applicable to financial institutions. DORA's direct-applicability satisfies the precondition in the current Article 17(6) first paragraph, meaning EBA (or its successor in the respective file) retains full capacity under Regulation 1093/2010 to address decisions directly to financial institutions for DORA breaches — without needing to invoke the AML track at all.

### 5.3 Legacy AML Procedure — Historical Context Only

Between 27 December 2019 and the entry into force of Regulation (EU) 2024/1620, Article 17(6) of Regulation (EU) No 1093/2010 contained a second paragraph — added by Regulation (EU) 2019/2175 — that extended EBA's decision-making power to national law transposing AML directives. That paragraph has been replaced in the course of the AMLA transfer; it is noted here solely because older supervisory practice and some of the academic literature reference it. Contemporary analysis of the case study should proceed under the DORA track described in 5.1 rather than under that historical AML track.

### 5.4 Article 18 — The Crisis Mechanism

Article 18 provides an alternative path that bypasses the entire Article 17 sequential chain. If the Council adopts a decision under Article 18(2) that a crisis situation exists — defined as "adverse developments which may seriously jeopardise the orderly functioning and integrity of financial markets or the stability of the whole or part of the financial system in the Union" — EBA may under Article 18(3) adopt individual decisions requiring competent authorities to take action. If the competent authority does not comply, EBA may under Article 18(4) adopt an individual decision addressed directly to a financial institution.

Article 18 requires no recommendation, no Commission formal opinion, and no waiting period — but it requires a Council decision on the existence of a crisis. The threshold is high, and this mechanism is noted here for completeness rather than as a primary escalation path.

### 5.5 Passivity Remedies — Article 61(3) and TFEU Article 265

If EBA itself fails to act on the information provided, Article 61(3) of Regulation 1093/2010 explicitly provides that "where the Authority is obliged to act but fails to take a decision, proceedings for failure to act may be brought before the Court of Justice of the European Union in accordance with Article 265 TFEU." This provision ensures that no node in the institutional chain — not the competent authority, not EBA, and not the Commission — can choose passivity without procedural consequence.

### 5.6 Why Article 17 Rather Than Article 16

Where a documented systemic deficiency exists — confirmed in writing by the actor itself, with a reference implementation proving feasibility and quantifiable non-compliance — the question arises whether EBA has an obligation to use Article 17 rather than Article 16. Voluntary guidelines with a "comply or explain" mechanism cannot remedy a deficiency that EBA knows to be systemic. Deliberately choosing a tool one knows to be insufficient, when the obligations required by the regulation presuppose binding measures, itself raises the question of whether EBA fulfils its mandate under Regulation (EU) No 1093/2010.

In addition to the Article 17 procedure, EBA has a parallel and independent legal basis through the Oversight Framework established in DORA Chapter V, Section II. As set out in Section 3.6 above, Article 32(2) requires the Oversight Forum to annually assess concentration risk and "explore mitigants," while Article 35(1)(d)(ii) grants the Lead Overseer authority to examine the technical implementation of conditions under which critical ICT third-party service providers provide services — including conditions relevant to "preventing the generation of single points of failure." These two paths — the Article 17 breach-of-Union-law procedure directed at Finansinspektionen's supervisory failure, and the Oversight Framework directed at the systemic risk in the infrastructure itself — reinforce each other. A finding under either path strengthens the case under the other, and EBA cannot argue that one path renders the other unnecessary since they address different aspects of the same deficiency: Article 17 addresses the supervisory failure, while the Oversight Framework addresses the operational risk.

### 5.7 The Practical Consequence — EBA Must Be Prepared to Act Directly

As established in Section 6 below, Finansinspektionen's supervisory model — built on principles-based assessment — is structurally incapable of performing the material verification DORA requires. This is not a correctable error in Finansinspektionen's application of its methodology; it is a fundamental incompatibility between the methodology itself and the regulation's requirements. A recommendation to Finansinspektionen under Article 17(3) to "perform material verification" may not be implementable within a supervisory framework that is not constructed for material verification. If the competent authority cannot comply — not because it chooses not to, but because its methodology does not permit it — the sequential progression through Article 17(4) to 17(6) becomes not merely available but structurally necessary.

A further consequence follows from the preventive requirement established in Section 3.8. If DORA requires verification at the point of certificate issuance — because Article 9(3)(c) mandates prevention, not post-incident detection — then the supervisory authority receiving verification reports must be capable of receiving them in real time. EBA's current reporting infrastructure, built on file-based XBRL-CSV packages submitted periodically through national portals, is designed for reactive reporting and cannot fulfil this function. The obligation to perform material supervision, combined with the preventive standard under Article 9(3)(c), requires EBA to establish or mandate reporting infrastructure capable of automated, real-time receipt of verification data at the moment of certificate issuance. This is not a technical upgrade — it is a precondition for fulfilling the supervisory function DORA assigns.

---

## 6. Regulatory Theory: The Structural Paradox

Applying Julia Black's paradox analysis of principles-based regulation ('Forms and Paradoxes of Principles-Based Regulation', Capital Markets Law Journal, vol. 3, no. 4, 2008, pp. 425–457), the verification gap documented in this case is not an anomaly but a structurally expected outcome. Black identified seven paradoxes inherent in principles-based regulation and designated the trust paradox as the "ultimate paradox" — that principles-based regulation "is based on trust that it alone cannot create" (p. 456). Five of these paradoxes are directly operative in the present case:

**The trust paradox.** Principles-based regulation presupposes the institutional trust between supervisor and regulated entities that it simultaneously aims to create. The supervisory system presupposes that banks verify HSM compliance, banks presuppose that GetSwish AB controls certificate issuance, and GetSwish AB presupposes that customers comply with contractual terms. Each institution's compliance is predicated on the assumption that another institution has verified — and none has. Cryptographic chain of trust — the verifiable confidence established by HSM attestation evidence — delivers the trust that the principles-based system presupposes but cannot create, from outside the institutional logic that produces the paradox.

**The interpretation paradox.** The concept of "adequate" ICT risk management (Article 6(1)) leaves interpretive space that enables minimalist compliance. When verification is binary — COMPLIANT or NON-COMPLIANT based on HSM attestation evidence — the interpretive space ceases to exist.

**The compliance paradox.** In the absence of verification requirements, regulated actors fall back on formal compliance — formulating the requirement without controlling its implementation. Black described this as "creative compliance" (p. 426). When the verification result is deterministic, minimalist formal compliance becomes structurally impossible: either valid attestation evidence is presented and the certificate is issued, or it is not and the certificate is refused.

**The supervision and enforcement paradox.** Principles-based regulation gives supervisors flexibility but can lead to conservative or unpredictable enforcement (pp. 450–452). Automated verification at certificate issuance eliminates the trade-off between insufficient and excessive enforcement, because the control occurs without human judgement and the result is binary.

**The communication paradox.** Principles express purpose but can fail to communicate what is concretely expected (pp. 445–447). The data triangulation procedure specified in Section 4.1 eliminates this gap by replacing principle-based communication with a procedural structure that makes the expected behaviour self-evident. Banks report all active customer agreements. GetSwish AB reports all active certificates. EBA verifies attestation evidence against manufacturers' root certificates. No actor can claim that it did not understand what was expected, because the procedure communicates the requirement through its own structure.

**The two remaining paradoxes** — the internal management paradox (pp. 452–454) and the ethical paradox (pp. 454–456) — operate in dimensions the verification mechanism does not address. They concern organisational culture and ethical judgement rather than information processes, and their resolution requires mechanisms of a different kind.

### 6.1 The Deeper Observation: Paradoxes Survive Rule-Based Regulation

Black observed that "many of these paradoxes are not necessarily avoided by using detailed rules instead of principles" (p. 457). The present case confirms this observation but identifies a more precise cause. DORA's relevant provisions are not principles but rules: Article 9(3)(c) prescribes "prevent," Article 6(10) prescribes "the verification" in definite form, Article 28(1)(a) prescribes "at all times" and "fully responsible." The legislature drafted DORA with precisely the absolute, rule-based formulations that Black's analysis suggested might avoid the paradoxes. Yet the paradoxes manifested nonetheless — not because rules fail to avoid paradoxes, as Black suggested, but because the regulation is applied by a supervisory authority whose method remains principles-based. The paradoxes reside not in the regulation's form but in the supervisory method through which it is applied. A rule-based regulation supervised through a principles-based method produces the same structural outcomes as a principles-based regulation: formal compliance without substantive verification.

### 6.2 The Recursive Failure

If EBA does not act, the appearance of compliance becomes recursive through every institutional level: banks appear compliant because they have contractual HSM requirements, Finansinspektionen appears to supervise because it reviews documentation and frameworks, and EBA appears to oversee because it receives reports from national competent authorities — yet at no point in the chain does actual verification of the underlying cryptographic reality occur. Each institution's compliance is predicated on the assumption that another institution has verified — and none has.

At this point, EBA's decision to act is no longer discretionary. Under the Treaties establishing the European Union, EBA was created to ensure the consistent application of Union law in the financial sector (Article 1(2), Regulation 1093/2010). Where the recursive failure of verification is documented, quantified, and independently provable, issuing voluntary guidelines under Article 16 — rather than pursuing the binding mechanisms of Articles 17(3), 17(4) and 17(6) — is itself a failure to fulfil EBA's Treaty-based mandate, since guidelines addressed to a supervisory authority that is structurally incapable of material verification cannot produce the outcome the regulation requires.

---

## Technical Definition

### Requirement for Real-Time Reporting Infrastructure

The legal analysis in Sections 1-6 establishes that DORA requires preventive verification at the point of certificate issuance (Section 3.8). This has a direct technical consequence for supervisory reporting infrastructure. EBA's current reporting framework — file-based XBRL-CSV packages submitted through national portals on periodic schedules — was designed for reactive reporting: registers of information submitted quarterly, incident reports filed after events. This infrastructure is structurally incompatible with the preventive requirement in Article 9(3)(c), which requires that impairment of authenticity and integrity is *prevented*, not reported after the fact.

If DORA's material verification requirements are to be fulfilled, the supervisory authority must be capable of receiving automated reports at the moment of certificate issuance — not in a batch file weeks or months later. This requires a real-time API endpoint capable of receiving structured verification reports as they are generated. The reference implementation provides this capability as a REST API, which is the industry standard for real-time machine-to-machine communication. This is not a technical preference — it is a necessary consequence of the regulation's preventive requirements. A supervisory infrastructure that cannot receive real-time data cannot perform real-time supervision, and supervision that is not real-time cannot be preventive.

### Verification Principle

HSM attestation relies on a **hardware root of trust**. Every certified HSM device contains a unique attestation key, signed by the manufacturer's root certificate authority (CA). When a signing key is generated inside the HSM, the device produces an **attestation certificate** that cryptographically binds:

- The public key of the generated signing key
- The identity of the HSM device (serial number, model, firmware)
- Key attributes (generated on-device, non-exportable)

This chain can be verified against the HSM manufacturer's publicly available root CA certificate.

### Verification Flow — NCA (or EBA in the transitional phase) as Gatekeeper

The architecture places the gatekeeper's verification *before* certificate issuance, making the gatekeeper's approval a precondition — not a post-issuance report. Under the stable operator model the gatekeeper is the NCA; during the transitional phase described below it is EBA.

```
                         CERTIFICATE ISSUANCE FLOW
                         
  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────────────┐
  │  Technical   │    │  GetSwish AB     │    │  EBA / NCA               │
  │  Supplier    │    │  (or Bank)       │    │  Gatekeeper API          │
  │              │    │                  │    │  dora-api.eba.europa.eu  │
  └──────┬───────┘    └────────┬─────────┘    └────────────┬─────────────┘
         │                     │                           │
         │  1. CSR +           │                           │
         │  attestation ──────▶│                           │
         │  evidence           │                           │
         │                     │  2. Forward               │
         │                     │  attestation ────────────▶│
         │                     │  evidence                 │
         │                     │                           │  3. Verify chain
         │                     │                           │  against HSM mfr
         │                     │                           │  root CA
         │                     │                           │
         │                     │                           │  4. Register in
         │                     │                           │  approval
         │                     │                           │  registry
         │                     │                           │
         │                     │       5. Signed             │
         │                     │◀──── verification ────────│
         │                     │       receipt              │
         │                     │                           │
         │                     │                           │
         │  IF COMPLIANT:      │                           │
         │◀─── 6. Issue  ─────│                           │
         │  signing certificate│                           │
         │                     │  7. Confirm: send full    │
         │                     │  signing certificate ────▶│
         │                     │  (or non-issuance notice) │
         │  IF NON-COMPLIANT:  │                           │
         │◀─── 6. Refuse ─────│                           │
         │  certificate denied │  7. Confirm: send         │
         │                     │  non-issuance notice ────▶│
         │                     │                           │
```

In the description below, "the gatekeeper" denotes whichever authority is operating the endpoint at a given time — NCA under the stable operator model, EBA during the transitional phase described below. The implementation is identical in both cases.

**Step 1.** The technical supplier submits CSR and HSM attestation evidence to GetSwish AB (or the issuing bank). The attestation evidence includes the attestation certificate chain and, depending on the HSM vendor, additional vendor-specific data.

**Step 2.** GetSwish AB forwards the attestation evidence — together with the public key extracted from the CSR — to the gatekeeper API for independent verification. This occurs *before* any certificate is issued.

**Step 3.** The gatekeeper verifies the attestation certificate chain against the HSM manufacturer's root CA pinned in the verifier, or since 1.7.0 the root the operator configured in its place ("Replacing a trust anchor") (PKIX `CertPathValidator` anchored at the manufacturer's root for Securosys, Yubico and Fortanix; explicit signature checks up to the pinned root for the other vendors). The verification confirms that the signing key was generated inside a genuine HSM and is non-exportable. The result is binary: COMPLIANT or NON-COMPLIANT. The compliance predicate in the code is `publicKeyMatch && attestationChainValid && attestationSignatureValid && generatedOnDevice && !exportable && errors.isEmpty()` (see `VerificationService.verify()`), and every DORA article bit in the receipt likewise requires a valid attestation signature. The key itself must also be allowed by the key policy (`gatekeeper.key-policy.allowed-keys`, default `RSA-4096`, the Swish signing key); any other key adds `KEY_NOT_ALLOWED` to the errors and is NON-COMPLIANT however its attestation verifies. The key policy can also require attested FIPS-approved mode (`gatekeeper.key-policy.require-fips-approved-mode`, default `false`, since 1.7.0): a Yubico attestation is then compliant only if its chain validated and it states FIPS-approved mode true (`FIPS_APPROVED_MODE_NOT_ATTESTED` otherwise), and every other vendor's attestation adds `FIPS_MODE_NOT_IN_ATTESTATION_FORMAT`, because no other format, as these verifiers read it, carries such a statement. The reference YubiHSM 2 attestation carries no FIPS-approved flag, so the requirement refuses it too.

**Step 4.** The gatekeeper registers every verification result — both compliant and non-compliant — in its approval registry (`ApprovalRegistry.register(...)`). This registry serves as the authoritative record of all attestation verifications and enables the secondary reconciliation control described below.

**Step 5.** The gatekeeper returns a signed verification receipt to GetSwish AB. The receipt is not a simple boolean but a traceable, cryptographically signed document containing: a unique verification ID, the verification timestamp, the public key fingerprint, HSM vendor and model, the DORA article compliance determination, and the operator's digital signature over a canonical byte representation of the decision-relevant fields (`ReceiptCanonicalizer`, `ReceiptSigner.signInto(...)`). Under the NCA profile, signing uses a configured PKCS#12 keystore loaded via `ConfiguredReceiptSigner` (since 1.7.0 the key may instead be held by an HSM through a JCA keystore type and provider; see "Log-signing key in an HSM"); the reference `EphemeralReceiptSigner` generates a throwaway RSA key at startup and emits prominent WARN logs so it cannot be deployed unnoticed. The signature allows GetSwish AB — and any subsequent auditor — to independently verify that the approval originated from the gatekeeper. The receipt ID is the key that links the certificate to the gatekeeper's approval registry.

**Step 6.** GetSwish AB issues the signing certificate *only* if the gatekeeper's receipt confirms COMPLIANT status, and embeds the verification ID in its own records alongside the issued certificate. If NON-COMPLIANT, the certificate request is refused and no signing certificate is created. The technical supplier must resolve the attestation deficiency before resubmitting.

**Step 7 — Closing the loop.** GetSwish AB sends a confirmation back to the gatekeeper via `POST /v1/attestation/{countryCode}/confirm`. If the certificate was issued, the confirmation includes the full signing certificate, optionally followed by its intermediate CA certificates in the same PEM field; a confirmation that reports issuance without a certificate is recorded as an anomaly and does not close the loop. The gatekeeper then performs two binding checks before accepting the confirmation:

1. **Issuer-CA validation.** A PKIX path is built from the submitted certificate to the configured issuer-CA trust anchors (`IssuerCaValidator`, configured via `gatekeeper.confirmation.issuer-ca-bundle-path`; reference bundle `issuer-ca-bundle.pem` ships with Getswish Root CA v2 as trust anchor and Swish Customer CA1 v2 for Swish, the CA that issues Swish signing certificates, as intermediate). Intermediates come from the submitted PEM and from bundle certificates issued by another bundle certificate; every other bundle certificate is a trust anchor. A certificate for which no path to a trusted issuer CA can be built is rejected regardless of its public key — this prevents an attacker who knows a `verificationId` from substituting arbitrary certificates for comparison.
2. **Public-key match.** Only after the issuer-CA validation passes does the gatekeeper extract the public key and compare its fingerprint (constant-time) against the one approved in Step 3. When it matches, the issued certificate, its serial number and its issuer DN are stored on the registry entry, which is what lets `POST /api/v1/verify` find the certificate at settlement time from `certSerial` and `issuerDn` alone.

The loop is closed cryptographically, not contractually — the gatekeeper does not rely on GetSwish AB's assertion that the correct certificate was issued; it verifies the issuer, the chain, and the key match itself. If the certificate was not issued (whether due to NON-COMPLIANT status or any other reason), GetSwish AB sends a non-issuance notice with timestamp and the verification ID. This ensures that the registry reflects the actual outcome for every verification request — an approved attestation without a corresponding issued certificate, or vice versa, is immediately visible.

**Secondary control — registry reconciliation.** The gatekeeper maintains a registry of all approved attestation verifications. This registry serves as a safeguard against any alternative certificate issuance path that might bypass the gatekeeper verification step. Through the triangulation procedure described in Section 4.1, any certificate that exists in GetSwish AB's system but does not have a corresponding entry in the gatekeeper registry is immediately identifiable as issued outside the approved process — a qualitatively more serious offence than mere non-compliance, as it constitutes active circumvention of the supervisory mechanism. In the triangulation report (since 1.7.0) such a certificate appears under `certificatesWithoutVerifiedAttestation` with `registryStatus: NOT_IN_REGISTRY`.

**Transitional architecture — EBA to NCA.** EBA's gatekeeper role under Article 17(4) is not permanent. It is activated to remedy a specific supervisory failure and remains in effect until the NCA demonstrates the capability to perform the same function. The API and verification infrastructure is therefore designed to be operated by either authority with no code differences — a single build of `gatekeeper` runs in both modes, selected by Spring profile. In the initial phase, EBA operates the endpoint (e.g. on a domain controlled by EBA). Once the NCA has established equivalent real-time verification capability — the same API infrastructure, the same independent verification against HSM manufacturers' root certificates, the same registry — the gatekeeper function transitions to the NCA (e.g. `dora-api.fi.se` for Sweden, or the equivalent domain for another Member State), and EBA's role reverts to supervisory convergence oversight under Article 29 of Regulation 1093/2010 plus the breach-of-Union-law procedure under Article 17. The transition condition is not a policy decision but a technical verification: the NCA must demonstrate that its infrastructure produces the same deterministic verification results as EBA's, confirmed by running both implementations against identical attestation evidence (the same unit-test harness in `src/test/java/.../verification/` can be run side by side against both deployments).

### Attestation Verification Logic

```
┌────────────────────┐
│  Attestation Input │
│                    │
│  • Public key      │  ──→  Extract public key fingerprint
│  • Attestation     │  ──→  Verify attestation certificate chain
│    certificate     │       against HSM manufacturer root CA
│  • HSM vendor      │  ──→  Verify key attributes:
│                    │       - keyOrigin = "generated"
│                    │       - keyExportable = false
└────────────────────┘
           │
           ▼
┌────────────────────┐
│   Binary Result    │
│                    │
│  ✅ COMPLIANT:     │  Public key proven to be generated and
│     HSM-attested   │  stored in genuine HSM, non-exportable
│                    │
│  ❌ NON-COMPLIANT: │  Attestation chain invalid, key not
│     Not attested   │  generated on-device, or key exportable
└────────────────────┘
```

### Key Property: Independent Verifiability

The critical property is that verification is **independent of the entity being verified**:

1. The entity submits attestation evidence (or EBA requests it under its supervisory powers).
2. This tool verifies the evidence against the HSM manufacturer's root CA.
3. The HSM manufacturer is an independent third party (Securosys, Yubico, Thales, Crypto4A, Fortanix, Entrust, Marvell — whose roots also anchor the Azure and Google cloud HSMs — and Google for its owner root).
4. The result is deterministic — the same input always produces the same output.
5. No cooperation from the entity is required beyond providing the attestation data.

This is the practical manifestation of the distinction between contractual and cryptographic compliance: the mathematical proof validates or it does not.

### API Endpoint

#### POST dora-api.eba.europa.eu/v1/attestation/se/verify

Accepts attestation evidence and returns an independent verification result with DORA article compliance mapping.

**Request:**

```json
{
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIB...",
  "hsmVendor": "SECUROSYS",
  "attestationData": "PD94bWwgdmVyc2lvbj0iMS4wI...",
  "attestationSignature": "eywPlJWUEiLDnaq+NEAs4zB3...",
  "attestationCertChain": [
    "-----BEGIN CERTIFICATE-----\n...",
    "-----BEGIN CERTIFICATE-----\n..."
  ],
  "customerOrganisationNumber": "5569743098",
  "customerSwishNumber": "1231015932",
  "supplierIdentifier": "5569741234",
  "supplierNumber": "9871234567",
  "supplierName": "Example Teknisk Leverantör AB",
  "keyPurpose": "Swish payment signing"
}
```

**Compliant response:**

```json
{
  "verificationId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "confirmationNonce": "9Qk7t0nO2s6bYyq0ZP1c8VJ0aXQ4tRk3mB1nS7dLuFo",
  "compliant": true,
  "verificationTimestamp": "2026-03-20T14:30:00Z",
  "signature": "MIIEpQIBAAKCAQEA...",
  "signingCertificate": "-----BEGIN CERTIFICATE-----\nMIIDozCCAougAwIBAgIUG...\n-----END CERTIFICATE-----\n",
  "publicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:...",
  "publicKeyAlgorithm": "RSA",
  "hsmVendor": "Securosys",
  "hsmModel": "Primus HSM",
  "hsmSerialNumber": "18000000",
  "hsmFirmwareVersion": null,
  "hsmFipsIndicator": null,
  "hsmFipsApprovedMode": null,
  "keyProperties": {
    "generatedOnDevice": true,
    "exportable": false,
    "attestationChainValid": true,
    "publicKeyMatchesAttestation": true
  },
  "doraCompliance": {
    "article5_2b": true,
    "article6_10": true,
    "article9_3c": true,
    "article9_3d": true,
    "article9_4d": true,
    "article28_1a": true,
    "summary": "Signing key is cryptographically proven to be generated and stored in a certified HSM with non-exportable attribute. All DORA requirements for cryptographic key management are independently verifiable."
  },
  "customerOrganisationNumber": "5569743098",
  "customerSwishNumber": "1231015932",
  "supplierIdentifier": "5569741234",
  "supplierNumber": "9871234567",
  "supplierName": "Example Teknisk Leverantör AB",
  "keyPurpose": "Swish payment signing",
  "countryCode": "SE",
  "errors": [],
  "warnings": []
}
```

The `signature` is a detached Base64-encoded RSA/ECDSA signature computed over the canonical byte representation of the decision-relevant fields (see `ReceiptCanonicalizer` — `v3|verificationId|confirmationNonce|compliant|timestamp|fingerprint|algorithm|hsmVendor|hsmModel|hsmSerialNumber|customerOrganisationNumber|customerSwishNumber|supplierIdentifier|supplierNumber|supplierName|keyPurpose|countryCode|keyProperties...|doraCompliance...`). The version marker moved to `v3` in 1.6.0, when the customer's organisation and Swish numbers and the supplier number were brought inside the signed form; a receipt signed under `v2` (1.4.0–1.5.0) is re-verified with `ReceiptCanonicalizer.canonicalize(receipt, "v2")`. It moved from `v1` to `v2` in release 1.4.0 when `confirmationNonce` was brought inside the signed form; a financial entity still computing `v1` bytes will fail to verify every receipt, so the `hsm` repository must be upgraded in lock-step (see `CHANGELOG.md`). The `signingCertificate` PEM lets any party independently verify the signature without a prior key-exchange step. Under the NCA profile (`gatekeeper.signing.mode=configured`) the signing certificate is the NCA's organisation certificate — the certificate the NCA uses for ordinary administrative signing of supervisory acts. The reference `EphemeralReceiptSigner` produces a throwaway `CN=REFERENCE-EPHEMERAL` certificate marked as such.

**Parties** *(since 1.6.0)*. `customerOrganisationNumber` and `customerSwishNumber` name the customer the certificate is for. When a technical supplier holds the key, `supplierIdentifier` is its organisation number and `supplierNumber` its 987 number, as its transport certificate carries them; a customer without a technical supplier has no supplier fields. The registry stores all of them and the receipt signs them, so the supervisor can compare who holds each verified key with the banks' customer registers (`SUPERVISORY_OPERATIONS.md` §3.5). They are personal data when the customer is a sole trader, whose organisation number is the personal identity number; the processing is part of the supervisory task.

**Firmware and FIPS state** *(since 1.7.0)*. `hsmFirmwareVersion`, `hsmFipsIndicator` and `hsmFipsApprovedMode` report what a YubiHSM 2 attestation states: the firmware (`1.3.6.1.4.1.41482.4.1`), the FIPS indicator (`.4.10`, an integer) and the FIPS-approved flag (`.4.12`), each read from the key attestation certificate or, when it has none, from the device attestation certificate. They are set only when the Yubico chain validated to the pinned root, compliant or not, and are `null` for every other vendor (hence `null` in the Securosys examples here). For the reference YubiHSM 2 they are `"2.2.0"`, `5` and `null`. They are not part of the `v3` canonical form, so the receipt signature does not cover them; the `VERIFY` audit entry records the firmware and the flag inside its hash. The indicator is reported, not interpreted, and nothing maps firmware to a FIPS 140 or Common Criteria certificate.

**Evidence kept** *(since 1.6.0)*. The registry entry keeps the verification request as submitted (`submission`): public key, attestation data, signature and chain, parties. Until 1.5.0 only a digest of it was kept, in the audit log, so the supervisor depended on the financial entity for the evidence and could not repeat a verification, for instance with a corrected verifier. `VerificationService.requestDigestBase64(submission)` equals the entry's `requestDigestBase64` in the audit log, which shows that what is kept is what was verified. The evidence is not secret; an attestation is a few kilobytes (4–7 kB for the samples in hsm).

**Non-compliant response:**

```json
{
  "verificationId": "2c9d4b6a-8e1f-4b3c-af2e-5d6a7b8c9d0e",
  "confirmationNonce": "Tz3m5Xc9pQw1LbN8vR2kJ7dHs0YgU4eA6fC1oIhKrEs",
  "compliant": false,
  "verificationTimestamp": "2026-03-20T14:30:00Z",
  "signature": "MIIEpQIBAAKCAQEA...",
  "signingCertificate": "-----BEGIN CERTIFICATE-----\nMIIDozCCAougAwIBAgIUG...\n-----END CERTIFICATE-----\n",
  "publicKeyFingerprint": "a1:b2:c3:...",
  "publicKeyAlgorithm": "RSA",
  "hsmVendor": null,
  "hsmModel": null,
  "hsmSerialNumber": null,
  "hsmFirmwareVersion": null,
  "hsmFipsIndicator": null,
  "hsmFipsApprovedMode": null,
  "keyProperties": {
    "generatedOnDevice": false,
    "exportable": true,
    "attestationChainValid": false,
    "publicKeyMatchesAttestation": false
  },
  "doraCompliance": {
    "article5_2b": false,
    "article6_10": false,
    "article9_3c": false,
    "article9_3d": false,
    "article9_4d": false,
    "article28_1a": false,
    "summary": "Non-compliant: attestation chain invalid, attestation signature invalid, public key does not match attestation, key not generated on device, key is exportable. The absence of valid attestation means the financial entity cannot demonstrate compliance with DORA Articles 5(2)(b), 6(10), 9(3)(c)-(d), 9(4)(d), or 28(1)(a). The entity must provide cryptographic attestation evidence or be considered non-compliant."
  },
  "customerOrganisationNumber": "5569743098",
  "customerSwishNumber": "1231015932",
  "supplierIdentifier": "5569741234",
  "supplierNumber": "9871234567",
  "supplierName": "Example Teknisk Leverantör AB",
  "keyPurpose": "Swish payment signing",
  "countryCode": "SE",
  "errors": [
    "Certificate chain verification failed"
  ],
  "warnings": []
}
```

Non-compliant receipts are signed by the same operator key as compliant ones — otherwise a supervisee could repudiate a NON-COMPLIANT finding. The HSM-specific fields (`hsmVendor`, `hsmModel`, `hsmSerialNumber`) are set to `null` on non-compliance to avoid recording unverified vendor claims in the signed receipt.

#### POST dora-api.eba.europa.eu/v1/attestation/se/verify/batch

Batch verification for multiple entities. Returns individual results plus aggregate compliance statistics. A compliance rate significantly below 100% indicates a systemic supervisory failure by the national competent authority — precisely the type of finding that triggers EBA's obligations under Article 17 of Regulation 1093/2010.

#### POST /v1/attestation/{countryCode}/confirm

Step 7 of the verification flow. GetSwish AB (or the issuing bank) posts the outcome of the certificate-issuance decision back to the gatekeeper. The gatekeeper builds and validates a PKIX path from the submitted certificate to the configured issuer-CA trust bundle (`IssuerCaValidator` + `issuer-ca-bundle.pem`; any further certificates in `signingCertificatePem` are used as intermediates), extracts the public key, and verifies that its fingerprint matches the attestation evidence approved in Step 3. On a match (`VERIFIED_AND_ISSUED`) the certificate is stored on the registry entry for the settlement-time lookup. Anomalies (public-key mismatch, certificate issued despite NON-COMPLIANT status, issuance reported without a certificate, confirmation for unknown verification ID, or certificate not chaining to a trusted issuer CA) are flagged. Those that concern an existing entry are persisted in the approval registry; a confirmation for an unknown verification ID has no entry to record it in and is recorded in the audit log only, so `/registry/anomalies` does not list it.

**Request — certificate was issued:**

```json
{
  "verificationId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "confirmationNonce": "9Qk7t0nO2s6bYyq0ZP1c8VJ0aXQ4tRk3mB1nS7dLuFo",
  "issued": true,
  "signingCertificatePem": "-----BEGIN CERTIFICATE-----\nMIIEozCCA4ugAwIBAgIUB...\n-----END CERTIFICATE-----\n",
  "timestamp": "2026-03-20T14:32:15Z",
  "swishNumber": "1234567890",
  "organisationNumber": "5569741234"
}
```

**Request — certificate was not issued (non-issuance notice):**

```json
{
  "verificationId": "2c9d4b6a-8e1f-4b3c-af2e-5d6a7b8c9d0e",
  "confirmationNonce": "Tz3m5Xc9pQw1LbN8vR2kJ7dHs0YgU4eA6fC1oIhKrEs",
  "issued": false,
  "signingCertificatePem": null,
  "timestamp": "2026-03-20T14:32:15Z",
  "nonIssuanceReason": "NON-COMPLIANT attestation — certificate request refused at Step 6",
  "swishNumber": "1234567890",
  "organisationNumber": "5569741234"
}
```

**Response — loop closed successfully (verified and issued):**

```json
{
  "verificationId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "loopClosed": true,
  "publicKeyMatch": true,
  "expectedPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:...",
  "actualPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:...",
  "registryStatus": "VERIFIED_AND_ISSUED",
  "processedTimestamp": "2026-03-20T14:32:16.481Z",
  "anomalies": [],
  "signature": "MEUCIQ...",
  "signingCertificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

Every confirmation response carries `signature` and `signingCertificate` *(since 1.6.0)*: a signature with the receipt key over the canonical form defined in `ConfirmationCanonicalizer` (`c1|verificationId|loopClosed|publicKeyMatch|expectedPublicKeyFingerprint|actualPublicKeyFingerprint|registryStatus|processedTimestamp|anomalies`). Before 1.6.0 the response was unsigned, so its integrity rested on TLS alone; the financial entity now verifies it against `swish.gatekeeper.trusted-keys` exactly as it verifies the receipt. The two fields are omitted from the remaining examples.

**Response — non-issuance notice accepted:**

```json
{
  "verificationId": "2c9d4b6a-8e1f-4b3c-af2e-5d6a7b8c9d0e",
  "loopClosed": true,
  "publicKeyMatch": null,
  "expectedPublicKeyFingerprint": "a1:b2:c3:...",
  "actualPublicKeyFingerprint": null,
  "registryStatus": "REJECTED_NOT_ISSUED",
  "processedTimestamp": "2026-03-20T14:32:16.481Z",
  "anomalies": []
}
```

**Response — anomaly detected (submitted certificate not chained to a trusted issuer CA):**

```json
{
  "verificationId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "loopClosed": false,
  "publicKeyMatch": false,
  "expectedPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:...",
  "actualPublicKeyFingerprint": null,
  "registryStatus": "ANOMALY_PUBLIC_KEY_MISMATCH",
  "processedTimestamp": "2026-03-20T14:32:16.481Z",
  "anomalies": [
    "ANOMALY: Submitted signing certificate is not issued by a trusted issuer CA (PKIX validation failed against the configured gatekeeper.confirmation.issuer-ca-bundle-path trust anchors)."
  ]
}
```

`registryStatus` is one of: `VERIFIED_AND_ISSUED`, `VERIFIED_NOT_ISSUED`, `REJECTED_NOT_ISSUED`, `ANOMALY_ISSUED_DESPITE_REJECTION`, `ANOMALY_PUBLIC_KEY_MISMATCH`, `ANOMALY_UNKNOWN_VERIFICATION` (answered with `404`), `ANOMALY_NONCE_MISMATCH` (see `IssuanceConfirmationResponse.RegistryStatus`). Since 1.7.0 the enum also has `SUPERSEDED`, `REVOKED` and `DECOMMISSIONED`, which only a key-lifecycle event sets (see `POST /v1/attestation/{countryCode}/lifecycle` below); a Step 7 confirmation never produces them. `ANOMALY_NONCE_MISMATCH` is the `400` answer to a confirmation whose `confirmationNonce` does not match the one bound at verify time; the registry entry is left unchanged, and from 1.5.0 the attempt is written to the audit log as a `CONFIRM` entry with `compliant=false` (before 1.5.0 it reached only the application log, and the `400` body said `ANOMALY_PUBLIC_KEY_MISMATCH`). `loopClosed` is `true` iff the confirmation was consistent with the registry entry and passed all binding checks; any anomaly sets it to `false` and the entry remains flagged for supervisory review.

#### POST /api/v1/verify (settlement-time signature verification, since v1.2.0)

Companion endpoint to the issuance-time attestation flow. Whereas the `/v1/attestation/{countryCode}/verify` endpoint runs the 7-step verification protocol at certificate issuance, this endpoint answers a different question at settlement time: *given a digest, signature, and certificate, is the signature valid and is the certificate compliant?*

The intended caller is a settlement-rail enforcement layer such as **railgate**, which receives pacs.008 messages at the central-bank settlement rail (RIX-INST in Sweden, TIPS in the Eurosystem, FedNow in the US) and queries this endpoint to determine whether to allow or default-deny the settlement.

**Data minimisation.** This endpoint never receives or stores transaction payload content. Only cryptographic artefacts (digest, signature, certificate) traverse the boundary. The supervisor never sees transaction amounts, sender/receiver detail, or business message content. SHA-512 collision resistance binds the signature to the payload the digest was taken over; binding it to the settled message is a property of the caller, not of this endpoint (see `[RG]/README.md`). This satisfies GDPR Article 5(1)(c) (data minimisation) and the proportionality requirement implicit in DORA Article 32 supervisory data processing.

**Request — as sent by railgate (four fields):**

```json
{
  "certSerial": "4c3a9f0e12d7",
  "issuerDn": "CN=Swish Customer CA1 v2 for Swish, SERIALNUMBER=GETSWISH, O=Getswish AB (publ), C=SE",
  "digestHex": "a3f5e8b...64-byte-hex...",
  "signatureBase64": "Q2lyY3VsYXIuLi4="
}
```

Without `signingCertificatePem` the gatekeeper looks the certificate up among those stored at Step 7. `certSerial` is the certificate serial number in hexadecimal, case-insensitive, with an optional `0x` prefix, and is compared as a number with the certificate's serial. `issuerDn` is compared as an X.500 name (`javax.security.auth.x500.X500Principal.equals`), so attribute spacing and case do not matter but RDN order does: most specific first, as `X509Certificate.getIssuerX500Principal()` renders it (the reverse of OpenSSL's default display). Only a confirmation that ended in `VERIFIED_AND_ISSUED` stores a certificate. No stored certificate for `(certSerial, issuerDn)` gives `CERT_NOT_FOUND` with `signatureValid=false`, since there is no key to verify against; an unparseable serial or DN gives `MALFORMED_INPUT`. The lookup was added in 1.5.0 — before it, every request without a PEM was answered `MALFORMED_INPUT`, so railgate's four-field requests could never settle.

**Request — with the certificate supplied:**

```json
{
  "certSerial": "4c3a9f0e12d7",
  "issuerDn": "CN=Swish Customer CA1 v2 for Swish, SERIALNUMBER=GETSWISH, O=Getswish AB (publ), C=SE",
  "digestHex": "a3f5e8b...64-byte-hex...",
  "signatureBase64": "Q2lyY3VsYXIuLi4=",
  "signingCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "algorithm": "SHA512withRSA"
}
```

A supplied `signingCertificatePem` must be byte-identical to the certificate stored at Step 7 for its own serial and issuer; `certSerial`/`issuerDn` in the request are then not consulted. In both forms the registry entry is the one whose confirmation stored that certificate. *(Changed 1.6.0: until then a supplied PEM was not compared with anything and compliance was read by the fingerprint of the certificate's public key.)*

`algorithm` is optional and defaults to `SHA512withRSA` (RSA-PKCS#1 v1.5 with SHA-512), the algorithm used by the reference Swish utbetalning signing flow. The other accepted values are `SHA384withRSA`, `SHA256withRSA`, `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA` and `RSASSA-PSS`; anything else is `ALGORITHM_NOT_SUPPORTED`. `RSASSA-PSS` is verified with one fixed parameter set — SHA-512, MGF1 with SHA-512, a 64-byte salt, trailer field 1 — and a PSS signature made with other parameters does not verify. Before 1.5.0 `RSASSA-PSS` was accepted by the whitelist but never verified, because the parameters were not set and the JCA provider refused to verify without them.

**Response — verified compliant signature (settle):**

```json
{
  "signatureValid": true,
  "compliant": true,
  "auditEntryId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "reason": "OK",
  "auditEntryHashHex": "3b0f6e2a9c41d8e7f5a2b6c90d1e4f7a8b3c5d6e7f809a1b2c3d4e5f60718293",
  "verifiedAt": "2026-10-30T12:00:00.417Z",
  "verdictSignatureBase64": "Kp7Lw2...",
  "verdictSignatureAlgorithm": "SHA256withRSA",
  "signingKeyFingerprintHex": "d41f6a0c93b27e58a1c4f0e9b6d3a2785c1e0f4b9a6d2c7e8f3b1a0d5c9e7f24"
}
```

**Response — a certificate with no registry entry (default-deny; the signature is not checked, so `signatureValid` is false):**

```json
{
  "signatureValid": false,
  "compliant": false,
  "auditEntryId": null,
  "reason": "CERT_NOT_FOUND",
  "auditEntryHashHex": "9e4c1a7b2d5f8e0c3a6b9d2e5f8a1c4b7d0e3f6a9c2b5d8e1f4a7c0b3d6e9f21",
  "verifiedAt": "2026-10-30T12:00:01.032Z",
  "verdictSignatureBase64": "aQ93Fz...",
  "verdictSignatureAlgorithm": "SHA256withRSA",
  "signingKeyFingerprintHex": "d41f6a0c93b27e58a1c4f0e9b6d3a2785c1e0f4b9a6d2c7e8f3b1a0d5c9e7f24"
}
```

**Response — signature does not match digest (default-deny):**

```json
{
  "signatureValid": false,
  "compliant": false,
  "auditEntryId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "reason": "SIGNATURE_INVALID",
  "auditEntryHashHex": "c7d2e9f4a1b6c3d8e5f2a7b4c9d6e1f8a3b0c5d2e7f4a9b6c1d8e3f0a5b2c7d4",
  "verifiedAt": "2026-10-30T12:00:02.880Z",
  "verdictSignatureBase64": "Ub0Xr4...",
  "verdictSignatureAlgorithm": "SHA256withRSA",
  "signingKeyFingerprintHex": "d41f6a0c93b27e58a1c4f0e9b6d3a2785c1e0f4b9a6d2c7e8f3b1a0d5c9e7f24"
}
```

`reason` is one of: `OK`, `CERT_NOT_FOUND`, `SIGNATURE_INVALID`, `CERT_NON_COMPLIANT`, `CERT_EXPIRED`, `CERT_SUPERSEDED`, `CERT_REVOKED`, `CERT_DECOMMISSIONED`, `MALFORMED_INPUT`, `ALGORITHM_NOT_SUPPORTED`. They are evaluated in this order: `MALFORMED_INPUT` → `CERT_NOT_FOUND` → `ALGORITHM_NOT_SUPPORTED` / `SIGNATURE_INVALID` → `CERT_SUPERSEDED` / `CERT_REVOKED` / `CERT_DECOMMISSIONED` → `CERT_EXPIRED` → `CERT_NON_COMPLIANT` / `OK`. From 1.6.0 the certificate is resolved before the signature is checked, so `CERT_NOT_FOUND` comes with `signatureValid=false`; `CERT_EXPIRED` means the stored certificate is outside its validity period at the time of the call. `CERT_SUPERSEDED`, `CERT_REVOKED` and `CERT_DECOMMISSIONED` *(since 1.7.0)* come with `signatureValid=true` and `compliant=false` for a certificate whose registry entry a key-lifecycle event has moved to `SUPERSEDED`, `REVOKED` or `DECOMMISSIONED`; a revoked certificate with a bad signature therefore answers `SIGNATURE_INVALID`, and a revoked, expired one `CERT_REVOKED`. Only an entry whose confirmation ended in `VERIFIED_AND_ISSUED` settles; until 1.6.0 an entry still awaiting Step 7, or confirmed as `VERIFIED_NOT_ISSUED`, also settled. `auditEntryId` is the approval-registry `verificationId` the compliance verdict was read from: it is shared by every settlement against the same certificate and by the `VERIFY` and `CONFIRM` audit entries of that issuance, and it is `null` when no registry entry matched. `auditEntryHashHex`, added in 1.5.0, is the `thisEntryHashHex` of the `SETTLEMENT_VERIFY` audit entry written for this call, so it identifies that one decision in the chain; it is present on every `200` response, `CERT_NOT_FOUND` included. It is not covered by the entry's `receiptDigestBase64`, which is computed over the other four fields before the entry exists. The settlement-rail enforcement layer (railgate) allows the settlement only if both `signatureValid` and `compliant` are `true` — from railgate 1.7.0, by default, also only if the verdict's signature verifies under a gatekeeper key it trusts. Any other combination triggers default-deny: the originating bank receives a structured error code and the transaction does not settle until the bank resubmits with valid data, or the settlement is abandoned.

**Signed verdict** *(since 1.7.0)*. Every response is signed, denials included, so that the settlement rail can check the verdict independently of the TLS session that delivered it (railgate 1.7.0 does, and by default requires it). `verdictSignatureBase64` is the active receipt signer's signature (`verdictSignatureAlgorithm`, e.g. `SHA256withRSA`) over the UTF-8 bytes of the `sv1` canonical form (`SettlementVerdictCanonicalizer`):

```
sv1|verifiedAt|certSerialHex|issuerDn|digestHex|signatureValid|compliant|reason|auditEntryId|auditEntryHashHex
```

`verifiedAt` is the instant the call started, truncated to milliseconds, exactly as in the response field. `certSerialHex`, `issuerDn` and `digestHex` are the request's values normalised: the serial without an optional `0x`/`0X` as `new BigInteger(s, 16).toString(16)`, the issuer as `X500Principal.getName(RFC2253)`, the digest lowercased; booleans are `true`/`false` and a `null` string is empty; in `verifiedAt`, `issuerDn`, `reason`, `auditEntryId` and `auditEntryHashHex` `%` becomes `%25` and then `|` becomes `%7C`. Because `auditEntryHashHex` is inside the signed form, the verdict is bound to the audit entry of the same call. `signingKeyFingerprintHex` names the key: the lowercase hex SHA-256 of the active signing certificate's DER SubjectPublicKeyInfo, which is `publicKeyFingerprintHex` on `GET /v1/gatekeeper/keys` (not the SHA-256 of the certificate). When the request's `certSerial`, `issuerDn` or `digestHex` cannot be normalised (normally `MALFORMED_INPUT`; also a `certSerial` with surrounding whitespace, which the lookup itself tolerates), the response is returned with the four fields `null`. The form carries no per-call nonce, so a verdict for an identical request can be presented again; a relying party bounds that with its own clock skew check.

The role-based access policy in `SecurityConfig` restricts this endpoint to clients holding the `SETTLEMENT_RAIL` role (typically the central-bank settlement system) or `SUPERVISOR` (for sandbox and incident-response scenarios).

#### POST /v1/attestation/{countryCode}/lifecycle (key-lifecycle events, since 1.7.0)

Records the events of Article 2 §6.2 that happen after issuance. Roles: `FE` or `SUPERVISOR` (one path for all four event types); rate-limited under its own `lifecycle` bucket. The body names the certificate by `certSerial` (hex, optional `0x`) and `issuerDn`, as the settlement request does.

| `eventType` | Other fields | Effect | Audit operation |
| --- | --- | --- | --- |
| `SIGNED` | `digestHex`, `signatureBase64` (required) | Verified exactly as a settlement — certificate stored at Step 7 in this jurisdiction, lifecycle status, validity, `SHA512withRSA` over the digest bytes — and answered with the `/api/v1/verify` fields plus `"eventType": "SIGNED"`, signed over `sv1` like a settlement verdict. Not bound to the principal that verified the key | `SIGNED` |
| `ROTATED` | `reason` (required), `successorVerificationId` (optional, an entry of this jurisdiction) | `VERIFIED_AND_ISSUED` → `SUPERSEDED` | `ROTATED` |
| `REVOKED` | `reason` (required) | `VERIFIED_AND_ISSUED` or `SUPERSEDED` → `REVOKED` (final) | `REVOKED` |
| `DECOMMISSIONED` | `reason` (required) | `VERIFIED_AND_ISSUED` or `SUPERSEDED` → `DECOMMISSIONED` (final) | `DECOMMISSIONED` |

A status change answers `eventType`, `verificationId`, `applied`, `previousStatus`, `registryStatus` (after the event), `successorVerificationId`, `reason` and `processedAt`, plus `auditEntryHashHex`, with HTTP 200 `OK`, 404 `CERT_NOT_FOUND`, 409 `TRANSITION_NOT_ALLOWED`, 409 `SUCCESSOR_NOT_FOUND` or 400 `MALFORMED_INPUT`. These responses are not signed; their audit entries are. With mTLS a caller without `SUPERVISOR` may change only an entry whose verification it performed itself; any other entry is answered `CERT_NOT_FOUND` and logged at WARN. The issued certificate stays on the entry, which is why settlement still finds it and denies it (`CERT_SUPERSEDED`, `CERT_REVOKED`, `CERT_DECOMMISSIONED`). With the file-backed registry the change is journalled (`STATUS_CHANGE`) before it takes effect. Every request that passes bean validation appends one audit entry, refusals included; it carries the key's fingerprint, the certificate's serial and issuer and the resulting status when the event resolved to a registry entry, and so continues that key's per-key chain (see "Audit and supervisory access").

The manuscript's six events map to the audit log as follows: Generated → `VERIFY` / `BATCH_VERIFY` (recorded when the gatekeeper verifies the attestation, not when the HSM generates the key), Issued → `CONFIRM`, Signed → `SIGNED` (reported by the organisation) and `SETTLEMENT_VERIFY` (at the rail), Rotated → `ROTATED`, Revoked → `REVOKED`, Decommissioned → `DECOMMISSIONED`.

#### Data triangulation (since 1.7.0)

`SUPERVISOR` only, every method; rate-limited under the `audit` bucket. `{countryCode}` is upper-cased and an inquiry is visible only under its own.

| Method and path | Body | Answer |
| --- | --- | --- |
| `POST /v1/triangulation/{cc}/inquiries` | — | 201 `{inquiryId, countryCode, createdAt}`; 409 `INQUIRY_CAP_REACHED` |
| `POST /v1/triangulation/{cc}/inquiries/{id}/bank-reports` | `{bankId, entries: [{organisationNumber, swishNumber, certSerial?, issuerDn?}]}` | 200 `{inquiryId, reporterId, entriesAccepted, entriesHeld, sha256Hex}`; 409 `BANK_PHASE_CLOSED` once the operator has reported, `ENTRY_CAP_REACHED`; 404; 400 `MALFORMED_INPUT` |
| `POST /v1/triangulation/{cc}/inquiries/{id}/operator-report` | `{operatorId, entries: [{swishNumber, organisationNumber?, certSerial, issuerDn}]}` | 200 (same shape); 409 `OPERATOR_MISMATCH` (one operator per inquiry), `ENTRY_CAP_REACHED`; 404; 400 `MALFORMED_INPUT` |
| `GET /v1/triangulation/{cc}/inquiries/{id}/discrepancies` | — | 200 report; 404 |
| `DELETE /v1/triangulation/{cc}/inquiries/{id}` | — | 204; 404 |

Organisation and Swish numbers follow the patterns of the verification request (`^\d{10}(\d{2})?$`, `^123\d{7}$`); at most 50 000 entries per submission. The report compares all bank reports, the operator report and the registry entries of the jurisdiction that hold an issued certificate, as the registry stands when the report is generated, and lists `swishNumbersMissingFromOperatorReport`, `swishNumbersMissingFromBankReports`, `certificatesWithoutVerifiedAttestation` (with the entry's status or `NOT_IN_REGISTRY`), `verifiedCertificatesNotReportedByOperator` and `organisationNumberMismatches`, with `discrepancyCount`, `zeroDiscrepancies` and `inputDigests` (SHA-256 of each bank report, the operator report and the registry input in their canonical forms). It is signed with the receipt key over the `tr1` canonical form (`TriangulationCanonicalizer`; `reportSignatureBase64`, `signatureAlgorithm`, `signingKeyFingerprintHex`), and each GET appends a `TRIANGULATION` audit entry whose request digest commits to the inputs (`auditEntryHashHex`). Inquiries are held in memory only: a restart discards them, and at most `gatekeeper.triangulation.max-inquiries` (10) exist at a time, with at most `gatekeeper.triangulation.max-entries-per-inquiry` (100 000) entries. Bank-reported certificate fields are kept and covered by the digest but not compared in this version. The reports may contain personal data: a sole trader's organisation number is a personal identity number.

### Supported HSM Vendors

**Inclusion criterion.** A vendor is supported when a third party can verify offline, against a published vendor root and without a human witness or the involvement of the vendor or the financial entity, that an individual key was generated in the HSM and cannot be exported from it. The criterion follows from DORA (Regulation (EU) 2022/2554) Article 9(3)(d), under which ICT solutions and processes shall "ensure that data is protected from risks arising from data management, including poor administration, processing-related risks and human error" (Swedish text: "säkerställa att uppgifterna skyddas mot risker som uppstår från datahanteringen, inbegripet bristfällig förvaltning, processrelaterade risker och den mänskliga faktorn"), and from Article 9(4)(d), under which financial entities shall "implement policies and protocols for strong authentication mechanisms, based on relevant standards and dedicated control systems, and protection measures of cryptographic keys whereby data is encrypted based on results of approved data classification and ICT risk assessment processes". The same question is put to every vendor: can the requirement be shown to be met with the vendor's attestation? A vendor marked ❌ is one for which it cannot be shown; that is not a finding that the vendor, or an entity using it, fails DORA.

| Vendor | Attestation Method | Root CA Verification |
|---|---|---|
| Crypto4A QASM | QASM attestation message (signed claims) | ✅ Every signature block (ECDSA P-384, HSS) over the claims, chained to the pinned C4A_RCA key; `key-spki` must be the CSR key, with private-key class, confined, hardware-generated and never-extracted claims. The PKI Consortium's published message reaches COMPLIANT (`AttestationSignatureValidityTest.genuineCrypto4AMessageSetsEveryArticleBit`) |
| Entrust nShield | Key attestation bundle JSON (`nfkmattest`) | ✅ Warrant from the pinned KWARN-1 key to the module's KLF2 and ESN; module state, world binding and key generation certificates; the CSR key's generation-time ACL must not make it recoverable by the Administrator Card Set nor allow export or key-wrapping permissions. Only `ModuleInformation` warrants are accepted; `FieldUpgradeModuleInformation` depends on legacy DSA-1024 signatures (Entrust). Entrust's two examples carry such warrants and are NON-COMPLIANT with no article bit (`AttestationSignatureValidityTest.entrustsFieldUpgradeBundlesSetNoArticleBit`); below the warrant they verify as Entrust reports (`NShieldVerifierTest`) |
| Fortanix DSM | Key attestation JSON (`key_attestation_<key UUID>.json`) | ✅ Authority by PKIX with Fortanix's attestation policy under the pinned Fortanix root at signing time; statement attests the CSR key with generated-in-DSM and never-exportable claims. Fortanix's documented sample reaches COMPLIANT (`AttestationSignatureValidityTest.genuineFortanixStatementSetsEveryArticleBit`) |
| Securosys Primus | XML attestation + signature + cert chain | ✅ Chain under the pinned Securosys root; XML signature by the attestation key; key attributes (generated, never extractable) and the CSR key read from the signed XML. The reference Primus HSM's attestation of an RSA-4096 key reaches COMPLIANT under the default key policy (`AttestationSignatureValidityTest.genuineSecurosysAttestationSetsEveryArticleBit`) |
| Thales Luna | Public Key Confirmation (`cmu getpkc`, PKCS#7) | ✅ PKC chain under the pinned Chrysalis-ITS Root key; Proof of Origin key must be the CSR key. Thales's own test vector reaches COMPLIANT (`AttestationSignatureValidityTest.genuineThalesLunaPkcSetsEveryArticleBit`) |
| Yubico YubiHSM 2 | Attestation certificate chain | ✅ Chain under the pinned Yubico root; origin (generated) and capabilities (not exportable under wrap) read from the attestation certificate, whose key must be the CSR key. The reference YubiHSM 2's attestation of an RSA-4096 key reaches COMPLIANT under the default key policy (`AttestationSignatureValidityTest.genuineYubiHsm2AttestationSetsEveryArticleBit`) |
| Azure Managed HSM | `az keyvault key get-attestation` JSON | ⚠️ Marvell chain under the pinned Marvell roots, both attestations signed by the partition certificate, key attributes and RSA modulus read from the signed blobs (`MarvellAttestation`); never COMPLIANT until a real attestation confirms the Marvell format (`MARVELL_FORMAT_UNCONFIRMED`) |
| Google Cloud HSM | `attestation.dat` (gzip or decompressed) + cert chain | ⚠️ Marvell chain and Google owner chain (Hawksbill Root v1 prod), both pinned; key attributes and RSA modulus read from the signed blob; never COMPLIANT until a real attestation confirms the Marvell format (`MARVELL_FORMAT_UNCONFIRMED`) |
| Marvell LiquidSecurity | `attest.dat` (from key generation) + partition and card certificates | ⚠️ Marvell chain under the pinned Marvell roots; key attributes and RSA modulus or EKCV read from the signed blob; never COMPLIANT until a real attestation confirms the Marvell format (`MARVELL_FORMAT_UNCONFIRMED`) |
| AWS CloudHSM | No per-key attestation | ❌ Excluded: the requirement in Article 9(3)(d) cannot be shown to be met for an individual key. AWS CloudHSM attests the identity of the HSM and the cluster, and only until the cluster is initialised (AWS CloudHSM User Guide, page `verify-hsm-identity`). That attestation does not cover individual keys, so it cannot be independently verified that a key was generated in the HSM and cannot be exported. |

The published Thales, Crypto4A and Fortanix samples attest RSA-2048 and EC P-256 keys; under the default key policy they are NON-COMPLIANT with `KEY_NOT_ALLOWED` only (`defaultPolicyRefusesEveryKeyButRsa4096`), and the tests above run them under a policy that also allows those keys.

Firmware and FIPS state are reported for Yubico only (receipt fields `hsmFirmwareVersion`, `hsmFipsIndicator`, `hsmFipsApprovedMode`, since 1.7.0). With `gatekeeper.key-policy.require-fips-approved-mode=true` every other vendor is NON-COMPLIANT with `FIPS_MODE_NOT_IN_ATTESTATION_FORMAT`. For Entrust nShield that code means that the verifier reads no FIPS-approved-mode statement, not that the format cannot carry one: the bundle's FIPS 140 Level 3 world-binding certificate is verified but not reported, and whether such a security world equals FIPS-approved mode is not established here; nor is the relation of Crypto4A's `qasm-certified-production` claim to it.

#### Pinned trust anchors

Every anchor below is a constant in the verifier source, with a "Pinned trust anchor" comment block beside it, and `TrustAnchorPinningTest` (8 tests, the same in hsm) asserts its subject, SHA-256 and validity, that each certificate is self-issued and its self-signature verifies, the key hashes, and that the verifier built by its no-argument constructor holds exactly this anchor. SHA-256 is of the DER certificate unless stated. Compare these values with what the manufacturer publishes before relying on them.

| Anchor (constant) | Pinned as | SHA-256 | Validity (UTC) |
| --- | --- | --- | --- |
| Yubico YubiHSM Root CA, `CN=Yubico YubiHSM Root CA` (`YubicoVerifier.YUBICO_ROOT_CA`) | PKIX trust anchor | `09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24` | 2017-01-01T00:00:00Z – 2071-10-05T00:00:00Z |
| Securosys Primus root, `ST=ZH,O=Securosys,L=Zurich,C=CH,CN=PRIMUS_HSM_ROOTKEY` (`SecurosysVerifier.SECUROSYS_ROOT_CA`) | PKIX trust anchor | `D2:C9:3D:8F:69:BC:8D:62:4E:37:F2:5B:9E:6E:7B:EC:41:76:1A:AB:86:4C:94:F3:79:36:1B:9B:78:A9:DB:97` | 2024-08-21T12:33:45Z – 2054-08-14T12:33:45Z |
| Marvell LiquidSecurity root, `CN=localca.liquidsecurity.cavium.com,OU=LiquidSecurity,O=Cavium\, Inc.,L=San Jose,ST=California,C=US` (`MarvellAttestation.MARVELL_ROOT_PEM`) | issuer a card certificate must name and be signed by (Azure, Google, Marvell) | `23:01:43:DF:00:E0:B4:52:74:3E:06:8A:5B:3F:C0:8D:F8:F0:6C:EF:C4:85:4E:A6:27:AE:B7:EB:D7:0E:E2:F4` | 2024-07-25T20:29:20Z – 2034-07-23T20:29:20Z |
| Marvell LiquidSecurity 2 root, `CN=cavium-liquidsecurity-ls2,C=US+ST=CA+OU=SSBU+L=SanJose+O=Marvell` (`MarvellAttestation.MARVELL_LS2_ROOT_PEM`) | as above | `17:64:4D:E0:D3:3B:C7:3B:2F:4E:F4:C2:0A:11:F6:C8:CC:1F:72:3A:4C:D8:3E:E6:00:36:1C:BB:24:D8:D2:E5` | 2024-07-22T20:34:23Z – 2034-07-20T20:34:23Z |
| Google owner root, `CN=Hawksbill Root v1 prod,O=Google Inc,L=Mountain View,ST=CA,C=US` (`GoogleCloudHsmVerifier.HAWKSBILL_ROOT_PEM`) | issuer the owner card and partition certificates must name and be signed by | `46:B5:FD:35:1D:56:A0:72:1C:A0:AF:CD:17:31:C0:F7:B7:4E:39:41:EB:81:8B:FD:0E:C3:6E:29:DF:0D:E0:95` | 2017-07-01T00:00:00Z – 2030-01-01T00:00:00Z |
| Thales Chrysalis-ITS Root, `CN=Chrysalis-ITS Root,O=Chrysalis-ITS Inc.,L=Ottawa,ST=Ontario,C=CA`, serial 80450000000D (`ThalesLunaVerifier.CHRYSALIS_ROOT_PEM`) | public key | certificate `69:6A:7E:E6:7B:C4:FA:CF:F6:09:11:BC:0B:24:A3:A6:BC:E7:5A:2E:F4:C4:23:18:44:8A:DD:45:01:B6:99:69`; key (DER SubjectPublicKeyInfo) `5D:31:FC:46:2A:E8:A1:A5:32:7B:14:9F:F4:3A:A6:D8:67:A2:8D:7E:17:CA:1C:CA:7E:7D:51:4C:F8:CD:C1:32` | 2002-01-01T00:00:00Z – 2032-01-01T00:00:00Z |
| Crypto4A C4A_RCA, `CN=C4A_RCA,O=Crypto4A,L=Ottawa,ST=Ontario,C=Canada` (`Crypto4AVerifier.C4A_ROOT_PEM`) | public key | certificate `63:7E:6A:7E:95:DE:D7:27:2F:5B:3E:5A:0D:94:41:4D:23:E1:B5:4F:9E:2E:65:93:B6:41:75:62:BB:B5:43:3C`; key `40:14:6C:BF:79:12:E0:A2:9C:A6:01:F9:A1:63:5E:37:BA:8D:69:A4:CD:B8:8A:9A:F1:63:16:33:E7:34:9B:F0` | 2020-07-13T13:06:33Z – 2045-07-13T13:06:33Z |
| Fortanix Attestation and Provisioning Root CA, `CN=Fortanix Attestation and Provisioning Root CA,O=Fortanix\, Inc.,L=Santa Clara,ST=California,C=US` (`FortanixVerifier.FORTANIX_ROOT_PEM`) | PKIX trust anchor (a copy in the submitted chain is recognised by its key and skipped) | certificate `D7:1A:15:B3:4E:78:1E:9E:F9:13:54:FA:BA:E8:B1:15:E0:62:B8:97:95:FE:C3:AE:C0:E0:45:FE:D2:66:C2:C2`; key `D0:12:75:CC:16:BD:C2:DA:D8:CD:51:53:2B:CF:C9:E6:9E:DB:99:63:A4:32:4A:A5:E1:29:45:37:2A:FB:5E:15` | 2023-09-01T16:38:12Z – 2033-08-29T16:38:12Z |
| Entrust nShield KWARN-1, ECDSA P-521 (`NShieldVerifier.KWARN_1_X`, `KWARN_1_Y`) | bare public key (the warrant's first signature is checked against it) | DER SubjectPublicKeyInfo of the key built from X and Y: `DF:8F:05:A3:95:96:BB:9C:4A:8C:C4:D3:B6:DE:10:60:7F:36:2D:71:82:E8:81:EA:82:A5:ED:C7:CD:CD:F8:4F` | none (bare key) |

Since 1.7.0 each comment block also records where the manufacturer publishes the anchor, and tells operators to download it and compare its SHA-256 with the value above. The last column says what each constant is confirmed against. **Every anchor is confirmed against the manufacturer's own material.**

| Anchor | Manufacturer source recorded in the comment block | What was checked |
| --- | --- | --- |
| Yubico | https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem (block unchanged) | the attestation from the reference YubiHSM 2 FIPS (serial 20783176) validates under it |
| Securosys | https://support.securosys.com/external/knowledge-base/article/147 (file `hsm_rsa_root.crt`), linked from https://docs.securosys.com/primus-hsm/tutorials/key_attestation_verify, which warns: "Always download the root certificate directly from Securosys. Do not accept it from an auditee." | the attestation from the reference Primus HSM (serial 18386101) validates under it |
| Marvell (both roots) | https://www.marvell.com/content/dam/marvell/en/public-collateral/security-solutions/liquid_security_certificate.zip, next to the existing source (Microsoft's `Azure/azure-managed-hsm-key-attestation` repository) | compared on 2026-10-31: the archive holds one root, another certificate for the key of `localca.liquidsecurity.cavium.com` (serial C0EAADF434DEDC17, 2015-11-19 to 2025-11-16; key SHA-256 `78:AD:CB:A1:F3:8B:EE:30:4B:C4:4D:6A:08:65:03:F2:94:00:37:D4:B3:D5:8A:1B:F6:6A:32:82:EF:58:CD:41`); it does not hold the `cavium-liquidsecurity-ls2` root. Marvell shows that root on https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/liquidsecurity2-certificate-ls2-g-axxx-mi-f-bo.html, as another certificate (2022-01-07 to 2032-01-05) whose RSA modulus and exponent are the pinned root's, compared in full on 2026-10-31. An override with the archive's file alone replaces both roots and drops the LS2 one |
| Google owner | https://www.gstatic.com/cloudhsm/roots/global_1498867200.pem, as named in Google's sample `verify_attestation_chains.py` (`googleapis/python-kms`) | byte-identical to `OWNER_ROOT_CERT_PEM` in Google's `verify_attestation_chains.py` (`GoogleCloudPlatform/python-docs-samples`, `kms/attestations`), compared on 2026-10-31 |
| Thales | https://thalesdocs.com/gphsm/luna/10.2/docs/network/Content/admin_partition/confirm/safenet-root.pem, the Thales-published root used by `cmu verifyhsm`, next to the existing PKI Consortium source | compared on 2026-10-31: another certificate for the pinned key (serial 804500000007, SHA-1 signature, SHA-256 `80:7E:16:80:AB:0C:93:39:71:FE:70:75:59:5C:10:72:E3:18:39:51:A5:A8:AB:53:50:6F:10:93:FE:FF:66:E7`), the same certificate Thales's PKC test vector ends in; compare the key SHA-256, not the certificate's |
| Crypto4A | https://support.crypto4a.com/cs/Certificate (C4A_RCA; the page also shows C4A_RCA_HSS and the firmware trust anchor C4A_TA_FW, which are not pinned), and https://github.com/pkic/remote-key-attestation/blob/main/validation/crypto4a-qasm.md, contributed by Crypto4A to the PKI Consortium's repository (pull request #21, commit `6a923ce8` by `olivier@crypto4a.com`, 2024-06-12) | both certificates are byte-identical to the constant, compared on 2026-10-31 |
| Fortanix | https://pki.fortanix.com/Fortanix_Attestation_and_Provisioning_Root_CA.crt | byte-identical to the root certificate in the sample statement of Fortanix's "Fortanix DSM for Verifying Key Attestation Statements" (`vendor-fixtures/fortanix`), compared on 2026-10-31 |
| Entrust | https://nshielddocs.entrust.com/app-notes/warrants/root-key.html, which publishes the key as ECDSA NIST P-521 | the first and last 16 hex digits of X and Y against the page; the whole key by Entrust's example warrants (`vendor-fixtures/nshield`), which verify under it. Entrust's nCore key hash is recorded as published, not computed |

Crypto4A publishes C4A_RCA on its support site, so that anchor too can be obtained independently of the device under verification, as §3.6 above asks.

#### Replacing a trust anchor (since 1.7.0)

An authority that has obtained a root from its manufacturer can run the verifiers on that root instead of the pinned constant by naming a PEM file under `gatekeeper.trust-anchors.<key>` (environment placeholder `GATEKEEPER_TRUST_ANCHOR_<KEY>`, for example `GATEKEEPER_TRUST_ANCHOR_GOOGLE_OWNER`). A blank value, the default in every profile, keeps the pinned anchor, and verification is then as before (`TrustAnchorsTest`, `TrustAnchorDefaultWiringTest`).

| Key | Replaces | File content |
| --- | --- | --- |
| `yubico` | Yubico root (Yubico verifier and, for the log key, `SigningKeyAttestation`) | one RSA certificate, self-signed |
| `securosys` | Securosys root (Securosys verifier and `SigningKeyAttestation`) | one RSA certificate, self-signed |
| `marvell` | both Marvell roots, for AZURE, GOOGLE and MARVELL together | one or more RSA certificates, each self-signed, no duplicates |
| `google-owner` | Google owner root (GOOGLE) | one RSA certificate, self-signed |
| `thales` | Chrysalis-ITS Root key (the verifier uses the certificate's key) | one RSA certificate, self-signed |
| `crypto4a` | C4A_RCA key (the verifier uses the certificate's key) | one EC P-384 certificate, self-signed |
| `fortanix` | Fortanix root | one RSA certificate, self-signed |
| `entrust` | KWARN-1 key | one PEM `PUBLIC KEY` on P-521, named curve, uncompressed point |

Any other content stops start-up with an `IllegalStateException` naming the property and the path, and so does a missing file, a file over 1 MiB, a DER file (convert it to PEM first, for example `openssl x509 -inform DER -in root.crt -out root.pem`), or an unknown key such as `yubikey`. At start-up each override is logged at INFO with its path and SHA-256, and at WARN, with both the override's and the pinned SHA-256, when it is not the pinned anchor; for a certificate the WARN also says whether its key is the pinned key. `GET /v1/attestation/supported-vendors` reports, per vendor, the anchors in use (see "Gatekeeper public endpoints"); it does not publish the file's path.

What is not checked: an override's validity period (only logged), BasicConstraints, key usage and key size. The Thales, Crypto4A and Fortanix key-hash checks apply only to the pinned constants. A Thales, Crypto4A or Fortanix certificate re-issued over the pinned key is reported `matchesPinned: false`, with a WARN saying "(the same key)". The keys must be set by environment variable, command-line argument, system property or external configuration file; `SpringApplication.setDefaultProperties` does not work, because the packaged `application.yaml` declares the keys. Environment variables have not been tested. `DEPLOYMENT.md` §2.7 has the procedure.

---

## Audit and supervisory access

The gatekeeper persists every decision into a hash-chained, append-only audit log. The combination of per-entry hash linkage and per-entry seal signature is what allows a supervisor to verify that the audit trail has not been retroactively rewritten — a property required by DORA Regulation (EU) 2022/2554 Article 28(6), which mandates 5-year retention with discoverable verifiability of records relating to ICT third-party service providers.

### Hash-chained append-only audit log

`AppendOnlyFileAuditLog` writes a JSON Lines file at `gatekeeper.audit.path` (default `./audit-log.jsonl`). Each `AuditEntry` (see `eu.gillstrom.gatekeeper.audit.AuditEntry`) contains:

- `sequenceNumber` — strictly monotonic, starting at 1.
- `timestamp` — ISO-8601 instant of the append.
- `mtlsClientPrincipal` — the supervisory principal extracted from the mTLS client certificate (resolved via `MtlsPrincipalResolver`).
- `operation` — one of:
  - `VERIFY`, `BATCH_VERIFY`, `CONFIRM` — issuance time (`VerificationService`);
  - `SETTLEMENT_VERIFY` — each `POST /api/v1/verify` (`SignatureVerificationService`), so a supervisor can separate issuance-time from settlement-time decisions;
  - `SIGNED`, `ROTATED`, `REVOKED`, `DECOMMISSIONED` *(since 1.7.0)* — key-lifecycle events on `POST /v1/attestation/{countryCode}/lifecycle`;
  - `TRIANGULATION` *(since 1.7.0)* — a sealed triangulation report; `verificationId` is then the inquiry id.
- `verificationId`, `requestDigestBase64`, `receiptDigestBase64`, `compliant` — the decision-relevant fields. Where an event resolved to no registry entry (`SETTLEMENT_VERIFY`, `SIGNED`, the status changes) `verificationId` is `NO-REGISTRY-MATCH`.
- `prevEntryHashHex` — the predecessor entry's `thisEntryHashHex`, copied verbatim (not re-hashed). The first entry uses 64 ASCII zeros (`AuditEntry.SENTINEL_PREV_HASH_HEX`) so "empty log" is a deterministic, well-known starting point.
- `canonicalVersion` *(since 1.7.0)* — `"v2"` for every new entry; entries written before 1.7.0 have none and are hashed in the v1 form.
- Inventory fields *(since 1.7.0)* — `keyFingerprintHex` (the attested key, lower-case colon-separated SHA-256 of its SubjectPublicKeyInfo, as on receipts and in the registry), `certSerialHex` and `certIssuerDn` (the issued certificate, lower-case hex and RFC 2253), `hsmVendor` and `hsmSerial` (as on the receipt), `registryStatus`, `hsmFirmwareVersion` and `hsmFipsApprovedMode` (`"true"`, `"false"` or `null`). Which operation sets which: `VERIFY` and `BATCH_VERIFY` the key fingerprint whenever the submitted key parsed, vendor and serial only when compliant, and the firmware and FIPS flag for a Yubico chain that validated; `CONFIRM` the key of the entry it resolved to, the submitted certificate's serial and issuer once it passed issuer-CA validation, and the status of the signed response; `SETTLEMENT_VERIFY` and `SIGNED` key, certificate and status of the matched registry row; `ROTATED`, `REVOKED` and `DECOMMISSIONED` the same from the entry the event resolved to, with the status after the event; `TRIANGULATION` none. A field that does not apply is `null`.
- `prevKeyEntryHashHex` *(since 1.7.0)* — the `thisEntryHashHex` of the previous entry with the same `keyFingerprintHex` (64 zeros for the key's first entry; `null` when the entry has no fingerprint). The verification, confirmation, settlements and lifecycle events of one key therefore form a chain of their own inside the global chain, from generation to decommissioning.
- `thisEntryHashHex` — SHA-256 over the canonical bytes of the entry. v2: `v2|sequenceNumber|timestamp|mtlsClientPrincipal|operation|verificationId|requestDigestBase64|receiptDigestBase64|compliant|prevEntryHashHex|keyFingerprintHex|certSerialHex|certIssuerDn|hsmVendor|hsmSerial|registryStatus|hsmFirmwareVersion|hsmFipsApprovedMode|prevKeyEntryHashHex`, each value escaped (`%` → `%25`, then `|` → `%7C`) and every `null` written as `%N`; v1: the first ten fields with `v1`, and `<no-receipt>` for a missing receipt digest.
- `entrySignatureBase64` — `ReceiptSigner.sign(thisEntryHashHex.getBytes(UTF_8))`. In production the signer uses the NCA's organisation-certificate-backed signing key — the certificate the NCA uses for ordinary administrative signing of supervisory acts. In the reference build the signer is the `EphemeralReceiptSigner` (clearly marked as such — see `THREAT_MODEL.md`).
- `timestampTokenBase64` *(since 1.7.0)* — in time-stamping `entry` mode, an RFC 3161 token over SHA-256 of the entry's signature input; outside the hash, like the signature.

The chain is verified by `AuditLog.verifyChainIntegrity()`. Tampering with any historical entry's content — the inventory fields of a v2 entry included — breaks the chain at that entry and at every entry that follows; replacing entries en bloc by an attacker who controls the storage layer also requires possessing the seal private key, because every individual entry signature is computed over its own `thisEntryHashHex`. `AppendOnlyFileAuditLog` walks the file as it is on disk, re-parsed with the parser used at start-up, and requires it to end at the in-memory head, so tampering with or truncating the file while the gatekeeper runs is reported (before 1.5.0 the walk ran over the in-memory copy, which a change to the file does not touch). Each entry signature is verified with the configured `gatekeeper.signing.algorithm` under the active signing certificate or any certificate listed in `gatekeeper.signing.retired-keys`, so the chain stays verifiable across a key rotation. Since 1.7.0 the check also requires each v2 entry's per-key link to be right, refuses a v1 entry after a v2 entry or a v1 entry carrying a v2-only field or a token, and refuses an unknown `canonicalVersion`; when `gatekeeper.timestamping.trusted-certs-path` is set it also validates every stored RFC 3161 token and anchor record.

### Log-signing key in an HSM *(since 1.7.0)*

The seal that signs receipts, audit entries, verdicts and reports can be held by an HSM instead of a PKCS#12 file. `ConfiguredReceiptSigner` (`gatekeeper.signing.mode=configured`) loads any JCA keystore: `gatekeeper.signing.keystore-type` (default `PKCS12`), optionally `gatekeeper.signing.provider-class` — a `java.security.Provider` such as `sun.security.pkcs11.SunPKCS11` or a vendor's JCE provider, found through `ServiceLoader` or by its no-argument constructor — and `gatekeeper.signing.provider-config` (passed to `Provider.configure`, e.g. a PKCS#11 configuration file). `keystore-path` is required only for the file types (PKCS12, JKS, JCEKS, BCFKS, BKS, UBER); otherwise the keystore is loaded with `KeyStore.load(null, keystore-password)`, the password being the PIN. At start-up the signer signs a probe and verifies it under the alias's certificate; a mismatch, like any misconfiguration, stops start-up. The INFO line at start-up states the keystore type, the provider and whether `PrivateKey.getEncoded()` is non-null (an extractable key).

With `gatekeeper.signing.attestation.vendor` (`YUBICO` or `SECUROSYS`) the gatekeeper also verifies, once at start-up, the HSM's attestation of that key — with the same `YubicoVerifier` or `SecurosysVerifier` it applies to the keys it supervises, against the public key of the active signing certificate. Evidence: `gatekeeper.signing.attestation.yubico.chain-path` (PEM: attestation certificate, device certificate, Yubico intermediate), or `gatekeeper.signing.attestation.securosys.xml-path` (the XML exactly as delivered), `signature-path` (Base64 text of the signature) and `chain-path`. An attestation that does not verify stops start-up; one that does is published on `GET /v1/gatekeeper/keys` and reported as `activeKeyAttested: true` on `GET /v1/gatekeeper/health`. Without it start-up logs a WARN that the signing key is not attested. Retired keys carry no attestation, and revocation of the attestation chain is not checked.

All of this is off in every shipped profile (commented examples in `application-nca.yaml` and `application-org.yaml`; see `DEPLOYMENT.md` §2.5). It is tested with a test-only JCA provider and with vendor-shaped evidence on a test PKI, not with a real HSM; the SunPKCS11 path is implemented but not exercised by any test.

### RFC 3161 time-stamping *(since 1.7.0)*

`gatekeeper.timestamping.mode` (default `off`) adds external timestamps from an RFC 3161 time-stamping authority:

- `entry` — every new audit entry gets a token over SHA-256 of its signature input (the UTF-8 bytes of `thisEntryHashHex`), stored in `timestampTokenBase64`. The TSA is called while the append lock is held, so every audited request can wait up to `connect-timeout-ms` + `read-timeout-ms`; a TSA failure writes the entry without a token, and `GET /v1/gatekeeper/health` counts such entries as `untimestampedEntries`.
- `anchor` — a background thread time-stamps the chain head at start-up and then every `anchor-interval-seconds` (default 3600) when the head has moved, and appends `{headSequenceNumber, headHashHex, tokenBase64, genTime}`, fsynced, to `anchor-path` (default `<audit path>.tsa-anchors.jsonl`). The latest is on `GET /v1/gatekeeper/anchor` (`latestTimestamp`), all of them on `GET /v1/gatekeeper/anchor/timestamps`.

Both modes need `tsa-url` and `trusted-certs-path` (the TSA certificate and/or its CA). Each token is validated before it is stored: the imprint, the signing-certificate binding and the `id-kp-timeStamping` usage, the CMS signature, and a path to a trusted certificate valid at the token's `genTime`. TSA certificate revocation is not checked, the policy OID (`policy-oid`) is checked when the token is obtained but not on stored tokens, and `genTime` is not compared with the entry's `timestamp`. A token protects an entry against rewriting by whoever holds the seal key: the token covers the entry's hash, so a rewritten entry no longer matches it, which the chain check reports when `trusted-certs-path` is set. Because tokens and anchor records are outside the entry hash, removing one is not detected by the chain check; a missing entry token shows in `untimestampedEntries`, and an anchor token protects once a third party has retrieved it. A qualified TSA is a matter of `tsa-url`; the code has been tested only against a local BouncyCastle TSA, in process and over loopback HTTP.

Spring configuration:

```yaml
gatekeeper:
  audit:
    # JSON Lines file path. Each append opens the file with RandomAccessFile
    # in "rwd" mode, seeks to the current length, writes, and calls
    # getFD().sync() before returning — not O_APPEND; the seek is what makes
    # the write an append, and the in-process append lock is what makes
    # concurrent appends safe.
    path: ${GATEKEEPER_AUDIT_PATH:./audit-log.jsonl}
    # DORA Regulation (EU) 2022/2554 Article 28(6) minimum retention.
    # Declarative only: no code reads this value, and the gatekeeper
    # never prunes the log (see SUPERVISORY_OPERATIONS.md §5.3).
    retention-years: 5
    # How long a chain-integrity result is served before it is recomputed.
    # verifyChainIntegrity() is O(chain length) with one signature
    # verification per entry, so GET /v1/gatekeeper/health serves a cached
    # answer plus the instant it was computed.
    integrity-check-interval-seconds: ${GATEKEEPER_INTEGRITY_CHECK_INTERVAL_SECONDS:300}
```

A deployer who wants archival retention beyond the live-file lifetime configures `path` as a symlink that rotates periodically, and ensures backup procedures preserve the chain head across rotations.

### Gatekeeper public endpoints

`GET /v1/gatekeeper/keys`, `GET /v1/gatekeeper/anchor` and, since 1.7.0, `GET /v1/gatekeeper/anchor/timestamps` need no role, so that any relying party can verify gatekeeper-signed evidence retroactively. Under the `nca` profile the listener requires a client certificate from a trusted CA for every connection (`server.ssl.client-auth: need`), so "public" means that no role is required, not that no certificate is: a relying party without a certificate the trust store accepts cannot complete the TLS handshake. A deployment that must serve these endpoints to holders of no client certificate needs a separate listener or proxy with `client-auth: want` or none. `GET /v1/gatekeeper/health` is not: it reports operational state rather than evidence, and requires the `SUPERVISOR` role (see `SecurityConfig`). All four are rate limited under the registry bucket.

- **`GET /v1/gatekeeper/keys`** — returns the active and retired signing certificates with SHA-256 fingerprints. Operators paste this list into the financial entity's `swish.gatekeeper.trusted-keys` configuration (or a supervisory tool's equivalent trust store) so receipts signed under any historically active key remain verifiable for the DORA Regulation (EU) 2022/2554 Article 28(6) retention window. Backed by `GatekeeperKeyDirectory`. The entry's `publicKeyFingerprintHex` is the lowercase hex SHA-256 of the certificate's DER SubjectPublicKeyInfo, without separators; signed verdicts, triangulation reports and both exports name their key by it. When the log key's attestation is configured *(since 1.7.0)* the active entry also carries `attestation`: `vendor`, `hsmSerial`, `valid`, `chainValid`, `publicKeyMatch`, `attestationSignatureValid` (Securosys), `keyOrigin`, `exportable`, `firmwareVersion` (Yubico), `verifiedAgainstRootSha256Hex` (the root the chain was validated against), `verifiedAt`, `errors` and the `evidence` itself, so a relying party can repeat the verification.
- **`GET /v1/gatekeeper/anchor`** — returns the current chain-head, signed. The body carries `headSequenceNumber`, `headHashHex`, `headTimestamp`, `headSignatureBase64`, `signingKeyFingerprintHex` and `totalEntries`. The signature is computed over the canonical bytes of the head entry (`AuditEntry.canonicalBytesForSignature`). A supervisor or relying party publishes this anchor periodically to a public commitment — for instance, posting the daily anchor JSON on Finansinspektionen's web site, or anchoring the head hash in a transparency log. The published anchor commits the gatekeeper to the audit content as of that timestamp, making subsequent retroactive rewriting detectable. In time-stamping `anchor` mode *(since 1.7.0)* the body also carries `latestTimestamp`, the latest RFC 3161 anchor record, which may name an older head than `headSequenceNumber`.
- **`GET /v1/gatekeeper/anchor/timestamps?offset=0&limit=100`** *(since 1.7.0)* — `{timestampingMode, total, offset, records}`, the RFC 3161 anchor records oldest first (`limit` 1–1000). With time-stamping off: `{"timestampingMode":"off","total":0,"offset":0,"records":[]}`.
- **`GET /v1/attestation/supported-vendors`** — also needs no role (rate limited under the verify bucket). Each element is `{vendorId, productName, requirements, trustAnchors}`. `trustAnchors` *(since 1.7.0, also without configuration)* lists the anchors the vendor's verifier starts from, each with `anchor` (the key of "Replacing a trust anchor"), `origin` (`pinned` or `override`), `sha256Of` (`DER certificate`, or `DER SubjectPublicKeyInfo` for Entrust), `sha256` and `publicKeySha256` (one per certificate, colon-separated upper-case hex), `subjects` (RFC 2253; empty for Entrust) and `matchesPinned` (true when `sha256` holds exactly the pinned values). AZURE and MARVELL report `marvell`, GOOGLE `marvell` and `google-owner`, every other vendor its own. A relying party can thus compare the anchors a running gatekeeper uses with the manufacturer's published roots. The override file's path on the server is not published; it is in the start-up log only.
- **`GET /v1/gatekeeper/health`** — returns `auditLogReadable`, `chainIntact`, `chainCheckedAt`, `headSequenceNumber`, `headTimestamp`, `totalEntries`, `activeKeyFingerprint`, and `mode`. Monitoring pipelines should fail closed if `chainIntact=false` or `mode=ephemeral` in production. `chainIntact` is served from a cache recomputed at most once per `gatekeeper.audit.integrity-check-interval-seconds`, and `chainCheckedAt` says when it was computed: the chain walk is O(chain length) with one signature verification per entry, so running it per request made the endpoint a lever for unbounded work. A pipeline that needs a fresher answer lowers the interval rather than polling harder. Since 1.7.0 the body may also carry, each only when applicable: `activeKeyAttested` (present only when the log key's attestation is configured, then `true`; absent means not attested), `timestampingMode`, `untimestampedEntries` (entry mode) and `latestTimestampAnchorSequenceNumber` / `latestTimestampAnchorGenTime` (anchor mode). Requires the `SUPERVISOR` role.

### Supervisory query endpoints

These endpoints require authentication *and* the `SUPERVISOR` role. With `gatekeeper.security.mtls.enabled=true`, `SecurityConfig` restricts `/v1/audit/**`, `/v1/triangulation/**` and `GET /v1/attestation/*/registry/**` to `SUPERVISOR`, while `FE` clients reach only the verification protocol itself. Roles come from `RoleMappingProperties`: an ordered list of principal-pattern → role-set mappings under `gatekeeper.security.roles`, first match wins, with `default-roles: []` meaning deny by default. What the deployer supplies is the mapping — the patterns in `application-nca.yaml` are illustrative templates and must be replaced with the NCA's own client-certificate conventions (see `DEPLOYMENT.md` §4).

- **`GET /v1/audit/witness/{verificationId}`** — single-event lookup. Returns `404` if the verification ID is unknown; otherwise the earliest `AuditEntry` with that ID, which for an issuance is the `VERIFY` or `BATCH_VERIFY` entry. The `CONFIRM` entries (one per confirmation attempt) and `SETTLEMENT_VERIFY` entries carrying the same ID are not returned here; list them with `range` or `export`. Used by an inspector who has been presented with a receipt by a financial entity and wants to verify the decision against the gatekeeper's own record.
- **`GET /v1/audit/range?from=ISO&to=ISO`** — entries in a half-open `[from, to)` time window. The maximum window is 90 days (`AuditController.MAX_RANGE`) to bound the cost of a malicious or careless query. Returns entries in ascending sequence-number order.
- **`GET /v1/audit/entity/{principal}`** — entries for a given mTLS principal, URL-encoded and compared exactly with the recorded value. That value is the exact value of the subject attribute named by `gatekeeper.security.mtls.principal-attribute` — by default CN, so a client `CN=swishTL,O=GetSwish` is queried as `swishTL`, not as the DN. A certificate whose subject lacks the attribute, or carries it more than once, is not authenticated. *(Changed 1.6.0: the earlier `principal-regex` stopped at an escaped comma and fell back to the full DN when it did not match.)* Used to inspect a specific supervisee's full history, for example when investigating a systemic problem with a particular technical supplier.
- **`GET /v1/audit/export?from=ISO&to=ISO&inspectionId=...`** — a packaged `AuditExport` bundle covering the requested window, sealed under the gatekeeper's active signing key. The body includes the chain-head hash at the moment of export and the active key's fingerprint, so a supervisor can simultaneously verify the export integrity and reconcile against the chain head visible from `GET /v1/gatekeeper/anchor` at the same moment. If `inspectionId` is omitted the gatekeeper generates a UUID; for a formal supervisory inspection the supervisor passes its own case identifier (for example `FI-2026-001`) so the dump is bound to the inspection record. With `&format=cose` *(since 1.7.0)* the same window is returned as `application/cbor-seq` (RFC 8742): one COSE_Sign1 (RFC 9052) per entry, protected header `{1: alg, 4: kid}` with `kid` the 32 bytes of the active key's `publicKeyFingerprintHex`, and a deterministic CBOR payload holding every field the entry hash covers in the form that was hashed, the original `entrySignature` and the `timestampToken` when present. The COSE signature is an export seal made at export time by the active key; the entry's own signature, hashes and token remain the evidence and can be checked from the payload alone. The COSE form has no envelope: `inspectionId` is ignored and there is no chain head or generation time. `format` other than `json` or `cose` is 400; a signing algorithm without a COSE mapping (anything but SHA-256/384/512 with RSA or ECDSA) is 501. See `FORENSIC_INSPECTION.md` §2.5.

For step-by-step procedures see `SUPERVISORY_OPERATIONS.md` (NCA operations runbook) and `FORENSIC_INSPECTION.md` (forensic evidence-extraction procedures).

---

## Prerequisites

```bash
brew install openjdk@21
sudo ln -sfn $(brew --prefix openjdk@21)/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk-21.jdk
export JAVA_HOME=/Library/Java/JavaVirtualMachines/openjdk-21.jdk/Contents/Home
java -version
```

```bash
mvn dependency:resolve
```

## Build and Run

```bash
mvn clean package

# Reference / developer profile — permissive mTLS, ephemeral receipt signer
java -jar target/gatekeeper-1.7.0.jar --spring.profiles.active=eba

# Production-shaped NCA profile — mTLS enforced, configured receipt signer
# (see src/main/resources/application-nca.yaml for required environment
# variables: keystore paths and passwords)
java -jar target/gatekeeper-1.7.0.jar --spring.profiles.active=nca

# Organisation-internal profile (since 1.7.0) — the same code run by a
# regulated organisation inside its own ISMS, sealed with its own key
# (see src/main/resources/application-org.yaml)
java -jar target/gatekeeper-1.7.0.jar --spring.profiles.active=org
```

**End-to-end test of all three repositories.** `e2e/` is a separate Maven project that starts the built gatekeeper, hsm and railgate jars locally and drives Steps 2–7 and the settlement path between them; `mvn verify` here does not run it. See `e2e/README.md`.

All profiles share the same codebase; the profile selects between the reference-default beans (permissive defaults that emit WARN logs at startup so they cannot be deployed to production unnoticed) and the configured production beans. See `PEER_REVIEW_GUIDE.md` for the full configuration reference.

**Organisation-internal deployment** *(profile `org`, since 1.7.0)*. Article 2 describes a second deployment form: the gatekeeper inside the regulated organisation, producing a signed event stream for its own ISMS. `application-org.yaml` configures the `nca` code for that operator: TLS on port 8443 with `client-auth: need`, the organisation's own seal (`gatekeeper.signing.mode: configured`; `GATEKEEPER_SEAL_KEYSTORE`, `GATEKEEPER_SEAL_KEYSTORE_PASSWORD`, `GATEKEEPER_SEAL_ALIAS`, and `GATEKEEPER_SEAL_ALGORITHM`, default `SHA256withRSA`), the file-backed registry and audit log, mTLS role templates (`^internal-audit-.*$|^ciso-tool-.*$` → `SUPERVISOR`; `^issuance-service-.*$|^signing-service-.*$` → `FE`; no `SETTLEMENT_RAIL`, so `/api/v1/verify` is reachable by `SUPERVISOR` only), and rate limits sized for one organisation, the `lifecycle` bucket at 6000 per 60 s for one `SIGNED` report per signature. The role patterns are illustrative and match no real certificates. Commented, off-by-default examples cover an HSM-held seal, its attestation and RFC 3161 time-stamping (see above and `DEPLOYMENT.md`). A supervisor verifies the organisation's evidence against its `GET /v1/gatekeeper/keys` like any other. The profile's tests run with a generated PKCS#12 seal and without TLS; the TLS listener is not exercised.

**Swagger UI** and the OpenAPI document are off in the `eba` and `nca` profiles and in the default configuration (`springdoc.*.enabled=false`); they have no run-time function and are kept out of the deployed surface. To browse the API locally add the `dev` profile: `--spring.profiles.active=eba,dev`, then http://localhost:8080/swagger-ui.html and http://localhost:8080/v3/api-docs.

## How to cite

See `CITATION.cff` for citation metadata. GitHub renders a "Cite this repository" button from this file once the repo is public.

## Licence

MIT — Niklas Gillström <https://orcid.org/0009-0001-6485-4596>. Full text in `LICENSE`.

## Reference

Gillström, N., *Verifieringsansvar för kryptografiska nycklar i betalinfrastruktur — En rättsdogmatisk fallstudie av kontraktuell riskallokering och DORA-förordningens krav på IKT-riskhantering*, bachelor's thesis in Commercial Law (15 ECTS), Department of Law, Uppsala University, Spring 2026. Supervisor: Docent Malou Larsson Klevhill. Available at DiVA: [link to be added after publication]

Open source reference implementations (the triadic system):

- **hsm** — financial-entity-side HSM attestation verification: https://github.com/niklasgillstrom/hsm ([10.5281/zenodo.19930310](https://doi.org/10.5281/zenodo.19930310), concept DOI)
- **gatekeeper** — this repository, NCA-operated certificate-issuance gate and settlement-time signature verification: https://github.com/niklasgillstrom/gatekeeper ([10.5281/zenodo.19930395](https://doi.org/10.5281/zenodo.19930395), concept DOI)
- **railgate** — central-bank settlement-rail enforcement: https://github.com/niklasgillstrom/railgate ([10.5281/zenodo.19952991](https://doi.org/10.5281/zenodo.19952991), concept DOI)
