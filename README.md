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
| **Article 9(4)(d)** | Implement **policies and protocols for strong authentication mechanisms**, based on relevant standards and **dedicated control systems**, and protection measures of cryptographic keys whereby data is encrypted in line with results of approved data classification and ICT risk assessment processes. | Digital signing is an authentication mechanism. The requirement that it be "strong" means it must actually provide authenticity, not merely give the appearance of it. The requirement for "dedicated control systems" means there must be mechanisms to verify that the authenticity guarantee is maintained. The explicit reference to "protection measures of cryptographic keys" directly addresses the HSM verification question. |

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

The concentration risk framework provides EBA with an additional, independent legal basis — beyond the Article 17 breach-of-Union-law procedure — to address the verification gap. The tools already exist in the regulation. The mitigant already exists as open source, supporting multiple HSM vendors, with independently auditable code. Any alternative implementation must meet the same functional standard — multi-vendor attestation verification, key origin and exportability checks, and DORA article compliance mapping — or fail the proportionality assessment under Article 9(3), since a less capable solution cannot be justified when a more complete one is freely available. Compliance of any alternative implementation is independently testable: cryptographic chain validation is mathematically deterministic, meaning the same attestation input must produce the same verification result — EBA can run both implementations against the same signing certificate attestation evidence and compare, leaving no room for interpretive divergence. The critical requirement for independent verification is that EBA or the national competent authority obtains the HSM manufacturers' root certificates directly from the manufacturers (Securosys, Yubico, Microsoft, Google) — not from any party in the chain being verified. This ensures that the verification is independent of all parties: the bank, GetSwish AB, the technical supplier, and the reference implementation provider alike.

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

Should the initial list of verified technical suppliers contain only a single provider, this does not constitute ICT concentration risk within the meaning of Article 3(29). The reference implementation is published as open source, supporting multiple HSM vendors (Securosys, Yubico, Azure, Google Cloud), with no vendor lock-in. The barrier to becoming a compliant technical supplier is low: acquire a certified HSM, implement attestation verification, and register a TL-number. A market with a single initial provider due to first-mover advantage — where the technology is open, the standards are published, and the entry barrier is minimal — is structurally different from the concentration risk DORA addresses, which concerns dependency on providers that are not easily substitutable. Any technical supplier with a certified HSM can replicate the capability.

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

**Step 3.** The gatekeeper verifies the attestation certificate chain against the HSM manufacturer's root CA pinned in the verifier (`java.security.cert.CertPathValidator` with `PKIXParameters` anchored at the manufacturer's root). The verification confirms that the signing key was generated inside a genuine HSM and is non-exportable. The result is binary: COMPLIANT or NON-COMPLIANT. The compliance predicate in the code is `publicKeyMatch && attestationChainValid && generatedOnDevice && !exportable && errors.isEmpty()` (see `VerificationService.verify()`).

**Step 4.** The gatekeeper registers every verification result — both compliant and non-compliant — in its approval registry (`ApprovalRegistry.register(...)`). This registry serves as the authoritative record of all attestation verifications and enables the secondary reconciliation control described below.

**Step 5.** The gatekeeper returns a signed verification receipt to GetSwish AB. The receipt is not a simple boolean but a traceable, cryptographically signed document containing: a unique verification ID, the verification timestamp, the public key fingerprint, HSM vendor and model, the DORA article compliance determination, and the operator's digital signature over a canonical byte representation of the decision-relevant fields (`ReceiptCanonicalizer`, `ReceiptSigner.signInto(...)`). Under the NCA profile, signing uses a configured PKCS#12 keystore loaded via `ConfiguredReceiptSigner`; the reference `EphemeralReceiptSigner` generates a throwaway RSA key at startup and emits prominent WARN logs so it cannot be deployed unnoticed. The signature allows GetSwish AB — and any subsequent auditor — to independently verify that the approval originated from the gatekeeper. The receipt ID is the key that links the certificate to the gatekeeper's approval registry.

**Step 6.** GetSwish AB issues the signing certificate *only* if the gatekeeper's receipt confirms COMPLIANT status, and embeds the verification ID in its own records alongside the issued certificate. If NON-COMPLIANT, the certificate request is refused and no signing certificate is created. The technical supplier must resolve the attestation deficiency before resubmitting.

**Step 7 — Closing the loop.** GetSwish AB sends a confirmation back to the gatekeeper via `POST /v1/attestation/{countryCode}/confirm`. If the certificate was issued, the confirmation includes the full signing certificate. The gatekeeper then performs two binding checks before accepting the confirmation:

1. **Issuer-CA validation.** The submitted certificate is PKIX-validated against the configured issuer-CA trust bundle (`IssuerCaValidator`, configured via `gatekeeper.confirmation.issuer-ca-bundle-path`; reference bundle `issuer-ca-bundle.pem` ships with Getswish Root CA v2). A certificate that does not chain to a trusted issuer CA is rejected regardless of its public key — this prevents an attacker who knows a `verificationId` from substituting arbitrary certificates for comparison.
2. **Public-key match.** Only after the issuer-CA validation passes does the gatekeeper extract the public key and compare its fingerprint (constant-time) against the one approved in Step 3.

The loop is closed cryptographically, not contractually — the gatekeeper does not rely on GetSwish AB's assertion that the correct certificate was issued; it verifies the issuer, the chain, and the key match itself. If the certificate was not issued (whether due to NON-COMPLIANT status or any other reason), GetSwish AB sends a non-issuance notice with timestamp and the verification ID. This ensures that the registry reflects the actual outcome for every verification request — an approved attestation without a corresponding issued certificate, or vice versa, is immediately visible.

**Secondary control — registry reconciliation.** The gatekeeper maintains a registry of all approved attestation verifications. This registry serves as a safeguard against any alternative certificate issuance path that might bypass the gatekeeper verification step. Through the triangulation procedure described in Section 4.1, any certificate that exists in GetSwish AB's system but does not have a corresponding entry in the gatekeeper registry is immediately identifiable as issued outside the approved process — a qualitatively more serious offence than mere non-compliance, as it constitutes active circumvention of the supervisory mechanism.

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
3. The HSM manufacturer is an independent third party (Securosys SA, Yubico AB, Microsoft, Google).
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
  "supplierIdentifier": "5569741234",
  "supplierName": "Example Teknisk Leverantör AB",
  "keyPurpose": "Swish payment signing"
}
```

**Compliant response:**

```json
{
  "verificationId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "compliant": true,
  "verificationTimestamp": "2026-03-20T14:30:00Z",
  "signature": "MIIEpQIBAAKCAQEA...",
  "signingCertificate": "-----BEGIN CERTIFICATE-----\nMIIDozCCAougAwIBAgIUG...\n-----END CERTIFICATE-----\n",
  "publicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:...",
  "publicKeyAlgorithm": "RSA",
  "hsmVendor": "Securosys",
  "hsmModel": "Primus HSM",
  "hsmSerialNumber": "18000000",
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
  "supplierIdentifier": "5569741234",
  "supplierName": "Example Teknisk Leverantör AB",
  "keyPurpose": "Swish payment signing",
  "countryCode": "SE",
  "errors": [],
  "warnings": []
}
```

The `signature` is a detached Base64-encoded RSA/ECDSA signature computed over the canonical byte representation of the decision-relevant fields (see `ReceiptCanonicalizer` — `v1|verificationId|compliant|timestamp|fingerprint|algorithm|hsmVendor|hsmModel|hsmSerialNumber|supplierIdentifier|supplierName|keyPurpose|countryCode|keyProperties...|doraCompliance...`). The `signingCertificate` PEM lets any party independently verify the signature without a prior key-exchange step. Under the NCA profile (`gatekeeper.signing.mode=configured`) the signing certificate is the NCA's organisation certificate — the certificate the NCA uses for ordinary administrative signing of supervisory acts. The reference `EphemeralReceiptSigner` produces a throwaway `CN=REFERENCE-EPHEMERAL` certificate marked as such.

**Non-compliant response:**

```json
{
  "verificationId": "2c9d4b6a-8e1f-4b3c-af2e-5d6a7b8c9d0e",
  "compliant": false,
  "verificationTimestamp": "2026-03-20T14:30:00Z",
  "signature": "MIIEpQIBAAKCAQEA...",
  "signingCertificate": "-----BEGIN CERTIFICATE-----\nMIIDozCCAougAwIBAgIUG...\n-----END CERTIFICATE-----\n",
  "publicKeyFingerprint": "a1:b2:c3:...",
  "publicKeyAlgorithm": "RSA",
  "hsmVendor": null,
  "hsmModel": null,
  "hsmSerialNumber": null,
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
    "summary": "No valid HSM attestation provided. Cannot verify that signing key is hardware-protected. The absence of attestation means the financial entity cannot demonstrate compliance with DORA Articles 5(2)(b), 6(10), 9(3)(c)-(d), 9(4)(d), or 28(1)(a). The entity must provide cryptographic attestation evidence or be considered non-compliant."
  },
  "supplierIdentifier": "5569741234",
  "supplierName": "Example Teknisk Leverantör AB",
  "keyPurpose": "Swish payment signing",
  "countryCode": "SE",
  "errors": [
    "Attestation certificate chain verification failed against manufacturer root CA"
  ],
  "warnings": []
}
```

Non-compliant receipts are signed by the same operator key as compliant ones — otherwise a supervisee could repudiate a NON-COMPLIANT finding. The HSM-specific fields (`hsmVendor`, `hsmModel`, `hsmSerialNumber`) are set to `null` on non-compliance to avoid recording unverified vendor claims in the signed receipt.

#### POST dora-api.eba.europa.eu/v1/attestation/se/verify/batch

Batch verification for multiple entities. Returns individual results plus aggregate compliance statistics. A compliance rate significantly below 100% indicates a systemic supervisory failure by the national competent authority — precisely the type of finding that triggers EBA's obligations under Article 17 of Regulation 1093/2010.

#### POST /v1/attestation/{countryCode}/confirm

Step 7 of the verification flow. GetSwish AB (or the issuing bank) posts the outcome of the certificate-issuance decision back to the gatekeeper. The gatekeeper PKIX-validates the submitted certificate against the configured issuer-CA trust bundle (`IssuerCaValidator` + `issuer-ca-bundle.pem`), extracts the public key, and verifies that its fingerprint matches the attestation evidence approved in Step 3. Anomalies (public-key mismatch, certificate issued despite NON-COMPLIANT status, confirmation for unknown verification ID, or certificate not chaining to a trusted issuer CA) are flagged and persisted in the approval registry.

**Request — certificate was issued:**

```json
{
  "verificationId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
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
  "anomalies": []
}
```

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

`registryStatus` is one of: `VERIFIED_AND_ISSUED`, `VERIFIED_NOT_ISSUED`, `REJECTED_NOT_ISSUED`, `ANOMALY_ISSUED_DESPITE_REJECTION`, `ANOMALY_PUBLIC_KEY_MISMATCH`, `ANOMALY_UNKNOWN_VERIFICATION` (see `IssuanceConfirmationResponse.RegistryStatus`). `loopClosed` is `true` iff the confirmation was consistent with the registry entry and passed all binding checks; any anomaly sets it to `false` and the entry remains flagged for supervisory review.

#### POST /api/v1/verify (settlement-time signature verification, since v1.2.0)

Companion endpoint to the issuance-time attestation flow. Whereas the `/v1/attestation/{countryCode}/verify` endpoint runs the 7-step verification protocol at certificate issuance, this endpoint answers a different question at settlement time: *given a digest, signature, and certificate, is the signature valid and is the certificate compliant?*

The intended caller is a settlement-rail enforcement layer such as **railgate**, which receives pacs.008 messages at the central-bank settlement rail (RIX-INST in Sweden, TIPS in the Eurosystem, FedNow in the US) and queries this endpoint to determine whether to allow or default-deny the settlement.

**Data minimisation.** This endpoint never receives or stores transaction payload content. Only cryptographic artefacts (digest, signature, certificate) traverse the boundary. The supervisor never sees transaction amounts, sender/receiver detail, or business message content. SHA-512 collision resistance ensures the digest uniquely binds the signature to the exact transaction performed. This satisfies GDPR Article 5(1)(c) (data minimisation) and the proportionality requirement implicit in DORA Article 32 supervisory data processing.

**Request:**

```json
{
  "certSerial": "1234567890123456789",
  "issuerDn": "CN=SEB Customer CA1 v2 for Swish, O=Skandinaviska Enskilda Banken AB (publ), C=SE",
  "digestHex": "a3f5e8b...64-byte-hex...",
  "signatureBase64": "Q2lyY3VsYXIuLi4=",
  "signingCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "algorithm": "SHA512withRSA"
}
```

`algorithm` is optional and defaults to `SHA512withRSA` (RSA-PKCS#1 v1.5 with SHA-512), the algorithm used by the reference Swish utbetalning signing flow. `signingCertificatePem` is required — the supervisor uses it to extract the public key. `algorithm`-supported values include `SHA512withRSA`, `SHA384withRSA`, `SHA256withRSA`, and PSS variants registered with the JCA provider.

**Response — verified compliant signature (settle):**

```json
{
  "signatureValid": true,
  "compliant": true,
  "auditEntryId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "reason": "OK"
}
```

**Response — cryptographically valid signature against an unknown certificate (default-deny):**

```json
{
  "signatureValid": true,
  "compliant": false,
  "auditEntryId": null,
  "reason": "CERT_NOT_FOUND"
}
```

**Response — signature does not match digest (default-deny):**

```json
{
  "signatureValid": false,
  "compliant": false,
  "auditEntryId": "8f1d2c4a-6b3e-4a5f-9c8d-1e2f3a4b5c6d",
  "reason": "SIGNATURE_INVALID"
}
```

`reason` is one of: `OK`, `CERT_NOT_FOUND`, `SIGNATURE_INVALID`, `CERT_NON_COMPLIANT`, `MALFORMED_INPUT`, `ALGORITHM_NOT_SUPPORTED`. The settlement-rail enforcement layer (railgate) allows the settlement if and only if both `signatureValid` and `compliant` are `true`. Any other combination triggers default-deny: the originating bank receives a structured error code and the transaction does not settle until the bank resubmits with valid data, or the settlement is abandoned.

The role-based access policy in `SecurityConfig` restricts this endpoint to clients holding the `SETTLEMENT_RAIL` role (typically the central-bank settlement system) or `SUPERVISOR` (for sandbox and incident-response scenarios).

### Supported HSM Vendors

| Vendor | Attestation Method | Root CA Verification |
|---|---|---|
| Securosys Primus | XML attestation + signature + cert chain | Securosys root CA |
| Yubico YubiHSM 2 | Attestation certificate chain | Yubico root CA |
| Azure Managed HSM | `az keyvault key get-attestation` JSON | ⚠️ Marvell manufacturer chain only (Microsoft MAA owner-chain not yet implemented; trust anchor expired 2025-11-16) |
| Google Cloud HSM | Attestation bundle + cert chain | ⚠️ Marvell manufacturer chain only (Google Hawksbill owner-chain not yet implemented; trust anchor expired 2025-11-16) |
| AWS CloudHSM | ❌ Lacks per-key attestation | Not supported |

---

## Audit and supervisory access

The gatekeeper persists every decision into a hash-chained, append-only audit log. The combination of per-entry hash linkage and per-entry seal signature is what allows a supervisor to verify that the audit trail has not been retroactively rewritten — a property required by DORA Regulation (EU) 2022/2554 Article 28(6), which mandates 5-year retention with discoverable verifiability of records relating to ICT third-party service providers.

### Hash-chained append-only audit log

`AppendOnlyFileAuditLog` writes a JSON Lines file at `gatekeeper.audit.path` (default `./audit-log.jsonl`). Each `AuditEntry` (see `eu.gillstrom.gatekeeper.audit.AuditEntry`) contains:

- `sequenceNumber` — strictly monotonic, starting at 1.
- `timestamp` — ISO-8601 instant of the append.
- `mtlsClientPrincipal` — the supervisory principal extracted from the mTLS client certificate (resolved via `MtlsPrincipalResolver`).
- `operation` — one of `verify`, `verify-batch`, `confirm`.
- `verificationId`, `requestDigestBase64`, `receiptDigestBase64`, `compliant` — the decision-relevant fields.
- `prevEntryHashHex` — the SHA-256 of the predecessor entry's `thisEntryHashHex`. The first entry uses 64 ASCII zeros (`AuditEntry.SENTINEL_PREV_HASH_HEX`) so "empty log" is a deterministic, well-known starting point.
- `thisEntryHashHex` — SHA-256 over the canonical bytes of the entry plus `prevEntryHashHex`.
- `entrySignatureBase64` — `ReceiptSigner.sign(thisEntryHashHex.getBytes(UTF_8))`. In production the signer uses the NCA's organisation-certificate-backed signing key — the certificate the NCA uses for ordinary administrative signing of supervisory acts. In the reference build the signer is the `EphemeralReceiptSigner` (clearly marked as such — see `THREAT_MODEL.md`).

The chain is verified by `AuditLog.verifyChainIntegrity()`. Tampering with any historical entry's content breaks the chain at that entry and at every entry that follows; replacing entries en bloc by an attacker who controls the storage layer also requires possessing the seal private key, because every individual entry signature is computed over its own `thisEntryHashHex`.

Spring configuration:

```yaml
gatekeeper:
  audit:
    # JSON Lines file path; written with O_APPEND and fsynced on every append.
    path: ${GATEKEEPER_AUDIT_PATH:./audit-log.jsonl}
    # DORA Regulation (EU) 2022/2554 Article 28(6) minimum retention.
    retention-years: 5
```

A deployer who wants archival retention beyond the live-file lifetime configures `path` as a symlink that rotates periodically, and ensures backup procedures preserve the chain head across rotations.

### Gatekeeper public endpoints

These endpoints are published unauthenticated (or under the same mTLS policy as the verification endpoints; see `SecurityConfig`) so that any relying party can verify gatekeeper-signed evidence retroactively.

- **`GET /v1/gatekeeper/keys`** — returns the active and retired signing certificates with SHA-256 fingerprints. Operators paste this list into the financial entity's `swish.gatekeeper.trusted-keys` configuration (or a supervisory tool's equivalent trust store) so receipts signed under any historically active key remain verifiable for the DORA Regulation (EU) 2022/2554 Article 28(6) retention window. Backed by `GatekeeperKeyDirectory`.
- **`GET /v1/gatekeeper/anchor`** — returns the current chain-head, signed. The body carries `headSequenceNumber`, `headHashHex`, `headTimestamp`, `headSignatureBase64`, and `activeSigningKeyFingerprintHex`. The signature is computed over the canonical bytes of the head entry (`AuditEntry.canonicalBytesForSignature`). A supervisor or relying party publishes this anchor periodically to a public commitment — for instance, posting the daily anchor JSON on Finansinspektionen's web site, or anchoring the head hash in a transparency log. The published anchor commits the gatekeeper to the audit content as of that timestamp, making subsequent retroactive rewriting detectable.
- **`GET /v1/gatekeeper/health`** — returns `auditLogReadable`, `chainIntact`, `headSequenceNumber`, `headTimestamp`, `size`, `activeSigningKeyFingerprintHex`, and `signingMode`. Monitoring pipelines should fail closed if `chainIntact=false` or `signingMode=ephemeral` in production.

### Supervisory query endpoints

These endpoints require authentication. With `gatekeeper.security.mtls.enabled=true` the standard NCA mTLS policy applies; the deployer's authorisation policy beyond mTLS — for instance role differentiation between supervisory inspectors and audit operators — is the `TODO-NCA` extension point in `SecurityConfig`.

- **`GET /v1/audit/witness/{verificationId}`** — single-event lookup. Returns `404` if the verification ID is unknown; returns the full `AuditEntry` otherwise. Used by an inspector who has been presented with a receipt by a financial entity and wants to verify the decision against the gatekeeper's own record.
- **`GET /v1/audit/range?from=ISO&to=ISO`** — entries in a half-open `[from, to)` time window. The maximum window is 90 days (`AuditController.MAX_RANGE`) to bound the cost of a malicious or careless query. Returns entries in ascending sequence-number order.
- **`GET /v1/audit/entity/{principal}`** — entries for a given mTLS principal (URL-encoded, so DNs containing commas or equals can be passed: `CN%3DswishTL%2COC%3DSwish%2CO%3DGetSwish`). Used to inspect a specific supervisee's full history, for example when investigating a systemic problem with a particular technical supplier.
- **`GET /v1/audit/export?from=ISO&to=ISO&inspectionId=...`** — a packaged `AuditExport` bundle covering the requested window, sealed under the gatekeeper's active signing key. The body includes the chain-head hash at the moment of export and the active key's fingerprint, so a supervisor can simultaneously verify the export integrity and reconcile against the chain head visible from `GET /v1/gatekeeper/anchor` at the same moment. If `inspectionId` is omitted the gatekeeper generates a UUID; for a formal supervisory inspection the supervisor passes its own case identifier (for example `FI-2026-001`) so the dump is bound to the inspection record.

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
java -jar target/gatekeeper-1.0.0.jar --spring.profiles.active=eba

# Production-shaped NCA profile — mTLS enforced, configured receipt signer
# (see src/main/resources/application-nca.yaml for required environment
# variables: keystore paths, passwords, signatory-rights mode)
java -jar target/gatekeeper-1.0.0.jar --spring.profiles.active=nca
```

Both profiles share the same codebase; the profile selects between the reference-default beans (permissive defaults that emit WARN logs at startup so they cannot be deployed to production unnoticed) and the configured production beans. See `PEER_REVIEW_GUIDE.md` for the full configuration reference.

**Swagger UI:** http://localhost:8080/swagger-ui.html (developer profile), or https://localhost:8443/swagger-ui.html (NCA profile over TLS)

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
