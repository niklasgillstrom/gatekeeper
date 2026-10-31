# Deployment runbook — gatekeeper

This document is the single deployment checklist for an NCA (or EBA, during the transitional phase) deploying the gatekeeper to production.

The audience is a **systems engineer** at the NCA who has been asked to bring up a gatekeeper instance against the NCA's existing PKI, mTLS infrastructure and observability stack. Operational responsibilities once the instance is running live in `SUPERVISORY_OPERATIONS.md`. Forensic and inspection procedures live in `FORENSIC_INSPECTION.md`.

The same runbook applies, with the substitutions in §3.1, to a regulated organisation that runs the gatekeeper inside its own ISMS (profile `org`, since 1.7.0).

The Securosys Primus path is the intended primary path for the case-study deployment. The Crypto4A, Entrust nShield, Fortanix, Thales Luna and Yubico paths can also end in COMPLIANT. The Azure Managed HSM, Google Cloud HSM and Marvell paths are refused with `MARVELL_FORMAT_UNCONFIRMED` until a real attestation confirms the format (`README.md`, "Supported HSM Vendors").

---

## 1. Prerequisites

### 1.1 Build environment (CI / build server)

- **Java 21** (LTS).
- **Maven ≥ 3.8.1** (enforced by `maven-enforcer-plugin`; recent stable 3.9.x recommended).
- **An NVD API key** for the OWASP Dependency-Check scan, read from the environment variable `NVD_API_KEY` (`nvdApiKeyEnvironmentVariable` in `pom.xml`); dependency-check-maven 13.0.0 does not run without one. Obtain a free key at https://nvd.nist.gov/developers/request-an-api-key. With it, the first scan takes ~5 minutes.

Build the production JAR:

```bash
mvn -U clean package
# The OWASP scan is in the owasp profile (since 1.6.0) and runs separately:
NVD_API_KEY=... mvn -Powasp verify
```

The artefact lands in `target/gatekeeper-1.7.0.jar`. (The 1.7.0 dependency versions — Spring Boot 4.1.2, Jackson 3.2.4 / 2.22.4, swagger-ui 5.34.1, maven-enforcer-plugin 3.7.0 — were not available to the build that produced the 1.7.0 test results, which ran against the 1.6.0 versions; build and test once with network access before deploying.)

### 1.2 Runtime environment (production host)

- **Java 21** runtime.
- **Filesystem** for persistent state. The audit log and approval registry are append-only journals; total size grows ~1–2 KB per supervisory decision, so a 10 GB partition holds approximately 5–10 million decisions before rotation is required (well above the DORA Article 28(6) 5-year retention horizon for any realistic supervisee population).
- **Service account** with ownership of the journal directory. POSIX permissions on the journal files are enforced to `0640` by the gatekeeper at startup; the parent directory should be `0750`.
- **Time synchronisation.** Audit entries carry `Instant` timestamps; deploy with NTP or PTP (the case-study deployment uses GPS-PPS per `HARDWARE_BASELINE.md` §3.1). The settlement verdict's `verifiedAt` is checked by railgate against its own clock (default ±60 s), so the two hosts' clocks must agree within that window.
- **Network reach to a TSA**, if RFC 3161 time-stamping is enabled (§2.6).
- **Reverse proxy or load balancer that does NOT terminate TLS.** Client certificates must reach the gatekeeper's Tomcat connector unchanged for mTLS to function. If a reverse proxy is in front, configure pass-through TLS (TCP-level), not HTTP termination.

---

## 2. Cryptographic material to provision

The deployer must obtain three PKCS#12 keystores before first startup — or, for the receipt-signing key, a key held in an HSM (§2.5). None of them are bundled in the repo.

### 2.1 Receipt-signing keystore (`GATEKEEPER_SEAL_KEYSTORE`)

Holds the NCA's **organisation certificate** and the corresponding private key. This is the certificate the NCA uses for ordinary administrative signing of supervisory acts (cf. Förvaltningslagen (2017:900) handläggning av förvaltningsärenden + Förordning (2009:93) med instruktion för Finansinspektionen).

Source: the NCA's own PKI / signing-cert issuer. In Sweden, FI's organisation certificate is issued by FI's internal PKI or a contracted CA.

Format: PKCS#12 (`.p12` or `.pfx`) by default; since 1.7.0 any JCA keystore type, so that the key can stay in an HSM (§2.5). The same key signs receipts, confirmation responses, audit entries, settlement verdicts, triangulation reports and exports.

### 2.2 Server-TLS keystore (`GATEKEEPER_SERVER_KEYSTORE`)

Holds the gatekeeper's **server-side TLS certificate** and private key — distinct from 2.1 above. This is what the gatekeeper presents to incoming TLS clients.

Source: an internal or public CA, depending on the NCA's policy. Subject CN should match the gatekeeper's deployment hostname (e.g., `gatekeeper.fi.se`).

### 2.3 Client-trust keystore (`GATEKEEPER_TRUSTSTORE`)

Holds the **CA certificates** that issued the client certificates the gatekeeper will accept. This is what enforces who is allowed to connect — financial entities (FE) and supervisors (SUPERVISOR).

Typically contains:

- The NCA's internal CA (issues SUPERVISOR client certs to NCA staff).
- The CA(s) that issue FE client certs to supervisees who will call `verify`/`confirm`. In Sweden this might be the FE's own internal CA, or a domestic CA that the NCA has registered.

### 2.4 Issuer-CA bundle (`gatekeeper.confirmation.issuer-ca-bundle-path`)

Holds the **CA certificates that the gatekeeper accepts as legitimate issuers** for the certificates the FE confirms back via `gatekeeper.confirm` (Step 7). Typically the certificate-issuing CA at the FE — e.g., GetSwish AB's internal payment-cert CA in the Swish architecture.

A bundle certificate that is issued by another certificate in the same bundle is used as an intermediate; every other bundle certificate is a trust anchor. At Step 7 the gatekeeper builds a PKIX path from the submitted certificate to a trust anchor, using as intermediates the bundle's intermediates and any further certificates the FE sends after the signing certificate in `signingCertificatePem`.

A sample `issuer-ca-bundle.pem` ships in the classpath as a placeholder: Getswish Root CA v2 for Swish as trust anchor and Swish Customer CA1 v2 for Swish, the CA that issues Swish signing certificates, as intermediate. Production deployments override the path to point at the operator-controlled bundle.

### 2.5 Receipt-signing key in an HSM, and its attestation *(since 1.7.0; optional, off by default)*

`ConfiguredReceiptSigner` loads the key through any JCA keystore:

| Property | Default | Meaning |
| --- | --- | --- |
| `gatekeeper.signing.keystore-type` | `PKCS12` | JCA keystore type, e.g. `PKCS11` or a vendor type |
| `gatekeeper.signing.provider-class` | empty | `java.security.Provider` class, found through `ServiceLoader` (this reaches JDK module providers such as `sun.security.pkcs11.SunPKCS11`) or by its public no-argument constructor; registered if no provider of that name is; used for `KeyStore.getInstance` and, when it offers the algorithm, for `Signature.getInstance` |
| `gatekeeper.signing.provider-config` | empty | passed to `Provider.configure(String)`, e.g. the path of a SunPKCS11 configuration (`name=…`, `library=/usr/lib/<vendor>-pkcs11.so`, `slot=…`); requires `provider-class` |
| `gatekeeper.signing.keystore-path` | empty | required for PKCS12, JKS, JCEKS, BCFKS, BKS and UBER; otherwise left empty, and the keystore is loaded with `KeyStore.load(null, keystore-password)` — the password is the HSM PIN |
| `gatekeeper.signing.key-alias` | — | the key's alias (for PKCS#11 its `CKA_LABEL`) |

At start-up the signer signs a fixed probe and verifies it under the alias's certificate. A provider-config without provider-class, an unknown or non-`Provider` class, a `configure()` failure, a file type without path, a load failure (wrong PIN, unknown type), an alias without key or certificate, and a probe that does not verify under the certificate all stop start-up. The INFO line names the keystore type, the provider and whether `PrivateKey.getEncoded()` is non-null; a non-exportable HSM key reports it as null. Whether a vendor provider accepts `load(null, pin)` or needs a stream is vendor-specific. **Tested with a test-only JCA provider only; the SunPKCS11 path has not been exercised by any test.**

To publish proof that the key is HSM-generated and non-exportable, configure its attestation:

| Property | Meaning |
| --- | --- |
| `gatekeeper.signing.attestation.vendor` | `YUBICO` or `SECUROSYS` (empty: not configured) |
| `gatekeeper.signing.attestation.yubico.chain-path` | PEM: the attestation certificate first, then the device certificate and the Yubico intermediate(s) |
| `gatekeeper.signing.attestation.securosys.xml-path` | the attestation XML exactly as delivered (the signature is over these bytes) |
| `gatekeeper.signing.attestation.securosys.signature-path` | Base64 text of the attestation signature |
| `gatekeeper.signing.attestation.securosys.chain-path` | PEM, attestation certificate first |

The attestation is verified once, at start-up, with the same verifier the gatekeeper applies to supervised keys, against the public key of the first certificate of the active signing certificate chain; an attestation that does not verify, an unknown vendor and a missing or unreadable file stop start-up. The result and the evidence are published on `GET /v1/gatekeeper/keys` (`attestation`, with `verifiedAgainstRootSha256Hex`) and `GET /v1/gatekeeper/health` reports `activeKeyAttested: true`; a monitor that requires an attested key must check for `true`, because the field is absent when attestation is not configured. Without it start-up logs a WARN ("the gatekeeper signing key is NOT attested"). Only the active key is attested; retired keys carry none. **Tested with vendor-shaped evidence on a test PKI only.** `application-nca.yaml` and `application-org.yaml` contain commented examples of both blocks.

### 2.6 RFC 3161 time-stamping *(since 1.7.0; optional, off by default)*

| Property | Default | Meaning |
| --- | --- | --- |
| `gatekeeper.timestamping.mode` | `off` | `off`, `entry` or `anchor`. Quote the value in YAML (`"entry"`): YAML reads a bare `off` as `false`, which also means off |
| `gatekeeper.timestamping.tsa-url` | empty | `http://` or `https://` URL of the TSA; required for `entry` and `anchor` |
| `gatekeeper.timestamping.trusted-certs-path` | empty | PEM with at least one certificate: the TSA certificate and/or its CA(s); required for `entry` and `anchor`. When set in any mode, the chain check validates stored tokens and anchor records |
| `gatekeeper.timestamping.hash-algorithm` | `SHA-256` | the only accepted value |
| `gatekeeper.timestamping.policy-oid` | empty | sent as `reqPolicy` and checked on the response when the token is obtained |
| `gatekeeper.timestamping.connect-timeout-ms` / `read-timeout-ms` | `5000` / `10000` | TSA connection timeouts |
| `gatekeeper.timestamping.anchor-interval-seconds` | `3600` | anchor mode: interval between attempts (> 0) |
| `gatekeeper.timestamping.anchor-path` | `<gatekeeper.audit.path>.tsa-anchors.jsonl` | anchor mode: the anchor record file, created on the first anchor (0640) |

`entry` gives every new audit entry a token over SHA-256 of its signature input. The TSA call is made while the append lock is held, so each audited request can wait up to the sum of the timeouts; a TSA failure writes the entry without a token, counted by `untimestampedEntries` on `/v1/gatekeeper/health`. Size the timeouts accordingly, or use `anchor`. `anchor` time-stamps the chain head at start-up and then every interval when the head has moved; records are fsynced to the anchor file and served on `GET /v1/gatekeeper/anchor/timestamps`. Each token is validated before it is stored. Misconfiguration (unknown mode, missing URL or trust file, a non-http(s) URL, another hash algorithm, an unparseable policy OID, non-positive timeouts or interval, an unreadable trust file, an anchor file with an unparseable line before the last) stops start-up; a torn last anchor line is removed with a WARN. TSA certificate revocation is not checked. A qualified TSA is chosen through `tsa-url` and `trusted-certs-path`; **only a local BouncyCastle TSA has been used in tests.**

### 2.7 Trust anchors obtained from the manufacturers *(since 1.7.0; optional)*

Without configuration the verifiers use the anchors pinned in their source (README, "Pinned trust anchors"). Each is confirmed against the manufacturer's own material (README, "Pinned trust anchors"). An NCA that obtains the roots itself can either confirm that they equal the pinned constants or run the gatekeeper on its own copies:

1. Download each root from the manufacturer source listed in the README table, not from a supervised entity or its supplier. Marvell's roots come in a `.zip` archive, which must be extracted. Only PEM is accepted; convert a DER file first (`openssl x509 -inform DER -in root.crt -out root.pem`).
2. Compare its SHA-256 with the pinned value: for a certificate the SHA-256 of the DER certificate (`openssl x509 -in root.pem -noout -fingerprint -sha256`), for Entrust's KWARN-1 key the SHA-256 of the DER SubjectPublicKeyInfo. For Thales, Crypto4A and Fortanix, whose verifiers use the certificate's key, compare the key SHA-256 too.
3. To use the file, name it under `gatekeeper.trust-anchors.<key>`:

| Key | Environment placeholder | Replaces | File content |
| --- | --- | --- | --- |
| `yubico` | `GATEKEEPER_TRUST_ANCHOR_YUBICO` | Yubico root; also for the log key's attestation (§2.5) | one RSA certificate, self-signed |
| `securosys` | `GATEKEEPER_TRUST_ANCHOR_SECUROSYS` | Securosys root; also for the log key's attestation (§2.5) | one RSA certificate, self-signed |
| `marvell` | `GATEKEEPER_TRUST_ANCHOR_MARVELL` | both Marvell roots, for the AZURE, GOOGLE and MARVELL verifiers together | one or more RSA certificates, each self-signed, no duplicates |
| `google-owner` | `GATEKEEPER_TRUST_ANCHOR_GOOGLE_OWNER` | Google owner root (GOOGLE) | one RSA certificate, self-signed |
| `thales` | `GATEKEEPER_TRUST_ANCHOR_THALES` | Chrysalis-ITS Root key | one RSA certificate, self-signed |
| `crypto4a` | `GATEKEEPER_TRUST_ANCHOR_CRYPTO4A` | C4A_RCA key | one EC P-384 certificate, self-signed |
| `fortanix` | `GATEKEEPER_TRUST_ANCHOR_FORTANIX` | Fortanix root | one RSA certificate, self-signed |
| `entrust` | `GATEKEEPER_TRUST_ANCHOR_ENTRUST` | KWARN-1 key | one PEM `PUBLIC KEY` (SubjectPublicKeyInfo) on P-521, named curve, uncompressed point |

Set the keys by environment variable, command-line argument, system property or an external configuration file; all of these outrank the packaged `application.yaml`. `SpringApplication.setDefaultProperties` and `SpringApplicationBuilder.properties()` do not work, because `application.yaml` declares the keys with empty placeholders. Command-line arguments and test property sources have been tested; **environment variables have not**. A blank value keeps the pinned anchor.

4. Start the gatekeeper and read the log of `eu.gillstrom.gatekeeper.verification.TrustAnchors`. Every override gives an INFO line `Trust anchor gatekeeper.trust-anchors.<key>: override <path>; SHA-256 of the …` (for certificates with subject and validity), then either an INFO line saying it is the pinned anchor or a WARN saying it is NOT, with both SHA-256 values and, for certificates, whether the key is the same. A WARN for a root downloaded from the manufacturer means that the manufacturer's root differs from the pinned constant; resolve that before production.
5. Check `GET /v1/attestation/supported-vendors`: each replaced anchor shows `origin: "override"` and its `sha256`; `matchesPinned` is `true` only when the certificate SHA-256s equal the pinned ones (a certificate re-issued over the pinned key is `false`). The path is not published there.

Start-up is refused, with an `IllegalStateException` naming the property and the path, when the file is missing or not a regular file, unreadable or over 1 MiB; holds no PEM block, mismatched BEGIN/END lines, invalid base64, an unparseable certificate or key, or bytes after the certificate; has the wrong block type or number of blocks; holds a key of the wrong type or curve, or a point not on the curve; holds a certificate that is not self-issued and self-signed, or the same certificate twice; or when the key is unknown (keys are matched case-insensitively) or named twice. Not checked: the validity period (only logged), BasicConstraints, key usage, key size; and the Thales, Crypto4A and Fortanix key-hash checks of the verifier constructors apply only to the pinned constants. The Marvell roots cannot be replaced for one vendor alone. **Tested only with test roots and with the pinned anchors written to files; no file downloaded from a manufacturer has been loaded.**

---

## 3. Environment variables — full reference

| Variable | Purpose | Required? | Example |
| --- | --- | --- | --- |
| `GATEKEEPER_SEAL_KEYSTORE` | Path to receipt-signing PKCS#12 (§2.1); not used for an HSM keystore (§2.5) | Yes, for a file keystore | `/etc/gatekeeper/nca-seal.p12` |
| `GATEKEEPER_SEAL_KEYSTORE_PASSWORD` | Password for above keystore | Yes | (from secrets manager) |
| `GATEKEEPER_SEAL_ALIAS` | Key alias inside the PKCS#12 | If non-default | `nca-seal` |
| `GATEKEEPER_SERVER_KEYSTORE` | Path to server-TLS PKCS#12 (§2.2) | Yes | `/etc/gatekeeper/nca-tls.p12` |
| `GATEKEEPER_SERVER_KEYSTORE_PASSWORD` | Password for above | Yes | (from secrets manager) |
| `GATEKEEPER_SERVER_KEY_ALIAS` | Key alias inside the PKCS#12 | If non-default | `nca-tls` |
| `GATEKEEPER_TRUSTSTORE` | Path to client-trust PKCS#12 (§2.3) | Yes | `/etc/gatekeeper/client-trust.p12` |
| `GATEKEEPER_TRUSTSTORE_PASSWORD` | Password for above | Yes | (from secrets manager) |
| `GATEKEEPER_AUDIT_PATH` | Path to the hash-chained audit log journal | No (has default) | `/var/lib/gatekeeper/audit-log.jsonl` |
| `GATEKEEPER_REGISTRY_PATH` | Path to the file-backed approval-registry journal | No (has default) | `/var/lib/gatekeeper/approval-registry.jsonl` |
| `GATEKEEPER_RETIRED_KEYS` | Comma-separated PEMs of historical signing certs (for retroactive verification of receipts within retention window; the audit-chain integrity check also accepts entry signatures under them). Never list a compromised key (§9) | No (empty default) | (multiline PEM block, newlines as `\n`) |
| `GATEKEEPER_REQUIRE_FIPS_APPROVED_MODE` | `gatekeeper.key-policy.require-fips-approved-mode` (since 1.7.0): require supervised keys' attestations to state FIPS-approved mode; only a YubiHSM 2 attestation can, and the reference one does not | No (`false`) | `false` |
| `GATEKEEPER_TRUST_ANCHOR_<KEY>` | `gatekeeper.trust-anchors.<key>` (since 1.7.0): PEM file replacing a pinned trust anchor (§2.7); `<KEY>` is `YUBICO`, `SECUROSYS`, `MARVELL`, `GOOGLE_OWNER`, `THALES`, `CRYPTO4A`, `FORTANIX` or `ENTRUST`. Not tested as environment variables | No (empty: pinned anchor) | `/etc/gatekeeper/anchors/securosys-root.pem` |
| `NVD_API_KEY` | NVD API key for OWASP scans (build/CI side); read by the `owasp` profile (`nvdApiKeyEnvironmentVariable` in `pom.xml`) | Required for `-Powasp` | (from NVD) |
| `OSS_INDEX_TOKEN` | Sonatype Guide token (`sonatype_pat_…`) for the OSS Index analyzer of the OWASP scan (build/CI side); without it that analyzer is disabled | Recommended for `-Powasp` | (from Sonatype Guide) |

The HSM, attestation and time-stamping properties of §2.5 and §2.6 have no environment variables of their own in the shipped profiles; set them in a configuration overlay (`--spring.config.additional-location=...`), as `application-nca.yaml` and `application-org.yaml` show in commented form.

Production secrets (`*_PASSWORD`) MUST come from the NCA's secrets manager, not from a checked-in file.

### 3.1 Profile `org` — organisation-internal deployment *(since 1.7.0)*

`--spring.profiles.active=org` runs the same code for a regulated organisation (a bank, a technical supplier) that operates the gatekeeper inside its own ISMS. The evidence is the organisation's, sealed under its own key. Differences from the NCA deployment:

| Item | `org` profile |
| --- | --- |
| TLS listener | port 8443, `client-auth: need`; `GATEKEEPER_SERVER_KEYSTORE` (default `/etc/gatekeeper/org-tls.p12`), `GATEKEEPER_SERVER_KEYSTORE_PASSWORD`, `GATEKEEPER_SERVER_KEY_ALIAS` (`org-tls`), `GATEKEEPER_TRUSTSTORE` (`/etc/gatekeeper/org-client-trust.p12`), `GATEKEEPER_TRUSTSTORE_PASSWORD` |
| Seal | `gatekeeper.signing.mode: configured`; `GATEKEEPER_SEAL_KEYSTORE` (`/etc/gatekeeper/org-seal.p12`), `GATEKEEPER_SEAL_KEYSTORE_PASSWORD`, `GATEKEEPER_SEAL_ALIAS` (`org-seal`), `GATEKEEPER_SEAL_ALGORITHM` (`SHA256withRSA`; exists only in this profile), `GATEKEEPER_RETIRED_KEYS` |
| Registry and audit | file-backed; `GATEKEEPER_REGISTRY_PATH`, `GATEKEEPER_AUDIT_PATH` (under `/var/lib/gatekeeper/`), `retention-years: 5`, `GATEKEEPER_INTEGRITY_CHECK_INTERVAL_SECONDS` (300) |
| Roles (templates) | `^internal-audit-.*$\|^ciso-tool-.*$` → `SUPERVISOR` (audit, registry, triangulation, health, every lifecycle event); `^issuance-service-.*$\|^signing-service-.*$` → `FE` (verify, confirm, lifecycle for entries it verified, `SIGNED`); no `SETTLEMENT_RAIL`, so `/api/v1/verify` is `SUPERVISOR`-only. Replace the patterns with the organisation's own; they match no real certificates |
| Rate limits | as `nca`, except `lifecycle` 6000/60 s (one `SIGNED` report per signature; raise to the actual signing rate) |
| Other | `GATEKEEPER_TRUSTED_PROXIES`, `GATEKEEPER_MAX_REQUEST_SIZE` (2MB); triangulation caps 10 / 100 000; springdoc off |

Commented examples for an HSM-held seal, its attestation and time-stamping (§2.5, §2.6) are in `application-org.yaml`. In `entry` mode every `SIGNED` report waits for the TSA under the append lock, so at signing volume `anchor` mode is the better fit. The profile's tests (`OrgProfileContextLoadsTest`, `OrgProfileAuthorisationTest`) run with a generated PKCS#12 seal and with TLS off; the TLS listener has not been exercised. The `application-nca.yaml` references them via `${ENV_VAR:default}` so a secrets injector that exposes them as environment variables (Kubernetes Secret → env, HashiCorp Vault Agent, etc.) works without modification.

---

## 4. Role mapping — production override

`application-nca.yaml` ships with example CN-pattern → role mappings. **These are illustrative templates**, not production-ready patterns; a real NCA deployment must override them with patterns matching its actual client-cert PKI.

### 4.1 Principal extractor — CN vs SERIALNUMBER

Swedish Expisoft-issued **organisationscertifikat** (the standard client-cert format used by Finansinspektionen and Swedish FEs) carry the org-/myndighetsnummer in the **`SERIALNUMBER` attribute of the subject DN**, not in `CN`. A typical FI organisation certificate has:

```
Subject:
   C=SE
   O=Finansinspektionen
   SERIALNUMBER=202100-4235        ← myndighetsnummer (stable identifier)
   CN=Finansinspektionen           ← typically the organisation name
```

The default `gatekeeper.security.mtls.principal-attribute` is `CN`, which works for non-Swedish PKI but is suboptimal for Expisoft-style certs because CN can change at certificate renewal. For Swedish deployments, override to:

```yaml
gatekeeper:
  security:
    mtls:
      principal-attribute: SERIALNUMBER
```

This makes the extracted principal the org-/myndighetsnummer, which is stable across renames and renewals.

### 4.2 Role-mapping examples

The defaults shipped with the build are:

```yaml
gatekeeper:
  security:
    roles:
      mappings:
        - cn-pattern: "^FI-.*$|^supervisor-.*$|^NCA-.*$"
          roles: [SUPERVISOR]
        - cn-pattern: "^FE-.*$|^GetSwish.*$|^.*-FE$"
          roles: [FE]
      default-roles: []
```

These are **fictional** — they exist so the reference build has working examples for tests. A real Swedish FI deployment overrides them with org-nummer-based patterns:

```yaml
# Production override for Swedish FI deployment using Expisoft client certs
gatekeeper:
  security:
    mtls:
      principal-attribute: SERIALNUMBER
    roles:
      mappings:
        - cn-pattern: "^202100-4235$"             # Finansinspektionen
          roles: [SUPERVISOR]
        - cn-pattern: "^556[0-9]{4}-[0-9]{4}$"    # Any Swedish AB org-nr
          roles: [FE]
      default-roles: []                            # deny by default
```

Note that `cn-pattern` is a regex matched against the **extracted principal**, regardless of which DN attribute principal-attribute names from. The name `cn-pattern` is historical; for Expisoft deployments it is matching on SERIALNUMBER content.

For **finer-grained FE allow-listing** (only specific supervisee org-numbers, not every Swedish AB), expand the pattern to a list of explicit org-numbers:

```yaml
        - cn-pattern: "^(5564801213|5560000000|5561234567)$"   # explicit FE org-nrs
          roles: [FE]
```

A separate config overlay (`application-nca-overrides.yaml` loaded via `--spring.config.additional-location=...`) is the recommended way to keep the FE allow-list maintainable without editing the bundled profile.

**Three roles** are defined and have meaning to the authorisation matchers in `SecurityConfig`:

| Role | Endpoints permitted |
| --- | --- |
| `SUPERVISOR` | Everything: audit query (`/v1/audit/**`), registry inspection (`/v1/attestation/{cc}/registry/**`), triangulation inquiries (`/v1/triangulation/**`, since 1.7.0), verify/confirm, key-lifecycle events on any entry, settlement-time verification (`/api/v1/verify`). For NCA staff. |
| `FE` | Verify protocol: `POST /v1/attestation/{cc}/verify`, `verify/batch`, `confirm`, and since 1.7.0 `POST /v1/attestation/{cc}/lifecycle` — a status change only for an entry whose verification the same principal performed, `SIGNED` for any. For supervisees calling the gatekeeper. |
| `SETTLEMENT_RAIL` (since v1.2.0) | Settlement-time signature verification only: `POST /api/v1/verify`. For the central-bank settlement-rail operator (Sveriges Riksbank for RIX-INST; ECB for TIPS, etc.). |

**Production role-mapping for `SETTLEMENT_RAIL`** — example for Swedish RIX-INST integration via Expisoft-issued client cert:

```yaml
        - cn-pattern: "^202100-2684$"             # Sveriges Riksbank
          roles: [SETTLEMENT_RAIL]
```

The settlement-rail client provisions a single mTLS client certificate per environment (test, production) and the gatekeeper authorises it under the `SETTLEMENT_RAIL` role to call `POST /api/v1/verify`. The reference deployment scenario is documented in the railgate companion repo (`railgate/README.md`).

Public endpoints (`/v1/gatekeeper/keys`, `/v1/gatekeeper/anchor`, `/v1/gatekeeper/anchor/timestamps` since 1.7.0, `/v1/attestation/health`, `/v1/attestation/supported-vendors`) need no role, so a relying party can verify retroactive receipt evidence under DORA Article 28(6). Under the `nca` profile the listener requires a client certificate from a trusted CA for every connection (`server.ssl.client-auth: need`), so "public" means that no role is required, not that no certificate is: a relying party without a certificate the trust store accepts cannot complete the TLS handshake. A deployment that must serve these endpoints to holders of no client certificate needs a separate listener or proxy with `client-auth: want` or none. `/v1/gatekeeper/health` is **not** among them from release 1.4.0: it reports operational state rather than evidence and requires the `SUPERVISOR` role, so a monitoring pipeline calling it needs a client certificate that maps to that role. The OpenAPI document and Swagger UI are disabled in the `nca` and `eba` profiles (`springdoc.*.enabled=false`); they are served only with the `dev` profile, which must not be active on a deployed host.

To override the defaults, ship an additional config file (e.g. `application-nca-overrides.yaml`) with the NCA's own patterns and add it to the Spring profile chain via `--spring.config.additional-location=...`.

---

## 5. Bring-up sequence

The first startup of a new deployment should follow this sequence to verify the configuration is correct.

```bash
# 1. Verify the JAR exists and has the right version
java -jar target/gatekeeper-1.7.0.jar --version 2>&1 | head

# 2. Pre-flight: keystore reachability and password correctness
keytool -list -keystore "$GATEKEEPER_SEAL_KEYSTORE" -storepass "$GATEKEEPER_SEAL_KEYSTORE_PASSWORD" -storetype PKCS12
keytool -list -keystore "$GATEKEEPER_SERVER_KEYSTORE" -storepass "$GATEKEEPER_SERVER_KEYSTORE_PASSWORD" -storetype PKCS12
keytool -list -keystore "$GATEKEEPER_TRUSTSTORE" -storepass "$GATEKEEPER_TRUSTSTORE_PASSWORD" -storetype PKCS12

# 3. Boot with the NCA profile
java -jar target/gatekeeper-1.7.0.jar --spring.profiles.active=nca

# 4. In another shell, smoke-test the endpoints that need no role. The nca
#    profile still requires a client certificate at the TLS layer
#    (client-auth: need), so any certificate the trust store accepts will do.
curl -s --cacert <server-CA> --cert <client-cert>.pem --key <client-key>.pem \
     https://gatekeeper.fi.se:8443/v1/attestation/health
curl -s --cacert <server-CA> --cert <client-cert>.pem --key <client-key>.pem \
     https://gatekeeper.fi.se:8443/v1/gatekeeper/keys | jq .
curl -s --cacert <server-CA> --cert <client-cert>.pem --key <client-key>.pem \
     https://gatekeeper.fi.se:8443/v1/gatekeeper/anchor | jq .

# 5. Smoke-test an authenticated endpoint with a SUPERVISOR client cert
curl -s --cacert <server-CA> \
     --cert <supervisor-client-cert>.pem \
     --key  <supervisor-client-key>.pem \
     https://gatekeeper.fi.se:8443/v1/audit/range?from=2026-01-01T00:00:00Z\&to=2026-01-02T00:00:00Z
curl -s --cacert <server-CA> \
     --cert <supervisor-client-cert>.pem \
     --key  <supervisor-client-key>.pem \
     https://gatekeeper.fi.se:8443/v1/gatekeeper/health
```

Expected results:

- `/v1/attestation/health` returns 200; `/v1/gatekeeper/health` returns 200 with a status payload for the SUPERVISOR certificate.
- `keys` returns the active receipt-signing certificate plus any retired keys.
- `anchor` returns a signed chain head (initially the empty-log sentinel hash, signed by the active key).
- With the seal in an HSM (§2.5): the start-up INFO line names the keystore type and provider and reports the key as not extractable; with attestation configured, `keys` carries `attestation` with `valid: true` and `health` reports `activeKeyAttested: true`. Without attestation the start-up log carries the "NOT attested" WARN.
- With time-stamping (§2.6): `health` reports `timestampingMode`; in anchor mode `GET /v1/gatekeeper/anchor/timestamps` lists a first record shortly after start-up.
- With replaced trust anchors (§2.7): the start-up log names each override, with its SHA-256, at INFO, and has a WARN for each that is not the pinned anchor; `GET /v1/attestation/supported-vendors` shows `origin: "override"` for those anchors and `"pinned"` for the rest.
- The supervisor-authenticated `/v1/audit/range` returns an empty JSON array on a fresh deploy. It is not signed; the signed form is `/v1/audit/export`.

If any of these fails, do NOT enable supervisee traffic; consult the troubleshooting section below.

---

## 6. Verification of mTLS and role enforcement

After bring-up, run these negative tests to confirm the security posture:

```bash
# A. No client cert → the TLS handshake fails (client-auth: need); no HTTP status
curl -sw '%{http_code}\n' --cacert <ca> \
     https://gatekeeper.fi.se:8443/v1/audit/export?inspectionId=NEG-1 -o /dev/null
# Expected: curl reports a TLS alert and prints 000

# B. FE client cert → 403 on supervisor endpoints
curl -sw '%{http_code}\n' --cacert <ca> --cert <fe-cert> --key <fe-key> \
     https://gatekeeper.fi.se:8443/v1/audit/export?inspectionId=NEG-2 -o /dev/null
# Expected: 403

# C. FE client cert → 200 on verify endpoint (with valid request body)
curl -sw '%{http_code}\n' --cacert <ca> --cert <fe-cert> --key <fe-key> \
     -H 'Content-Type: application/json' \
     --data @valid-verify-request.json \
     https://gatekeeper.fi.se:8443/v1/attestation/SE/verify -o /dev/null
# Expected: 200
```

If any of these gives the wrong code, the role mapping is misconfigured. Inspect the gatekeeper logs at startup — they print the resolved role count and (at DEBUG) the role assigned to each principal that connects.

---

## 7. Operational handoff

Once §5 and §6 pass, hand the deployment over to the supervisory operations team. Their daily / inspection / forensic / retention / GDPR procedures live in:

- `SUPERVISORY_OPERATIONS.md` — daily ops, periodic data triangulation (§3.5), retention, GDPR
- `FORENSIC_INSPECTION.md` — forensic evidence extraction, chain-of-custody
- `THREAT_MODEL.md` — adversary model, residual risks

The deployer's responsibilities after handoff are:

- Patching dependencies on the OWASP Dependency-Check schedule (CI runs `mvn -Powasp verify` weekly; high/critical CVEs fail the build).
- Backup of the journal directory (audit log + approval registry) on the same cadence as other critical NCA records.
- Disaster-recovery procedure: detailed in §9 below.
- Marvell trust-anchor rotation if the Azure or Google Cloud HSM paths are in use (see `PEER_REVIEW_GUIDE.md` "Rotation note for cloud-HSM trust anchor").

---

## 8. Backup and integrity

Both journals are append-only; only the audit log is integrity-protected:

- The audit log is hash-chained and per-entry-signed, with a per-key chain since 1.7.0; chain integrity is checked at startup (a WARN if the chain does not verify) and by `AppendOnlyFileAuditLog.verifyChainIntegrity()` behind `GET /v1/gatekeeper/health` (cached, `chainCheckedAt`). An export does not run the check; verify the exported chain independently (`FORENSIC_INSPECTION.md`).
- The approval registry journal is a flat append-only operations log (`REGISTER` / `CONFIRM` and, since 1.7.0, `STATUS_CHANGE`) without hash chain or signature; the in-memory index is rebuilt by replaying the journal at startup. A build older than 1.7.0 skips `STATUS_CHANGE` lines, so a downgrade loses lifecycle status changes.
- In time-stamping anchor mode (§2.6) the anchor record file (`<audit path>.tsa-anchors.jsonl` by default) belongs with the audit log; the chain check reads it when trusted TSA certificates are configured, and an anchor that names an entry beyond a restored, shorter log fails the check.

Backup procedure:

1. Snapshot the journal directory (atomic filesystem snapshot, ZFS / LVM / equivalent) at the operator's chosen cadence — at minimum daily for production.
2. Off-site replicate the snapshot per the NCA's standard backup policy.
3. To restore: stop the gatekeeper, replace the journal directory contents from the latest snapshot, restart. The startup replay logs a chain that does not verify at WARN, and refuses to start if a line other than the last does not parse.

The approval registry cannot be rebuilt from the audit log. Since 1.7.0 a v2 audit entry also carries the key fingerprint, the issued certificate's serial and issuer and the registry status, but not the issued certificate itself, the confirmation nonce, the parties or the submitted evidence (only digests of the requests), and entries written before 1.7.0 carry none of these. Losing the registry file without a backup loses the settlement-time lookup for every issued certificate; back it up with the audit log.

---

## 9. Disaster recovery

Two failure modes:

- **Journal corruption (mid-file).** Detected at startup. A line before the last that does not parse stops start-up. A file that parses but whose chain does not verify lets the service boot, so that supervisors can retrieve evidence; the chain-integrity warning surfaces in the logs and as `chainIntact=false` on `GET /v1/gatekeeper/health`. The operator must investigate manually — typical cause is filesystem-level damage. Restore from backup.
- **Active signing key compromise.** Do **not** add the compromised certificate to `GATEKEEPER_RETIRED_KEYS`: the audit-chain integrity check accepts entry signatures under every retired key, so listing it would let entries forged under it pass (this document said the opposite before 1.5.0, and it contradicted `SUPERVISORY_OPERATIONS.md` §2.3 even then). Publish a compromise notice naming its fingerprint, provision a new key in the secure key store (Section 2.3 of `SUPERVISORY_OPERATIONS.md`), publish the new key via the next chain anchor, and notify supervisees via the supervisor-cooperation channel. Periodic data triangulation (`SUPERVISORY_OPERATIONS.md` §3.5) will surface any receipts an attacker minted under the compromised key in the window between compromise and rotation.

---

## 10. Troubleshooting common failures

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Spring Boot fails at startup with `Failed to load Yubico root CA` / `Failed to load attestation trust anchor` | Bundled root cert is corrupted | Restore from a clean checkout — these constants are baked into the source |
| `EphemeralReceiptSigner initialised` log appears in production | `gatekeeper.signing.mode` is not `configured` (NCA profile not active) | Add `--spring.profiles.active=nca` |
| TLS handshake fails for a client that holds a valid certificate | The trust store does not contain the CA that issued it | Verify `keytool -list` against the trust store |
| Every request is accepted without a client certificate | mTLS is off (`gatekeeper.security.mtls.enabled=false`), so the open reference chain is active | Confirm `--spring.profiles.active=nca` is set |
| 403 on every authenticated request | Client cert principal does not match any role pattern | Inspect startup log for "did not match any role mapping" warnings; override role patterns in a config overlay |
| OWASP scan fails at start | NVD API key not set | Export `NVD_API_KEY` and rerun `mvn -Powasp verify` |
| `AppendOnlyFileAuditLog: chain integrity check FAILED` at startup | Journal corruption, or (time-stamping) a token or anchor record that no longer validates | Restore from backup; investigate filesystem; check `trusted-certs-path` holds the TSA's current certificate or CA |
| Start-up fails in `ConfiguredReceiptSigner` with a self-test failure | The alias's certificate does not belong to its key (§2.5) | Re-provision the certificate for the key |
| Start-up fails in `SigningKeyAttestation` | Attestation evidence missing, unreadable, for another key, or not chaining to the vendor root in use (pinned, or replaced under §2.7) | Supply the HSM's attestation of the active seal key (§2.5) |
| Start-up fails with `Trust anchor gatekeeper.trust-anchors.<key> (<path>): …` or `Unknown trust anchor …` | The file named for that key is missing, not PEM, of the wrong type, key or curve, not self-signed, or the key name is misspelt (§2.7) | Fix the file or the key name, or blank the value to use the pinned anchor |
| WARN `Trust anchor …: the override … is NOT the pinned anchor` | The file differs from the pinned constant | Expected for a deliberately different root; otherwise compare it with the manufacturer's published root before production (§2.7) |
| Start-up fails in `AuditTimestamping` | Time-stamping misconfigured (§2.6) | Set `tsa-url` and `trusted-certs-path`, or `mode: "off"` |
| Audited requests slow, `untimestampedEntries` rising | TSA slow or unreachable in `entry` mode | Fix the TSA link, lower the timeouts, or use `anchor` mode |

---

## 11. Final pre-production checklist

Before declaring the deployment production-ready, verify each of the following:

- [ ] `--spring.profiles.active=nca` is applied (no `EphemeralReceiptSigner` warning)
- [ ] All three keystores load cleanly via `keytool -list`
- [ ] Server certificate's CN matches the deployment hostname
- [ ] `/v1/gatekeeper/keys` returns the production receipt-signing certificate (CN matches the NCA's organisation cert)
- [ ] `/v1/gatekeeper/anchor` returns a valid signed anchor
- [ ] Negative-test §6.A fails the TLS handshake (no cert → denied)
- [ ] Negative-test §6.B returns 403 (FE cert → no audit access)
- [ ] Positive-test §6.C returns 200 (FE cert → can verify)
- [ ] Audit log journal is created with permissions `0640` owned by the service account
- [ ] Approval registry journal is created with permissions `0640` owned by the service account
- [ ] OWASP scan in CI is green (no CVEs ≥ 7.0 unsuppressed)
- [ ] If the seal is in an HSM: start-up reports the key as not extractable, and with attestation configured `/v1/gatekeeper/keys` carries a valid `attestation` and `/v1/gatekeeper/health` `activeKeyAttested: true`
- [ ] If time-stamping is on: the TSA is reachable, `trusted-certs-path` validates its tokens, and somebody outside the NCA retrieves the anchor records
- [ ] The pinned trust anchors have been compared with the roots obtained from the manufacturers (§2.7), and every override's start-up line and its `supported-vendors` entry show the expected SHA-256
- [ ] railgate's `railgate.gatekeeper.trusted-keys` holds the certificate `/v1/gatekeeper/keys` publishes, so that it accepts the signed verdicts
- [ ] Backup of the journal directory is configured and tested
- [ ] On-call rotation is established for chain-integrity warnings
- [ ] Supervisory operations team has been handed `SUPERVISORY_OPERATIONS.md` and confirmed familiarity

When every box is ticked, the deployment is ready to accept supervisee traffic.
