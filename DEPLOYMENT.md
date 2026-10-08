# Deployment runbook — gatekeeper

This document is the single deployment checklist for an NCA (or EBA, during the transitional phase) deploying the gatekeeper to production.

The audience is a **systems engineer** at the NCA who has been asked to bring up a gatekeeper instance against the NCA's existing PKI, mTLS infrastructure and observability stack. Operational responsibilities once the instance is running live in `SUPERVISORY_OPERATIONS.md`. Forensic and inspection procedures live in `FORENSIC_INSPECTION.md`.

The Securosys Primus path is the intended primary path for the case-study deployment. The Crypto4A, Entrust nShield, Fortanix, Thales Luna and Yubico paths can also end in COMPLIANT. The Azure Managed HSM, Google Cloud HSM and Marvell paths are refused with `MARVELL_FORMAT_UNCONFIRMED` until a real attestation confirms the format (`README.md`, "Supported HSM Vendors").

---

## 1. Prerequisites

### 1.1 Build environment (CI / build server)

- **Java 21** (LTS).
- **Maven ≥ 3.6.3** (enforced by `maven-enforcer-plugin`; recent stable 3.9.x recommended).
- **An NVD API key** for the OWASP Dependency-Check scan, passed by naming an environment variable that holds it: `-DnvdApiKeyEnvironmentVariable=NVD_API_KEY` (see `pom.xml` for why the pom does not wire one in). Obtain a free key at https://nvd.nist.gov/developers/request-an-api-key. Without it, the first scan can take 30–60 minutes due to rate-limiting; with it, ~5 minutes.

Build the production JAR:

```bash
mvn -U clean package
# The OWASP scan is in the owasp profile (since 1.6.0) and runs separately:
NVD_API_KEY=... mvn -Powasp verify -DnvdApiKeyEnvironmentVariable=NVD_API_KEY
```

The artefact lands in `target/gatekeeper-1.6.0.jar`.

### 1.2 Runtime environment (production host)

- **Java 21** runtime.
- **Filesystem** for persistent state. The audit log and approval registry are append-only journals; total size grows ~1–2 KB per supervisory decision, so a 10 GB partition holds approximately 5–10 million decisions before rotation is required (well above the DORA Article 28(6) 5-year retention horizon for any realistic supervisee population).
- **Service account** with ownership of the journal directory. POSIX permissions on the journal files are enforced to `0640` by the gatekeeper at startup; the parent directory should be `0750`.
- **Time synchronisation.** Audit entries carry `Instant` timestamps; deploy with NTP or PTP (the case-study deployment uses GPS-PPS per `HARDWARE_BASELINE.md` §3.1).
- **Reverse proxy or load balancer that does NOT terminate TLS.** Client certificates must reach the gatekeeper's Tomcat connector unchanged for mTLS to function. If a reverse proxy is in front, configure pass-through TLS (TCP-level), not HTTP termination.

---

## 2. Cryptographic material to provision

The deployer must obtain three PKCS#12 keystores before first startup. None of them are bundled in the repo.

### 2.1 Receipt-signing keystore (`GATEKEEPER_SEAL_KEYSTORE`)

Holds the NCA's **organisation certificate** and the corresponding private key. This is the certificate the NCA uses for ordinary administrative signing of supervisory acts (cf. Förvaltningslagen (2017:900) handläggning av förvaltningsärenden + Förordning (2009:93) med instruktion för Finansinspektionen).

Source: the NCA's own PKI / signing-cert issuer. In Sweden, FI's organisation certificate is issued by FI's internal PKI or a contracted CA.

Format: PKCS#12 (`.p12` or `.pfx`).

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

---

## 3. Environment variables — full reference

| Variable | Purpose | Required? | Example |
| --- | --- | --- | --- |
| `GATEKEEPER_SEAL_KEYSTORE` | Path to receipt-signing PKCS#12 (§2.1) | Yes | `/etc/gatekeeper/nca-seal.p12` |
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
| `NVD_API_KEY` | NVD API key for OWASP scans (build/CI side); read only when the build is run with `-DnvdApiKeyEnvironmentVariable=NVD_API_KEY` | Recommended | (from NVD) |

Production secrets (`*_PASSWORD`) MUST come from the NCA's secrets manager, not from a checked-in file. The `application-nca.yaml` references them via `${ENV_VAR:default}` so a secrets injector that exposes them as environment variables (Kubernetes Secret → env, HashiCorp Vault Agent, etc.) works without modification.

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
| `SUPERVISOR` | Everything: audit query (`/v1/audit/**`), registry inspection (`/v1/attestation/{cc}/registry/**`), verify/confirm, settlement-time verification (`/api/v1/verify`). For NCA staff. |
| `FE` | Verify protocol only: `POST /v1/attestation/{cc}/verify`, `verify/batch`, `confirm`. For supervisees calling the gatekeeper. |
| `SETTLEMENT_RAIL` (since v1.2.0) | Settlement-time signature verification only: `POST /api/v1/verify`. For the central-bank settlement-rail operator (Sveriges Riksbank for RIX-INST; ECB for TIPS, etc.). |

**Production role-mapping for `SETTLEMENT_RAIL`** — example for Swedish RIX-INST integration via Expisoft-issued client cert:

```yaml
        - cn-pattern: "^202100-2684$"             # Sveriges Riksbank
          roles: [SETTLEMENT_RAIL]
```

The settlement-rail client provisions a single mTLS client certificate per environment (test, production) and the gatekeeper authorises it under the `SETTLEMENT_RAIL` role to call `POST /api/v1/verify`. The reference deployment scenario is documented in the railgate companion repo (`railgate/README.md`).

Public endpoints (`/v1/gatekeeper/keys`, `/v1/gatekeeper/anchor`, `/v1/attestation/health`, `/v1/attestation/supported-vendors`) need no role, so a relying party can verify retroactive receipt evidence under DORA Article 28(6). Under the `nca` profile the listener requires a client certificate from a trusted CA for every connection (`server.ssl.client-auth: need`), so "public" means that no role is required, not that no certificate is: a relying party without a certificate the trust store accepts cannot complete the TLS handshake. A deployment that must serve these endpoints to holders of no client certificate needs a separate listener or proxy with `client-auth: want` or none. `/v1/gatekeeper/health` is **not** among them from release 1.4.0: it reports operational state rather than evidence and requires the `SUPERVISOR` role, so a monitoring pipeline calling it needs a client certificate that maps to that role. The OpenAPI document and Swagger UI are disabled in the `nca` and `eba` profiles (`springdoc.*.enabled=false`); they are served only with the `dev` profile, which must not be active on a deployed host.

To override the defaults, ship an additional config file (e.g. `application-nca-overrides.yaml`) with the NCA's own patterns and add it to the Spring profile chain via `--spring.config.additional-location=...`.

---

## 5. Bring-up sequence

The first startup of a new deployment should follow this sequence to verify the configuration is correct.

```bash
# 1. Verify the JAR exists and has the right version
java -jar target/gatekeeper-1.6.0.jar --version 2>&1 | head

# 2. Pre-flight: keystore reachability and password correctness
keytool -list -keystore "$GATEKEEPER_SEAL_KEYSTORE" -storepass "$GATEKEEPER_SEAL_KEYSTORE_PASSWORD" -storetype PKCS12
keytool -list -keystore "$GATEKEEPER_SERVER_KEYSTORE" -storepass "$GATEKEEPER_SERVER_KEYSTORE_PASSWORD" -storetype PKCS12
keytool -list -keystore "$GATEKEEPER_TRUSTSTORE" -storepass "$GATEKEEPER_TRUSTSTORE_PASSWORD" -storetype PKCS12

# 3. Boot with the NCA profile
java -jar target/gatekeeper-1.6.0.jar --spring.profiles.active=nca

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

Both journals are append-only and integrity-protected:

- The audit log is hash-chained and per-entry-signed; chain integrity is checked at startup (a WARN if the chain does not verify) and by `AppendOnlyFileAuditLog.verifyChainIntegrity()` behind `GET /v1/gatekeeper/health` (cached, `chainCheckedAt`). An export does not run the check; verify the exported chain independently (`FORENSIC_INSPECTION.md`).
- The approval registry journal is a flat append-only operations log (`REGISTER` / `CONFIRM`); the in-memory index is rebuilt by replaying the journal at startup.

Backup procedure:

1. Snapshot the journal directory (atomic filesystem snapshot, ZFS / LVM / equivalent) at the operator's chosen cadence — at minimum daily for production.
2. Off-site replicate the snapshot per the NCA's standard backup policy.
3. To restore: stop the gatekeeper, replace the journal directory contents from the latest snapshot, restart. The startup replay logs a chain that does not verify at WARN, and refuses to start if a line other than the last does not parse.

The approval registry cannot be rebuilt from the audit log: an audit entry holds the verification id, the request and receipt digests, the compliance bit and the principal, but no public-key fingerprint, status, nonce or issued certificate. Losing the registry file without a backup loses the settlement-time lookup for every issued certificate; back it up with the audit log.

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
| Slow OWASP scan on first run | NVD API key not set | Export `NVD_API_KEY` and rerun with `-DnvdApiKeyEnvironmentVariable=NVD_API_KEY` |
| `AppendOnlyFileAuditLog: chain integrity check FAILED` at startup | Journal corruption | Restore from backup; investigate filesystem |

---

## 11. Final pre-production checklist

Before declaring the deployment production-ready, verify each of the following:

- [ ] `--spring.profiles.active=nca` is applied (no `EphemeralReceiptSigner` warning)
- [ ] All three keystores load cleanly via `keytool -list`
- [ ] Server certificate's CN matches the deployment hostname
- [ ] `/v1/gatekeeper/keys` returns the production receipt-signing certificate (CN matches the NCA's organisation cert)
- [ ] `/v1/gatekeeper/anchor` returns a valid signed anchor
- [ ] Negative-test §6.A returns 401 (no cert → denied)
- [ ] Negative-test §6.B returns 403 (FE cert → no audit access)
- [ ] Positive-test §6.C returns 200 (FE cert → can verify)
- [ ] Audit log journal is created with permissions `0640` owned by the service account
- [ ] Approval registry journal is created with permissions `0640` owned by the service account
- [ ] OWASP scan in CI is green (no CVEs ≥ 7.0 unsuppressed)
- [ ] Backup of the journal directory is configured and tested
- [ ] On-call rotation is established for chain-integrity warnings
- [ ] Supervisory operations team has been handed `SUPERVISORY_OPERATIONS.md` and confirmed familiarity

When every box is ticked, the deployment is ready to accept supervisee traffic.
