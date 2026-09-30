# gatekeeper/e2e — local end-to-end test of hsm, gatekeeper and railgate 1.5.0

A local test only. It starts the three already-built service jars as child processes on free loopback ports, drives the real HTTP flow between them, and stops them afterwards. It deploys nothing and calls nothing outside `127.0.0.1`.

It lives in the gatekeeper repository because the supervisor that operates gatekeeper is the party that verifies the whole flow, in cooperation with the central bank that operates railgate. It is a separate Maven project: `mvn verify` in the gatekeeper root does not build or run it.

## Run

Clone the three repositories side by side, at the same release:

```
git clone --branch v1.5.0 https://github.com/niklasgillstrom/gatekeeper.git
git clone --branch v1.5.0 https://github.com/niklasgillstrom/hsm.git
git clone --branch v1.5.0 https://github.com/niklasgillstrom/railgate.git
(cd gatekeeper && mvn verify)
(cd hsm && mvn verify)
(cd railgate && mvn verify)
cd gatekeeper/e2e && ./run.sh
```

hsm and railgate are looked up next to the gatekeeper checkout; `-De2e.reposDir=<dir>` points elsewhere. `run.sh` checks that the three `target/*-1.5.0.jar` exist, stops processes left over from an interrupted run, and runs `mvn -B verify` here. Requires Java 21 or later (`java` and `keytool`; `-De2e.javaHome=<JDK>` selects another JDK for the three services) and Maven. Logs from the three services are written to `target/e2e-logs/`, working files to `target/e2e-work/`.

## What is exercised, and how

| Order | Test | Processes involved | Asserts |
|---|---|---|---|
| 1 | `gatekeeperPublishesReceiptKeyAndHsmIsStartedWithIt` | gatekeeper, hsm | hsm is started with the receipt-signing key that gatekeeper publishes at `GET /v1/gatekeeper/keys`, in `swish.gatekeeper.mode=http` |
| 2–3 | `hsmPath…` (Yubico, Securosys) | hsm → gatekeeper | hsm's real `POST /api/v1/attestation/verifyAndIssue`: gatekeeper verifies the real attestation, hsm verifies the signed receipt, the mock CA issues, and Step 7 closes the loop (`VERIFIED_AND_ISSUED`, `loopClosed=true`). **Needs a real BankID signature, see below; skipped otherwise.** |
| 4 | `gatekeeperDirectStepsTwoToSevenCloseTheLoop` (Yubico, Securosys) | gatekeeper | Steps 2–7 against the running gatekeeper with the real attestation fixtures from `hsm/examples`, which chain to the real pinned Yubico and Securosys roots; the receipt signature is checked over the v2 canonical form; the certificate is issued by the harness CA that gatekeeper is configured to trust |
| 5–7 | `settlement…` | gatekeeper | railgate's exact four-field request to `POST /api/v1/verify`: the certificate stored at Step 7 is found by (serial, issuer DN); an unknown serial and a foreign issuer give `CERT_NOT_FOUND`; a signature that does not verify gives `SIGNATURE_INVALID` |
| 8 | `settlementWithOwnerSuppliedSignature…` | gatekeeper | allowed settlement, only with a supplied signature pair (below) |
| 9 | `railgateAuthenticatesAndDefaultDenies…` | railgate | 401 without credentials; `DORA_32_AUDIT_MISSING` when the payment network has no artefacts |
| 10 | `railgateCallsGatekeeperAndPassesItsVerdictsThrough` | railgate → gatekeeper | `POST /api/v1/settle/precheck` on railgate, artefacts read from the payment-network file, railgate calls gatekeeper and passes `SIGNATURE_INVALID` and `CERT_NOT_FOUND` through, carrying gatekeeper's registry id and audit-entry hash |
| 11 | `railgateAllowsSettlementWithOwnerSuppliedSignature…` | railgate → gatekeeper | `ALLOWED` through railgate, only with a supplied signature pair |

Local-only configuration used: gatekeeper with mTLS off, the ephemeral receipt signer, the in-memory registry and `gatekeeper.confirmation.issuer-ca-bundle-path` pointing at the harness CA; hsm with `swish.issuance.mock.ca-keystore` pointing at the same CA and the mock signatory-rights registry; railgate with `railgate.payment-network.mode=file` and `allow-insecure-http=true` against the local gatekeeper. The harness CA is a throwaway PKCS12 created with `keytool` for each run.

## What is not proven locally, and why

- **hsm path without BankID.** hsm's issuance requires a BankID signature whose `userNonVisibleData` binds the exact request (organisation number, Swish number and CSR hash). That cannot be produced without a BankID signing. To run tests 2–3, sign with BankID for test (hsm's `dev` profile trusts the test root) and supply:

  ```
  ./run.sh -De2e.bankid.yubico.signature=<file> -De2e.bankid.yubico.ocsp=<file> \
           -De2e.bankid.securosys.signature=<file> -De2e.bankid.securosys.ocsp=<file> \
           -De2e.bankid.personalNumber=<12-digit personnummer of the signer>
  ```

  The binding string to sign is printed at start-up as `[e2e] BankID userNonVisibleData … for <vendor>`.

- **An allowed settlement.** It needs `(digestHex, signatureBase64)` made with the HSM private key that the fixture attests. The fixtures contain no private key. If you hold that key (the Securosys fixture comes from the reference Primus HSM), supply a pair as JSON `{"digestHex": "...", "signatureBase64": "..."}`:

  ```
  ./run.sh -De2e.positive.file=<json> [-De2e.positive.vendor=securosys|yubico]
  ```

  The signature must be RSA PKCS#1 v1.5 with SHA-512 over the digest bytes (`SHA512withRSA`), which is how Swish Utbetalning payouts are signed. Test 8 checks the pair locally first and says so if it was made by another key.

Tests that cannot run for these reasons are reported as skipped (aborted assumptions), not as passed.
