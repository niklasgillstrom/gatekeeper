# Fortanix DSM key attestation statement

`key_attestation.json` holds the sample Key Attestation Statement in section
3.0 of Fortanix's "Fortanix DSM for Verifying Key Attestation Statements"
(support.fortanix.com), as saved on 2026-10-06. The four base64 certificates
(Key Attestation Authority, Key Attestation CA, Fortanix Attestation and
Provisioning Root CA, and the statement) are copied unchanged; only the JSON
whitespace differs from the page.

The statement attests an RSA-2048 key (Fortanix key ID
18ec8b96-8845-4ce3-9fd1-50407b4b1fc0) signed on 2023-09-05 and carries
fortanixKeyGeneratedInDSM and fortanixKeyNeverExportable. No CSR was
published with it.

Certificates are public data; the statement is Fortanix's documented example.
