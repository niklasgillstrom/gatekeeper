# Entrust nShield key attestation bundles

`key_simple_test1.att` and `key_pkcs11_test2.att` are the two example bundles
in Entrust's nShield key attestation application note ("Verifying an
attestation bundle", nshielddocs.entrust.com, as saved on 2026-10-06). The page
prints each bundle's fields; the files rebuild the JSON from them. Every field
value is copied unchanged except `modstatemsg` and `warrant`, which the page
shows decoded and which are re-encoded as base64url with padding; both are
covered by signatures (`modstatesig` under the warrant's KLF2, the warrant
under KWARN-1), so a re-encoding error would not verify.

| File | SHA-256 |
|------|---------|
| key_simple_test1.att | b4ec1b8d31ec2a2f0d179b35c275ec811ca0141ccda14ba360d2a0230b379bf0 |
| key_pkcs11_test2.att | af601aa8a97ad7a7674947d937c68a0d9f268fe8715a4ea18cea369b5ff5ac42 |

Both come from the module with ESN 8938-1075-88BB, whose warrant is a
`FieldUpgradeModuleInformation` certificate under KWARN-1, in a security world
with ciphersuite `DLf3072s256mAEScSP800131Ar1`. The verifier refuses such
warrants (they depend on legacy DSA-1024 signatures, per Entrust), so the
tests verify the rest of each bundle under a warrant reissued as
`ModuleInformation` by a test root, with the real KLF2 and ESN.

- `key_simple_test1.att`: an RSA-2048 key (application `simple`), module
  protected. Its ACL has a group certified by the security officer's key
  ("trump ops") and a MakeArchiveBlob action under the recovery key, so it is
  recoverable; Entrust's verifier output reports protection `module` and
  recovery `true`.
- `key_pkcs11_test2.att`: an EC P-256 key (application `pkcs11`), softcard
  protected, not recoverable; Entrust's verifier output reports protection
  `softcard` and recovery `false`.

No CSR was published with either bundle. The bundles are Entrust's documented
examples.
