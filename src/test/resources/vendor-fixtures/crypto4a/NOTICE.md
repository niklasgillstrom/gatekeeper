# Crypto4A QASM attestation message

`attestation.der` is the DER form of the `ATTESTATION MESSAGE` in the
"Examples" section of `validation/crypto4a-qasm.md` in
https://github.com/pkic/remote-key-attestation, commit
00820612d32f6ecdbc5b0f8707eeb940c1f0a96b (base64 decoded, otherwise
unchanged). SHA-256 of the file:
95d26fc9bac25840b6949cd84bcaa50da65cd2807826cc47ceea277549426eb9

The message attests an EC P-256 private key on a production QASM (serial in
the qasm-serial claim) and carries ECDSA P-384 and HSS signatures by the
device's attestation keys under C4A_SCA_MFG4 and C4A_RCA. No CSR was
published with it.

It is distributed under the PKI Consortium's licence:

```
MIT License

Copyright (c) 2021 PKI Consortium

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
