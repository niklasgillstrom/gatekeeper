# Thales Luna PKC test vectors

`rsa-pkc.p7b` and `rsa-test.csr` are copied unchanged from
https://github.com/ThalesGroup/luna-pkc-validator, directory `tests/`,
commit 4718eb04a850f6c70516badcb5dc27794478d36e (2025-03-14).

| File | SHA-256 |
|------|---------|
| rsa-pkc.p7b | 0dd96abdc4a4328703cf7db9b5315b308c81daa9573caa13b1bbe47c55ee1c57 |
| rsa-test.csr | 79d8cb97f2e10c12be7bcff1ef33931c6cc87caaac6217e806bf411da47d96e4 |

The PKC is a Public Key Confirmation chain from a Luna K7 HSM (serial 521174)
for an RSA-2048 key; the CSR is signed by that key. They are Thales's test
vectors, not output of the reference hardware described in `examples/`.

They are distributed under Thales's licence:

```
This software is provided under the MIT license (see the following Web site
for further details: https://mit-license.org/ ).

Copyright © 2024 Thales Group

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
