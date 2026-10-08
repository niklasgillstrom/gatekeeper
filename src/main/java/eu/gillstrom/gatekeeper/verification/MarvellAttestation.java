package eu.gillstrom.gatekeeper.verification;

/*
 * The blob layout, attribute numbers and signature schemes below are a Java
 * port of the Marvell LiquidSecurity key-attestation parser and validator in
 * Microsoft's https://github.com/Azure/azure-managed-hsm-key-attestation
 * (src/vendor/marvell/marvell_parse_key_attestation.py and
 * marvell_validate_key_attestation.py, commit 02f14d1c), used under this
 * licence:
 *
 * MIT License
 *
 * Copyright (c) Microsoft Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * Parser and verifier for Marvell LiquidSecurity key attestations, the HSM
 * behind both Azure Managed HSM and Google Cloud HSM.
 *
 * <p><strong>Provenance.</strong> Three published sources, each checked
 * here: Marvell's "LiquidSecurity HSM - Software Key Attestation" page
 * (response layout, attribute numbers and names, firmware 2.x raw-padding
 * and 3.x PKCS#1 signatures, and a parsed RSA key-pair example), Microsoft's
 * MIT-licensed parser and validator (byte-level offsets, Marvell roots) and
 * Google's Apache-licensed {@code verify_attestation_chains.py} in
 * {@code GoogleCloudPlatform/python-docs-samples} (gzip container, SHA-256
 * PKCS#1 v1.5 signature over all but the last 256 bytes, owner chain under
 * "Hawksbill Root v1 prod"). Marvell's MIT-licensed {@code verify_pubkey.py}
 * was read; its parsers ({@code parse_v1.py}, {@code parse_v2.py},
 * {@code parse_attest_2.x.py}) were not. The firmware 3.x layout agrees
 * with {@code icedevml/kms-attest-verifier} (MIT, 2024), a port of Marvell's
 * {@code parse_v2.py} written to audit Google Cloud KMS attestations for
 * CA/Browser Forum key-generation requirements: response header, info header
 * with the public key at the first offset and the private key at the second,
 * object header (handle, attribute count, size), {@code >II} records; it
 * requires the same private-key attributes (EXTRACTABLE 0, NEVER_EXTRACTABLE,
 * LOCAL and SENSITIVE 1) and reads the modulus from the private-key object. No real Azure or Google attestation has
 * been run through this class; see {@link #FORMAT_CONFIRMED_BY_REAL_SAMPLE}.</p>
 *
 * <p><strong>Layouts.</strong> The last 256 bytes are the signature and the
 * rest is the signed data. Firmware 3.x follows Marvell's response format: a
 * {@code ResponseHeader} ({@code >IIII}: response code, flags,
 * {@code ulTotalSize}, {@code ulBufferSize}), where {@code ulTotalSize} is
 * the whole response and the attribute buffer is the {@code ulBufferSize}
 * bytes before the signature. The buffer opens with {@code TLVKeyInfo}
 * ({@code >HHHH}: version, flags, key-1 offset, key-2 offset); a key pair
 * carries a public- and a private-key object. Each object is a {@code >III}
 * header whose second word is the attribute count, then {@code >II} (type,
 * length) records and their values (Microsoft's offsets). Firmware 2.x puts a
 * single object at byte 20 (Microsoft only). Both layouts are parsed strictly
 * inside the signed data, and a blob that parses as both, or as neither, is
 * rejected.</p>
 *
 * <p><strong>Signature.</strong> Firmware 3.x: PKCS#1 v1.5 with the hash of
 * the partition certificate's own signature algorithm (Microsoft), which is
 * SHA-256 in Google's tool. Firmware 2.x ("raw padding" in Marvell's
 * example): Microsoft's validator raises the signature to the public exponent
 * and compares only the trailing 32 bytes with SHA-256 of the data. That
 * check is accepted here only for an exponent of at least 65537. With e = 3
 * and no padding, a cube root modulo 2^256 forges any trailing 32 bytes
 * without the private key.</p>
 *
 * <p><strong>Key binding.</strong> Microsoft's validator binds the
 * attestation to no public key at all, and Google's reads no attributes. The
 * Azure JSON's {@code key} JWK and the cloud APIs' get-public-key calls are
 * outside the signed blob, so taking the key from them means trusting the
 * cloud provider. Marvell's attribute table lists {@code OBJ_ATTR_MODULUS}
 * ({@code 0x0120}), the KCV ({@code 0x0173}) and the EKCV ({@code 0x1003})
 * inside the signed blob, and its example carries all three for both halves
 * of the key pair. In that example the KCV is the first three bytes of SHA-1
 * and the EKCV the SHA-256 of the key's DER SubjectPublicKeyInfo; the page's
 * prose calls the EKCV an HKDF extract, which its own example does not
 * match; Marvell's {@code verify_pubkey.py} computes both from the PEM
 * body, as here.</p>
 */
public final class MarvellAttestation {

    /**
     * False until a real Azure Managed HSM or Google Cloud HSM attestation has
     * been checked against this class and committed as a test fixture. While
     * false, the Azure and Google verifiers never report a valid attestation.
     */
    public static final boolean FORMAT_CONFIRMED_BY_REAL_SAMPLE = false;

    public static final String FORMAT_UNCONFIRMED_ERROR = "MARVELL_FORMAT_UNCONFIRMED: the Marvell "
            + "attestation layout follows Marvell's and the cloud vendors' published documentation "
            + "and tools but has not been confirmed against a real Azure Managed HSM or Google Cloud "
            + "HSM attestation; none is accepted until a real fixture is committed";

    public static final int SIGNATURE_SIZE = 256;
    static final int FW2_ATTRIBUTE_OFFSET = 20;
    /** Bounds the attribute walk; a real key carries a few dozen attributes. */
    static final int MAX_ATTRIBUTES = 512;
    /** Bounds gzip expansion of a submitted attestation. */
    static final int MAX_DECOMPRESSED_SIZE = 1 << 20;

    public static final int ATTR_CLASS = 0x0000;
    public static final int ATTR_KEY_TYPE = 0x0100;
    public static final int ATTR_ID = 0x0102;
    public static final int ATTR_MODULUS = 0x0120;
    public static final int ATTR_PUBLIC_EXPONENT = 0x0122;
    public static final int ATTR_EXTRACTABLE = 0x0162;
    public static final int ATTR_LOCAL = 0x0163;
    public static final int ATTR_NEVER_EXTRACTABLE = 0x0164;
    public static final int ATTR_KCV = 0x0173;
    public static final int ATTR_EKCV = 0x1003;

    public static final long CKO_PUBLIC_KEY = 2;
    public static final long CKO_PRIVATE_KEY = 3;
    public static final long CKK_RSA = 0;

    /**
     * Marvell LiquidSecurity root, reissued 2024-07-25 to 2034-07-23 with the
     * same key as the 2015 root this repository pinned before. Copied from
     * {@code MARVELL_HSM_ROOT_CERTIFICATE} in Microsoft's validator.
     * SHA-256 23:01:43:DF:00:E0:B4:52:74:3E:06:8A:5B:3F:C0:8D:F8:F0:6C:EF:C4:85:4E:A6:27:AE:B7:EB:D7:0E:E2:F4
     */
    static final String MARVELL_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDvzCCAqegAwIBAgIBADANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UEBhMCVVMx
            EzARBgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQK
            DAxDYXZpdW0sIEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQD
            DCFsb2NhbGNhLmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wHhcNMjQwNzI1MjAy
            OTIwWhcNMzQwNzIzMjAyOTIwWjCBkTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh
            bGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQKDAxDYXZpdW0sIElu
            Yy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQDDCFsb2NhbGNhLmxp
            cXVpZHNlY3VyaXR5LmNhdml1bS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
            ggEKAoIBAQDckvqQM4cvZjdyqOLGMTjKJwvfxJOhVqw6pojgUMz10VU7z3CtJrwH
            cESwEDUxUkMxzof55kForURLaVVCjedYauEisnZwwSWkAemp9GREm8iX6BXtoZ8V
            DWoO2H0AJiHCM62qJeZVXhm8A/zWG0PyLrCINH0yz9ah6BcwdsZGLvQvkpUNJhwV
            Mrb9nI9BlRmTWhoot1YSTf7jfibEkc/pN+0Ez30RFaL3MhyIaNJS22+10tny4sOU
            TsPEtXKah5mPlHpnrGcB18z5Yxgr0vDNYx+FCPGo95XGrq9NYfNMlwsSeFSr8D1V
            Q7HZmipeTB1hQTUQw/K/Rmtw5NiljkYTAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIC
            hDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCYlr7aeTnbRfPJGc5Q
            5LEVreY91mp0e5KN331iG3DXQ6x07RMY4PPN+MvVgIPD21Ix6Xtp6Vj9VcsBpV7h
            +6X69s79Ix8j0XV+6+AnrLuftjUjNw7iI9shOYa9aSTg/R6YpwwpXH+L3SZZ+VEF
            yBg5gM7az0aJvuF48fSxNNwel11VC6xkrUFTuzI13GqYe+2rWhc/4TWvs1PpSzA0
            K0W7KYFX2jhGi7H1uOrVneJiaVgD9bgIao/UaQabjlLT62wE9DegpdKPOHbIiQp5
            XOV1rIP/pAWSSiyY7BB7c1acC/3ucDoSjTNUEsVIk3Zsm2jiUy0XC/rZTxaZkHaH
            Bux7
            -----END CERTIFICATE-----""";

    /**
     * Marvell LiquidSecurity 2 root, 2024-07-22 to 2034-07-20. Copied from
     * {@code MARVELL_LS2_HSM_ROOT_CERTIFICATE} in Microsoft's validator.
     * SHA-256 17:64:4D:E0:D3:3B:C7:3B:2F:4E:F4:C2:0A:11:F6:C8:CC:1F:72:3A:4C:D8:3E:E6:00:36:1C:BB:24:D8:D2:E5
     */
    static final String MARVELL_LS2_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIFbTCCA1WgAwIBAgIBADANBgkqhkiG9w0BAQsFADBpMUMwCQYDVQQGEwJVUzAJ
            BgNVBAgMAkNBMAsGA1UECwwEU1NCVTAOBgNVBAcMB1Nhbkpvc2UwDgYDVQQKDAdN
            YXJ2ZWxsMSIwIAYDVQQDDBljYXZpdW0tbGlxdWlkc2VjdXJpdHktbHMyMB4XDTI0
            MDcyMjIwMzQyM1oXDTM0MDcyMDIwMzQyM1owaTFDMAkGA1UEBhMCVVMwCQYDVQQI
            DAJDQTALBgNVBAsMBFNTQlUwDgYDVQQHDAdTYW5Kb3NlMA4GA1UECgwHTWFydmVs
            bDEiMCAGA1UEAwwZY2F2aXVtLWxpcXVpZHNlY3VyaXR5LWxzMjCCAiIwDQYJKoZI
            hvcNAQEBBQADggIPADCCAgoCggIBAM8x8JJPLiULUzlmnDKTQpFvg0iy5Gajj7Vt
            OU04sszOVxcFWM4aUIhGxq7bbKtX7SxMiuR7wfSIkTW+O5AR3kG+PxhPKycfKaAS
            0HTO38eRmI1q94E26g/kn4+6H8ECWOcRm1UxNljEJNsHc6NCw3NotVFfefvEYgpj
            2NS5RGcWs9IcPhXfz7uEdA60taEdyhvqetoPQoYUKFpWB3uuhOXuYUuNyiXqDem6
            QLG1zlc7da9tZ9H/xZZUwfhPxDYhi7j6PQbgbookN/csVC29tNitTZ8CKFPxLoGD
            JMKCoV87Kn9Uce8Q6+6x7uGvngpJuzTksX7F69hEPA+qwmPu5+NczaxNHtgffcsM
            +1Yoz0HJF7EQwXb8eST729Y7KHOF/rMOv3pCpKVIVpMrlfPZrIsf8pEMDKGKyHnZ
            27Vyd1YwkHGLpw5oEsbctlzz0YbKntj5srToQflRj/8Gb27W4SgFJ8FpaTnNnHrE
            SUKrXgFgfShA7wOZbdPzgNbRD1kdeptqypwXYr2OGlqidWRFtoQsLjmy+DO7/Y8T
            0KzI5WpNpS2fxP/JlW070mCW0BmvMZBy9QarJjhwOWKD2lRqDWCkguRJpjKnLBUU
            jjnBWQuJnFYcLuM1IGvIBhRyMuvsuv+iwNwabIaAffb55NK52jR695XN53/VqrW/
            GGXVRbXbAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIChDAMBgNVHRMEBTADAQH/MA0G
            CSqGSIb3DQEBCwUAA4ICAQCNdyJeWTIyOQ6mymRYta5tXfzIdBUT01RYSkLmsCga
            sLbSHAZlq8HOwmozEr8ZL39f2BQ798VFHvHwsjJJVbJNY6Y9CmXehssPWxFlNYTX
            j4P4GIevp19St9VU1d9alThYDyP7ZHTZhMoqlZfvqYQ6pzdvI+R+9vhHumENn8Nm
            0HBz7lwc0rwM1LpnfqD2k/dmCk1x943e5o+Rzi7kYzm4+gjtaEftbvTX5FZ/jTpv
            dOOkGv50kn37JHaR/+FJwEmYQEbst7hVykyQO/FJ0wtkFkjNDpPqQyTeuWpAeTn8
            xYe8zZ8UGiolqFGJO2SimLITCsbofoEUnnYr4Hp7z4N1vZIbg65GvVTdo8be8IDz
            AKrK3fMOT+zsKjaGPhVCvMObfu3w+yQ6Xon8850BXIkQbizuLprEW/TwhTMAta4N
            1c5rGEQf7Ew0NuO3kGyANWub63ZzAMaLCJ8hRKh6VdbtF16E/ShjmbvXXV6O0Sg5
            B81l7Hads8Z/DWNTYpqyt4MqW0429+31VwZle4yryV8bfsRi7Yj7Y0FUxCQYeNc0
            zJ+6GDHbEW5D+DB2S7Kyd4IK2WEg6HJZWS2EM6+oVEO9dBgKOAVMZL74ozlhRS7m
            783mhtSNzDnJe2DHaTofytCJFWeIntMvl7KWljI9LBaJ3PczFfg2b0IbkFE/hMJI
            sA==
            -----END CERTIFICATE-----""";

    private MarvellAttestation() {
    }

    /** The Marvell roots a manufacturer chain may start from. */
    public static List<X509Certificate> marvellRoots() {
        return List.of(certificate(MARVELL_ROOT_PEM), certificate(MARVELL_LS2_ROOT_PEM));
    }

    static X509Certificate certificate(String pem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(pem.trim().getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException("Pinned certificate does not parse", e);
        }
    }

    /** Which layout a blob parsed as. */
    public enum Layout {
        FIRMWARE_2X, FIRMWARE_3X
    }

    /** One key object's attributes, as Marvell's TLV list encodes them. */
    public record KeyObject(Map<Integer, byte[]> attributes) {

        public byte[] attribute(int type) {
            byte[] v = attributes.get(type);
            return v == null ? null : v.clone();
        }

        /** Big-endian unsigned value of a numeric attribute, or null when absent or empty. */
        public BigInteger number(int type) {
            byte[] v = attributes.get(type);
            return v == null || v.length == 0 ? null : new BigInteger(1, v);
        }

        /** {@code TRUE} or {@code FALSE} for a one-byte 0x01 or 0x00 attribute, null otherwise. */
        public Boolean flag(int type) {
            byte[] v = attributes.get(type);
            if (v == null || v.length != 1 || (v[0] != 0 && v[0] != 1)) {
                return null;
            }
            return v[0] == 1;
        }

        /** {@code OBJ_ATTR_ID} as text, NUL padding removed, as Microsoft's parser reads it. */
        public String id() {
            byte[] v = attributes.get(ATTR_ID);
            return v == null ? null : new String(v, StandardCharsets.UTF_8).replace("\0", "");
        }

        Long objectClass() {
            return longOrNull(number(ATTR_CLASS));
        }
    }

    /** A strictly parsed attestation: one key object, or the two of a key pair. */
    public record Parsed(Layout layout, List<KeyObject> objects, byte[] signedData, byte[] signature) {
    }

    /** Decompresses a gzip container (Google's {@code attestation.dat}); other input is returned as is. */
    public static byte[] gunzipIfCompressed(byte[] in) throws IOException {
        if (in.length < 2 || (in[0] & 0xFF) != 0x1F || (in[1] & 0xFF) != 0x8B) {
            return in;
        }
        try (InputStream gz = new GZIPInputStream(new ByteArrayInputStream(in))) {
            byte[] out = gz.readNBytes(MAX_DECOMPRESSED_SIZE + 1);
            if (out.length > MAX_DECOMPRESSED_SIZE) {
                throw new IOException("Decompressed attestation exceeds " + MAX_DECOMPRESSED_SIZE + " bytes");
            }
            return out;
        }
    }

    /**
     * Parses both layouts strictly inside the signed data and returns the one
     * that fits.
     *
     * @throws IllegalArgumentException when the blob fits neither layout or both
     */
    public static Parsed parse(byte[] blob) {
        if (blob == null || blob.length <= SIGNATURE_SIZE) {
            throw new IllegalArgumentException("Attestation is shorter than its " + SIGNATURE_SIZE + "-byte signature");
        }
        byte[] data = Arrays.copyOf(blob, blob.length - SIGNATURE_SIZE);
        byte[] sig = Arrays.copyOfRange(blob, blob.length - SIGNATURE_SIZE, blob.length);

        List<KeyObject> fw2 = tryParse(() -> List.of(new KeyObject(attributesAt(data, FW2_ATTRIBUTE_OFFSET))));
        List<KeyObject> fw3 = tryParse(() -> fw3Objects(blob, data));
        if (fw2 != null && fw3 != null) {
            throw new IllegalArgumentException("Attestation parses as both firmware 2.x and 3.x; layout is ambiguous");
        }
        if (fw2 == null && fw3 == null) {
            throw new IllegalArgumentException("Attestation parses as neither firmware 2.x nor 3.x");
        }
        return fw2 != null
                ? new Parsed(Layout.FIRMWARE_2X, fw2, data, sig)
                : new Parsed(Layout.FIRMWARE_3X, fw3, data, sig);
    }

    private interface ObjectParse {
        List<KeyObject> run();
    }

    private static List<KeyObject> tryParse(ObjectParse p) {
        try {
            return p.run();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Marvell's response layout: a {@code ResponseHeader} whose
     * {@code ulTotalSize} is the length of the whole response and whose
     * {@code ulBufferSize} is the length of the attribute buffer, which ends
     * where the signature starts. The buffer opens with {@code TLVKeyInfo}
     * ({@code usObjectVersion, usFlags, usKey1Offset, usKey2Offset}); a key
     * pair carries two objects, a single key one ({@code usKey2Offset = 0}).
     */
    private static List<KeyObject> fw3Objects(byte[] blob, byte[] data) {
        ByteBuffer b = ByteBuffer.wrap(blob);
        long total = u32(b, 8);
        long buffer = u32(b, 12);
        if (total != blob.length) {
            throw new IllegalArgumentException("ulTotalSize " + total + " is not the attestation length " + blob.length);
        }
        long start = total - (buffer + SIGNATURE_SIZE);
        if (start < 16) {
            throw new IllegalArgumentException("attribute buffer outside the signed data");
        }
        ByteBuffer d = ByteBuffer.wrap(data);
        int key1 = u16(d, (int) start + 4);
        int key2 = u16(d, (int) start + 6);
        if (key1 == 0) {
            throw new IllegalArgumentException("usKey1Offset is zero");
        }
        List<KeyObject> objects = new ArrayList<>();
        objects.add(new KeyObject(attributesAt(data, (int) start + key1)));
        if (key2 != 0) {
            objects.add(new KeyObject(attributesAt(data, (int) start + key2)));
        }
        return List.copyOf(objects);
    }

    /** Walks one {@code >III} header and its {@code >II} records; every byte read must lie in {@code data}. */
    static Map<Integer, byte[]> attributesAt(byte[] data, int offset) {
        ByteBuffer b = ByteBuffer.wrap(data);
        long count = u32(b, offset + 4);
        if (count == 0 || count > MAX_ATTRIBUTES) {
            throw new IllegalArgumentException("attribute count " + count + " out of range");
        }
        int pos = offset + 12;
        Map<Integer, byte[]> attributes = new LinkedHashMap<>();
        for (long i = 0; i < count; i++) {
            long type = u32(b, pos);
            long len = u32(b, pos + 4);
            pos += 8;
            if (type > Integer.MAX_VALUE || len > data.length - pos) {
                throw new IllegalArgumentException("attribute record runs past the signed data");
            }
            if (attributes.put((int) type, Arrays.copyOfRange(data, pos, pos + (int) len)) != null) {
                throw new IllegalArgumentException("attribute 0x" + Long.toHexString(type) + " appears twice");
            }
            pos += (int) len;
        }
        return Collections.unmodifiableMap(attributes);
    }

    /**
     * Reads past the end throw {@link IndexOutOfBoundsException} from the
     * buffer itself; every read runs inside {@link #tryParse}, which takes any
     * runtime exception as "does not fit this layout".
     */
    private static long u32(ByteBuffer b, int at) {
        return Integer.toUnsignedLong(b.getInt(at));
    }

    private static int u16(ByteBuffer b, int at) {
        return Short.toUnsignedInt(b.getShort(at));
    }

    /**
     * Whether {@code cert}'s key signed {@code parsed}, under the scheme its
     * layout uses: PKCS#1 v1.5 for firmware 3.x, Microsoft's raw trailing-hash
     * comparison for firmware 2.x (exponent at least 65537).
     */
    public static boolean signedBy(Parsed parsed, X509Certificate cert) {
        if (!(cert.getPublicKey() instanceof RSAPublicKey key)) {
            return false;
        }
        return parsed.layout() == Layout.FIRMWARE_3X
                ? pkcs1(parsed, key, digestOf(cert))
                : rawTrailingHash(parsed, key);
    }

    /** Whether {@code cert}'s key signed {@code parsed} with SHA-256 PKCS#1 v1.5, as Google's tool checks it. */
    public static boolean signedPkcs1Sha256(Parsed parsed, X509Certificate cert) {
        return cert.getPublicKey() instanceof RSAPublicKey key && pkcs1(parsed, key, "SHA256withRSA");
    }

    private static String digestOf(X509Certificate cert) {
        String alg = cert.getSigAlgName().toUpperCase();
        if (alg.startsWith("SHA384")) {
            return "SHA384withRSA";
        }
        if (alg.startsWith("SHA512")) {
            return "SHA512withRSA";
        }
        return "SHA256withRSA";
    }

    private static boolean pkcs1(Parsed parsed, PublicKey key, String algorithm) {
        try {
            Signature s = Signature.getInstance(algorithm);
            s.initVerify(key);
            s.update(parsed.signedData());
            return s.verify(parsed.signature());
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean rawTrailingHash(Parsed parsed, RSAPublicKey key) {
        if (key.getPublicExponent().compareTo(BigInteger.valueOf(65537)) < 0) {
            return false;
        }
        BigInteger s = new BigInteger(1, parsed.signature());
        // The signature representative must lie in [1, n - 1] (RFC 8017, 5.2.2).
        if (s.signum() == 0 || !s.equals(s.mod(key.getModulus()))) {
            return false;
        }
        byte[] m = s.modPow(key.getPublicExponent(), key.getModulus()).toByteArray();
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(parsed.signedData());
            return m.length >= hash.length
                    && MessageDigest.isEqual(Arrays.copyOfRange(m, m.length - hash.length, m.length), hash);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * What verified attestations say about the key.
     *
     * @param extractable    true unless EXTRACTABLE is false and NEVER_EXTRACTABLE is true
     * @param keyOrigin      {@code generated} when LOCAL and NEVER_EXTRACTABLE are both true,
     *                       otherwise {@code unverified}
     * @param publicKeyMatch the private key, or the public key attested with it, is the CSR key
     */
    public record KeyEvidence(boolean extractable, String keyOrigin, boolean publicKeyMatch,
                              String keyId, int keyBits, List<String> errors) {
    }

    /**
     * Reads key evidence from attestations whose signatures and chains the
     * caller has already verified. Exactly one private-key object
     * ({@code OBJ_ATTR_CLASS} = {@code CKO_PRIVATE_KEY}) must be present, and
     * its attributes must be present with well-formed values; a missing
     * attribute counts against the key. Every object that carries key material
     * (modulus and exponent, KCV, EKCV) must match the CSR key, and the private
     * key must be tied to it either directly or through a public-key object in
     * the same signed blob, which Marvell issues for the two halves of one
     * generated key pair.
     */
    public static KeyEvidence evaluate(List<Parsed> attestations, PublicKey csrKey) {
        List<String> errors = new ArrayList<>();
        KeyObject privateKey = null;
        Parsed privateBlob = null;
        int privateCount = 0;
        for (Parsed p : attestations) {
            for (KeyObject o : p.objects()) {
                Long cls = o.objectClass();
                if (Long.valueOf(CKO_PRIVATE_KEY).equals(cls)) {
                    privateKey = o;
                    privateBlob = p;
                    privateCount++;
                } else if (!Long.valueOf(CKO_PUBLIC_KEY).equals(cls)) {
                    errors.add("MARVELL_UNEXPECTED_OBJECT: OBJ_ATTR_CLASS " + cls + " is neither a public nor a private key");
                }
            }
        }
        if (privateCount != 1) {
            errors.add("MARVELL_NO_SINGLE_PRIVATE_KEY: the attestations carry " + privateCount
                    + " private-key objects; exactly one is required");
            return new KeyEvidence(true, "unverified", false, null, 0, List.copyOf(errors));
        }

        if (!Long.valueOf(CKK_RSA).equals(longOrNull(privateKey.number(ATTR_KEY_TYPE)))) {
            errors.add("MARVELL_KEY_NOT_RSA: OBJ_ATTR_KEY_TYPE is not CKK_RSA");
        }
        Boolean extractableFlag = privateKey.flag(ATTR_EXTRACTABLE);
        Boolean neverExtractable = privateKey.flag(ATTR_NEVER_EXTRACTABLE);
        Boolean local = privateKey.flag(ATTR_LOCAL);
        boolean extractable = !(Boolean.FALSE.equals(extractableFlag) && Boolean.TRUE.equals(neverExtractable));
        if (extractable) {
            errors.add("MARVELL_KEY_EXTRACTABLE: OBJ_ATTR_EXTRACTABLE=" + extractableFlag
                    + ", OBJ_ATTR_NEVER_EXTRACTABLE=" + neverExtractable
                    + " (required: false and true; null means absent or malformed)");
        }
        boolean generated = Boolean.TRUE.equals(local) && Boolean.TRUE.equals(neverExtractable);
        if (!generated) {
            errors.add("MARVELL_KEY_NOT_GENERATED: OBJ_ATTR_LOCAL=" + local
                    + ", OBJ_ATTR_NEVER_EXTRACTABLE=" + neverExtractable
                    + " (required: true and true; null means absent or malformed)");
        }

        if (!(csrKey instanceof RSAPublicKey rsa)) {
            errors.add("MARVELL_PUBLIC_KEY_MISMATCH: the CSR key is not an RSA key");
            return new KeyEvidence(extractable, generated ? "generated" : "unverified", false,
                    privateKey.id(), 0, List.copyOf(errors));
        }
        boolean mismatch = false;
        for (Parsed p : attestations) {
            for (KeyObject o : p.objects()) {
                mismatch |= keyMaterial(o, rsa) == Binding.MISMATCH;
            }
        }
        boolean bound = keyMaterial(privateKey, rsa) == Binding.MATCH;
        for (KeyObject o : privateBlob.objects()) {
            bound |= Long.valueOf(CKO_PUBLIC_KEY).equals(o.objectClass()) && keyMaterial(o, rsa) == Binding.MATCH;
        }
        if (mismatch) {
            errors.add("MARVELL_PUBLIC_KEY_MISMATCH: an attested modulus, exponent, KCV or EKCV is not the CSR key's");
        } else if (!bound) {
            errors.add("MARVELL_KEY_NOT_BOUND: neither the private key nor a public key attested with it "
                    + "carries a modulus or EKCV, so the attestation cannot be tied to the CSR key");
        }
        boolean match = bound && !mismatch;
        return new KeyEvidence(extractable, generated ? "generated" : "unverified", match,
                privateKey.id(), match ? rsa.getModulus().bitLength() : 0, List.copyOf(errors));
    }

    private enum Binding {
        MATCH, MISMATCH, ABSENT
    }

    /**
     * Compares an object's key material with the CSR key. The modulus is the
     * raw big-endian value; KCV is the first three bytes of SHA-1 and EKCV the
     * SHA-256 of the DER SubjectPublicKeyInfo, as Marvell's published example
     * shows ({@code MarvellAttestationTest.marvellPublishedExampleBindsItsKey}).
     */
    private static Binding keyMaterial(KeyObject o, RSAPublicKey csr) {
        BigInteger n = o.number(ATTR_MODULUS);
        BigInteger e = o.number(ATTR_PUBLIC_EXPONENT);
        byte[] kcv = o.attributes().get(ATTR_KCV);
        byte[] ekcv = o.attributes().get(ATTR_EKCV);
        boolean any = false;
        try {
            byte[] spki = csr.getEncoded();
            if (n != null) {
                any = true;
                if (!n.equals(csr.getModulus()) || (e != null && !e.equals(csr.getPublicExponent()))) {
                    return Binding.MISMATCH;
                }
            }
            if (kcv != null) {
                byte[] expected = Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(spki), 3);
                if (!MessageDigest.isEqual(kcv, expected)) {
                    return Binding.MISMATCH;
                }
            }
            if (ekcv != null) {
                any = true;
                if (!MessageDigest.isEqual(ekcv, MessageDigest.getInstance("SHA-256").digest(spki))) {
                    return Binding.MISMATCH;
                }
            }
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
        return any ? Binding.MATCH : Binding.ABSENT;
    }

    private static Long longOrNull(BigInteger v) {
        return v == null || v.bitLength() > 63 ? null : v.longValue();
    }

    /** Manufacturer chain found in a bundle: Marvell root, the card certificate it issued, and the partition certificate. */
    public record ManufacturerChain(X509Certificate root, X509Certificate card, X509Certificate partition) {
    }

    /**
     * Finds root → card → partition the way both vendor tools do: by issuer
     * name and signature, starting from one of {@code roots}.
     *
     * @return the chain, or null when the bundle holds none
     */
    public static ManufacturerChain manufacturerChain(List<X509Certificate> bundle, List<X509Certificate> roots) {
        for (X509Certificate root : roots) {
            for (X509Certificate card : issuedBy(root, bundle)) {
                for (X509Certificate partition : issuedBy(card, bundle)) {
                    return new ManufacturerChain(root, card, partition);
                }
            }
        }
        return null;
    }

    /** Certificates in {@code bundle}, other than {@code issuer} itself, that {@code issuer} signed. */
    public static List<X509Certificate> issuedBy(X509Certificate issuer, List<X509Certificate> bundle) {
        List<X509Certificate> out = new ArrayList<>();
        for (X509Certificate c : bundle) {
            if (c.equals(issuer) || !c.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                continue;
            }
            try {
                c.verify(issuer.getPublicKey());
                out.add(c);
            } catch (Exception ignored) {
                // not issued by this certificate
            }
        }
        return out;
    }

    /** Parses one or more concatenated PEM certificates. */
    public static List<X509Certificate> parsePemBundle(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> out = new ArrayList<>();
        for (var c : cf.generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))) {
            out.add((X509Certificate) c);
        }
        return out;
    }
}
