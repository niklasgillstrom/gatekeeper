package eu.gillstrom.gatekeeper.controller;

import eu.gillstrom.gatekeeper.audit.AppendOnlyFileAuditLog;
import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditEntry;
import eu.gillstrom.gatekeeper.cose.CborDecoder;
import eu.gillstrom.gatekeeper.service.GatekeeperKeyDirectory;
import eu.gillstrom.gatekeeper.signing.ConfiguredReceiptSigner;
import eu.gillstrom.gatekeeper.signing.EphemeralReceiptSigner;
import eu.gillstrom.gatekeeper.signing.ReceiptSigner;
import eu.gillstrom.gatekeeper.timestamp.AuditTimestamping;
import eu.gillstrom.gatekeeper.timestamp.TestTsa;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * {@code GET /v1/audit/export?format=cose}: decode the CBOR sequence, rebuild
 * each Sig_structure independently of the production encoder, and verify
 * every COSE signature with {@code java.security}; check that the payload
 * carries every hashed field so the entry hash and the original entry
 * signature can be re-verified from it.
 */
class AuditCoseExportTest {

    @TempDir
    Path tempDir;

    private static final String KEY = "aa:" + "00:".repeat(30) + "01";

    // ---- independent minimal CBOR writer for the Sig_structure ----------------------------

    private static void head(ByteArrayOutputStream out, int major, int length) {
        if (length < 24) {
            out.write((major << 5) | length);
        } else if (length < 256) {
            out.write((major << 5) | 24);
            out.write(length);
        } else if (length < 65536) {
            out.write((major << 5) | 25);
            out.write(length >> 8);
            out.write(length & 0xff);
        } else {
            out.write((major << 5) | 26);
            out.write(length >>> 24);
            out.write((length >> 16) & 0xff);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        }
    }

    private static byte[] sigStructure(byte[] protectedHeader, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        head(out, 4, 4);
        byte[] context = "Signature1".getBytes(StandardCharsets.UTF_8);
        head(out, 3, context.length);
        out.writeBytes(context);
        head(out, 2, protectedHeader.length);
        out.writeBytes(protectedHeader);
        head(out, 2, 0);
        head(out, 2, payload.length);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    // ---- fixtures ------------------------------------------------------------------------

    private record Fixture(MockMvc mvc, AppendOnlyFileAuditLog log, GatekeeperKeyDirectory keys,
                           ReceiptSigner signer) {
    }

    private Fixture fixture(ReceiptSigner signer, AuditTimestamping ts, String name) {
        AppendOnlyFileAuditLog log = new AppendOnlyFileAuditLog(tempDir.resolve(name + ".jsonl").toString(), signer,
                0, null, ts);
        log.initialise();
        GatekeeperKeyDirectory keys = new GatekeeperKeyDirectory(signer, "");
        keys.initialise();
        return new Fixture(MockMvcBuilders.standaloneSetup(new AuditController(log, signer, keys)).build(), log,
                keys, signer);
    }

    private ConfiguredReceiptSigner ecSigner(String curve, String algorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curve));
        KeyPair kp = kpg.generateKeyPair();
        long now = System.currentTimeMillis();
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                new X500Name("CN=EC SEAL"), BigInteger.valueOf(now), new Date(now - 60_000), new Date(now + 3_600_000),
                new X500Name("CN=EC SEAL"), kp.getPublic()).build(new JcaContentSignerBuilder(algorithm)
                .build(kp.getPrivate())));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("seal", kp.getPrivate(), "pw".toCharArray(), new Certificate[] {cert});
        Path p = tempDir.resolve(curve + ".p12");
        try (OutputStream out = Files.newOutputStream(p)) {
            ks.store(out, "pw".toCharArray());
        }
        return new ConfiguredReceiptSigner(p.toString(), "pw", "seal", "pw", algorithm);
    }

    private static List<AuditEntry> appendSample(AppendOnlyFileAuditLog log) {
        AuditEntry a = log.append(new AuditAppendRequest("CN=fe", "VERIFY", "v-1", "cmVxMQ==", "cmNwdDE=", true)
                .withKeyFingerprintHex(KEY).withHsm("Yubico", "12345678"));
        AuditEntry b = log.append(new AuditAppendRequest("CN=fe", "CONFIRM", "v-1", "cmVxMg==", null, true)
                .withKeyFingerprintHex(KEY).withCertificate("1f", "CN=Issuer, O=X|Y").withRegistryStatus(
                        "VERIFIED_AND_ISSUED"));
        AuditEntry c = log.append(new AuditAppendRequest("CN=rail", "SETTLEMENT_VERIFY", "NO-REGISTRY-MATCH",
                "cmVxMw==", "cmVzcA==", false));
        return List.of(a, b, c);
    }

    private static MockHttpServletResponse export(MockMvc mvc, List<AuditEntry> entries, String format)
            throws Exception {
        var request = get("/v1/audit/export")
                .param("from", DateTimeFormatter.ISO_INSTANT.format(entries.get(0).timestamp().minusSeconds(1)))
                .param("to", DateTimeFormatter.ISO_INSTANT.format(entries.get(entries.size() - 1).timestamp()
                        .plusSeconds(1)));
        if (format != null) {
            request.param("format", format);
        }
        return mvc.perform(request).andReturn().getResponse();
    }

    private static PublicKey activeKey(ReceiptSigner signer) throws Exception {
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(
                signer.getSigningCertificatePem().getBytes(StandardCharsets.UTF_8))).getPublicKey();
    }

    /**
     * Decode, check structure and header, verify the COSE signature with
     * {@code verifyAlgorithm}, and return the decoded payloads.
     */
    @SuppressWarnings("unchecked")
    private static List<Map<Object, Object>> decodeAndVerify(byte[] body, Fixture f, long expectedAlg,
                                                             String verifyAlgorithm, int expectedSignatureLength)
            throws Exception {
        CborDecoder decoder = new CborDecoder(body);
        List<Map<Object, Object>> payloads = new java.util.ArrayList<>();
        PublicKey key = activeKey(f.signer());
        byte[] expectedKid = HexFormat.of().parseHex(f.keys().activeFingerprintHex());
        while (!decoder.atEnd()) {
            CborDecoder.Tagged item = (CborDecoder.Tagged) decoder.next();
            assertThat(item.tag()).isEqualTo(18);
            List<Object> sign1 = (List<Object>) item.value();
            assertThat(sign1).hasSize(4);
            byte[] protectedHeader = (byte[]) sign1.get(0);
            assertThat((Map<Object, Object>) sign1.get(1)).as("unprotected").isEmpty();
            byte[] payload = (byte[]) sign1.get(2);
            byte[] signature = (byte[]) sign1.get(3);

            Map<Object, Object> header = (Map<Object, Object>) new CborDecoder(protectedHeader).next();
            assertThat(header).containsOnlyKeys(1L, 4L);
            assertThat(header.get(1L)).isEqualTo(expectedAlg);
            assertThat((byte[]) header.get(4L)).isEqualTo(expectedKid);
            assertThat(expectedKid).hasSize(32);
            if (expectedSignatureLength > 0) {
                assertThat(signature).hasSize(expectedSignatureLength);
            }

            Signature v = Signature.getInstance(verifyAlgorithm);
            v.initVerify(key);
            v.update(sigStructure(protectedHeader, payload));
            assertThat(v.verify(signature)).as("COSE_Sign1 signature").isTrue();

            CborDecoder payloadDecoder = new CborDecoder(payload);
            payloads.add((Map<Object, Object>) payloadDecoder.next());
            assertThat(payloadDecoder.atEnd()).isTrue();
            assertThat(payloadDecoder.allShortest()).as("deterministic heads").isTrue();
        }
        assertThat(decoder.allShortest()).isTrue();
        return payloads;
    }

    @Test
    void rsaExportVerifiesAndThePayloadReproducesTheEntryHashAndSignature() throws Exception {
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
        Fixture f = fixture(signer, null, "rsa");
        List<AuditEntry> entries = appendSample(f.log());

        MockHttpServletResponse response = export(f.mvc(), entries, "cose");

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).isEqualTo("application/cbor-seq");
        List<Map<Object, Object>> payloads = decodeAndVerify(response.getContentAsByteArray(), f, -257,
                "SHA256withRSA", 256);
        assertThat(payloads).hasSize(3);

        for (int i = 0; i < 3; i++) {
            AuditEntry e = entries.get(i);
            Map<Object, Object> p = payloads.get(i);
            assertThat(p.get("eventType")).isEqualTo(e.operation());
            assertThat(p.get("sequence")).isEqualTo(e.sequenceNumber());
            assertThat(p.get("timestamp")).isEqualTo(e.timestamp().toString());
            assertThat(p.get("principal")).isEqualTo(e.mtlsClientPrincipal());
            assertThat(p.get("verificationId")).isEqualTo(e.verificationId());
            assertThat(p.get("requestDigest")).isEqualTo(e.requestDigestBase64());
            assertThat(p.get("receiptDigest")).isEqualTo(e.receiptDigestBase64());
            assertThat(p.get("compliant")).isEqualTo(e.compliant());
            assertThat(p.get("canonicalVersion")).isEqualTo("v2");
            assertThat(p.get("keyFingerprint")).isEqualTo(e.keyFingerprintHex());
            assertThat(p.get("certSerial")).isEqualTo(e.certSerialHex());
            assertThat(p.get("certIssuerDn")).isEqualTo(e.certIssuerDn());
            assertThat(p.get("hsmVendor")).isEqualTo(e.hsmVendor());
            assertThat(p.get("hsmSerial")).isEqualTo(e.hsmSerial());
            assertThat(p.get("registryStatus")).isEqualTo(e.registryStatus());
            assertThat(p.get("prevEntryHash")).isEqualTo(e.prevEntryHashHex());
            assertThat(p.get("prevKeyEntryHash")).isEqualTo(e.prevKeyEntryHashHex());
            assertThat(p.get("thisEntryHash")).isEqualTo(e.thisEntryHashHex());
            assertThat((byte[]) p.get("entrySignature"))
                    .isEqualTo(Base64.getDecoder().decode(e.entrySignatureBase64()));
            assertThat(p).doesNotContainKey("timestampToken");

            // Recompute the entry hash from the payload alone.
            byte[] canonical = AuditEntry.canonicalBytesForHashV2((Long) p.get("sequence"),
                    Instant.parse((String) p.get("timestamp")), (String) p.get("principal"),
                    (String) p.get("eventType"), (String) p.get("verificationId"), (String) p.get("requestDigest"),
                    (String) p.get("receiptDigest"), (Boolean) p.get("compliant"), (String) p.get("prevEntryHash"),
                    (String) p.get("keyFingerprint"), (String) p.get("certSerial"), (String) p.get("certIssuerDn"),
                    (String) p.get("hsmVendor"), (String) p.get("hsmSerial"), (String) p.get("registryStatus"),
                    (String) p.get("hsmFirmwareVersion"), (String) p.get("hsmFipsApprovedMode"),
                    (String) p.get("prevKeyEntryHash"));
            assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical)))
                    .isEqualTo(p.get("thisEntryHash"));
            // And the original entry signature over it.
            Signature original = Signature.getInstance("SHA256withRSA");
            original.initVerify(activeKey(signer));
            original.update(((String) p.get("thisEntryHash")).getBytes(StandardCharsets.UTF_8));
            assertThat(original.verify((byte[]) p.get("entrySignature"))).isTrue();
        }
        assertThat(payloads.get(1)).doesNotContainKey("receiptDigest").doesNotContainKey("hsmVendor");
        assertThat(payloads.get(2)).doesNotContainKey("keyFingerprint").doesNotContainKey("prevKeyEntryHash");
    }

    @Test
    void ecdsaSealsAreRawRAndSAndVerify() throws Exception {
        Object[][] cases = {
                {"secp256r1", "SHA256withECDSA", -7L, "SHA256withECDSAinP1363Format", 64},
                {"secp384r1", "SHA384withECDSA", -35L, "SHA384withECDSAinP1363Format", 96},
                {"secp521r1", "SHA512withECDSA", -36L, "SHA512withECDSAinP1363Format", 132}};
        for (Object[] c : cases) {
            ConfiguredReceiptSigner signer = ecSigner((String) c[0], (String) c[1]);
            Fixture f = fixture(signer, null, "ec-" + c[0]);
            List<AuditEntry> entries = appendSample(f.log());

            MockHttpServletResponse response = export(f.mvc(), entries, "cose");

            assertThat(response.getStatus()).as((String) c[0]).isEqualTo(200);
            assertThat(decodeAndVerify(response.getContentAsByteArray(), f, (Long) c[2], (String) c[3], (Integer) c[4]))
                    .hasSize(3);
        }
    }

    @Test
    void aTimestampTokenIsCarriedInThePayload() throws Exception {
        TestTsa tsa = new TestTsa();
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
        Fixture f = fixture(signer, new AuditTimestamping(AuditTimestamping.Mode.ENTRY, tsa, tsa.verifier(), null, 0),
                "ts");
        List<AuditEntry> entries = appendSample(f.log());

        List<Map<Object, Object>> payloads = decodeAndVerify(
                export(f.mvc(), entries, "cose").getContentAsByteArray(), f, -257, "SHA256withRSA", 256);

        assertThat((byte[]) payloads.get(0).get("timestampToken"))
                .isEqualTo(Base64.getDecoder().decode(entries.get(0).timestampTokenBase64()));
    }

    @Test
    void aV1EntryIsExportedWithItsVersion() throws Exception {
        // One v1 line, as an older gatekeeper wrote it.
        EphemeralReceiptSigner signer = new EphemeralReceiptSigner(2048);
        Instant t = Instant.parse("2026-01-01T10:00:00Z");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                AuditEntry.canonicalBytesForHash(1, t, "CN=old", "VERIFY", "old-1", "cmVx", null, true,
                        AuditEntry.SENTINEL_PREV_HASH_HEX)));
        String sig = Base64.getEncoder().encodeToString(signer.sign(hash.getBytes(StandardCharsets.UTF_8)));
        Files.writeString(tempDir.resolve("v1.jsonl"), "{\"sequenceNumber\":1,\"timestamp\":\"" + t
                + "\",\"mtlsClientPrincipal\":\"CN=old\",\"operation\":\"VERIFY\",\"verificationId\":\"old-1\","
                + "\"requestDigestBase64\":\"cmVx\",\"receiptDigestBase64\":null,\"compliant\":true,"
                + "\"prevEntryHashHex\":\"" + AuditEntry.SENTINEL_PREV_HASH_HEX + "\",\"thisEntryHashHex\":\""
                + hash + "\",\"entrySignatureBase64\":\"" + sig + "\"}\n", StandardCharsets.UTF_8);
        Fixture f = fixture(signer, null, "v1");

        List<Map<Object, Object>> payloads = decodeAndVerify(export(f.mvc(), f.log().findInRange(Instant.EPOCH,
                Instant.now()), "cose").getContentAsByteArray(), f, -257, "SHA256withRSA", 256);

        assertThat(payloads).singleElement().satisfies(p -> {
            assertThat(p.get("canonicalVersion")).isEqualTo("v1");
            assertThat(p.get("thisEntryHash")).isEqualTo(hash);
        });
    }

    @Test
    void jsonStaysTheDefaultAndAnUnknownFormatIsRefused() throws Exception {
        Fixture f = fixture(new EphemeralReceiptSigner(2048), null, "json");
        List<AuditEntry> entries = appendSample(f.log());

        for (String format : new String[] {null, "json", "JSON"}) {
            MockHttpServletResponse r = export(f.mvc(), entries, format);
            assertThat(r.getStatus()).isEqualTo(200);
            assertThat(r.getContentType()).startsWith("application/json");
            assertThat(r.getContentAsString()).contains("\"exportSignatureBase64\"");
        }
        assertThat(export(f.mvc(), entries, "xml").getStatus()).isEqualTo(400);
    }

    @Test
    void aSigningAlgorithmWithoutACoseMappingIsNotImplemented() throws Exception {
        EphemeralReceiptSigner inner = new EphemeralReceiptSigner(2048);
        ReceiptSigner sha1 = new ReceiptSigner() {
            @Override
            public String getSignerIdentifier() {
                return inner.getSignerIdentifier();
            }

            @Override
            public byte[] sign(byte[] data) {
                return inner.sign(data);
            }

            @Override
            public String getSigningCertificatePem() {
                return inner.getSigningCertificatePem();
            }

            @Override
            public String getSignatureAlgorithm() {
                return "SHA1withRSA";
            }
        };
        Fixture f = fixture(sha1, null, "sha1");
        List<AuditEntry> entries = List.of(f.log().append(
                new AuditAppendRequest("CN=fe", "VERIFY", "v-1", "cmVx", null, true)));

        assertThat(export(f.mvc(), entries, "cose").getStatus()).isEqualTo(501);
    }
}
