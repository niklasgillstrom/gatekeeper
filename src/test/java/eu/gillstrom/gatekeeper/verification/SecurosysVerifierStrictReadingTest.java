package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXParseException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What {@link SecurosysVerifier} reads from an attestation, and from where.
 *
 * <p>Until 1.7.0 each value the verdict depends on was taken from the first
 * element of its name anywhere in the document. The key's label is chosen by
 * whoever creates the key and stands before {@code public_key} and
 * {@code attributes}; a label that carried markup into the attestation would
 * have put an element of the attacker's before the HSM's own. Every
 * attestation here is signed by an attestation key under a test root the
 * verifier is anchored at, so the chain and the signature are valid and only
 * the reading of the document decides.</p>
 */
class SecurosysVerifierStrictReadingTest {

    private static final String SAFE_ATTRIBUTES = "<attributes>"
            + "<sensitive>true</sensitive><always_sensitive>true</always_sensitive>"
            + "<extractable>false</extractable><never_extractable>true</never_extractable>"
            + "</attributes>";

    private static final String UNSAFE_ATTRIBUTES = "<attributes>"
            + "<sensitive>false</sensitive><always_sensitive>false</always_sensitive>"
            + "<extractable>true</extractable><never_extractable>false</never_extractable>"
            + "</attributes>";

    private SecurosysVerifier verifier;
    private KeyPair attestationKp;
    private List<String> chainPem;
    /** The key the HSM attests. */
    private KeyPair hsmKey;
    /** A key generated outside the HSM. */
    private KeyPair softwareKey;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate root = TestPki.selfSignedCa(rootKp, "TEST-SECUROSYS-ROOT");
        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate device = TestPki.subordinateCa(
                deviceKp, "PRIMUS HSM KEY (SN: 18386101)", root, rootKp.getPrivate());
        attestationKp = TestPki.newRsaKeyPair(2048);
        X509Certificate leaf = TestPki.endEntity(attestationKp, "attestation-key", device, deviceKp.getPrivate());
        chainPem = List.of(TestPki.toPem(leaf), TestPki.toPem(device));
        verifier = new SecurosysVerifier(root);
        hsmKey = TestPki.newRsaKeyPair(2048);
        softwareKey = TestPki.newRsaKeyPair(2048);
    }

    private static String b64(KeyPair kp) {
        return Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
    }

    private static String publicKey(KeyPair kp) {
        return "<public_key>" + b64(kp) + "</public_key>";
    }

    private static String attestation(String body) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<private_key creation=\"generated\">" + body
                + "</private_key>";
    }

    private SecurosysVerifier.SecurosysAttestationResult verify(String xml, KeyPair csrKey) throws Exception {
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(attestationKp.getPrivate());
        sig.update(bytes);
        return verifier.verifySecurosysAttestation(Base64.getEncoder().encodeToString(bytes),
                Base64.getEncoder().encodeToString(sig.sign()), chainPem, csrKey.getPublic());
    }

    @Test
    void anAttestationShapedAsTheHsmWritesItIsValid() throws Exception {
        SecurosysVerifier.SecurosysAttestationResult r = verify(attestation(
                "\n\t<label>rsa_4096_sign</label>\n\t" + publicKey(hsmKey) + "\n\t"
                        + "<attributes>\n\t\t<sensitive> true </sensitive><always_sensitive>true</always_sensitive>"
                        + "<extractable>\nfalse\n</extractable><never_extractable>true</never_extractable>\n\t"
                        + "</attributes>\n"), hsmKey);

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.isExtractable()).isFalse();
        assertThat(r.isNeverExtractable()).isTrue();
        assertThat(r.isSensitive()).isTrue();
        assertThat(r.isAlwaysSensitive()).isTrue();
    }

    /**
     * The label, creation time, algorithm and key size describe the key and
     * decide nothing. They are reported as the attestation states them, and
     * are absent, not empty, when it does not state them.
     */
    @Test
    void theDescriptiveFieldsAreReportedAsStatedAndAbsentWhenTheyAreNot() throws Exception {
        SecurosysVerifier.SecurosysAttestationResult stated = verify(attestation(
                "<label> rsa_4096_sign </label><create_time>2026-01-01T00:00:00Z</create_time>"
                        + "<algorithm>RSA</algorithm><key_size>\n4096\n</key_size>"
                        + publicKey(hsmKey) + SAFE_ATTRIBUTES), hsmKey);

        assertThat(stated.isValid()).isTrue();
        assertThat(stated.getKeyLabel()).isEqualTo("rsa_4096_sign");
        assertThat(stated.getCreateTime()).isEqualTo("2026-01-01T00:00:00Z");
        assertThat(stated.getAlgorithm()).isEqualTo("RSA");
        assertThat(stated.getKeySize()).isEqualTo("4096");

        SecurosysVerifier.SecurosysAttestationResult bare = verify(
                attestation(publicKey(hsmKey) + SAFE_ATTRIBUTES), hsmKey);

        assertThat(bare.isValid()).isTrue();
        assertThat(bare.getKeyLabel()).isNull();
        assertThat(bare.getCreateTime()).isNull();
        assertThat(bare.getAlgorithm()).isNull();
        assertThat(bare.getKeySize()).isNull();
    }

    /** What an unescaped label {@code x</label><public_key>…</public_key><label>y} would produce. */
    @Test
    void aSecondPublicKeyBeforeTheHsmsOwnIsNotTakenForTheAttestedKey() throws Exception {
        String xml = attestation("<label>x</label>" + publicKey(softwareKey) + "<label>y</label>"
                + publicKey(hsmKey) + SAFE_ATTRIBUTES);

        for (KeyPair csrKey : List.of(softwareKey, hsmKey)) {
            SecurosysVerifier.SecurosysAttestationResult r = verify(xml, csrKey);
            assertThat(r.getErrors()).containsExactly("Could not extract public_key from XML");
            assertThat(r.isPublicKeyMatch()).isFalse();
            assertThat(r.isValid()).isFalse();
        }
    }

    @Test
    void aSecondAttributesElementBeforeTheHsmsOwnIsNotTakenForTheKeysAttributes() throws Exception {
        SecurosysVerifier.SecurosysAttestationResult r = verify(attestation(
                "<label>x</label>" + SAFE_ATTRIBUTES + "<label>y</label>" + publicKey(hsmKey) + UNSAFE_ATTRIBUTES),
                hsmKey);

        assertThat(r.getErrors()).containsExactly(
                "Key attribute extractable must be false",
                "Key attribute never_extractable must be true",
                "Key attribute sensitive must be true",
                "Key attribute always_sensitive must be true");
        assertThat(r.isExtractable()).isTrue();
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void anAttributeIsReadOnlyFromInsideTheAttributesElement() throws Exception {
        // The four safe values stand directly under the root; <attributes> has none.
        SecurosysVerifier.SecurosysAttestationResult outside = verify(attestation(publicKey(hsmKey)
                + "<sensitive>true</sensitive><always_sensitive>true</always_sensitive>"
                + "<extractable>false</extractable><never_extractable>true</never_extractable>"
                + "<attributes><sign>true</sign></attributes>"), hsmKey);
        assertThat(outside.getErrors()).filteredOn(e -> e.startsWith("Key attribute")).hasSize(4);
        assertThat(outside.isValid()).isFalse();

        // <attributes> itself one level too deep.
        SecurosysVerifier.SecurosysAttestationResult nested = verify(attestation(publicKey(hsmKey)
                + "<wrapper>" + SAFE_ATTRIBUTES + "</wrapper>"), hsmKey);
        assertThat(nested.getErrors()).filteredOn(e -> e.startsWith("Key attribute")).hasSize(4);
        assertThat(nested.isValid()).isFalse();
    }

    /** Until 1.7.0 an attestation without {@code <extractable>} passed as {@code extractable=false}. */
    @Test
    void aMissingAttributeCountsAsTheUnsafeValue() throws Exception {
        String[][] cases = {
                {"extractable", "Key attribute extractable must be false"},
                {"never_extractable", "Key attribute never_extractable must be true"},
                {"sensitive", "Key attribute sensitive must be true"},
                {"always_sensitive", "Key attribute always_sensitive must be true"}};
        for (String[] c : cases) {
            String attributes = SAFE_ATTRIBUTES.replaceAll("<" + c[0] + ">[a-z]+</" + c[0] + ">", "");
            assertThat(attributes).as("the attribute is gone").doesNotContain("<" + c[0] + ">");

            SecurosysVerifier.SecurosysAttestationResult r = verify(attestation(publicKey(hsmKey) + attributes),
                    hsmKey);

            assertThat(r.getErrors()).as(c[0]).containsExactly(c[1]);
            assertThat(r.isValid()).as(c[0]).isFalse();
        }
        assertThat(verify(attestation(publicKey(hsmKey)
                + SAFE_ATTRIBUTES.replace("<extractable>false</extractable>", "")), hsmKey).isExtractable())
                .as("reported as extractable, which is the value that refuses").isTrue();
    }

    @Test
    void anAttributeMustBeExactlyTrueOrFalseAndRepeatedOnce() throws Exception {
        for (String value : new String[] {"FALSE", "False", "0", "", "no"}) {
            SecurosysVerifier.SecurosysAttestationResult r = verify(attestation(publicKey(hsmKey)
                    + SAFE_ATTRIBUTES.replace("<extractable>false</extractable>",
                            "<extractable>" + value + "</extractable>")), hsmKey);
            assertThat(r.getErrors()).as("extractable=" + value)
                    .containsExactly("Key attribute extractable must be false");
        }
        for (String value : new String[] {"TRUE", "True", "1", "", "yes"}) {
            SecurosysVerifier.SecurosysAttestationResult r = verify(attestation(publicKey(hsmKey)
                    + SAFE_ATTRIBUTES.replace("<sensitive>true</sensitive>",
                            "<sensitive>" + value + "</sensitive>")), hsmKey);
            assertThat(r.getErrors()).as("sensitive=" + value)
                    .containsExactly("Key attribute sensitive must be true");
        }

        SecurosysVerifier.SecurosysAttestationResult twice = verify(attestation(publicKey(hsmKey)
                + SAFE_ATTRIBUTES.replace("<extractable>false</extractable>",
                        "<extractable>false</extractable><extractable>false</extractable>")), hsmKey);
        assertThat(twice.getErrors()).containsExactly("Key attribute extractable must be false");
    }

    @Test
    void aValueWithMarkupInsideItIsNotRead() throws Exception {
        SecurosysVerifier.SecurosysAttestationResult key = verify(attestation(
                "<public_key>" + b64(hsmKey) + "<x/></public_key>" + SAFE_ATTRIBUTES), hsmKey);
        assertThat(key.getErrors()).containsExactly("Could not extract public_key from XML");

        SecurosysVerifier.SecurosysAttestationResult attribute = verify(attestation(publicKey(hsmKey)
                + SAFE_ATTRIBUTES.replace("<extractable>false</extractable>",
                        "<extractable>false<x/></extractable>")), hsmKey);
        assertThat(attribute.getErrors()).containsExactly("Key attribute extractable must be false");
    }

    @Test
    void thePublicKeyIsReadOnlyAsAChildOfTheRoot() throws Exception {
        SecurosysVerifier.SecurosysAttestationResult r = verify(attestation(
                "<wrapper>" + publicKey(hsmKey) + "</wrapper>" + SAFE_ATTRIBUTES), hsmKey);

        assertThat(r.getErrors()).containsExactly("Could not extract public_key from XML");
        assertThat(r.isValid()).isFalse();
    }

    // ---- nesting depth ---------------------------------------------------------------------

    private static byte[] nested(int depth) {
        return ("<a>".repeat(depth) + "x" + "</a>".repeat(depth)).getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void elementsMayBeNestedToTheLimitAndNotOneLevelDeeper() throws Exception {
        assertThat(SecurosysVerifier.MAX_ELEMENT_DEPTH).isEqualTo(64);
        assertThat(SecurosysVerifier.parseXmlSafely(nested(64)).getDocumentElement().getTextContent()).isEqualTo("x");

        assertThatThrownBy(() -> SecurosysVerifier.parseXmlSafely(nested(65)))
                .isInstanceOf(SAXParseException.class)
                .hasMessageContaining("JAXP00010006");
    }

    /** 49 kB nested 7 000 deep ended in a StackOverflowError on JDK 21, which sets no limit of its own. */
    @Test
    void aDeeplyNestedAttestationIsRefusedNotAStackOverflow() throws Exception {
        String xml = "<private_key creation=\"generated\">" + "<a>".repeat(7_000) + "</a>".repeat(7_000)
                + publicKey(hsmKey) + SAFE_ATTRIBUTES + "</private_key>";

        SecurosysVerifier.SecurosysAttestationResult r = verify(xml, hsmKey);

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).singleElement().asString()
                .startsWith("Verification error: ").contains("JAXP00010006");
    }
}
