package eu.gillstrom.e2e;

import com.fasterxml.jackson.databind.JsonNode;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.StringJoiner;

final class ReceiptCheck {

    private static final String[] TEXT_FIELDS = {
            "publicKeyFingerprint", "publicKeyAlgorithm", "hsmVendor", "hsmModel", "hsmSerialNumber",
            "supplierIdentifier", "supplierName", "keyPurpose", "countryCode"};

    private static final String[] KEY_PROPERTIES = {
            "generatedOnDevice", "exportable", "attestationChainValid", "publicKeyMatchesAttestation"};

    private static final String[] DORA_BITS = {
            "article5_2b", "article6_10", "article9_3c", "article9_3d", "article9_4d", "article28_1a"};

    private ReceiptCheck() {
    }

    static byte[] canonicalV2(JsonNode receipt) {
        StringJoiner joiner = new StringJoiner("|");
        joiner.add("v2");
        joiner.add(safe(text(receipt, "verificationId")));
        joiner.add(safe(text(receipt, "confirmationNonce")));
        joiner.add(Boolean.toString(receipt.path("compliant").asBoolean(false)));
        joiner.add(instant(receipt.get("verificationTimestamp")));
        for (String field : TEXT_FIELDS) {
            joiner.add(safe(text(receipt, field)));
        }
        appendBooleans(joiner, receipt.get("keyProperties"), KEY_PROPERTIES);
        appendBooleans(joiner, receipt.get("doraCompliance"), DORA_BITS);
        return joiner.toString().getBytes(StandardCharsets.UTF_8);
    }

    static boolean signatureVerifies(JsonNode receipt, X509Certificate trusted) throws Exception {
        String signature = text(receipt, "signature");
        if (signature == null || signature.isBlank()) {
            return false;
        }
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(trusted.getPublicKey());
        verifier.update(canonicalV2(receipt));
        return verifier.verify(Base64.getDecoder().decode(signature));
    }

    private static void appendBooleans(StringJoiner joiner, JsonNode node, String[] fields) {
        for (String field : fields) {
            joiner.add(node == null || node.isNull() ? "" : Boolean.toString(node.path(field).asBoolean(false)));
        }
    }

    private static String instant(JsonNode node) {
        if (node == null || node.isNull()) {
            return "";
        }
        if (node.isNumber()) {
            BigDecimal seconds = node.decimalValue();
            long whole = seconds.longValue();
            int nanos = seconds.subtract(BigDecimal.valueOf(whole)).movePointRight(9).intValue();
            return Instant.ofEpochSecond(whole, nanos).toString();
        }
        return Instant.parse(node.asText()).toString();
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String safe(String value) {
        return value == null ? "" : value.replace("%", "%25").replace("|", "%7C");
    }
}
