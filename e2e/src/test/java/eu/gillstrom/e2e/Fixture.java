package eu.gillstrom.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

record Fixture(
        String vendor,
        String hsmVendor,
        String csrPem,
        String attestationData,
        String attestationSignature,
        List<String> attestationCertChain,
        String expectedFingerprint,
        String expectedVendorName) {

    static final String ORGANISATION_NUMBER = "5569743098";

    static final String SWISH_NUMBER = "1231015932";

    static Fixture load(String vendor) throws IOException {
        Path dir = E2eConfig.fixtureDir(vendor);
        JsonNode request = Http.JSON.readTree(dir.resolve("request.json").toFile());
        JsonNode expected = Http.JSON.readTree(dir.resolve("expected.json").toFile());
        List<String> chain = new ArrayList<>();
        request.path("attestationCertChain").forEach(node -> chain.add(node.asText()));
        return new Fixture(
                vendor,
                request.path("hsmVendor").asText(),
                request.path("csr").asText(),
                textOrNull(request, "attestationData"),
                textOrNull(request, "attestationSignature"),
                List.copyOf(chain),
                expected.path("csrPublicKeyFingerprint").asText(),
                expected.path("hsmVendor").asText());
    }

    String bankIdBinding() {
        return "hsm-csr:v1;org=" + ORGANISATION_NUMBER
                + ";swish=" + SWISH_NUMBER
                + ";csr-sha256=" + HexFormat.of().formatHex(Pem.sha256(Pem.csrDer(csrPem)));
    }

    ObjectNode gatekeeperVerifyRequest() {
        ObjectNode node = Http.JSON.createObjectNode();
        node.put("publicKey", csrPem);
        node.put("hsmVendor", hsmVendor);
        putAttestation(node);
        node.put("supplierIdentifier", ORGANISATION_NUMBER);
        node.put("supplierName", "e2e harness (gatekeeper-direct)");
        node.put("keyPurpose", "Swish SIGNING");
        return node;
    }

    ObjectNode hsmCertificateRequest(String bankIdSignature, String bankIdOcsp) {
        ObjectNode node = Http.JSON.createObjectNode();
        node.put("csr", csrPem);
        node.put("bankIdSignatureResponse", bankIdSignature);
        node.put("bankIdOcspResponse", bankIdOcsp);
        node.put("organisationNumber", ORGANISATION_NUMBER);
        node.put("swishNumber", SWISH_NUMBER);
        node.put("certificateType", "SIGNING");
        node.put("hsmVendor", hsmVendor);
        putAttestation(node);
        return node;
    }

    private void putAttestation(ObjectNode node) {
        if (attestationData != null) {
            node.put("attestationData", attestationData);
        }
        if (attestationSignature != null) {
            node.put("attestationSignature", attestationSignature);
        }
        ArrayNode chain = node.putArray("attestationCertChain");
        attestationCertChain.forEach(chain::add);
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }
}
