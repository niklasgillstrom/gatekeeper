package eu.gillstrom.gatekeeper;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.gatekeeper.audit.AuditAppendRequest;
import eu.gillstrom.gatekeeper.audit.AuditLog;
import eu.gillstrom.gatekeeper.timestamp.AuditTimestamping;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * In the default profile, with none of the new features configured, the
 * existing gatekeeper endpoints answer with exactly the fields they had in
 * 1.6.0, through the application's own message converters. The audit
 * endpoints, which serialise {@code AuditEntry}, now carry the v2 fields.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = {
        "gatekeeper.audit.path=${java.io.tmpdir}/gatekeeper-evidence-output-test/${random.uuid}/audit-log.jsonl",
        "gatekeeper.registry.path=${java.io.tmpdir}/gatekeeper-evidence-output-test/approval-registry.jsonl"
})
class DefaultProfileEvidenceOutputTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private AuditLog auditLog;

    @Autowired
    private AuditTimestamping timestamping;

    private final ObjectMapper json = new ObjectMapper();

    private static Set<String> fields(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return Set.copyOf(names);
    }

    private JsonNode getJson(MockMvc mvc, String path) throws Exception {
        return json.readTree(mvc.perform(get(path)).andReturn().getResponse().getContentAsString());
    }

    @Test
    void existingEndpointsKeepTheirFieldsAndAuditEntriesShowTheV2Fields() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();
        assertThat(timestamping.mode()).isEqualTo(AuditTimestamping.Mode.OFF);
        assertThat(timestamping.anchorStore()).as("no anchor file is read or created").isEmpty();

        JsonNode emptyAnchor = getJson(mvc, "/v1/gatekeeper/anchor");
        assertThat(fields(emptyAnchor)).isEqualTo(Set.of("headSequenceNumber", "headHashHex", "headTimestamp",
                "headSignatureBase64", "signingKeyFingerprintHex", "totalEntries"));

        auditLog.append(new AuditAppendRequest("CN=fe", "VERIFY", "v-out", "cmVx", null, true)
                .withKeyFingerprintHex("ab:cd"));

        assertThat(fields(getJson(mvc, "/v1/gatekeeper/keys").get(0))).isEqualTo(Set.of("keyId", "certificatePem",
                "publicKeyFingerprintHex", "validFrom", "validTo", "algorithm", "status"));
        assertThat(fields(getJson(mvc, "/v1/gatekeeper/anchor"))).isEqualTo(fields(emptyAnchor));
        assertThat(fields(getJson(mvc, "/v1/gatekeeper/health"))).isEqualTo(Set.of("auditLogReadable",
                "chainIntact", "chainCheckedAt", "headSequenceNumber", "headTimestamp", "totalEntries",
                "activeKeyFingerprint", "mode"));

        JsonNode list = getJson(mvc, "/v1/gatekeeper/anchor/timestamps");
        assertThat(list.get("timestampingMode").asText()).isEqualTo("off");
        assertThat(list.get("total").asLong()).isZero();

        JsonNode witness = getJson(mvc, "/v1/audit/witness/v-out");
        assertThat(fields(witness)).isEqualTo(Set.of("sequenceNumber", "timestamp", "mtlsClientPrincipal",
                "operation", "verificationId", "requestDigestBase64", "receiptDigestBase64", "compliant",
                "prevEntryHashHex", "thisEntryHashHex", "entrySignatureBase64",
                "canonicalVersion", "keyFingerprintHex", "certSerialHex", "certIssuerDn", "hsmVendor", "hsmSerial",
                "registryStatus", "hsmFirmwareVersion", "hsmFipsApprovedMode", "prevKeyEntryHashHex",
                "timestampTokenBase64"));
        assertThat(witness.get("canonicalVersion").asText()).isEqualTo("v2");
        assertThat(witness.get("keyFingerprintHex").asText()).isEqualTo("ab:cd");
        assertThat(witness.get("prevKeyEntryHashHex").asText()).isEqualTo("0".repeat(64));
    }
}
