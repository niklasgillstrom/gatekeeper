package eu.gillstrom.gatekeeper.audit;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The v2 canonical form of {@link AuditEntry} and the v2 fields of {@link AuditAppendRequest}. */
class AuditEntryV2Test {

    private static final Instant T = Instant.parse("2026-10-30T12:00:00.123456789Z");
    private static final String ZERO = AuditEntry.SENTINEL_PREV_HASH_HEX;
    private static final String A = "aa".repeat(32);
    private static final String B = "bb".repeat(32);

    @Test
    void theV2CanonicalFormHasTheDocumentedFieldOrder() {
        String bytes = new String(AuditEntry.canonicalBytesForHashV2(7, T, "CN=fe", "CONFIRM", "vid",
                "req=", "rcpt=", true, A, "ab:cd", "1f", "CN=Issuer,O=X", "Yubico", "12345678",
                "VERIFIED_AND_ISSUED", "2.4.0", "true", B), StandardCharsets.UTF_8);

        assertThat(bytes).isEqualTo("v2|7|2026-10-30T12:00:00.123456789Z|CN=fe|CONFIRM|vid|req=|rcpt=|true|"
                + A + "|ab:cd|1f|CN=Issuer,O=X|Yubico|12345678|VERIFIED_AND_ISSUED|2.4.0|true|" + B);
    }

    @Test
    void everyNullIsTheNullMarkerIncludingTheReceiptDigest() {
        String bytes = new String(AuditEntry.canonicalBytesForHashV2(1, T, "p", "VERIFY", "v", "r", null,
                false, ZERO, null, null, null, null, null, null, null, null, null), StandardCharsets.UTF_8);

        assertThat(bytes).isEqualTo("v2|1|" + T + "|p|VERIFY|v|r|%N|false|" + ZERO
                + "|%N|%N|%N|%N|%N|%N|%N|%N|%N");
    }

    @Test
    void noValueCanEncodeToTheNullMarker() {
        // '%' is escaped to %25, so the literal marker, an empty string and
        // null all encode differently; '|' cannot shift a field.
        String literal = new String(AuditEntry.canonicalBytesForHashV2(1, T, "p", "VERIFY", "v", "r", null,
                false, ZERO, "%N", "", null, "a|b", null, null, null, null, null), StandardCharsets.UTF_8);

        assertThat(literal).contains("|%25N||%N|a%7Cb|");
    }

    @Test
    void anEntryIsHashedInTheFormItsVersionNames() {
        AuditEntry v1 = new AuditEntry(1, T, "p", "VERIFY", "v", "r", null, true, ZERO, A, "c2ln");
        AuditEntry v2 = new AuditEntry(1, T, "p", "VERIFY", "v", "r", null, true, ZERO, A, "c2ln",
                "v2", null, null, null, null, null, null, null, null, null, null);

        assertThat(AuditEntry.canonicalBytesForHash(v1))
                .isEqualTo(AuditEntry.canonicalBytesForHash(1, T, "p", "VERIFY", "v", "r", null, true, ZERO));
        assertThat(new String(AuditEntry.canonicalBytesForHash(v2), StandardCharsets.UTF_8)).startsWith("v2|");
        assertThat(v1.isV2()).isFalse();
        assertThat(v2.isV2()).isTrue();
    }

    @Test
    void anUnknownVersionCannotBeHashed() {
        AuditEntry v3 = new AuditEntry(1, T, "p", "VERIFY", "v", "r", null, true, ZERO, A, "c2ln",
                "v3", null, null, null, null, null, null, null, null, null, null);

        assertThatThrownBy(() -> AuditEntry.canonicalBytesForHash(v3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("v3");
    }

    @Test
    void theSixArgumentRequestHasNoInventoryAndTheWithersSetOneGroupEach() {
        AuditAppendRequest base = new AuditAppendRequest("p", "VERIFY", "v", "r", null, true);
        assertThat(base.keyFingerprintHex()).isNull();
        assertThat(base.certSerialHex()).isNull();
        assertThat(base.hsmFipsApprovedMode()).isNull();

        AuditAppendRequest full = base.withKeyFingerprintHex("ab:cd")
                .withCertificate("1f", "CN=I")
                .withHsm("Yubico", "123")
                .withRegistryStatus("VERIFIED_AND_ISSUED")
                .withHsmFirmware("2.4.0", "false");

        assertThat(full).isEqualTo(new AuditAppendRequest("p", "VERIFY", "v", "r", null, true,
                "ab:cd", "1f", "CN=I", "Yubico", "123", "VERIFIED_AND_ISSUED", "2.4.0", "false"));
    }

    @Test
    void aBlankKeyFingerprintOrAnUnknownFipsValueIsRefused() {
        AuditAppendRequest base = new AuditAppendRequest("p", "VERIFY", "v", "r", null, true);

        assertThatThrownBy(() -> base.withKeyFingerprintHex(" ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> base.withHsmFirmware("1", "yes")).isInstanceOf(IllegalArgumentException.class);
        assertThat(base.withHsmFirmware(null, "true").hsmFipsApprovedMode()).isEqualTo("true");
    }
}
