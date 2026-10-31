package eu.gillstrom.gatekeeper.timestamp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Every spelling {@code gatekeeper.timestamping.mode} accepts, and the one it refuses. */
class TimestampingModeTest {

    @Test
    void offHasFourSpellingsAndAnUnsetValue() {
        for (String raw : new String[] {null, "", "  ", "off", "OFF", "false", "none", " None "}) {
            assertThat(AuditTimestamping.Mode.parse(raw)).as(String.valueOf(raw)).isEqualTo(AuditTimestamping.Mode.OFF);
        }
    }

    @Test
    void entryAndAnchorAreReadCaseInsensitively() {
        assertThat(AuditTimestamping.Mode.parse("entry")).isEqualTo(AuditTimestamping.Mode.ENTRY);
        assertThat(AuditTimestamping.Mode.parse(" Entry ")).isEqualTo(AuditTimestamping.Mode.ENTRY);
        assertThat(AuditTimestamping.Mode.parse("anchor")).isEqualTo(AuditTimestamping.Mode.ANCHOR);
        assertThat(AuditTimestamping.Mode.parse("ANCHOR")).isEqualTo(AuditTimestamping.Mode.ANCHOR);
    }

    @Test
    void anythingElseStopsStartUp() {
        assertThatThrownBy(() -> AuditTimestamping.Mode.parse("on"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("gatekeeper.timestamping.mode must be off, entry or anchor, got 'on'");
    }
}
