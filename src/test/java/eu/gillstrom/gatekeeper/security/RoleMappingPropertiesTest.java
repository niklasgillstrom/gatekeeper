package eu.gillstrom.gatekeeper.security;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RoleMappingPropertiesTest {

    private static RoleMappingProperties.Mapping mapping(String pattern, String... roles) {
        RoleMappingProperties.Mapping mapping = new RoleMappingProperties.Mapping();
        mapping.setCnPattern(pattern);
        mapping.setRoles(List.of(roles));
        return mapping;
    }

    private static RoleMappingProperties properties(List<String> defaults, RoleMappingProperties.Mapping... mappings) {
        RoleMappingProperties properties = new RoleMappingProperties();
        properties.setMappings(List.of(mappings));
        properties.setDefaultRoles(defaults);
        return properties;
    }

    @Test
    void theFirstMatchingMappingWins() {
        RoleMappingProperties properties = properties(List.of("DEFAULT"),
                mapping("^FI-.*$", "SUPERVISOR"),
                mapping("^.*$", "FE"));

        assertThat(properties.resolve("FI-1")).containsExactly("SUPERVISOR");
        assertThat(properties.resolve("Bank AB")).containsExactly("FE");
    }

    @Test
    void anUnmatchedOrAbsentPrincipalGetsTheDefaultRoles() {
        RoleMappingProperties properties = properties(List.of("DEFAULT"), mapping("^FI-.*$", "SUPERVISOR"));

        assertThat(properties.resolve("Bank AB")).containsExactly("DEFAULT");
        assertThat(properties.resolve(null)).containsExactly("DEFAULT");
    }

    @Test
    void theWholePrincipalMustMatch() {
        RoleMappingProperties.Mapping mapping = mapping("FI-[0-9]+", "SUPERVISOR");

        assertThat(mapping.matches("FI-123")).isTrue();
        assertThat(mapping.matches("FI-123 extra")).isFalse();
        assertThat(mapping.matches("xFI-123")).isFalse();
    }

    @Test
    void aMissingOrBlankPatternMatchesNothing() {
        assertThat(mapping(null, "SUPERVISOR").matches("anything")).isFalse();
        assertThat(mapping(" ", "SUPERVISOR").matches("anything")).isFalse();
        assertThat(mapping("", "SUPERVISOR").matches("")).isFalse();
    }
}
