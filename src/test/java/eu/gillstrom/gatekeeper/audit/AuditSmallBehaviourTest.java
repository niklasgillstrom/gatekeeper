package eu.gillstrom.gatekeeper.audit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

class AuditSmallBehaviourTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void theRecordedPrincipalIsTheAuthenticatedNameOrAnonymous() {
        MtlsPrincipalResolver resolver = new MtlsPrincipalResolver();
        assertThat(resolver.currentPrincipal()).isEqualTo("anonymous");

        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("CN=FE-bank", null));
        assertThat(resolver.currentPrincipal()).isEqualTo("CN=FE-bank");

        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(" ", null));
        assertThat(resolver.currentPrincipal()).isEqualTo("anonymous");
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("", null));
        assertThat(resolver.currentPrincipal()).isEqualTo("anonymous");
    }

    @Test
    void aPipeInAFieldCannotShiftTheHashedFields() {
        Instant t = Instant.parse("2026-01-01T00:00:00Z");
        String zero = AuditEntry.SENTINEL_PREV_HASH_HEX;
        String withPipe = new String(AuditEntry.canonicalBytesForHash(1, t, "CN=a|VERIFY", "X", "v", "r", null,
                true, zero), StandardCharsets.UTF_8);
        String shifted = new String(AuditEntry.canonicalBytesForHash(1, t, "CN=a", "VERIFY|X", "v", "r", null,
                true, zero), StandardCharsets.UTF_8);

        assertThat(withPipe).contains("CN=a%7CVERIFY").isNotEqualTo(shifted);
        assertThat(new String(AuditEntry.canonicalBytesForHash(1, t, "100%", "X", "v", "r", null, true, zero),
                StandardCharsets.UTF_8)).contains("100%25");
    }

    @Test
    void theDefaultIntegrityStatusIsAFreshCheck() {
        AuditLog log = mock(AuditLog.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(log.verifyChainIntegrity()).thenReturn(true);

        AuditLog.IntegrityStatus status = log.cachedIntegrityStatus();

        assertThat(status.intact()).isTrue();
        assertThat(status.checkedAt()).isNotNull();
    }
}
