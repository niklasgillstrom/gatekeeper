package eu.gillstrom.gatekeeper.audit;

/**
 * Unchecked exception raised when the gatekeeper's tamper-evident audit log
 * cannot be appended to or its persistence layer is otherwise unavailable.
 *
 * <p>The audit log is legal evidence under DORA Article 28(6) (5-year
 * retention obligation) and EBA Regulation (EU) 1093/2010 Article 35
 * (cooperation with competent authorities). A failure to append MUST be
 * surfaced loudly: callers MUST treat an {@code AuditLogException} as a
 * supervisory-grade incident and not silently swallow it. Wrapping the
 * cause in a {@code RuntimeException} keeps the failure on the call path
 * without forcing every {@code verify()} / {@code confirm()} signature to
 * declare a checked exception.</p>
 */
public class AuditLogException extends RuntimeException {

    public AuditLogException(String message) {
        super(message);
    }

    public AuditLogException(String message, Throwable cause) {
        super(message, cause);
    }
}
