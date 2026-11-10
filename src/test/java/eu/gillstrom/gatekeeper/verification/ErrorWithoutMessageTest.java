package eu.gillstrom.gatekeeper.verification;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import javax.security.auth.x500.X500Principal;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Three helper methods answer {@code null} for "no error" and a description
 * otherwise. Until 1.7.0 the description of a caught exception was its
 * message, so an exception without one — which the JDK and BouncyCastle do
 * throw — read as "no error": a statement that did not verify, an authority
 * whose extensions could not be parsed or an expired certificate would have
 * passed. The description is now the exception itself, which is never null.
 */
class ErrorWithoutMessageTest {

    private static final X500Principal AUTHORITY = new X500Principal("CN=Key Attestation Authority");

    @Test
    void aFortanixStatementThatFailsWithoutAMessageIsStillAnError() throws Exception {
        X509Certificate authority = mock(X509Certificate.class);
        when(authority.getSubjectX500Principal()).thenReturn(AUTHORITY);
        X509Certificate statement = mock(X509Certificate.class);
        when(statement.getIssuerX500Principal()).thenReturn(AUTHORITY);
        doThrow(new SignatureException()).when(statement).verify(any());

        String error = ReflectionTestUtils.invokeMethod(FortanixVerifier.class, "statementError",
                statement, authority, new Date());

        assertThat(error).isEqualTo("java.security.SignatureException");
    }

    @Test
    void aFortanixAuthorityThatFailsWithoutAMessageIsStillAnError() throws Exception {
        X509Certificate authority = mock(X509Certificate.class);
        when(authority.getExtendedKeyUsage()).thenThrow(new CertificateParsingException());

        String error = ReflectionTestUtils.invokeMethod(new FortanixVerifier(), "authorityError",
                authority, List.of(), new Date());

        assertThat(error).isEqualTo("java.security.cert.CertificateParsingException");
    }

    @Test
    void aCrypto4AChainThatFailsWithoutAMessageIsStillAnError() throws Exception {
        X509Certificate signer = mock(X509Certificate.class);
        doThrow(new CertificateExpiredException()).when(signer).checkValidity();

        String error = ReflectionTestUtils.invokeMethod(new Crypto4AVerifier(), "chainError", signer, List.of());

        assertThat(error).isEqualTo("java.security.cert.CertificateExpiredException");
    }

    @Test
    void aMessageIsKeptWhenThereIsOne() throws Exception {
        X509Certificate signer = mock(X509Certificate.class);
        doThrow(new CertificateExpiredException("NotAfter: 2020")).when(signer).checkValidity();

        String error = ReflectionTestUtils.invokeMethod(new Crypto4AVerifier(), "chainError", signer, List.of());

        assertThat(error).isEqualTo("java.security.cert.CertificateExpiredException: NotAfter: 2020");
    }
}
