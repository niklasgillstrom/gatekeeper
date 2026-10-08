package eu.gillstrom.gatekeeper.security;

import eu.gillstrom.gatekeeper.testsupport.TestPki;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SubjectAttributePrincipalExtractorTest {

    private static KeyPair kp;

    @BeforeAll
    static void keys() throws Exception {
        kp = TestPki.newRsaKeyPair(2048);
    }

    @Test
    @DisplayName("A CN containing a comma is taken whole, so two such CNs stay distinct")
    void cnWithCommaIsTakenWhole() throws Exception {
        SubjectAttributePrincipalExtractor cn = new SubjectAttributePrincipalExtractor("CN");

        Object stockholm = cn.extractPrincipal(cert(new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "Acme AB, Stockholm").addRDN(BCStyle.O, "Acme").build()));
        Object malmo = cn.extractPrincipal(cert(new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "Acme AB, Malmo").addRDN(BCStyle.O, "Acme").build()));

        assertThat(stockholm).isEqualTo("Acme AB, Stockholm");
        assertThat(malmo).isEqualTo("Acme AB, Malmo");
    }

    @Test
    @DisplayName("SERIALNUMBER is read as its value, by name or by OID")
    void serialNumberIsReadAsItsValue() throws Exception {
        X509Certificate c = cert(new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "Bank AB").addRDN(BCStyle.SERIALNUMBER, "556677-8899")
                .addRDN(BCStyle.C, "SE").build());

        assertThat(new SubjectAttributePrincipalExtractor("SERIALNUMBER").extractPrincipal(c))
                .isEqualTo("556677-8899");
        assertThat(new SubjectAttributePrincipalExtractor("2.5.4.5").extractPrincipal(c))
                .isEqualTo("556677-8899");
    }

    @Test
    @DisplayName("A subject without the attribute yields no principal, not the whole DN")
    void missingAttributeYieldsNoPrincipal() throws Exception {
        X509Certificate c = cert(new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.O, "Evil").addRDN(BCStyle.OU, "x-FE").build());

        assertThat(new SubjectAttributePrincipalExtractor("CN").extractPrincipal(c)).isNull();
    }

    @Test
    @DisplayName("A repeated attribute yields no principal")
    void repeatedAttributeYieldsNoPrincipal() throws Exception {
        X509Certificate c = cert(new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "FE-Bank").addRDN(BCStyle.CN, "NCA-evil").build());

        assertThat(new SubjectAttributePrincipalExtractor("CN").extractPrincipal(c)).isNull();
    }

    @Test
    @DisplayName("The removed principal-regex property fails start-up instead of being ignored")
    void legacyRegexPropertyFailsStartup() {
        assertThatThrownBy(() -> new SecurityConfig().mtlsFilterChain(
                null, new RoleMappingProperties(), "CN", "SERIALNUMBER=(.*?)(?:,|$)"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("principal-attribute");
    }

    private static X509Certificate cert(X500Name subject) throws Exception {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                new Date(now - 60_000L), new Date(now + 3600_000L), subject, kp.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }
}
