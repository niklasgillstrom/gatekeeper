package eu.gillstrom.gatekeeper.security;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

import java.security.cert.X509Certificate;
import java.util.Locale;

/**
 * Takes the request principal from one attribute of the client certificate's
 * subject, read from the encoded name rather than from its string rendering.
 *
 * <p>The earlier extractor ran a regular expression ({@code CN=(.*?)(?:,|$)})
 * over the RFC 2253 string. That stopped at an escaped comma, so the subjects
 * {@code CN=Acme AB\, Stockholm} and {@code CN=Acme AB\, Malmo} both became
 * the principal {@code Acme AB\} and shared one identity for confirm binding,
 * rate limiting and the audit log; it fell back to the whole DN when the
 * attribute was missing; and it could not read SERIALNUMBER at all, because
 * {@code X500Principal.getName()} renders that attribute as
 * {@code 2.5.4.5=#13..} hex.</p>
 *
 * <p>The principal is the attribute's exact string value. A subject in which
 * the attribute is missing, appears more than once, or is part of a
 * multi-valued RDN yields no principal, and the request is not
 * authenticated.</p>
 */
public final class SubjectAttributePrincipalExtractor implements X509PrincipalExtractor {

    private final ASN1ObjectIdentifier attribute;

    /**
     * @param attribute {@code CN}, {@code SERIALNUMBER}, any other BC-style
     *                  attribute name, or a dotted OID such as {@code 2.5.4.5}
     */
    public SubjectAttributePrincipalExtractor(String attribute) {
        if (attribute == null || attribute.isBlank()) {
            throw new IllegalArgumentException("principal attribute must be named");
        }
        String a = attribute.trim();
        this.attribute = Character.isDigit(a.charAt(0))
                ? new ASN1ObjectIdentifier(a)
                : BCStyle.INSTANCE.attrNameToOID(a.toLowerCase(Locale.ROOT));
    }

    @Override
    public Object extractPrincipal(X509Certificate cert) {
        X500Name subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        RDN[] rdns = subject.getRDNs(attribute);
        if (rdns.length != 1 || rdns[0].isMultiValued()) {
            return null;
        }
        ASN1Encodable value = rdns[0].getFirst().getValue();
        if (!(value instanceof ASN1String s)) {
            return null;
        }
        String principal = s.getString();
        return principal.isEmpty() ? null : principal;
    }
}
