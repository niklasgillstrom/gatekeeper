package eu.gillstrom.gatekeeper.signing;

import eu.gillstrom.gatekeeper.model.TriangulationReport;
import eu.gillstrom.gatekeeper.model.TriangulationReport.CertificateWithoutVerifiedAttestation;
import eu.gillstrom.gatekeeper.model.TriangulationReport.InputDigest;
import eu.gillstrom.gatekeeper.model.TriangulationReport.InputDigests;
import eu.gillstrom.gatekeeper.model.TriangulationReport.OrganisationNumberMismatch;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SourcedOrganisationNumber;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SwishMissingFromBanks;
import eu.gillstrom.gatekeeper.model.TriangulationReport.SwishMissingFromOperator;
import eu.gillstrom.gatekeeper.model.TriangulationReport.VerifiedCertificateNotReported;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Pins the {@code tr1} report form and the input forms of {@link TriangulationCanonicalizer}. */
class TriangulationCanonicalizerTest {

    private static TriangulationReport report(InputDigest operator) {
        return new TriangulationReport("tr1", "inq-1", "SE", "2026-10-30T12:00:00Z",
                new InputDigests(List.of(new InputDigest("bank,2", 1, "bb"), new InputDigest("bank-1", 2, "aa")),
                        operator, new InputDigest(null, 4, "dd")),
                List.of(new SwishMissingFromOperator("1232222222", List.of("bank-1", "bank=2"))),
                List.of(new SwishMissingFromBanks("1234444444"), new SwishMissingFromBanks("1230000000")),
                List.of(new CertificateWithoutVerifiedAttestation("c3", "CN=A,O=B", "REVOKED", "VID-C",
                        List.of("1233333333"))),
                List.of(new VerifiedCertificateNotReported("b2", "CN=A", "VID-B")),
                List.of(new OrganisationNumberMismatch("1231111111", List.of(
                        new SourcedOrganisationNumber("bank:bank-1", "5560000001"),
                        new SourcedOrganisationNumber("operator:op-1", "5560000009")))),
                6, false, "ff", "IGNORED-SIGNATURE", "IGNORED-ALG", "IGNORED-AUDIT-HASH");
    }

    @Test
    void theReportFormIsExactlyThis() {
        String expected = """
                tr1|inq-1|SE|2026-10-30T12:00:00Z|ff
                in|bank|bank%2C2|1|bb
                in|bank|bank-1|2|aa
                in|operator|op%7C1|3|cc
                in|registry|4|dd
                d|SWISH_MISSING_FROM_OPERATOR|1232222222|bank-1,bank%3D2
                d|SWISH_MISSING_FROM_BANKS|1230000000
                d|SWISH_MISSING_FROM_BANKS|1234444444
                d|CERT_WITHOUT_VERIFIED_ATTESTATION|c3|CN%3DA%2CO%3DB|REVOKED|VID-C|1233333333
                d|VERIFIED_CERT_NOT_REPORTED|b2|CN%3DA|VID-B
                d|ORG_NUMBER_MISMATCH|1231111111|bank:bank-1=5560000001,operator:op-1=5560000009
                total|6
                """;

        byte[] actual = TriangulationCanonicalizer.canonicalize(report(new InputDigest("op|1", 3, "cc")));

        assertThat(new String(actual, StandardCharsets.UTF_8)).isEqualTo(expected);
    }

    @Test
    void anAbsentOperatorReportHasAnEmptyLine() {
        assertThat(new String(TriangulationCanonicalizer.canonicalize(report(null)), StandardCharsets.UTF_8))
                .contains("\nin|operator||0|\nin|registry|4|dd\n");
    }

    @Test
    void theSealAndTheAuditLinkAreNotPartOfTheForm() {
        TriangulationReport r = report(null);
        assertThat(TriangulationCanonicalizer.canonicalize(r))
                .isEqualTo(TriangulationCanonicalizer.canonicalize(r.sealed(null, null, null)));
    }

    @Test
    void theInputFormsAreAHeaderAndSortedLines() {
        String bank = new String(TriangulationCanonicalizer.inputBytes(
                TriangulationCanonicalizer.bankHeader("bank|1"),
                List.of(TriangulationCanonicalizer.bankEntryLine("5569743098", "1231015932", "ab", "CN=X,C=SE"),
                        TriangulationCanonicalizer.bankEntryLine("5560000001", "1230000001", null, null))),
                StandardCharsets.UTF_8);
        assertThat(bank).isEqualTo("tri-bank-v1|bank%7C1\n"
                + "5560000001|1230000001||\n"
                + "5569743098|1231015932|ab|CN%3DX%2CC%3DSE\n");

        assertThat(new String(TriangulationCanonicalizer.inputBytes(
                TriangulationCanonicalizer.operatorHeader("op"),
                List.of(TriangulationCanonicalizer.operatorEntryLine("1231015932", null, "ab", "CN=X"))),
                StandardCharsets.UTF_8))
                .isEqualTo("tri-operator-v1|op\n1231015932||ab|CN%3DX\n");

        assertThat(new String(TriangulationCanonicalizer.inputBytes(
                TriangulationCanonicalizer.registryHeader("SE"),
                List.of(TriangulationCanonicalizer.registryEntryLine("ab", "CN=X", "REVOKED", "V"))),
                StandardCharsets.UTF_8))
                .isEqualTo("tri-registry-v1|SE\nab|CN%3DX|REVOKED|V\n");

        assertThat(new String(TriangulationCanonicalizer.inputsCommitment("inq", "SE",
                report(null).inputDigests()), StandardCharsets.UTF_8))
                .isEqualTo("tri-inputs-v1|inq|SE\nin|bank|bank%2C2|1|bb\nin|bank|bank-1|2|aa\n"
                        + "in|operator||0|\nin|registry|4|dd\n");
    }

    @Test
    void everySeparatorIsEscaped() {
        assertThat(TriangulationCanonicalizer.escape("%|,=\n\r")).isEqualTo("%25%7C%2C%3D%0A%0D");
        assertThat(TriangulationCanonicalizer.escape(null)).isEmpty();
    }
}
