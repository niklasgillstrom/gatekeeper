package eu.gillstrom.gatekeeper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * DORA Attestation Gatekeeper.
 *
 * <p>National Competent Authority (NCA) gatekeeper API for HSM attestation
 * verification at certificate issuance under DORA (EU 2022/2554). In Sweden
 * the NCA is Finansinspektionen (FI); in other Member States the NCA is the
 * equivalent financial supervisor.</p>
 *
 * <p>The European Banking Authority (EBA) does not operate this gatekeeper
 * itself — EBA's DORA powers are supervisory-convergence (Article 29 of
 * Regulation (EU) 1093/2010) and breach-of-Union-law investigations
 * (Article 17). EBA receives read-only access to the NCA's approval registry
 * under those articles and can issue recommendations or opinions to the NCA,
 * but the operational verification is performed by the NCA.</p>
 *
 * <p>Implements the 7-step verification flow described in README.md.</p>
 *
 * <p>Run with: {@code --spring.profiles.active=nca}
 * Swagger UI: http://localhost:8080/swagger-ui.html</p>
 *
 * <p>© 2025-2026 Niklas Gillström &lt;https://orcid.org/0009-0001-6485-4596&gt; — MIT Licence</p>
 */
@SpringBootApplication
public class DoraAttestationGatekeeperApplication {

    public static void main(String[] args) {
        SpringApplication.run(DoraAttestationGatekeeperApplication.class, args);
    }
}
