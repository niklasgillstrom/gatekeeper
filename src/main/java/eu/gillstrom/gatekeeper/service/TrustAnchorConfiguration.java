package eu.gillstrom.gatekeeper.service;

import eu.gillstrom.gatekeeper.verification.TrustAnchors;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.util.Map;

/**
 * Binds {@code gatekeeper.trust-anchors.<key>} to the {@link TrustAnchors} the
 * vendor verifiers start from.
 *
 * <p>Each key ({@code yubico}, {@code securosys}, {@code marvell},
 * {@code google-owner}, {@code thales}, {@code crypto4a}, {@code fortanix},
 * {@code entrust}) optionally names a PEM file that replaces the pinned
 * anchor, so that the supervisory authority can verify against the
 * manufacturer roots it obtained from the manufacturers itself. Unset or empty
 * keeps the pinned anchor. A named file that {@link TrustAnchors#load}
 * refuses, or an unknown key, makes this bean, and so the application, fail
 * to start.</p>
 *
 * <p>The binding lives here, outside the verification package, so that the
 * verifier classes stay identical in gatekeeper and hsm; only the prefix
 * differs.</p>
 */
@Configuration(proxyBeanMethods = false)
public class TrustAnchorConfiguration {

    /** Property prefix of the per-vendor trust-anchor files. */
    public static final String PREFIX = "gatekeeper.trust-anchors";

    @Bean
    public TrustAnchors trustAnchors(Environment environment) {
        Map<String, String> paths = Binder.get(environment)
                .bind(PREFIX, Bindable.mapOf(String.class, String.class))
                .orElseGet(Map::of);
        return TrustAnchors.load(paths, PREFIX);
    }
}
