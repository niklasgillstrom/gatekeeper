package eu.gillstrom.e2e;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

final class E2eConfig {

    static final String VERSION = "1.5.0";

    static final Path BASE_DIR = Path.of(System.getProperty("basedir", System.getProperty("user.dir")))
            .toAbsolutePath().normalize();

    static final Path GATEKEEPER_DIR = BASE_DIR.getParent();

    static final Path REPOS_DIR = System.getProperty("e2e.reposDir") == null
            ? GATEKEEPER_DIR.getParent()
            : BASE_DIR.resolve(System.getProperty("e2e.reposDir")).normalize();

    static final Path TARGET_DIR = BASE_DIR.resolve("target");

    static final Path LOG_DIR = TARGET_DIR.resolve("e2e-logs");

    static final Path WORK_DIR = TARGET_DIR.resolve("e2e-work");

    static final Path PID_FILE = LOG_DIR.resolve("pids");

    private E2eConfig() {
    }

    static Path jar(String service) {
        return repoDir(service).resolve("target").resolve(service + "-" + VERSION + ".jar");
    }

    static Path repoDir(String service) {
        return "gatekeeper".equals(service) ? GATEKEEPER_DIR : REPOS_DIR.resolve(service);
    }

    static Path fixtureDir(String vendor) {
        return repoDir("hsm").resolve("examples").resolve(vendor);
    }

    static Path jdkTool(String tool) {
        String home = System.getProperty("e2e.javaHome", System.getProperty("java.home"));
        return Path.of(home).resolve("bin").resolve(tool);
    }

    static String property(String key) {
        String value = System.getProperty(key);
        return value == null || value.isBlank() ? null : value.trim();
    }

    static Duration startupTimeout() {
        String value = property("e2e.startupTimeoutSeconds");
        return Duration.ofSeconds(value == null ? 180 : Long.parseLong(value));
    }

    static List<String> extraArgs(String service) {
        String value = property("e2e." + service + ".extraArgs");
        if (value == null) {
            return List.of();
        }
        return Arrays.stream(value.split("\\s+")).filter(s -> !s.isBlank()).toList();
    }
}
