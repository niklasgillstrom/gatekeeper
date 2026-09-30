package eu.gillstrom.e2e;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

final class LocalIssuerCa {

    static final String ALIAS = "e2e-issuer-ca";

    static final String PASSWORD = "e2e-local-only";

    static final String DNAME = "CN=E2E Local Issuer CA,O=e2e-harness,C=SE";

    private final Path dir;
    private final Path keystore;
    private final Path certificatePem;

    private LocalIssuerCa(Path dir) {
        this.dir = dir;
        this.keystore = dir.resolve("issuer-ca.p12");
        this.certificatePem = dir.resolve("issuer-ca-bundle.pem");
    }

    static LocalIssuerCa create(Path dir) throws Exception {
        Files.createDirectories(dir);
        LocalIssuerCa ca = new LocalIssuerCa(dir);
        Files.deleteIfExists(ca.keystore);
        Files.deleteIfExists(ca.certificatePem);
        keytool("-genkeypair",
                "-keystore", ca.keystore.toString(),
                "-storetype", "PKCS12",
                "-storepass", PASSWORD,
                "-keypass", PASSWORD,
                "-alias", ALIAS,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-dname", DNAME,
                "-validity", "2",
                "-ext", "bc:c",
                "-ext", "ku:c=keyCertSign,cRLSign",
                "-noprompt");
        keytool("-exportcert", "-rfc",
                "-keystore", ca.keystore.toString(),
                "-storetype", "PKCS12",
                "-storepass", PASSWORD,
                "-alias", ALIAS,
                "-file", ca.certificatePem.toString());
        return ca;
    }

    Path keystore() {
        return keystore;
    }

    Path bundle() {
        return certificatePem;
    }

    X509Certificate certificate() throws IOException {
        return Pem.certificate(Files.readString(certificatePem, StandardCharsets.UTF_8));
    }

    X509Certificate issue(String name, String csrPem) throws Exception {
        Path csr = dir.resolve(name + ".csr");
        Path leaf = dir.resolve(name + "-leaf.pem");
        Files.writeString(csr, csrPem, StandardCharsets.US_ASCII);
        Files.deleteIfExists(leaf);
        keytool("-gencert", "-rfc",
                "-keystore", keystore.toString(),
                "-storetype", "PKCS12",
                "-storepass", PASSWORD,
                "-alias", ALIAS,
                "-infile", csr.toString(),
                "-outfile", leaf.toString(),
                "-validity", "1",
                "-ext", "bc:c=ca:false",
                "-ext", "ku:c=digitalSignature,nonRepudiation");
        return Pem.certificate(Files.readString(leaf, StandardCharsets.US_ASCII));
    }

    private static void keytool(String... arguments) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(E2eConfig.jdkTool("keytool").toString());
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        byte[] output = process.getInputStream().readAllBytes();
        if (!process.waitFor(120, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("keytool " + arguments[0] + " timed out");
        }
        if (process.exitValue() != 0) {
            throw new IllegalStateException("keytool " + arguments[0] + " failed with exit code "
                    + process.exitValue() + ": " + new String(output, StandardCharsets.UTF_8));
        }
    }
}
