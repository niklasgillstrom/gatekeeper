package eu.gillstrom.e2e;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

final class ServiceProcess implements AutoCloseable {

    private static final List<String> STRIPPED_ENVIRONMENT = List.of(
            "SPRING_PROFILES_ACTIVE",
            "SPRING_APPLICATION_JSON",
            "SPRING_CONFIG_LOCATION",
            "SPRING_CONFIG_ADDITIONAL_LOCATION",
            "SPRING_CONFIG_IMPORT");

    private final String name;
    private final Process process;
    private final Path logFile;
    private final URI baseUri;

    private ServiceProcess(String name, Process process, Path logFile, URI baseUri) {
        this.name = name;
        this.process = process;
        this.logFile = logFile;
        this.baseUri = baseUri;
    }

    static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }

    static ServiceProcess start(String name, int port, List<String> arguments) throws IOException {
        Path jar = E2eConfig.jar(name);
        Path workDir = E2eConfig.WORK_DIR.resolve(name);
        Files.createDirectories(workDir);
        Files.createDirectories(E2eConfig.LOG_DIR);

        List<String> command = new ArrayList<>();
        command.add(E2eConfig.jdkTool("java").toString());
        command.add("-jar");
        command.add(jar.toString());
        command.add("--server.port=" + port);
        command.add("--server.address=127.0.0.1");
        command.addAll(arguments);
        command.addAll(E2eConfig.extraArgs(name));

        Path logFile = E2eConfig.LOG_DIR.resolve(name + ".log");
        Files.writeString(logFile, "# e2e command: " + String.join(" ", printable(command)) + System.lineSeparator()
                + "# e2e working directory: " + workDir + System.lineSeparator(), StandardCharsets.UTF_8);

        ProcessBuilder builder = new ProcessBuilder(command)
                .directory(workDir.toFile())
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(logFile.toFile()));
        STRIPPED_ENVIRONMENT.forEach(builder.environment()::remove);

        Process process = builder.start();
        Files.writeString(E2eConfig.PID_FILE, process.pid() + " " + jar + System.lineSeparator(),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        return new ServiceProcess(name, process, logFile, URI.create("http://127.0.0.1:" + port));
    }

    URI uri(String path) {
        return baseUri.resolve(path);
    }

    URI baseUri() {
        return baseUri;
    }

    Path logFile() {
        return logFile;
    }

    String log() throws IOException {
        return Files.readString(logFile, StandardCharsets.UTF_8);
    }

    void awaitReady(String healthPath, String authorization) throws Exception {
        URI health = uri(healthPath);
        Duration timeout = E2eConfig.startupTimeout();
        Instant deadline = Instant.now().plus(timeout);
        String lastProblem = "no attempt made";
        while (Instant.now().isBefore(deadline)) {
            if (!process.isAlive()) {
                throw new IllegalStateException(name + " exited with code " + process.exitValue()
                        + " before " + health + " answered. Log: " + logFile + System.lineSeparator() + tail(40));
            }
            try {
                Http.Response response = Http.get(health, authorization);
                if (response.status() == 200) {
                    return;
                }
                String body = response.body() == null ? "" : response.body();
                lastProblem = "HTTP " + response.status() + ": " + body.substring(0, Math.min(300, body.length()));
            } catch (IOException e) {
                lastProblem = e.toString();
            }
            Thread.sleep(500);
        }
        throw new IllegalStateException(name + " did not answer 200 on " + health + " within " + timeout
                + " (last: " + lastProblem + "). Log: " + logFile + System.lineSeparator() + tail(40));
    }

    String tail(int lines) {
        try {
            List<String> all = Files.readAllLines(logFile, StandardCharsets.UTF_8);
            return String.join(System.lineSeparator(), all.subList(Math.max(0, all.size() - lines), all.size()));
        } catch (IOException e) {
            return "(log unreadable: " + e + ")";
        }
    }

    @Override
    public void close() {
        ProcessHandle handle = process.toHandle();
        List<ProcessHandle> descendants = handle.descendants().toList();
        if (process.isAlive()) {
            process.destroy();
            try {
                if (!process.waitFor(20, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    process.waitFor(10, TimeUnit.SECONDS);
                }
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
        descendants.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
    }

    private static List<String> printable(List<String> command) {
        List<String> out = new ArrayList<>(command.size());
        for (String argument : command) {
            int eq = argument.indexOf('=');
            if (eq > 0 && argument.contains("\n")) {
                out.add(argument.substring(0, eq + 1) + "<multi-line value, " + (argument.length() - eq - 1) + " chars>");
            } else if (eq > 0 && argument.substring(0, eq).toLowerCase().contains("password")) {
                out.add(argument.substring(0, eq + 1) + "***");
            } else {
                out.add(argument);
            }
        }
        return out;
    }
}
