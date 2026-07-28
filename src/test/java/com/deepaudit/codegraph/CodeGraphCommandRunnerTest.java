package com.deepaudit.codegraph;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CodeGraphCommandRunnerTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void capturesBoundedProcessOutput() {
        CodeGraphProperties properties = properties();
        CodeGraphCommandRunner runner = new CodeGraphCommandRunner(properties);

        CodeGraphCommandRunner.CommandOutput output = runner.run(temporaryDirectory,
                helper("echo"), Map.of("DO_NOT_TRACK", "1"));

        assertThat(output.exitCode()).isZero();
        assertThat(output.stdout()).contains("{\"ok\":true}");
    }

    @Test
    void rejectsOutputBeyondConfiguredLimit() {
        CodeGraphProperties properties = properties();
        properties.setMaxOutputBytes(1_024);
        CodeGraphCommandRunner runner = new CodeGraphCommandRunner(properties);

        assertThatThrownBy(() -> runner.run(temporaryDirectory, helper("overflow"), Map.of()))
                .isInstanceOf(CodeGraphException.class)
                .hasMessageContaining("输出超过安全上限");
    }

    @Test
    void terminatesCommandsThatExceedTimeout() {
        CodeGraphProperties properties = properties();
        properties.setTimeoutSeconds(1);
        CodeGraphCommandRunner runner = new CodeGraphCommandRunner(properties);

        assertThatThrownBy(() -> runner.run(temporaryDirectory, helper("sleep"), Map.of()))
                .isInstanceOf(CodeGraphException.class)
                .hasMessageContaining("执行超时");
    }

    @Test
    void buildsAShellFreeLauncherForTheOfficialWindowsZip() throws Exception {
        Path script = temporaryDirectory.resolve("lib/dist/bin/codegraph.js");
        Files.createDirectories(script.getParent());
        Files.createFile(temporaryDirectory.resolve("node.exe"));
        Files.createFile(script);
        CodeGraphProperties properties = new CodeGraphProperties();
        properties.setBundleRoot(temporaryDirectory.toString());

        List<String> prefix = new CodeGraphCommandRunner(properties).commandPrefix();

        assertThat(prefix).containsExactly(
                temporaryDirectory.resolve("node.exe").toAbsolutePath().normalize().toString(),
                "--liftoff-only", "--disable-warning=ExperimentalWarning",
                script.toAbsolutePath().normalize().toString());
    }

    private CodeGraphProperties properties() {
        CodeGraphProperties properties = new CodeGraphProperties();
        properties.setExecutable(Path.of(System.getProperty("java.home"), "bin",
                isWindows() ? "java.exe" : "java").toString());
        properties.setTimeoutSeconds(5);
        return properties;
    }

    private List<String> helper(String action) {
        return List.of("-cp", System.getProperty("java.class.path"), Helper.class.getName(), action);
    }

    private boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win");
    }

    public static class Helper {
        public static void main(String[] args) throws Exception {
            switch (args[0]) {
                case "echo" -> System.out.print("{\"ok\":true}");
                case "overflow" -> System.out.print("x".repeat(4_096));
                case "sleep" -> Thread.sleep(5_000);
                default -> throw new IllegalArgumentException(args[0]);
            }
        }
    }
}
