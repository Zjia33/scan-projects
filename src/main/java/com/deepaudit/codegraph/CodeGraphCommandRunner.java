package com.deepaudit.codegraph;

import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
@Slf4j
class CodeGraphCommandRunner {
    private static final Set<String> SAFE_INHERITED_ENVIRONMENT = Set.of(
            "path", "pathext", "systemroot", "windir", "temp", "tmp", "tmpdir",
            "home", "userprofile", "localappdata", "appdata", "programdata",
            "programfiles", "programfiles(x86)", "lang", "lc_all");

    private final CodeGraphProperties properties;

    // 执行 run 对应的处理流程。
    CommandOutput run(Path workingDirectory, List<String> arguments, Map<String, String> environment) {
        Path root = requireDirectory(workingDirectory);
        long startedAt = System.nanoTime();
        String operation = operation(arguments);
        List<String> command = new ArrayList<>(commandPrefix());
        command.addAll(arguments);
        Process process = null;
        try {
            logStarted(operation, root);
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(root.toFile());
            builder.redirectErrorStream(false);
            sanitizeEnvironment(builder.environment(), environment);
            process = builder.start();
            Process running = process;
            CompletableFuture<BoundedOutput> stdout = CompletableFuture.supplyAsync(
                    () -> readBounded(running.getInputStream(), properties.getMaxOutputBytes()));
            CompletableFuture<BoundedOutput> stderr = CompletableFuture.supplyAsync(
                    () -> readBounded(running.getErrorStream(), properties.getMaxOutputBytes()));
            boolean completed = process.waitFor(Math.max(1, properties.getTimeoutSeconds()), TimeUnit.SECONDS);
            if (!completed) {
                process.destroyForcibly();
                process.waitFor(5, TimeUnit.SECONDS);
                long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
                log.warn("CodeGraph 命令超时：operation={}，workspace={}，elapsedMs={}",
                        operation, root.getFileName(), elapsedMs);
                throw new CodeGraphException("CodeGraph " + operation + " 命令执行超时");
            }
            BoundedOutput out = stdout.get(5, TimeUnit.SECONDS);
            BoundedOutput err = stderr.get(5, TimeUnit.SECONDS);
            if (out.overflow() || err.overflow()) {
                log.warn("CodeGraph 命令输出超限：operation={}，stdoutBytes={}，stderrBytes={}，limitBytes={}",
                        operation, out.byteCount(), err.byteCount(), properties.getMaxOutputBytes());
                throw new CodeGraphException("CodeGraph 命令输出超过安全上限");
            }
            Duration duration = Duration.ofNanos(System.nanoTime() - startedAt);
            CommandOutput result = new CommandOutput(process.exitValue(), out.text(), err.text(), duration);
            logCompleted(operation, root, result, out.byteCount(), err.byteCount());
            return result;
        } catch (CodeGraphException exception) {
            throw exception;
        } catch (Exception exception) {
            if (process != null && process.isAlive()) process.destroyForcibly();
            throw new CodeGraphException("无法执行 CodeGraph 命令: " + exception.getMessage(), exception);
        }
    }

    private String operation(List<String> arguments) {
        if (arguments == null || arguments.isEmpty() || arguments.get(0) == null
                || arguments.get(0).isBlank()) return "unknown";
        return arguments.get(0).strip();
    }

    private void logStarted(String operation, Path root) {
        TimingDetailLog.info("CodeGraph 命令开始：operation={}，workspace={}，timeoutSeconds={}",
                operation, root.getFileName(), properties.getTimeoutSeconds());
    }

    private void logCompleted(String operation, Path root, CommandOutput output,
                              long stdoutBytes, long stderrBytes) {
        long elapsedMs = output.duration().toMillis();
        if (output.exitCode() != 0) {
            log.warn("CodeGraph 命令结束：operation={}，workspace={}，exitCode={}，elapsedMs={}，"
                            + "stdoutBytes={}，stderrBytes={}", operation, root.getFileName(),
                    output.exitCode(), elapsedMs, stdoutBytes, stderrBytes);
        } else {
            TimingDetailLog.info("CodeGraph 命令完成：operation={}，workspace={}，elapsedMs={}，stdoutBytes={}，stderrBytes={}",
                    operation, root.getFileName(), elapsedMs, stdoutBytes, stderrBytes);
        }
    }

    private Path requireDirectory(Path value) {
        if (value == null) throw new CodeGraphException("CodeGraph 工作目录不能为空");
        Path root = value.toAbsolutePath().normalize();
        if (!java.nio.file.Files.isDirectory(root)) {
            throw new CodeGraphException("CodeGraph 工作目录不存在: " + root);
        }
        return root;
    }

    private String requireExecutable(String value) {
        if (value == null || value.isBlank() || value.indexOf('\0') >= 0
                || value.contains("\n") || value.contains("\r")) {
            throw new CodeGraphException("CodeGraph 可执行文件配置无效");
        }
        return value.strip();
    }

    List<String> commandPrefix() {
        String configuredRoot = properties.getBundleRoot();
        if (configuredRoot == null || configuredRoot.isBlank()) {
            return List.of(requireExecutable(properties.getExecutable()));
        }
        if (configuredRoot.indexOf('\0') >= 0 || configuredRoot.contains("\n")
                || configuredRoot.contains("\r")) {
            throw new CodeGraphException("CodeGraph 发行包根目录配置无效");
        }
        Path bundleRoot = Path.of(configuredRoot.strip()).toAbsolutePath().normalize();
        Path node = bundleRoot.resolve("node.exe").normalize();
        Path script = bundleRoot.resolve("lib/dist/bin/codegraph.js").normalize();
        if (!node.startsWith(bundleRoot) || !script.startsWith(bundleRoot)
                || !Files.isRegularFile(node) || !Files.isRegularFile(script)) {
            throw new CodeGraphException("CodeGraph 发行包目录缺少 node.exe 或 lib/dist/bin/codegraph.js: "
                    + bundleRoot);
        }
        return List.of(node.toString(), "--liftoff-only", "--disable-warning=ExperimentalWarning",
                script.toString());
    }

    // 规范化 sanitizeEnvironment 对应的输入。
    private void sanitizeEnvironment(Map<String, String> processEnvironment,
                                     Map<String, String> explicitEnvironment) {
        Map<String, String> inherited = new LinkedHashMap<>();
        processEnvironment.forEach((key, value) -> {
            if (SAFE_INHERITED_ENVIRONMENT.contains(key.toLowerCase(Locale.ROOT))) {
                inherited.put(key, value);
            }
        });
        processEnvironment.clear();
        processEnvironment.putAll(inherited);
        processEnvironment.putAll(explicitEnvironment);
    }

    private BoundedOutput readBounded(InputStream input, long configuredLimit) {
        long limit = Math.max(1_024, configuredLimit);
        try (input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8_192];
            long total = 0;
            int read;
            while ((read = input.read(buffer)) >= 0) {
                total += read;
                if (output.size() < limit) {
                    int allowed = (int) Math.min(read, limit - output.size());
                    output.write(buffer, 0, allowed);
                }
            }
            return new BoundedOutput(output.toString(StandardCharsets.UTF_8), total > limit, total);
        } catch (IOException exception) {
            throw new CodeGraphException("读取 CodeGraph 进程输出失败", exception);
        }
    }

    record CommandOutput(int exitCode, String stdout, String stderr, Duration duration) {
    }

    private record BoundedOutput(String text, boolean overflow, long byteCount) {
    }
}
