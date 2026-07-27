package com.deepaudit.codegraph;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
class CodeGraphCommandRunner {
    private static final Set<String> SAFE_INHERITED_ENVIRONMENT = Set.of(
            "path", "pathext", "systemroot", "windir", "temp", "tmp", "tmpdir",
            "home", "userprofile", "localappdata", "appdata", "programdata",
            "programfiles", "programfiles(x86)", "lang", "lc_all");

    private final CodeGraphProperties properties;

    CommandOutput run(Path workingDirectory, List<String> arguments, Map<String, String> environment) {
        Path root = requireDirectory(workingDirectory);
        long startedAt = System.nanoTime();
        List<String> command = new ArrayList<>();
        command.add(requireExecutable(properties.getExecutable()));
        command.addAll(arguments);
        Process process = null;
        try {
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
                throw new CodeGraphException("CodeGraph 命令执行超时: " + String.join(" ", arguments));
            }
            BoundedOutput out = stdout.get(5, TimeUnit.SECONDS);
            BoundedOutput err = stderr.get(5, TimeUnit.SECONDS);
            if (out.overflow() || err.overflow()) {
                throw new CodeGraphException("CodeGraph 命令输出超过安全上限");
            }
            return new CommandOutput(process.exitValue(), out.text(), err.text(),
                    Duration.ofNanos(System.nanoTime() - startedAt));
        } catch (CodeGraphException exception) {
            throw exception;
        } catch (Exception exception) {
            if (process != null && process.isAlive()) process.destroyForcibly();
            throw new CodeGraphException("无法执行 CodeGraph 命令: " + exception.getMessage(), exception);
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
            return new BoundedOutput(output.toString(StandardCharsets.UTF_8), total > limit);
        } catch (IOException exception) {
            throw new CodeGraphException("读取 CodeGraph 进程输出失败", exception);
        }
    }

    record CommandOutput(int exitCode, String stdout, String stderr, Duration duration) {
    }

    private record BoundedOutput(String text, boolean overflow) {
    }
}
