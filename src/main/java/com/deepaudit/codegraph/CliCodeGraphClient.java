package com.deepaudit.codegraph;

import com.deepaudit.util.TimingDetailLog;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

// 封装 CliCodeGraphClient 相关的数据与处理逻辑。
@Slf4j
@Component
public class CliCodeGraphClient implements CodeGraphClient {
    private final CodeGraphProperties properties;
    private final CodeGraphCommandRunner runner;
    private final ObjectMapper objectMapper;
    private final Map<WorkspaceKey, Path> roots = new ConcurrentHashMap<>();

    // 创建 CliCodeGraphClient 实例并初始化所需依赖或状态。
    public CliCodeGraphClient(CodeGraphProperties properties, CodeGraphCommandRunner runner,
                              ObjectMapper objectMapper) {
        this.properties = properties;
        this.runner = runner;
        this.objectMapper = objectMapper;
    }

    // 执行 CliCodeGraphClient 中的 prepare 处理。
    @Override
    public void prepare(UUID taskId, CodeGraphSnapshot snapshot, Path projectRoot) {
        if (!properties.enabled()) return;
        Path root = requireTaskWorkspace(taskId, snapshot, projectRoot);
        verifyVersion(root);
        boolean cachedIndex = Files.isDirectory(root.resolve(requireIndexDirectory(properties.getIndexDirectory())));
        TimingDetailLog.info("任务 {} CodeGraph {} {}：workspace={}", taskId, snapshot,
                cachedIndex ? "尝试复用提交级索引" : "建立提交级索引", root.getFileName());
        CodeGraphCommandRunner.CommandOutput init = runner.run(root,
                List.of("init", root.toString(), "--no-color"), environment());
        requireSuccess("init", init);
        CodeGraphCommandRunner.CommandOutput status = runner.run(root,
                List.of("status", root.toString(), "--json", "--no-color"), environment());
        requireSuccess("status", status);
        validateStatus(status.stdout());
        roots.put(new WorkspaceKey(taskId, snapshot), root);
    }

    // 执行 CliCodeGraphClient 中的 impact 处理。
    @Override
    public List<CodeGraphLocation> impact(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int depth) {
        Path root = requirePrepared(taskId, snapshot);
        CodeGraphCommandRunner.CommandOutput output = runner.run(root, List.of(
                "impact", requireSymbol(symbol), "--path", root.toString(),
                "--depth", String.valueOf(Math.max(1, Math.min(depth, 10))), "--json", "--no-color"), environment());
        requireSuccess("impact", output);
        return parseLocations(output.stdout(), "affected");
    }

    // 执行 CliCodeGraphClient 中的 related 处理。
    @Override
    public RelatedLocations related(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int limit) {
        Path root = requirePrepared(taskId, snapshot);
        int safeLimit = Math.max(1, Math.min(limit, 100));
        String query = requireSymbol(symbol);
        List<CodeGraphLocation> callers = relation(root, "callers", query, safeLimit);
        List<CodeGraphLocation> callees = relation(root, "callees", query, safeLimit);
        return new RelatedLocations(callers, callees);
    }

    // 执行 CliCodeGraphClient 中的 release 处理。
    @Override
    public void release(UUID taskId) {
        roots.keySet().removeIf(key -> key.taskId().equals(taskId));
    }

    // 执行 CliCodeGraphClient 中的 relation 处理。
    private List<CodeGraphLocation> relation(Path root, String command, String symbol, int limit) {
        CodeGraphCommandRunner.CommandOutput output = runner.run(root, List.of(
                command, symbol, "--path", root.toString(), "--limit", String.valueOf(limit),
                "--json", "--no-color"), environment());
        requireSuccess(command, output);
        return parseLocations(output.stdout(), command);
    }

    // 校验 verifyVersion 对应的数据或约束。
    private void verifyVersion(Path root) {
        String expected = properties.getExpectedVersion();
        if (expected == null || expected.isBlank()) return;
        CodeGraphCommandRunner.CommandOutput output = runner.run(root, List.of("version", "--no-color"), environment());
        requireSuccess("version", output);
        String actual = output.stdout().strip();
        if (!expected.strip().equals(actual)) {
            throw new CodeGraphException("CodeGraph 版本不匹配，期望 " + expected.strip() + "，实际 " + actual);
        }
    }

    // 校验 validateStatus 对应的数据或约束。
    private void validateStatus(String json) {
        try {
            JsonNode root = objectMapper.readTree(requireJson(json));
            if (!root.path("initialized").asBoolean(false)) {
                throw new CodeGraphException("CodeGraph 索引没有成功初始化");
            }
            String state = root.path("index").path("state").asText("");
            int pendingRefs = root.path("index").path("pendingRefs").asInt(0);
            if (!state.isBlank() && !"complete".equals(state)) {
                throw new CodeGraphException("CodeGraph 索引不完整，状态为 " + state);
            }
            if (pendingRefs > 0) {
                throw new CodeGraphException("CodeGraph 索引仍有 " + pendingRefs + " 条未完成引用解析");
            }
        } catch (CodeGraphException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new CodeGraphException("无法解析 CodeGraph status JSON", exception);
        }
    }

    // 解析输入并生成 parseLocations 对应的结构化结果。
    List<CodeGraphLocation> parseLocations(String json, String field) {
        if (json == null || json.isBlank()) return List.of();
        String trimmed = json.strip();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
            log.debug("CodeGraph {} 没有返回 JSON，按无结果处理: {}", field, summarize(trimmed));
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(trimmed);
            JsonNode values = root.isArray() ? root : root.path(field);
            if (!values.isArray()) return List.of();
            List<CodeGraphLocation> result = new ArrayList<>();
            for (JsonNode value : values) {
                JsonNode node = value.has("node") ? value.path("node") : value;
                String filePath = node.path("filePath").asText("");
                if (filePath.isBlank()) continue;
                Integer startLine = node.hasNonNull("startLine") ? node.path("startLine").asInt() : null;
                result.add(new CodeGraphLocation(node.path("name").asText(""),
                        node.path("kind").asText(""), normalizePath(filePath), startLine));
            }
            return List.copyOf(result);
        } catch (Exception exception) {
            throw new CodeGraphException("无法解析 CodeGraph " + field + " JSON", exception);
        }
    }

    // 执行 CliCodeGraphClient 中的 requireJson 处理。
    private String requireJson(String value) {
        String json = value == null ? "" : value.strip();
        if (!json.startsWith("{")) throw new CodeGraphException("CodeGraph 没有返回预期 JSON");
        return json;
    }

    // 执行 CliCodeGraphClient 中的 requireTaskWorkspace 处理。
    private Path requireTaskWorkspace(UUID taskId, CodeGraphSnapshot snapshot, Path value) {
        if (taskId == null || snapshot == null || value == null) {
            throw new CodeGraphException("任务 ID、快照类型和源码快照不能为空");
        }
        Path root = value.toAbsolutePath().normalize();
        String expected = "workspace-" + taskId + "-" + snapshot.workspaceSuffix();
        boolean taskWorkspace = root.getFileName() != null && expected.equals(root.getFileName().toString());
        boolean commitCache = root.getFileName() != null
                && root.getFileName().toString().matches("[0-9a-f]{40}")
                && root.getParent() != null && root.getParent().getFileName() != null
                && "commit-cache".equals(root.getParent().getFileName().toString());
        if (!taskWorkspace && !commitCache) {
            throw new CodeGraphException("CodeGraph 只允许索引当前任务的 " + snapshot + " 快照: " + root);
        }
        if (!Files.isDirectory(root)) {
            throw new CodeGraphException(snapshot + " 快照目录不存在: " + root);
        }
        try {
            Path realRoot = root.toRealPath();
            boolean realTaskWorkspace = realRoot.getFileName() != null
                    && expected.equals(realRoot.getFileName().toString());
            boolean realCommitCache = realRoot.getFileName() != null
                    && realRoot.getFileName().toString().matches("[0-9a-f]{40}")
                    && realRoot.getParent() != null && realRoot.getParent().getFileName() != null
                    && "commit-cache".equals(realRoot.getParent().getFileName().toString());
            if (!realTaskWorkspace && !realCommitCache) {
            throw new CodeGraphException("CodeGraph " + snapshot + " 快照不能通过符号链接跳出任务目录: " + root);
            }
            return realRoot;
        } catch (IOException exception) {
            throw new CodeGraphException("无法解析 CodeGraph " + snapshot + " 快照: " + root, exception);
        }
    }

    // 执行 CliCodeGraphClient 中的 requirePrepared 处理。
    private Path requirePrepared(UUID taskId, CodeGraphSnapshot snapshot) {
        Path root = roots.get(new WorkspaceKey(taskId, snapshot));
        if (root == null) {
            throw new CodeGraphException("任务尚未建立 CodeGraph " + snapshot + " 索引: " + taskId);
        }
        return root;
    }

    // 执行 CliCodeGraphClient 中的 requireSymbol 处理。
    private String requireSymbol(String value) {
        if (value == null || value.isBlank() || value.length() > 1_000
                || value.indexOf('\0') >= 0 || value.contains("\n") || value.contains("\r")) {
            throw new CodeGraphException("CodeGraph 符号查询无效");
        }
        return value.strip();
    }

    // 执行 CliCodeGraphClient 中的 environment 处理。
    private Map<String, String> environment() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("DO_NOT_TRACK", "1");
        values.put("CODEGRAPH_TELEMETRY", "0");
        values.put("CODEGRAPH_NO_DAEMON", "1");
        values.put("CODEGRAPH_NO_PROMPT_HOOK", "1");
        values.put("NO_COLOR", "1");
        values.put("CI", "1");
        values.put("CODEGRAPH_DIR", requireIndexDirectory(properties.getIndexDirectory()));
        return values;
    }

    // 执行 CliCodeGraphClient 中的 requireIndexDirectory 处理。
    private String requireIndexDirectory(String value) {
        String directory = value == null ? "" : value.strip();
        if (directory.isBlank() || directory.equals(".") || directory.equals("..")
                || directory.length() > 80 || !directory.matches("[A-Za-z0-9._-]+")) {
            throw new CodeGraphException("CodeGraph 索引目录必须是安全的单级相对目录名");
        }
        return directory;
    }

    // 执行 CliCodeGraphClient 中的 requireSuccess 处理。
    private void requireSuccess(String command, CodeGraphCommandRunner.CommandOutput output) {
        if (output.exitCode() == 0) return;
        String detail = output.stderr().isBlank() ? output.stdout() : output.stderr();
        throw new CodeGraphException("CodeGraph " + command + " 执行失败（exit=" + output.exitCode()
                + "）：" + summarize(detail));
    }

    // 规范化 normalizePath 对应的输入。
    private String normalizePath(String value) {
        String normalized = value.replace('\\', '/');
        while (normalized.startsWith("./")) normalized = normalized.substring(2);
        return normalized;
    }

    // 执行 CliCodeGraphClient 中的 summarize 处理。
    private String summarize(String value) {
        String text = value == null ? "" : value.replaceAll("\\s+", " ").strip();
        return text.substring(0, Math.min(text.length(), 500));
    }

    private record WorkspaceKey(UUID taskId, CodeGraphSnapshot snapshot) {
    }
}
