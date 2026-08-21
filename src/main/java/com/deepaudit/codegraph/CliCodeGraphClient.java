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

@Slf4j
@Component
public class CliCodeGraphClient implements CodeGraphClient {
    private final CodeGraphProperties properties;
    private final CodeGraphCommandRunner runner;
    private final ObjectMapper objectMapper;
    private final Map<WorkspaceKey, Path> roots = new ConcurrentHashMap<>();

    public CliCodeGraphClient(CodeGraphProperties properties, CodeGraphCommandRunner runner,
                              ObjectMapper objectMapper) {
        this.properties = properties;
        this.runner = runner;
        this.objectMapper = objectMapper;
    }

    @Override
    public void prepare(UUID taskId, CodeGraphSnapshot snapshot, Path projectRoot) {
        if (!properties.isEnabled()) return;
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

    @Override
    public List<CodeGraphLocation> impact(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int depth) {
        Path root = requirePrepared(taskId, snapshot);
        CodeGraphCommandRunner.CommandOutput output = runner.run(root, List.of(
                "impact", requireSymbol(symbol), "--path", root.toString(),
                "--depth", String.valueOf(Math.max(1, Math.min(depth, 10))), "--json", "--no-color"), environment());
        requireSuccess("impact", output);
        return parseLocations(output.stdout(), "affected");
    }

    @Override
    public List<CodeGraphLocation> query(UUID taskId, CodeGraphSnapshot snapshot,
                                         String search, String kind, int limit) {
        Path root = requirePrepared(taskId, snapshot);
        List<String> arguments = new ArrayList<>(List.of(
                "query", requireSymbol(search), "--path", root.toString()));
        if (kind != null && !kind.isBlank()) {
            arguments.add("--kind");
            arguments.add(kind.strip().toLowerCase(java.util.Locale.ROOT));
        }
        arguments.addAll(List.of("--limit", String.valueOf(Math.max(1, Math.min(limit, 100))),
                "--json", "--no-color"));
        CodeGraphCommandRunner.CommandOutput output = runner.run(root, arguments, environment());
        requireSuccess("query", output);
        return parseQueryLocations(output.stdout());
    }

    @Override
    public List<CodeGraphLocation> callers(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int limit) {
        Path root = requirePrepared(taskId, snapshot);
        int safeLimit = Math.max(1, Math.min(limit, 100));
        return relation(root, "callers", requireSymbol(symbol), safeLimit);
    }

    @Override
    public List<CodeGraphLocation> callees(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int limit) {
        Path root = requirePrepared(taskId, snapshot);
        int safeLimit = Math.max(1, Math.min(limit, 100));
        return relation(root, "callees", requireSymbol(symbol), safeLimit);
    }

    @Override
    public void release(UUID taskId) {
        roots.keySet().removeIf(key -> key.taskId().equals(taskId));
    }

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

    List<CodeGraphLocation> parseQueryLocations(String json) {
        if (json == null || json.isBlank()) return List.of();
        String trimmed = json.strip();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
            throw new CodeGraphException("CodeGraph query 没有返回预期 JSON");
        }
        try {
            JsonNode root = objectMapper.readTree(trimmed);
            if (root.isArray()) return parseLocationArray(root);
            for (String field : List.of("results", "matches", "nodes", "query")) {
                JsonNode values = root.path(field);
                if (values.isArray()) return parseLocationArray(values);
            }
            throw new CodeGraphException("CodeGraph query JSON 缺少结果数组");
        } catch (CodeGraphException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new CodeGraphException("无法解析 CodeGraph query JSON", exception);
        }
    }

    private List<CodeGraphLocation> parseLocationArray(JsonNode values) {
        List<CodeGraphLocation> result = new ArrayList<>();
        for (JsonNode value : values) {
            JsonNode node = value.has("node") ? value.path("node") : value;
            String filePath = firstText(node, "filePath", "file_path", "path");
            if (filePath.isBlank()) continue;
            Integer startLine = firstInteger(node, "startLine", "start_line", "line");
            result.add(new CodeGraphLocation(node.path("name").asText(""),
                    node.path("kind").asText(""), normalizePath(filePath), startLine));
        }
        return List.copyOf(result);
    }

    private String firstText(JsonNode node, String... fields) {
        for (String field : fields) {
            String value = node.path(field).asText("");
            if (!value.isBlank()) return value;
        }
        return "";
    }

    private Integer firstInteger(JsonNode node, String... fields) {
        for (String field : fields) {
            if (node.hasNonNull(field) && node.path(field).canConvertToInt()) {
                return node.path(field).asInt();
            }
        }
        return null;
    }

    private String requireJson(String value) {
        String json = value == null ? "" : value.strip();
        if (!json.startsWith("{")) throw new CodeGraphException("CodeGraph 没有返回预期 JSON");
        return json;
    }

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

    private Path requirePrepared(UUID taskId, CodeGraphSnapshot snapshot) {
        Path root = roots.get(new WorkspaceKey(taskId, snapshot));
        if (root == null) {
            throw new CodeGraphException("任务尚未建立 CodeGraph " + snapshot + " 索引: " + taskId);
        }
        return root;
    }

    private String requireSymbol(String value) {
        if (value == null || value.isBlank() || value.length() > 1_000
                || value.indexOf('\0') >= 0 || value.contains("\n") || value.contains("\r")) {
            throw new CodeGraphException("CodeGraph 符号查询无效");
        }
        return value.strip();
    }

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

    private String requireIndexDirectory(String value) {
        String directory = value == null ? "" : value.strip();
        if (directory.isBlank() || directory.equals(".") || directory.equals("..")
                || directory.length() > 80 || !directory.matches("[A-Za-z0-9._-]+")) {
            throw new CodeGraphException("CodeGraph 索引目录必须是安全的单级相对目录名");
        }
        return directory;
    }

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

    private String summarize(String value) {
        String text = value == null ? "" : value.replaceAll("\\s+", " ").strip();
        return text.substring(0, Math.min(text.length(), 500));
    }

    private record WorkspaceKey(UUID taskId, CodeGraphSnapshot snapshot) {
    }
}
