package com.deepaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.AnalysisScope;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.eclipse.jgit.api.Git;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles("test")
@AutoConfigureMockMvc
@SpringBootTest
@Import(TestLlmConfiguration.class)
class AuditFlowIntegrationTest {

    @TempDir
    Path temporaryDirectory;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SemanticCallEdgeMapper semanticCallEdgeMapper;

    @Autowired
    private SecurityFlowMapper securityFlowMapper;

    @Autowired
    private CodeChunkMapper codeChunkMapper;

    @Autowired
    private AuditTaskMapper auditTaskMapper;

    @Test
    void cancelsQueuedAuditAndExposesConsoleAction() throws Exception {
        IncrementalRepository source = incrementalProjectRepository();
        String importJson = mockMvc.perform(post("/api/projects/git")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "name", "可中断审计项目", "repositoryUrl", source.path().toUri().toString()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        UUID projectId = UUID.fromString(objectMapper.readTree(importJson)
                .path("project").path("projectId").asText());
        AuditTask task = new AuditTask(projectId, source.baseCommit(), source.targetCommit(), source.baseCommit());
        auditTaskMapper.insert(task);

        String cancelled = mockMvc.perform(post("/api/tasks/{taskId}/cancel", task.getId()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(cancelled).contains("\"status\":\"CANCELLED\"", "审计任务已中断");
        assertThat(auditTaskMapper.findById(task.getId()).getStatus().name()).isEqualTo("CANCELLED");
        String script = mockMvc.perform(get("/app.js"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(script).contains("中断审计", "/cancel", "确认中断",
                        "taskRequestSequence", "selectedTask() !== task",
                        "withoutInternalChunkIds", "readerFacingFindingText", "finding-evidence-chunk",
                        "正在创建审计任务并加入队列", "queuedTaskFromSubmission",
                        "void loadTasks({ forceDetail: true })", "state.submittingAudit")
                .doesNotContain("chunk.id ? `CHUNK", "代码证据 ${index + 1}");
    }

    @Test
    void importsGitCommitScansAndReportsVulnerableProject() throws Exception {
        String console = mockMvc.perform(get("/index.html"))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(console).contains("SECURITY POSTURE / LIVE", "Git 仓库地址",
                "白名单内网主机可使用 HTTP", "Base → Target",
                "扫描项目管理", "项目归档", "审计任务")
                .doesNotContain("全量扫描", "id=\"scan-mode\"");

        IncrementalRepository repository = vulnerableProjectRepository();
        String importJson = mockMvc.perform(post("/api/projects/git")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "name", "漏洞演示项目", "repositoryUrl", repository.path().toUri().toString()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        JsonNode imported = objectMapper.readTree(importJson);
        String projectId = imported.path("project").path("projectId").asText();
        String targetCommit = repository.targetCommit();

        String auditJson = mockMvc.perform(post("/api/projects/{projectId}/audits", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "baseCommit", repository.baseCommit(), "targetCommit", targetCommit))))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        JsonNode submission = objectMapper.readTree(auditJson);
        String taskId = submission.path("taskId").asText();
        assertThat(submission.path("status").asText()).isEqualTo("UPLOADED");
        assertThat(submission.path("progress").asInt()).isZero();
        assertThat(submission.path("currentStage").asText()).isEqualTo("等待扫描");
        assertThat(submission.path("createdAt").asText()).isNotBlank();

        JsonNode task = waitForCompletion(taskId);
        assertThat(task.path("status").asText()).isEqualTo("COMPLETED");
        assertThat(task.path("findingCount").asLong()).isGreaterThanOrEqualTo(6);
        assertThat(semanticCallEdgeMapper.findByTaskId(java.util.UUID.fromString(taskId))).isNotEmpty();
        assertThat(securityFlowMapper.findByTaskId(java.util.UUID.fromString(taskId))).isNotEmpty();

        String findingsJson = mockMvc.perform(get("/api/tasks/{taskId}/findings", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        Set<String> types = objectMapper.readTree(findingsJson).findValues("type").stream()
                .map(JsonNode::asText).collect(Collectors.toSet());
        assertThat(types).contains("SQL_INJECTION", "AUTHORIZATION",
                "SENSITIVE_INFORMATION_DISCLOSURE", "STORED_XSS", "VALIDATION_BYPASS");
        assertThat(findingsJson).doesNotContain("[SEMANTIC_FLOW]", "[CRITIC]");
        assertThat(findingsJson).doesNotContain("Critic Agent 复核：");
        assertThat(findingsJson).containsAnyOf("[漏洞根因]", "[责任锚点]").contains(">>>");
        assertThat(findingsJson).contains("\"deltaStatus\":\"NEW\"");

        String report = mockMvc.perform(get("/api/tasks/{taskId}/report.html", taskId))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(report).contains("代码安全审计报告", "越权漏洞", "SQL 注入", "严重", "可信度 高");
        assertThat(report).contains("class='finding-description'", "class='vulnerability-location'",
                        "class='evidence-chunk'", "实际漏洞位置", "代码证据")
                .doesNotContain("class='critic-review'", "class='vulnerable-line'", "&gt;&gt;&gt;",
                        "[SEMANTIC_FLOW]", "[CRITIC]", ">CHUNK 1<", "代码证据 1");

        String events = mockMvc.perform(get("/api/tasks/{taskId}/events", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(events).contains("RECON", "ORCHESTRATOR", "MODEL_CALL", "REASONING", "TOOL_CALL",
                "REPORT", "SEMANTIC_EVIDENCE", "Spring MVC");
        assertThat(events).doesNotContain("\"agentType\":\"CRITIC\"");

        String jsonReport = mockMvc.perform(get("/api/tasks/{taskId}/report.json", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(jsonReport).contains("AI Agents 已完成", "agentRuns", "hypotheses");

        String updatedProject = mockMvc.perform(patch("/api/projects/{projectId}", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "name", "更新后的漏洞演示项目", "description", "项目管理集成测试"))))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(updatedProject).contains("更新后的漏洞演示项目", "项目管理集成测试", "\"archived\":false");

        String history = mockMvc.perform(get("/api/projects/{projectId}/audits", projectId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(history).contains(taskId, repository.baseCommit(), repository.targetCommit())
                .doesNotContain("scanMode");

        mockMvc.perform(post("/api/projects/{projectId}/cleanup", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "confirmation", "DELETE_SCAN_DATA"))))
                .andExpect(status().isBadRequest());

        String archived = mockMvc.perform(post("/api/projects/{projectId}/archive", projectId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(archived).contains("\"archived\":true");
        String activeProjects = mockMvc.perform(get("/api/projects"))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(activeProjects).doesNotContain(projectId);
        String allProjects = mockMvc.perform(get("/api/projects").param("includeArchived", "true"))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(allProjects).contains(projectId, "\"archived\":true");
        mockMvc.perform(post("/api/projects/{projectId}/audits", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "baseCommit", repository.baseCommit(), "targetCommit", targetCommit))))
                .andExpect(status().isBadRequest());

        String cleanup = mockMvc.perform(post("/api/projects/{projectId}/cleanup", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "confirmation", "DELETE_SCAN_DATA"))))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(cleanup).contains("\"deletedTaskCount\":1", "扫描任务及其代码块");
        mockMvc.perform(get("/api/projects/{projectId}/audits", projectId))
                .andExpect(status().isOk())
                .andExpect(result -> assertThat(result.getResponse()
                        .getContentAsString(StandardCharsets.UTF_8)).isEqualTo("[]"));

        String restored = mockMvc.perform(post("/api/projects/{projectId}/restore", projectId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(restored).contains("\"archived\":false");
    }

    @Test
    void comparesTwoCommitsAndLimitsAuditToIncrementalScope() throws Exception {
        IncrementalRepository source = incrementalProjectRepository();
        String importJson = mockMvc.perform(post("/api/projects/git")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "name", "增量演示项目", "repositoryUrl", source.path().toUri().toString()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String projectId = objectMapper.readTree(importJson).path("project").path("projectId").asText();

        String auditJson = mockMvc.perform(post("/api/projects/{projectId}/audits", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "baseCommit", source.baseCommit(),
                                "targetCommit", source.targetCommit()))))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String taskId = objectMapper.readTree(auditJson).path("taskId").asText();

        JsonNode task = waitForCompletion(taskId);
        assertThat(task.path("status").asText()).isEqualTo("COMPLETED");
        assertThat(task.has("scanMode")).isFalse();
        assertThat(task.path("changeSummary").asText()).contains("1 个文件发生变化");

        String changes = mockMvc.perform(get("/api/tasks/{taskId}/changes", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(changes).contains("SearchController.java", "\"changeType\":\"MODIFY\"");

        String methodChanges = mockMvc.perform(get("/api/tasks/{taskId}/method-changes", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(methodChanges).contains("\"changeKind\":\"METHOD_MODIFIED\"",
                "SearchController.search", "repository.findByName");
        assertThat(codeChunkMapper.findByTaskId(java.util.UUID.fromString(taskId)))
                .anyMatch(chunk -> chunk.getAnalysisScope() == AnalysisScope.CHANGED);

        String findings = mockMvc.perform(get("/api/tasks/{taskId}/findings", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(findings).contains("SQL_INJECTION", "\"deltaStatus\":\"NEW\"");
    }

    @Test
    void rejectsMissingBaseAndIdenticalCommitRange() throws Exception {
        IncrementalRepository source = incrementalProjectRepository();
        String importJson = mockMvc.perform(post("/api/projects/git")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "name", "范围校验项目", "repositoryUrl", source.path().toUri().toString()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String projectId = objectMapper.readTree(importJson).path("project").path("projectId").asText();

        mockMvc.perform(post("/api/projects/{projectId}/audits", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "targetCommit", source.targetCommit()))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/projects/{projectId}/audits", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "baseCommit", source.targetCommit(),
                                "targetCommit", source.targetCommit()))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void auditsDivergedTargetBranchFromMergeBaseAndReturnsCommitBranches() throws Exception {
        BranchRepository source = divergedBranchRepository();
        String importJson = mockMvc.perform(post("/api/projects/git")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "name", "分支变更演示项目",
                                "repositoryUrl", source.path().toUri().toString()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        JsonNode imported = objectMapper.readTree(importJson);
        String projectId = imported.path("project").path("projectId").asText();
        assertThat(commit(imported.path("commits"), source.mainCommit()).path("branches").toString())
                .contains("\"main\"");
        assertThat(commit(imported.path("commits"), source.featureCommit()).path("branches").toString())
                .contains("\"feature/login\"");

        String auditJson = mockMvc.perform(post("/api/projects/{projectId}/audits", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "baseCommit", source.mainCommit(),
                                "targetCommit", source.featureCommit()))))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        JsonNode submission = objectMapper.readTree(auditJson);
        assertThat(submission.path("baseCommit").asText()).isEqualTo(source.mainCommit());
        assertThat(submission.path("mergeBase").asText()).isEqualTo(source.commonCommit());

        JsonNode task = waitForCompletion(submission.path("taskId").asText());
        assertThat(task.path("status").asText()).isEqualTo("COMPLETED");
        assertThat(task.path("baseCommit").asText()).isEqualTo(source.mainCommit());
        assertThat(task.path("mergeBase").asText()).isEqualTo(source.commonCommit());

        String changes = mockMvc.perform(get("/api/tasks/{taskId}/changes", submission.path("taskId").asText()))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(changes).contains("SearchController.java").doesNotContain("MainOnlyController.java");
    }

    private JsonNode commit(JsonNode commits, String sha) {
        for (JsonNode commit : commits) {
            if (sha.equals(commit.path("sha").asText())) return commit;
        }
        throw new AssertionError("提交列表中不存在 " + sha);
    }

    private JsonNode waitForCompletion(String taskId) throws Exception {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(25));
        JsonNode task = objectMapper.createObjectNode();
        while (Instant.now().isBefore(deadline)) {
            String json = mockMvc.perform(get("/api/tasks/{taskId}", taskId))
                    .andExpect(status().isOk()).andReturn().getResponse()
                    .getContentAsString(StandardCharsets.UTF_8);
            task = objectMapper.readTree(json);
            if (task.path("status").asText().matches("COMPLETED|FAILED")) return task;
            Thread.sleep(100);
        }
        return task;
    }

    private IncrementalRepository vulnerableProjectRepository() throws Exception {
        String source = """
                package demo;
                import org.springframework.web.bind.annotation.*;
                @RestController
                @RequestMapping("/orders")
                class OrderController {
                    @GetMapping("/{id}")
                    Object detail(@PathVariable Long id) {
                        return orderRepository.findById(id);
                    }
                    @GetMapping("/search")
                    Object search(@RequestParam String keyword) {
                        String sql = "SELECT * FROM orders WHERE name='" + keyword + "'";
                        return statement.execute(sql);
                    }
                    @DeleteMapping("/admin/delete/{id}")
                    void adminDelete(@PathVariable Long id) {
                        orderRepository.deleteById(id);
                    }
                    @PermitAll
                    @GetMapping("/public/profile")
                    Object publicProfile() {
                        return user.password;
                    }
                    @PostMapping("/verify/pay")
                    void pay(boolean skipVerify) {
                        if (skipVerify) paymentService.execute();
                    }
                    @PostMapping("/payment/refund")
                    void refund() {
                        double amount = request.amount;
                        order.setAmount(amount);
                    }
                }
                """;
        Path repository = temporaryDirectory.resolve("vulnerable-demo");
        Path javaFile = repository.resolve("src/main/java/demo/OrderController.java");
        Path template = repository.resolve("src/main/resources/templates/comment.html");
        Files.createDirectories(javaFile.getParent());
        Files.createDirectories(template.getParent());
        try (Git git = Git.init().setDirectory(repository.toFile()).call()) {
            Files.writeString(javaFile, "package demo; class OrderController {}", StandardCharsets.UTF_8);
            Files.writeString(template, "<div>safe</div>", StandardCharsets.UTF_8);
            git.add().addFilepattern(".").call();
            String base = git.commit().setMessage("safe baseline")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid").call().getId().name();
            Files.writeString(javaFile, source, StandardCharsets.UTF_8);
            Files.writeString(template, "<div v-html=\"comment.content\"></div>", StandardCharsets.UTF_8);
            git.add().addFilepattern(".").call();
            String target = git.commit().setMessage("introduce vulnerable project")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid").call().getId().name();
            return new IncrementalRepository(repository, base, target);
        }
    }

    private IncrementalRepository incrementalProjectRepository() throws Exception {
        Path repository = temporaryDirectory.resolve("incremental-demo");
        Path source = repository.resolve("src/main/java/demo/SearchController.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, """
                package demo;
                import org.springframework.web.bind.annotation.*;
                @RestController
                class SearchController {
                    @GetMapping("/search")
                    Object search(String keyword) {
                        return repository.findByName(keyword);
                    }
                }
                """, StandardCharsets.UTF_8);
        try (Git git = Git.init().setDirectory(repository.toFile()).call()) {
            git.add().addFilepattern(".").call();
            String base = git.commit().setMessage("safe baseline")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid").call().getId().name();
            Files.writeString(source, """
                    package demo;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    class SearchController {
                        @GetMapping("/search")
                        Object search(String keyword) {
                            String sql = "SELECT * FROM users WHERE name='" + keyword + "'";
                            return statement.execute(sql);
                        }
                    }
                    """, StandardCharsets.UTF_8);
            git.add().addFilepattern(".").call();
            String target = git.commit().setMessage("introduce dynamic query")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid").call().getId().name();
            return new IncrementalRepository(repository, base, target);
        }
    }

    private BranchRepository divergedBranchRepository() throws Exception {
        Path repository = temporaryDirectory.resolve("diverged-branch-demo");
        Path source = repository.resolve("src/main/java/demo/SearchController.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, """
                package demo;
                class SearchController {
                    Object search(String keyword) {
                        return repository.findByName(keyword);
                    }
                }
                """, StandardCharsets.UTF_8);
        try (Git git = Git.init().setDirectory(repository.toFile()).call()) {
            git.add().addFilepattern(".").call();
            String common = git.commit().setMessage("common baseline")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid").call().getId().name();
            git.branchRename().setNewName("main").call();

            Path mainOnly = repository.resolve("src/main/java/demo/MainOnlyController.java");
            Files.writeString(mainOnly, "class MainOnlyController { void maintained() {} }\n",
                    StandardCharsets.UTF_8);
            git.add().addFilepattern(".").call();
            String main = git.commit().setMessage("main branch maintenance")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid").call().getId().name();

            git.checkout().setCreateBranch(true).setName("feature/login").setStartPoint(common).call();
            Files.writeString(source, """
                    package demo;
                    class SearchController {
                        Object search(String keyword) {
                            String sql = "SELECT * FROM users WHERE name='" + keyword + "'";
                            return statement.execute(sql);
                        }
                    }
                    """, StandardCharsets.UTF_8);
            git.add().addFilepattern(".").call();
            String feature = git.commit().setMessage("feature introduces dynamic query")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid").call().getId().name();
            return new BranchRepository(repository, common, main, feature);
        }
    }

    private record IncrementalRepository(Path path, String baseCommit, String targetCommit) {
    }

    private record BranchRepository(Path path, String commonCommit, String mainCommit,
                                    String featureCommit) {
    }
}
