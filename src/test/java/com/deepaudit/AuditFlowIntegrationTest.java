package com.deepaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
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
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

    @Test
    void importsGitCommitScansAndReportsVulnerableProject() throws Exception {
        String console = mockMvc.perform(get("/index.html"))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(console).contains("SECURITY POSTURE / LIVE", "HTTPS Git 仓库地址", "增量比较 Base → Target", "审计任务");

        Path repository = vulnerableProjectRepository();
        String importJson = mockMvc.perform(post("/api/projects/git")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "name", "漏洞演示项目", "repositoryUrl", repository.toUri().toString()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        JsonNode imported = objectMapper.readTree(importJson);
        String projectId = imported.path("project").path("projectId").asText();
        String targetCommit = imported.path("commits").path(0).path("sha").asText();

        String auditJson = mockMvc.perform(post("/api/projects/{projectId}/audits", projectId)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsBytes(java.util.Map.of(
                                "scanMode", "FULL", "targetCommit", targetCommit))))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String taskId = objectMapper.readTree(auditJson).path("taskId").asText();

        JsonNode task = waitForCompletion(taskId);
        assertThat(task.path("status").asText()).isEqualTo("COMPLETED");
        assertThat(task.path("findingCount").asLong()).isGreaterThanOrEqualTo(7);
        assertThat(semanticCallEdgeMapper.findByTaskId(java.util.UUID.fromString(taskId))).isNotEmpty();
        assertThat(securityFlowMapper.findByTaskId(java.util.UUID.fromString(taskId))).isNotEmpty();

        String findingsJson = mockMvc.perform(get("/api/tasks/{taskId}/findings", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        Set<String> types = objectMapper.readTree(findingsJson).findValues("type").stream()
                .map(JsonNode::asText).collect(Collectors.toSet());
        assertThat(types).contains("SQL_INJECTION", "AUTHORIZATION",
                "UNAUTHORIZED_DISCLOSURE", "STORED_XSS", "VALIDATION_BYPASS", "FINANCIAL_RISK");
        assertThat(types).doesNotContain("HORIZONTAL_AUTHORIZATION", "VERTICAL_AUTHORIZATION");
        assertThat(findingsJson).doesNotContain("[SEMANTIC_FLOW]", "[CRITIC]");
        assertThat(findingsJson).contains("\\n\\nCritic Agent 复核：");
        assertThat(findingsJson).contains("\"deltaStatus\":\"BASELINE\"");

        String report = mockMvc.perform(get("/api/tasks/{taskId}/report.html", taskId))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(report).contains("DeepAudit Java 安全审计报告", "越权漏洞", "SQL 注入", "严重", "可信度 高");
        assertThat(report).contains("class='finding-description'", "class='critic-review'")
                .doesNotContain("[SEMANTIC_FLOW]", "[CRITIC]");

        String events = mockMvc.perform(get("/api/tasks/{taskId}/events", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(events).contains("RECON", "ORCHESTRATOR", "MODEL_CALL", "REASONING", "TOOL_CALL",
                "CRITIC", "REPORT", "SEMANTIC_EVIDENCE", "Spring MVC");

        String jsonReport = mockMvc.perform(get("/api/tasks/{taskId}/report.json", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(jsonReport).contains("AI Agents 已完成", "agentRuns", "hypotheses");
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
                                "scanMode", "INCREMENTAL", "baseCommit", source.baseCommit(),
                                "targetCommit", source.targetCommit()))))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String taskId = objectMapper.readTree(auditJson).path("taskId").asText();

        JsonNode task = waitForCompletion(taskId);
        assertThat(task.path("status").asText()).isEqualTo("COMPLETED");
        assertThat(task.path("scanMode").asText()).isEqualTo("INCREMENTAL");
        assertThat(task.path("changeSummary").asText()).contains("1 个文件发生变化");

        String changes = mockMvc.perform(get("/api/tasks/{taskId}/changes", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(changes).contains("SearchController.java", "\"changeType\":\"MODIFY\"");

        String findings = mockMvc.perform(get("/api/tasks/{taskId}/findings", taskId))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(findings).contains("SQL_INJECTION", "\"deltaStatus\":\"NEW\"");
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

    private Path vulnerableProjectRepository() throws Exception {
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
        Files.writeString(javaFile, source, StandardCharsets.UTF_8);
        Files.writeString(template, "<div v-html=\"comment.content\"></div>", StandardCharsets.UTF_8);
        try (Git git = Git.init().setDirectory(repository.toFile()).call()) {
            git.add().addFilepattern(".").call();
            git.commit().setMessage("initial vulnerable project")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid").call();
        }
        return repository;
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

    private record IncrementalRepository(Path path, String baseCommit, String targetCommit) {
    }
}
