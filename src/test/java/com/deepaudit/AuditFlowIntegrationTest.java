package com.deepaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles("test")
@AutoConfigureMockMvc
@SpringBootTest
@Import(TestLlmConfiguration.class)
class AuditFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SemanticCallEdgeMapper semanticCallEdgeMapper;

    @Autowired
    private SecurityFlowMapper securityFlowMapper;

    @Test
    void uploadsScansAndReportsVulnerableProject() throws Exception {
        String console = mockMvc.perform(get("/index.html"))
                .andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(console).contains("SECURITY POSTURE / LIVE", "选择或拖入项目压缩包", "审计任务");

        MockMultipartFile zip = new MockMultipartFile(
                "file", "vulnerable-demo.zip", "application/zip", vulnerableProjectZip());

        String uploadJson = mockMvc.perform(multipart("/api/projects/upload")
                        .file(zip).param("name", "漏洞演示项目"))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String taskId = objectMapper.readTree(uploadJson).path("taskId").asText();

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

    private JsonNode waitForCompletion(String taskId) throws Exception {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(15));
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

    private byte[] vulnerableProjectZip() throws Exception {
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
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("demo/src/main/java/demo/OrderController.java"));
            zip.write(source.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("demo/src/main/resources/templates/comment.html"));
            zip.write("<div v-html=\"comment.content\"></div>".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return bytes.toByteArray();
    }
}
