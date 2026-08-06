package com.deepaudit;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.agent.IncrementalReviewUnit;
import com.deepaudit.agent.TriageDisposition;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.VulnerabilityType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 真实模型 API 手动集成测试，可直接在 IDEA 中点击类或测试方法左侧的绿色按钮运行。
 *
 * <p>类名以 IT 结尾，因此普通 mvn test 不会自动执行，不会意外产生外部请求和费用。</p>
 */
@ActiveProfiles("model-api-test")
@SpringBootTest
class ModelApiManualIT {

    private static final long TARGET_CHUNK_ID = 1001L;
    private static final String VULNERABLE_CODE = """
            @RestController
            @RequestMapping("/users")
            class UserController {
                @GetMapping("/search")
                Object search(@RequestParam String name) {
                    String sql = "SELECT id, username FROM users WHERE username = '" + name + "'";
                    return jdbcTemplate.queryForList(sql);
                }
            }
            """;

    @Autowired
    private LlmGateway llmGateway;

    @Autowired
    private AiProperties aiProperties;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void conversationModelRecognizesSqlInjectionAndReturnsAgentJson() throws Exception {
        requireConfigured("对话模型", aiProperties.getBaseUrl(), aiProperties.getApiKey(), aiProperties.getModel());
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit reviewUnit = new IncrementalReviewUnit(
                "change-" + TARGET_CHUNK_ID, TARGET_CHUNK_ID,
                "src/main/java/demo/UserController.java", "UserController#search", "/users/search",
                "JAVA_METHOD", "ADDED", List.of(VulnerabilityType.SQL_INJECTION), List.of(),
                List.of("DIRECT_CHANGE", "HAS_EXTERNAL_ENDPOINT", "HAS_DATA_ACCESS"), "String name",
                "@GetMapping(\"/search\")", "queryForList", "", VULNERABLE_CODE,
                "METHOD_ADDED", "", 1, 20);
        LlmGateway.Target target = new LlmGateway.Target(TARGET_CHUNK_ID,
                "src/main/java/demo/UserController.java", "UserController#search", "/users/search",
                "JAVA_METHOD", "String name", "@GetMapping(\"/search\")", "queryForList",
                VULNERABLE_CODE, "MODIFIED", "CHANGED", "",
                List.of(VulnerabilityType.SQL_INJECTION));
        LlmGateway.ReconInsight recon = new LlmGateway.ReconInsight(
                "Spring MVC 接口直接使用 JdbcTemplate 访问数据库",
                com.deepaudit.recon.TechnologyProfile.empty());

        LlmGateway.TriagePlan plan = llmGateway.triageIncremental(taskId, recon, List.of(reviewUnit));
        printJson("对话模型配置", new ModelConfiguration(aiProperties.getBaseUrl(), aiProperties.getModel()));
        printJson("Triage Orchestrator 返回", plan);
        assertThat(plan.decisions())
                .as("模型应把明显的字符串拼接 SQL 分流到 SQL_INJECTION 调查")
                .anySatisfy(decision -> {
                    assertThat(decision.primaryChunkId()).isEqualTo(TARGET_CHUNK_ID);
                    assertThat(decision.disposition()).isEqualTo(TriageDisposition.INVESTIGATE);
                    assertThat(decision.vulnerabilityTypes()).contains(VulnerabilityType.SQL_INJECTION);
                });

        List<LlmGateway.Observation> observations = new ArrayList<>();
        LlmGateway.AgentDecision finalDecision = null;
        for (int iteration = 1; iteration <= 3; iteration++) {
            LlmGateway.AgentTurn turn = new LlmGateway.AgentTurn(
                    taskId,
                    AgentType.SQL_INJECTION,
                    VulnerabilityType.SQL_INJECTION,
                    target,
                    null,
                    "没有预计算语义路径",
                    recon,
                    List.copyOf(observations),
                    iteration,
                    new LlmGateway.AgentBudget(iteration, 3, 3 - iteration,
                            observations.size(), 3, Math.max(0, 3 - observations.size()),
                            iteration == 3)
            );
            LlmGateway.AgentDecision decision = llmGateway.decide(turn);
            printJson("专业 Agent 第 " + iteration + " 轮返回", decision);
            if ("FINDING".equalsIgnoreCase(decision.action())) {
                finalDecision = decision;
                break;
            }
            if (!"TOOL".equalsIgnoreCase(decision.action())) {
                finalDecision = decision;
                break;
            }
            observations.add(new LlmGateway.Observation(
                    decision.tool(),
                    decision.arguments(),
                    "CHUNK_ID=" + TARGET_CHUNK_ID + " | UserController.java:5 | UserController#search\n"
                            + "<UNTRUSTED_CODE>\n" + VULNERABLE_CODE + "\n</UNTRUSTED_CODE>\n"
                            + "未检索到 PreparedStatement、占位符参数绑定或输入白名单。"
            ));
        }

        assertThat(finalDecision).as("专业 Agent 应在三轮内形成结论").isNotNull();
        assertThat(finalDecision.action())
                .as("这段代码存在明确 SQL 注入，模型不应拒绝")
                .isEqualToIgnoringCase("FINDING");
        assertThat(finalDecision.finding()).isNotNull();
        assertThat(finalDecision.finding().type()).isEqualTo(VulnerabilityType.SQL_INJECTION);
        assertThat(finalDecision.finding().primaryChunkId()).isEqualTo(TARGET_CHUNK_ID);
    }

    private void printJson(String title, Object value) throws Exception {
        System.out.println("\n=== " + title + " ===");
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(value));
    }

    private void requireConfigured(String type, String baseUrl, String apiKey, String model) {
        assertThat(baseUrl).as(type + " base-url 未配置").isNotBlank();
        assertThat(model).as(type + " model 未配置").isNotBlank();
        assertThat(apiKey)
                .as(type + " api-key 仍是占位符，请先修改 application-model-api-test.yml")
                .isNotBlank()
                .doesNotContain("在这里填写", "替换为", "placeholder");
    }

    private record ModelConfiguration(String baseUrl, String model) {
    }
}
