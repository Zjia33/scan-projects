package com.deepaudit;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.rag.EmbeddingService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
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
    private EmbeddingService embeddingService;

    @Autowired
    private AiProperties aiProperties;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${deepaudit.embedding.base-url}")
    private String embeddingBaseUrl;

    @Value("${deepaudit.embedding.api-key}")
    private String embeddingApiKey;

    @Value("${deepaudit.embedding.model}")
    private String embeddingModel;

    @Test
    void conversationModelRecognizesSqlInjectionAndReturnsAgentJson() throws Exception {
        requireConfigured("对话模型", aiProperties.getBaseUrl(), aiProperties.getApiKey(), aiProperties.getModel());
        UUID taskId = UUID.randomUUID();
        LlmGateway.Target target = new LlmGateway.Target(
                TARGET_CHUNK_ID,
                "src/main/java/demo/UserController.java",
                "UserController#search",
                "/users/search",
                "JAVA_METHOD",
                "String name",
                "@GetMapping(\"/search\")",
                "queryForList",
                VULNERABLE_CODE,
                List.of()
        );
        LlmGateway.ReconInsight recon = new LlmGateway.ReconInsight(
                "Spring MVC 接口直接使用 JdbcTemplate 访问数据库",
                List.of("GET /users/search"),
                List.of(),
                List.of("用户输入进入动态 SQL")
        );

        LlmGateway.AuditPlan plan = llmGateway.createPlan(taskId, recon, List.of(target));
        printJson("对话模型配置", new ModelConfiguration(aiProperties.getBaseUrl(), aiProperties.getModel()));
        printJson("Orchestrator 返回", plan);
        assertThat(plan.tasks())
                .as("模型应为明显的字符串拼接 SQL 安排 SQL_INJECTION 调查")
                .anySatisfy(task -> {
                    assertThat(task.chunkId()).isEqualTo(TARGET_CHUNK_ID);
                    assertThat(task.agentType()).isEqualTo(AgentType.SQL_INJECTION);
                    assertThat(task.vulnerabilityType()).isEqualTo(VulnerabilityType.SQL_INJECTION);
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
                    iteration
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
                    decision.query(),
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

    @Test
    void embeddingModelRanksSecurityRelatedCodeAboveUnrelatedCode() {
        requireConfigured("嵌入模型", embeddingBaseUrl, embeddingApiKey, embeddingModel);
        String query = "查找用户输入直接拼接 SQL 并执行所造成的 SQL 注入漏洞";
        String relatedCode = "String sql = \"SELECT * FROM users WHERE name='\" + name + \"'\"; "
                + "return jdbcTemplate.queryForList(sql);";
        String unrelatedCode = "log.info(\"application started, timezone={}\", ZoneId.systemDefault());";

        List<double[]> vectors = embeddingService.embedAll(List.of(query, relatedCode, unrelatedCode));
        assertThat(vectors).hasSize(3);
        assertThat(vectors.get(0).length).as("向量维度必须大于零").isPositive();
        assertThat(vectors).allSatisfy(vector -> {
            assertThat(vector.length).isEqualTo(vectors.get(0).length);
            for (double value : vector) {
                assertThat(Double.isFinite(value)).isTrue();
            }
        });

        double relatedScore = cosine(vectors.get(0), vectors.get(1));
        double unrelatedScore = cosine(vectors.get(0), vectors.get(2));
        System.out.printf(Locale.ROOT, "%n=== 嵌入模型测试 ===%nAPI: %s%n模型: %s%n向量维度: %d%n"
                        + "安全相关代码相似度: %.6f%n无关代码相似度: %.6f%n差值: %.6f%n%n",
                embeddingBaseUrl, embeddingModel, vectors.get(0).length,
                relatedScore, unrelatedScore, relatedScore - unrelatedScore);

        assertThat(relatedScore)
                .as("安全查询与漏洞代码的相似度应高于无关日志代码")
                .isGreaterThan(unrelatedScore);
    }

    private double cosine(double[] left, double[] right) {
        assertThat(left.length).isEqualTo(right.length);
        double dot = 0;
        double leftNorm = 0;
        double rightNorm = 0;
        for (int index = 0; index < left.length; index++) {
            dot += left[index] * right[index];
            leftNorm += left[index] * left[index];
            rightNorm += right[index] * right[index];
        }
        assertThat(leftNorm).isPositive();
        assertThat(rightNorm).isPositive();
        return dot / (Math.sqrt(leftNorm) * Math.sqrt(rightNorm));
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
