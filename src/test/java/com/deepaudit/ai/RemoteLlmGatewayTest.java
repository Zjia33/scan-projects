package com.deepaudit.ai;

import com.deepaudit.agent.IncrementalReviewUnit;
import com.deepaudit.agent.TriageDisposition;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.recon.ProjectStructureProfile;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.recon.TechnologyProfile;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RemoteLlmGatewayTest {

    @Test
    void sendsOnlyFrameworkFactsAndPriorityConfigurationFilesToRecon() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"architectureSummary":"Spring MVC 分层服务"}
                """);
        ProjectStructureProfile structure = new ProjectStructureProfile(
                List.of(new ProjectStructureProfile.ModuleProfile(".", 12, 80, 6, 0, 0)),
                List.of(new ProjectStructureProfile.LayerProfile(".", "WEB", 2, 6)),
                List.of(new ProjectStructureProfile.FactGroup(".", "HTTP_GET", 6)),
                List.of(new ProjectStructureProfile.FactGroup(".", "ROUTE_AUTHORIZATION", 1)),
                List.of(), List.of(), List.of());
        ReconSummary summary = new ReconSummary(12, 80, 6, 90,
                new TechnologyProfile(List.of("Spring MVC"), List.of("Spring Security"),
                        List.of(), List.of("Maven"), List.of("@PreAuthorize"),
                        List.of("Spring MVC <- pom.xml [spring-boot-starter-web]")), structure,
                List.of(new com.deepaudit.recon.ReconFrameworkFile("pom.xml", "BUILD_DESCRIPTOR",
                                "<artifactId>spring-boot-starter-web</artifactId>"),
                        new com.deepaudit.recon.ReconFrameworkFile("src/main/resources/application.yml",
                                "APPLICATION_CONFIGURATION", "spring:\n  application:\n    name: orders")));

        gateway.inspectProject(UUID.randomUUID(), summary);

        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("只根据客观输入概括", "application 和 bootstrap 配置原文", "不进行漏洞判断")
                .contains("不复述具体敏感值");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"projectFramework\"", "\"entryPointTypes\":[\"HTTP_GET\"]", "\"Spring MVC\"",
                        "\"path\":\"pom.xml\"", "spring-boot-starter-web", "application.yml", "name: orders")
                .doesNotContain("sourceFileCount", "javaMethodCount", "endpointCount", "chunkCount",
                        "occurrenceCount", "changedChunkCount", "impactedChunkCount", "securityAnnotations",
                        "attackSurfaces", "riskAreas", "taskId", "OrderController", "/orders/{id}");
    }

    @Test
    void sendsRealBaseTargetAndObjectiveFactsToIncrementalTriageWithoutReconOpinion() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"summary":"已检查真实差异","decisions":[{"unitId":"change-7","primaryChunkId":7,
                 "disposition":"SKIP","vulnerabilityTypes":[],"reason":"差异仅修改格式"}]}
                """);
        IncrementalReviewUnit unit = new IncrementalReviewUnit(
                "change-7", 7L, "Formatter.java", "Formatter#format", null, "JAVA_METHOD",
                "MODIFIED", List.of(VulnerabilityType.values()), List.of(),
                List.of("DIRECT_CHANGE"), "String value", "", "strip",
                "return value.trim();", "return value.strip();", "METHOD_MODIFIED", "", 1, 5);

        gateway.triageIncremental(UUID.randomUUID(), recon(), List.of(unit));

        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("baseCodeExcerpt 和 targetCodeExcerpt", "逐行比较 Base 与 Target", "不得仅凭名称",
                        "INVESTIGATE 或 SKIP", "focusRanges", "investigationQuestions")
                .doesNotContain("NEED_CONTEXT");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"reviewUnits\"", "\"baseCodeExcerpt\":\"return value.trim();\"",
                        "\"targetCodeExcerpt\":\"return value.strip();\"", "\"DIRECT_CHANGE\"",
                        "\"projectTechnology\"")
                .doesNotContain("\"architectureSummary\"", "\"candidateTypes\"");
    }

    @Test
    void locallyRepairsUnescapedQuotesWithoutAnotherModelCall() {
        AiProperties properties = properties(2);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties,
                """
                        {"action":"FINDING","tool":null,"arguments":{},"summary":"发现问题",
                         "finding":{"type":"SQL_INJECTION","severity":"HIGH","confidence":"HIGH",
                         "title":"SQL 注入","description":"攻击者可访问 "http://internal" 获取数据",
                         "remediation":"使用参数化查询","primaryChunkId":1001,"evidenceChunkIds":[1001]}}
                        """);

        LlmGateway.AgentDecision decision = gateway.decide(turn());

        assertThat(decision.action()).isEqualTo("FINDING");
        assertThat(decision.finding().type()).isEqualTo(VulnerabilityType.SQL_INJECTION);
        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("所有面向人的文字使用简体中文", "technologyProfile",
                        "UNVERIFIED_CANDIDATE", "VERIFIED_EVIDENCE",
                        "turn.budget", "finalDecisionOnly")
                .contains("explore_call_graph", "read_verified_relations",
                        "search_code", "read_source", "服务端自动确认")
                .doesNotContain("get_call_chain({", "call_context({", "read_source_range({",
                        "read_impact_source");
    }

    @Test
    void asksModelToRebuildJsonWhenLocalRepairCannotRecoverIt() {
        AiProperties properties = properties(2);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, "{invalid", """
                {"action":"REJECT","tool":null,"arguments":{},
                 "summary":"没有足够证据支持漏洞结论","finding":null}
                """);

        LlmGateway.AgentDecision decision = gateway.decide(turn());

        assertThat(decision.action()).isEqualTo("REJECT");
        assertThat(gateway.requests).hasSize(2);
        assertThat(gateway.requests.get(1).get(gateway.requests.get(1).size() - 1).get("content"))
                .contains("重新生成", "更短的完整 JSON 对象", "不要使用 Markdown");
    }

    @Test
    void parsesStructuredProfessionalToolArguments() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"action":"TOOL","tool":"explore_call_graph",
                 "arguments":{"direction":"CALLERS","depth":3,"targetChunkId":2002,"limit":5},
                 "summary":"向上追踪入口调用者","finding":null}
                """);

        LlmGateway.AgentDecision decision = gateway.decide(turn());

        assertThat(decision.arguments()).containsEntry("direction", "CALLERS")
                .containsEntry("depth", 3).containsEntry("targetChunkId", 2002).containsEntry("limit", 5);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("search_symbols", "explore_call_graph", "get_change_context",
                        "resolve_data_access", "inspect_security_policy", "trace_value");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"arguments\"", "\"budget\"", "\"toolCallsRemaining\":8")
                .doesNotContain("\"query\"");
    }

    @Test
    void stopsAfterConfiguredRepairBudgetIsExhausted() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, "{invalid", "{still invalid");

        assertThatThrownBy(() -> gateway.decide(turn()))
                .isInstanceOf(AiResponseFormatException.class)
                .hasMessageContaining("2 次响应后仍未返回合法结构化结果");
        assertThat(gateway.requests).hasSize(2);
    }

    private AiProperties properties(int repairAttempts) {
        AiProperties properties = new AiProperties();
        properties.setJsonRepairAttempts(repairAttempts);
        return properties;
    }

    private LlmGateway.AgentTurn turn() {
        LlmGateway.Target target = new LlmGateway.Target(1001L, "UserController.java", "search", "/search",
                "JAVA_METHOD", "String name", "@GetMapping", "queryForList", "return query(name);",
                "MODIFIED", "CHANGED", "", List.of());
        return new LlmGateway.AgentTurn(UUID.randomUUID(), AgentType.SQL_INJECTION,
                VulnerabilityType.SQL_INJECTION, target, null, "没有预计算语义路径", recon(), List.of(), 1,
                new LlmGateway.AgentBudget(1, 11, 10, 0, 8, 8, false));
    }

    private LlmGateway.ReconInsight recon() {
        return new LlmGateway.ReconInsight("Spring MVC", com.deepaudit.recon.TechnologyProfile.empty());
    }

    private static class StubRemoteLlmGateway extends RemoteLlmGateway {
        private final Deque<String> responses = new ArrayDeque<>();
        private final List<List<Map<String, String>>> requests = new ArrayList<>();

        StubRemoteLlmGateway(AiProperties properties, String... responses) {
            super(properties, new ObjectMapper());
            this.responses.addAll(List.of(responses));
        }

        @Override
        protected String requestCompletion(List<Map<String, String>> messages) {
            requests.add(messages.stream().map(Map::copyOf).toList());
            return responses.removeFirst();
        }
    }
}
