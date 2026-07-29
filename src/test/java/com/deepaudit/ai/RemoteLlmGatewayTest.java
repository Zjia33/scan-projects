package com.deepaudit.ai;

import com.deepaudit.agent.AuditUnit;
import com.deepaudit.agent.TriageDisposition;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.FindingDeltaStatus;
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
    void sendsStructuredProjectFactsToReconWithoutBusinessSource() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"architectureSummary":"Spring MVC 分层服务","attackSurfaces":["HTTP API"],
                 "securityMechanisms":["Spring Security"],"riskAreas":["公开接口"]}
                """);
        ProjectStructureProfile structure = new ProjectStructureProfile(
                List.of(new ProjectStructureProfile.ModuleProfile(".", 12, 80, 6, 0, 0)),
                List.of(new ProjectStructureProfile.LayerProfile(".", "WEB", 2, 6)),
                List.of(new ProjectStructureProfile.FactGroup(".", "HTTP_GET", 6,
                        List.of("OrderController.java:10 OrderController#detail [/orders/{id}]"))),
                List.of(new ProjectStructureProfile.FactGroup(".", "ROUTE_AUTHORIZATION", 1,
                        List.of("SecurityConfig.java"))),
                List.of(), List.of(), List.of());
        ReconSummary summary = new ReconSummary(12, 80, 6, 90,
                new TechnologyProfile(List.of("Spring MVC"), List.of("Spring Security"),
                        List.of(), List.of("Maven"), List.of(), List.of()), structure);

        gateway.inspectProject(UUID.randomUUID(), summary);

        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("不负责审查具体业务逻辑", "occurrenceCount", "不能描述成已确认漏洞");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"projectFacts\"", "\"projectStructure\"", "\"HTTP_GET\"",
                        "\"occurrenceCount\":6", "OrderController#detail")
                .doesNotContain("representativeTargets", "codeExcerpt", "return orderService");
    }

    @Test
    void sendsCompactAuditUnitsToTriageOrchestrator() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"summary":"需要调查动态查询","decisions":[{
                  "unitId":"chunk-1001","primaryChunkId":1001,"disposition":"investigate",
                  "vulnerabilityTypes":["sql_injection"],
                  "reasonCodes":["DANGEROUS_DATA_ACCESS"],"requiredContext":[],
                  "reason":"外部输入参与数据库查询"}]}
                """);
        AuditUnit unit = new AuditUnit("chunk-1001", 1001L, "UserController.java",
                "UserController#search", "/search", "EXTERNAL_ENTRY", "MODIFIED", "CHANGED",
                List.of(VulnerabilityType.SQL_INJECTION),
                List.of("EXTERNAL_ENTRY", "DANGEROUS_DATA_ACCESS"), "String name",
                "@GetMapping", "queryForList -> DATABASE", "", "queryForList(sql)");

        LlmGateway.TriagePlan plan = gateway.triage(UUID.randomUUID(), recon(), List.of(unit));

        assertThat(plan.decisions()).singleElement().satisfies(decision -> {
            assertThat(decision.disposition()).isEqualTo(TriageDisposition.INVESTIGATE);
            assertThat(decision.vulnerabilityTypes()).containsExactly(VulnerabilityType.SQL_INJECTION);
        });
        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("轻量 Triage Orchestrator", "NEED_CONTEXT", "SKIP");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"auditUnits\"", "\"codeOutline\"")
                .doesNotContain("\"baseCodeExcerpt\"");
    }

    @Test
    void requiresCriticToReturnCorrectedPrimaryEvidenceAndLines() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"confirmed":true,"confidence":"HIGH","reason":"实际危险操作位于服务层",
                 "deltaStatus":"BASELINE","primaryChunkId":1549,
                 "vulnerabilityStartLine":86,"vulnerabilityEndLine":88}
                """);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.FINANCIAL_RISK, Severity.HIGH, Confidence.HIGH,
                "客户端报价被用于扣款", "服务端信任客户端报价", "查询可信价格",
                1497L, List.of(1497L, 1549L), 82, 83);
        LlmGateway.CriticRequest request = new LlmGateway.CriticRequest(UUID.randomUUID(),
                AgentType.FINANCIAL_RISK, proposal, "跨方法证据", "调用链证据", recon(),
                "UNCHANGED", "FULL", "");

        LlmGateway.CriticDecision decision = gateway.critique(request);

        assertThat(decision.primaryChunkId()).isEqualTo(1549L);
        assertThat(decision.vulnerabilityStartLine()).isEqualTo(86);
        assertThat(decision.vulnerabilityEndLine()).isEqualTo(88);
        assertThat(decision.deltaStatus()).isEqualTo(FindingDeltaStatus.BASELINE);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("负责最终漏洞定位", "Controller 入口", "最多标记连续 5 行");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"primaryChunkId\"", "\"vulnerabilityStartLine\"",
                        "\"vulnerabilityEndLine\"");
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
                .contains("所有供人阅读的摘要", "简体中文", "technologyProfile",
                        "UNVERIFIED_CANDIDATE", "verify_relation", "VERIFIED_EVIDENCE")
                .contains("get_call_chain", "call_context", "verify_relation");
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
                .contains("从头重建", "禁止源码", "不超过 180 个汉字");
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
                .contains("\"arguments\"").doesNotContain("\"query\"");
    }

    @Test
    void stopsAfterConfiguredRepairBudgetIsExhausted() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, "{invalid", "{still invalid");

        assertThatThrownBy(() -> gateway.decide(turn()))
                .isInstanceOf(AiResponseFormatException.class)
                .hasMessageContaining("2 次响应后仍未返回合法 JSON");
        assertThat(gateway.requests).hasSize(2);
    }

    private AiProperties properties(int repairAttempts) {
        AiProperties properties = new AiProperties();
        properties.setRequired(true);
        properties.setJsonRepairAttempts(repairAttempts);
        return properties;
    }

    private LlmGateway.AgentTurn turn() {
        LlmGateway.Target target = new LlmGateway.Target(1001L, "UserController.java", "search", "/search",
                "JAVA_METHOD", "String name", "@GetMapping", "queryForList", "return query(name);",
                "MODIFIED", "CHANGED", "", List.of());
        return new LlmGateway.AgentTurn(UUID.randomUUID(), AgentType.SQL_INJECTION,
                VulnerabilityType.SQL_INJECTION, target, null, "没有预计算语义路径", recon(), List.of(), 1);
    }

    private LlmGateway.ReconInsight recon() {
        return new LlmGateway.ReconInsight("Spring MVC", List.of("/search"),
                List.of(), List.of("动态 SQL"));
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
