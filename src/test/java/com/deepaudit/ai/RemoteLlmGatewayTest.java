package com.deepaudit.ai;

import com.deepaudit.agent.AuditUnit;
import com.deepaudit.agent.IncrementalReviewUnit;
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
    void sendsAggregateProjectFactsToReconWithoutLocationsOrBusinessSource() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"architectureSummary":"Spring MVC 分层服务","attackSurfaces":["HTTP API"],
                 "securityMechanisms":["Spring Security"],"riskAreas":["公开接口"]}
                """);
        ProjectStructureProfile structure = new ProjectStructureProfile(
                List.of(new ProjectStructureProfile.ModuleProfile(".", 12, 80, 6, 0, 0)),
                List.of(new ProjectStructureProfile.LayerProfile(".", "WEB", 2, 6)),
                List.of(new ProjectStructureProfile.FactGroup(".", "HTTP_GET", 6)),
                List.of(new ProjectStructureProfile.FactGroup(".", "ROUTE_AUTHORIZATION", 1)),
                List.of(), List.of(), List.of());
        ReconSummary summary = new ReconSummary(12, 80, 6, 90,
                new TechnologyProfile(List.of("Spring MVC"), List.of("Spring Security"),
                        List.of(), List.of("Maven"), List.of(),
                        List.of("Spring MVC <- pom.xml [spring-boot-starter-web]")), structure);

        gateway.inspectProject(UUID.randomUUID(), summary);

        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("整体技术框架", "只包含模块、分层和事实命中数量", "不负责审查具体业务逻辑、评估风险或确认漏洞")
                .contains("不得输出或推测具体文件、类、方法、接口路径、代码位置")
                .contains("attackSurfaces、securityMechanisms 和 riskAreas 必须返回空数组");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"projectFacts\"", "\"projectStructure\"", "\"HTTP_GET\"",
                        "\"occurrenceCount\":6", "\"Spring MVC\"", "\"evidence\":[]")
                .contains("必须为空的 string[]")
                .doesNotContain("\"occurrenceCount\":6,\"evidence\"", "pom.xml", "OrderController", "/orders/{id}",
                        "representativeTargets", "codeExcerpt", "return orderService");
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
    void sendsRealBaseTargetAndObjectiveFactsToIncrementalTriageWithoutReconOpinion() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"summary":"已检查真实差异","decisions":[{"unitId":"change-7","primaryChunkId":7,
                 "disposition":"SKIP","vulnerabilityTypes":[],"reasonCodes":["DIRECT_CHANGE"],
                 "requiredContext":[],"reason":"差异仅修改格式"}]}
                """);
        IncrementalReviewUnit unit = new IncrementalReviewUnit(
                "change-7", 7L, "Formatter.java", "Formatter#format", null, "JAVA_METHOD",
                "MODIFIED", "CHANGED", List.of(VulnerabilityType.values()), List.of(),
                List.of("DIRECT_CHANGE"), "String value", "", "strip",
                "return value.trim();", "return value.strip();", "METHOD_MODIFIED", "", "");

        gateway.triageIncremental(UUID.randomUUID(), recon(), List.of(unit));

        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("真实 targetCodeExcerpt", "逐个比较 Base/Target", "不得仅凭文件名");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"reviewUnits\"", "\"baseCodeExcerpt\":\"return value.trim();\"",
                        "\"targetCodeExcerpt\":\"return value.strip();\"", "\"DIRECT_CHANGE\"",
                        "\"projectTechnology\"")
                .doesNotContain("\"architectureSummary\"", "\"candidateTypes\"");
    }

    @Test
    void sendsSingleUnitFinalTriageWithConclusiveDispositionOnly() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"summary":"终审完成","decisions":[{"unitId":"change-8","primaryChunkId":8,
                 "disposition":"SKIP","vulnerabilityTypes":[],"reasonCodes":["DIRECT_CHANGE"],
                 "requiredContext":[],"reason":"现有证据不支持具体安全假设"}]}
                """);
        IncrementalReviewUnit unit = new IncrementalReviewUnit(
                "change-8", 8L, "Formatter.java", "Formatter#format", null, "JAVA_METHOD",
                "MODIFIED", "CHANGED", List.of(VulnerabilityType.values()), List.of(),
                List.of("DIRECT_CHANGE"), "String value", "", "strip",
                "return value.trim();", "return value.strip();", "METHOD_MODIFIED",
                "已补充调用上下文", "");

        gateway.triageIncrementalFinal(UUID.randomUUID(), recon(), unit);

        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("唯一一次补充上下文复判", "只能是 INVESTIGATE 或 SKIP", "不得再次返回 NEED_CONTEXT");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"reviewUnit\"", "disposition:INVESTIGATE|SKIP")
                .doesNotContain("\"reviewUnits\"");
    }

    @Test
    void requiresCriticToReturnCorrectedPrimaryEvidenceAndLines() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"confirmed":true,"confidence":"HIGH","reason":"实际危险操作位于服务层",
                 "deltaStatus":"NEW","primaryChunkId":1549,
                 "vulnerabilityStartLine":86,"vulnerabilityEndLine":88,
                 "rootCauseKind":"MISSING_VALIDATION","locationRole":"BUSINESS_OPERATION"}
                """);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "客户端报价被用于扣款", "服务端信任客户端报价", "查询可信价格",
                1497L, List.of(1497L, 1549L), 82, 83);
        LlmGateway.CriticRequest request = new LlmGateway.CriticRequest(UUID.randomUUID(),
                AgentType.VALIDATION_BYPASS, proposal, "跨方法证据", "调用链证据", recon(),
                "MODIFIED", "CHANGED", "", List.of());

        LlmGateway.CriticDecision decision = gateway.critique(request);

        assertThat(decision.primaryChunkId()).isEqualTo(1549L);
        assertThat(decision.vulnerabilityStartLine()).isEqualTo(86);
        assertThat(decision.vulnerabilityEndLine()).isEqualTo(88);
        assertThat(decision.deltaStatus()).isEqualTo(FindingDeltaStatus.NEW);
        assertThat(decision.rootCauseKind()).isEqualTo("MISSING_VALIDATION");
        assertThat(decision.locationRole()).isEqualTo("BUSINESS_OPERATION");
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("负责最终漏洞定位", "Controller 入口", "最多标记连续 5 行",
                        "INEFFECTIVE_SECURITY_CONTROL", "安全边界");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"primaryChunkId\"", "\"vulnerabilityStartLine\"",
                        "\"vulnerabilityEndLine\"", "\"rootCauseKind\"", "\"locationRole\"");
    }

    @Test
    void repairsLocationBySelectingOnlyServerGeneratedCandidateId() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, """
                {"locationCandidateId":"1549:87-87","reason":"危险扣款调用位于该候选"}
                """);
        LlmGateway.LocationCandidate candidate = new LlmGateway.LocationCandidate(
                "1549:87-87", 1549L, "LabScenarioService.java", "LabScenarioService#purchase",
                87, 87, "accountRepository.debit(accountNo, total);",
                List.of("DATA_ACCESS", "DANGEROUS_OPERATION"), "CHANGED");

        LlmGateway.LocationDecision decision = gateway.repairLocation(new LlmGateway.LocationRepairRequest(
                UUID.randomUUID(), VulnerabilityType.VALIDATION_BYPASS, "客户端报价缺少验证",
                "服务端直接信任客户端价格", "漏洞已经确认", "MISSING_VALIDATION",
                "1497:82-83", "原始位置不是危险操作", List.of(candidate)));

        assertThat(decision.locationCandidateId()).isEqualTo("1549:87-87");
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("漏洞已经由 Critic 确认", "只能从 locationCandidates 中选择", "禁止重新判断");
        assertThat(gateway.requests.get(0).get(1).get("content"))
                .contains("\"candidateId\":\"1549:87-87\"", "\"failureReason\"");
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
                .contains("explore_call_graph", "search_code", "read_source", "verify_relation")
                .doesNotContain("get_call_chain({", "call_context({", "read_source_range({");
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
