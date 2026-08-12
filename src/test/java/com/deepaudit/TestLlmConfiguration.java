package com.deepaudit;

import com.deepaudit.agent.IncrementalReviewUnit;
import com.deepaudit.agent.TriageDisposition;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.recon.ReconSummary;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@TestConfiguration
public class TestLlmConfiguration {

    @Bean
    @Primary
    LlmGateway deterministicAgentLlmGateway() {
        return new LlmGateway() {
            @Override
            public ReconInsight inspectProject(UUID taskId, ReconSummary summary) {
                return new ReconInsight("Spring Boot Web 分层项目",
                        com.deepaudit.recon.TechnologyProfile.empty());
            }

            @Override
            public TriagePlan triageIncremental(UUID taskId, ReconInsight recon,
                                                List<IncrementalReviewUnit> reviewUnits) {
                List<TriageDecision> decisions = reviewUnits.stream().map(unit -> {
                    String code = (unit.baseCodeExcerpt() + " " + unit.targetCodeExcerpt())
                            .toLowerCase(java.util.Locale.ROOT);
                    LinkedHashSet<VulnerabilityType> types = new LinkedHashSet<>();
                    if (code.contains("statement.execute") || code.contains("executequery")
                            || code.contains("executeupdate") || code.contains("createstatement")) {
                        types.add(VulnerabilityType.SQL_INJECTION);
                    }
                    if (code.contains("innerhtml") || code.contains("document.write")
                            || code.contains("th:utext") || code.contains("v-html")) {
                        types.add(VulnerabilityType.STORED_XSS);
                    }
                    if (code.contains("skipverify") || code.contains("bypass")) {
                        types.add(VulnerabilityType.VALIDATION_BYPASS);
                    }
                    TriageDisposition disposition = types.isEmpty()
                            ? TriageDisposition.SKIP : TriageDisposition.INVESTIGATE;
                    return new TriageDecision(unit.unitId(), unit.primaryChunkId(), disposition,
                            List.copyOf(types),
                            types.isEmpty() ? "真实差异不支持具体安全假设" : "真实差异包含需要深入调查的安全操作");
                }).toList();
                return new TriagePlan("测试模型已完成真实增量差异审查", decisions);
            }

            @Override
            public TriagePlan triageIncrementalFinal(UUID taskId, ReconInsight recon,
                                                     IncrementalReviewUnit reviewUnit) {
                return triageIncremental(taskId, recon, List.of(reviewUnit));
            }

            @Override
            public AgentDecision decide(AgentTurn turn) {
                if (turn.observations().isEmpty()) {
                    return new AgentDecision("TOOL", tool(turn.vulnerabilityType()), toolArguments(turn),
                            "先检索与当前接口和变量相关的跨文件证据", null);
                }
                VulnerabilityType type = turn.vulnerabilityType();
                FindingProposal finding = new FindingProposal(type, severity(type), Confidence.HIGH,
                        title(type), "测试 Agent 根据目标代码和工具返回的实际代码形成证据链。",
                        "根据漏洞类型补充服务端校验并避免信任客户端输入。", turn.target().chunkId(),
                        evidenceIds(turn), turn.target().startLine(), turn.target().endLine());
                return new AgentDecision("FINDING", null, Map.of(), "证据足以提交 Critic", finding);
            }

            @Override
            public CriticDecision critique(CriticRequest request) {
                com.deepaudit.domain.FindingDeltaStatus delta =
                        com.deepaudit.domain.FindingDeltaStatus.NEW;
                return new CriticDecision(true, Confidence.HIGH,
                        "未找到能够推翻候选的权限或参数化反证", delta,
                        request.proposal().primaryChunkId(), request.proposal().vulnerabilityStartLine(),
                        request.proposal().vulnerabilityEndLine(), rootCause(request.proposal().type()),
                        locationRole(request.proposal().type()), null,
                        CriticVerdict.CONFIRMED, List.of());
            }

            @Override
            public LocationDecision repairLocation(LocationRepairRequest request) {
                return request.locationCandidates().stream().findFirst()
                        .map(candidate -> new LocationDecision(candidate.candidateId(), "测试模型选择真实源码候选"))
                        .orElse(new LocationDecision(null, "没有可用位置候选"));
            }

            @Override
            public ReportNarrative writeReport(ReportRequest request) {
                return new ReportNarrative("AI Agents 已完成订单接口安全审查并确认 "
                        + request.findings().size() + " 个问题。");
            }

            private String tool(VulnerabilityType type) {
                return switch (type) {
                    case SQL_INJECTION -> "resolve_data_access";
                    case AUTHORIZATION -> "inspect_security_policy";
                    case SENSITIVE_INFORMATION_DISCLOSURE -> "read_source";
                    default -> "explore_call_graph";
                };
            }

            private Map<String, Object> toolArguments(AgentTurn turn) {
                return switch (turn.vulnerabilityType()) {
                    case SQL_INJECTION -> Map.of("selector", turn.target().symbolName(), "depth", 3, "limit", 5);
                    case AUTHORIZATION -> Map.of(
                            "endpoint", turn.target().endpoint() == null ? "" : turn.target().endpoint(), "limit", 5);
                    case SENSITIVE_INFORMATION_DISCLOSURE -> Map.of(
                            "chunkId", turn.target().chunkId());
                    default -> Map.of("limit", 5);
                };
            }

            private List<Long> evidenceIds(AgentTurn turn) {
                LinkedHashSet<Long> ids = new LinkedHashSet<>();
                ids.add(turn.target().chunkId());
                java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("CHUNK (\\d+)")
                        .matcher(turn.semanticEvidence() == null ? "" : turn.semanticEvidence());
                while (matcher.find()) ids.add(Long.parseLong(matcher.group(1)));
                return List.copyOf(ids);
            }

            private Severity severity(VulnerabilityType type) {
                return type == VulnerabilityType.SQL_INJECTION ? Severity.CRITICAL : Severity.HIGH;
            }

            private String title(VulnerabilityType type) {
                return switch (type) {
                    case SQL_INJECTION -> "动态 SQL 存在注入风险";
                    case AUTHORIZATION -> "接口存在越权访问风险";
                    case SENSITIVE_INFORMATION_DISCLOSURE -> "代码或响应中可能泄露敏感信息";
                    case STORED_XSS -> "持久化内容可能进入非转义输出";
                    case VALIDATION_BYPASS -> "验证流程可能被绕过";
                };
            }

            private String rootCause(VulnerabilityType type) {
                return switch (type) {
                    case SQL_INJECTION -> "UNSAFE_QUERY";
                    case AUTHORIZATION -> "MISSING_AUTHORIZATION_CHECK";
                    case SENSITIVE_INFORMATION_DISCLOSURE -> "UNSAFE_DATA_EXPOSURE";
                    case STORED_XSS -> "UNSAFE_OUTPUT";
                    case VALIDATION_BYPASS -> "MISSING_VALIDATION";
                };
            }

            private String locationRole(VulnerabilityType type) {
                return switch (type) {
                    case SQL_INJECTION -> "QUERY";
                    case AUTHORIZATION -> "SECURITY_BOUNDARY";
                    case SENSITIVE_INFORMATION_DISCLOSURE, STORED_XSS -> "DATA_OUTPUT";
                    case VALIDATION_BYPASS -> "VALIDATION";
                };
            }
        };
    }
}
