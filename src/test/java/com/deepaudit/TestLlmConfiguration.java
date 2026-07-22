package com.deepaudit;

import com.deepaudit.agent.OrchestratorAgentService;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.recon.ReconSummary;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;

@TestConfiguration
public class TestLlmConfiguration {

    @Bean
    @Primary
    LlmGateway deterministicAgentLlmGateway() {
        return new LlmGateway() {
            @Override
            public ReconInsight inspectProject(UUID taskId, ReconSummary summary, List<Target> targets) {
                return new ReconInsight("Spring Boot Web 项目，包含订单查询接口", List.of("HTTP API"),
                        List.of("未观察到统一权限配置"), List.of("订单资源访问", "动态 SQL"));
            }

            @Override
            public AuditPlan createPlan(UUID taskId, ReconInsight recon, List<Target> targets) {
                List<PlannedTask> tasks = new ArrayList<>();
                for (Target target : targets) {
                    for (VulnerabilityType type : target.hints()) {
                        tasks.add(new PlannedTask(target.chunkId(), OrchestratorAgentService.agentFor(type), type,
                                "测试模型根据代码事实选择专业 Agent"));
                    }
                }
                return new AuditPlan("测试模型已制定覆盖所有规则提示的计划", tasks);
            }

            @Override
            public AgentDecision decide(AgentTurn turn) {
                if (turn.observations().isEmpty()) {
                    return new AgentDecision("TOOL", tool(turn.vulnerabilityType()), dynamicQuery(turn), 5,
                            "先检索与当前接口和变量相关的跨文件证据", null);
                }
                VulnerabilityType type = turn.vulnerabilityType();
                FindingProposal finding = new FindingProposal(type, severity(type), Confidence.HIGH,
                        title(type), "测试 Agent 根据目标代码和工具返回的实际代码形成证据链。",
                        "根据漏洞类型补充服务端校验并避免信任客户端输入。", turn.target().chunkId(),
                        evidenceIds(turn));
                return new AgentDecision("FINDING", null, null, 0, "证据足以提交 Critic", finding);
            }

            @Override
            public CriticDecision critique(CriticRequest request) {
                return new CriticDecision(true, Confidence.HIGH, "未找到能够推翻候选的权限或参数化反证");
            }

            @Override
            public ReportNarrative writeReport(ReportRequest request) {
                return new ReportNarrative("AI Agents 已完成订单接口安全审查并确认 "
                        + request.findings().size() + " 个问题。", "已执行 Recon、规划、专业调查和 Critic 复核。");
            }

            private String tool(VulnerabilityType type) {
                return switch (type) {
                    case SQL_INJECTION -> "data_access";
                    case AUTHORIZATION, UNAUTHORIZED_DISCLOSURE -> "security_controls";
                    default -> "hybrid_search";
                };
            }

            private String dynamicQuery(AgentTurn turn) {
                return turn.target().symbolName() + " " + turn.target().endpoint() + " "
                        + turn.target().parameters() + " " + turn.vulnerabilityType();
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
                    case UNAUTHORIZED_DISCLOSURE -> "公开接口可能泄露敏感信息";
                    case STORED_XSS -> "持久化内容可能进入非转义输出";
                    case VALIDATION_BYPASS -> "验证流程可能被绕过";
                    case FINANCIAL_RISK -> "资金操作缺少关键安全约束";
                };
            }
        };
    }
}
