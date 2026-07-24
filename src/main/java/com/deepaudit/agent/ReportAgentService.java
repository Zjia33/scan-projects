package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.ai.AiResponseFormatException;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.AiReportSummary;
import com.deepaudit.domain.Finding;
import com.deepaudit.mapper.AiReportSummaryMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReportAgentService {
    private final LlmGateway llmGateway;
    private final AgentTraceService traceService;
    private final AiReportSummaryMapper summaryMapper;

    // 仅基于 Critic 已确认的发现生成管理摘要和覆盖说明。
    public AiReportSummary generate(UUID taskId, String projectName, LlmGateway.ReconInsight recon,
                                    List<Finding> findings, int completedAgents, int rejectedHypotheses,
                                    String auditContext) {
        AgentRun run = traceService.start(taskId, AgentType.REPORT, null, "AI 审计报告");
        try {
            // 将最终发现压缩为报告模型所需的只读事实，禁止引入新漏洞。
            List<LlmGateway.ReportFinding> facts = findings.stream().map(finding -> new LlmGateway.ReportFinding(
                    finding.getType(), finding.getSeverity(), finding.getConfidence(), finding.getTitle(),
                    finding.getFilePath() + ":" + finding.getStartLine(), finding.getDescription())).toList();
            run.setModelCallCount(1);
            traceService.event(taskId, run.getId(), AgentType.REPORT, AgentEventType.MODEL_CALL,
                    "正在将已通过 Critic 的发现整理为中文安全审计报告");
            LlmGateway.ReportNarrative narrative = llmGateway.writeReport(new LlmGateway.ReportRequest(
                    taskId, projectName, recon, facts, completedAgents, rejectedHypotheses, auditContext));
            AiReportSummary summary = persist(taskId, narrative.executiveSummary(), narrative.coverageSummary());
            traceService.event(taskId, run.getId(), AgentType.REPORT, AgentEventType.COMPLETED,
                    "Report Agent 已基于 " + findings.size() + " 个确认问题生成报告摘要");
            run.complete("AI 审计报告已生成");
            traceService.update(run);
            return summary;
        } catch (AiResponseFormatException exception) {
            // 报告模型格式异常时使用确定性摘要，保留已确认结果而不伪造内容。
            AiReportSummary summary = persist(taskId,
                    "本次代码安全审计共确认 " + findings.size() + " 个问题，所有问题均已通过独立 Critic 证据复核。",
                    auditContext + "。已完成项目侦察、智能规划、" + completedAgents + " 个专业 Agent 调查任务和反证检查；"
                            + rejectedHypotheses + " 个候选未进入最终报告。");
            traceService.event(taskId, run.getId(), AgentType.REPORT, AgentEventType.ERROR,
                    "Report Agent 返回格式异常，已使用确定性中文摘要完成报告");
            run.complete("已使用确定性中文摘要完成报告");
            traceService.update(run);
            return summary;
        } catch (RuntimeException exception) {
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), AgentType.REPORT, AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
    }

    // 以任务为粒度替换报告摘要，保证重新生成时只保留最新版本。
    private AiReportSummary persist(UUID taskId, String executiveSummary, String coverageSummary) {
        summaryMapper.deleteByTaskId(taskId);
        AiReportSummary summary = new AiReportSummary(taskId, safe(executiveSummary), safe(coverageSummary));
        summaryMapper.insert(summary);
        return summary;
    }

    private String safe(String value) {
        return value == null || value.isBlank() ? "模型未提供摘要" : value.strip();
    }
}
