package com.deepaudit.report;

import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AiReportSummary;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.Project;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.FindingMapper;
import com.deepaudit.mapper.ProjectMapper;
import com.deepaudit.mapper.AgentRunMapper;
import com.deepaudit.mapper.AiReportSummaryMapper;
import com.deepaudit.mapper.AuditHypothesisMapper;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class ReportService {

    private final AuditTaskMapper taskMapper;
    private final ProjectMapper projectMapper;
    private final FindingMapper findingMapper;
    private final AgentRunMapper agentRunMapper;
    private final AuditHypothesisMapper hypothesisMapper;
    private final AiReportSummaryMapper summaryMapper;

    public ReportService(AuditTaskMapper taskMapper,
                         ProjectMapper projectMapper,
                         FindingMapper findingMapper,
                         AgentRunMapper agentRunMapper,
                         AuditHypothesisMapper hypothesisMapper,
                         AiReportSummaryMapper summaryMapper) {
        this.taskMapper = taskMapper;
        this.projectMapper = projectMapper;
        this.findingMapper = findingMapper;
        this.agentRunMapper = agentRunMapper;
        this.hypothesisMapper = hypothesisMapper;
        this.summaryMapper = summaryMapper;
    }

    // 聚合任务、项目、确认发现、Agent 轨迹和假设为完整报告模型。
    public AuditReport report(UUID taskId) {
        AuditTask task = taskMapper.findById(taskId);
        if (task == null) throw new java.util.NoSuchElementException("扫描任务不存在: " + taskId);
        Project project = projectMapper.findById(task.getProjectId());
        if (project == null) throw new java.util.NoSuchElementException("项目不存在: " + task.getProjectId());
        return new AuditReport(project, task, summaryMapper.findByTaskId(taskId),
                findings(taskId), agentRunMapper.findByTaskId(taskId),
                hypothesisMapper.findByTaskId(taskId));
    }

    // 查询风险排序后的发现，并移除不面向用户展示的内部证据段。
    public List<Finding> findings(UUID taskId) {
        List<Finding> findings = findingMapper.findByTaskIdOrderByRisk(taskId);
        findings.forEach(finding -> finding.setEvidence(evidenceForDisplay(finding.getEvidence())));
        return findings;
    }

    // 将结构化报告渲染为自包含的中文 HTML 页面。
    public String html(UUID taskId) {
        AuditReport report = report(taskId);
        StringBuilder rows = new StringBuilder();
        for (Finding finding : report.findings()) {
            rows.append("<section><h2>").append(escape(finding.getTitle())).append("</h2>")
                    .append("<p><b>").append(escape(finding.getType().getDisplayName())).append(" · ")
                    .append(severityLabel(finding.getSeverity())).append(" · 可信度 ")
                    .append(confidenceLabel(finding.getConfidence())).append("</b></p>")
                    .append("<p>").append(escape(finding.getFilePath())).append(":").append(finding.getStartLine()).append("</p>")
                    .append(descriptionHtml(finding.getDescription()))
                    .append("<pre>").append(escape(finding.getEvidence())).append("</pre>")
                    .append("<p><b>修复建议：</b>").append(escape(finding.getRemediation())).append("</p></section>");
        }
        return "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>安全审计报告</title>"
                + "<style>body{max-width:980px;margin:40px auto;font:15px/1.7 sans-serif;color:#172033}"
                + "h1{border-bottom:3px solid #5b5cf0}section{margin:28px 0;padding:20px;border:1px solid #ddd;border-radius:12px}"
                + ".finding-description{margin-bottom:0}.critic-review{margin-top:1.2em;padding-top:1.2em;border-top:1px dashed #d7dce5}"
                + "pre{white-space:pre-wrap;background:#101727;color:#d8e3ff;padding:16px;border-radius:8px}</style></head><body>"
                + "<h1>DeepAudit Java 安全审计报告</h1><p>项目：" + escape(report.project().getName()) + "</p>"
                + "<p>任务状态：" + statusLabel(report.task().getStatus()) + "　问题数量："
                + report.findings().size() + "</p>"
                + "<section><h2>摘要</h2><p>" + escape(report.aiSummary() == null ? "暂无摘要"
                : report.aiSummary().getExecutiveSummary()) + "</p><p><b>审计覆盖：</b>"
                + escape(report.aiSummary() == null ? "暂无覆盖说明" : report.aiSummary().getCoverageSummary())
                // + "</p><p>Agent 运行数：" + report.agentRuns().size() + "　调查假设："
                // + report.hypotheses().size()
                + "</p>" + "</section>"
                + "<p>说明：本报告基于静态代码事实生成；所有结果仍建议人工复核。</p>"
                + rows + "</body></html>";
    }

    // 隐藏 SEMANTIC_FLOW 和 CRITIC 内部段，防止实现细节泄露到报告证据。
    private String evidenceForDisplay(String value) {
        if (value == null) return "";
        int semanticFlow = sectionStart(value, "[SEMANTIC_FLOW]");
        int critic = sectionStart(value, "[CRITIC]");
        int hiddenSection = semanticFlow < 0 ? critic : critic < 0 ? semanticFlow : Math.min(semanticFlow, critic);
        return (hiddenSection < 0 ? value : value.substring(0, hiddenSection)).stripTrailing();
    }

    private int sectionStart(String value, String marker) {
        int index = value.indexOf("\n\n" + marker);
        if (index >= 0) return index;
        return value.startsWith(marker) ? 0 : -1;
    }

    // 将漏洞描述与 Critic 复核意见拆成视觉上独立的报告段落。
    private String descriptionHtml(String value) {
        String description = value == null ? "" : value.strip();
        String marker = "Critic Agent 复核：";
        int critic = description.indexOf(marker);
        if (critic < 0) return "<p class='finding-description'>" + escape(description) + "</p>";
        String findingDescription = description.substring(0, critic).strip();
        String review = description.substring(critic + marker.length()).strip();
        return "<p class='finding-description'>" + escape(findingDescription) + "</p>"
                + "<p class='critic-review'><b>" + marker + "</b>" + escape(review) + "</p>";
    }

    private String severityLabel(com.deepaudit.domain.Severity severity) {
        return switch (severity) {
            case CRITICAL -> "严重";
            case HIGH -> "高危";
            case MEDIUM -> "中危";
            case LOW -> "低危";
        };
    }

    private String confidenceLabel(com.deepaudit.domain.Confidence confidence) {
        return switch (confidence) {
            case HIGH -> "高";
            case MEDIUM -> "中";
            case LOW -> "低";
        };
    }

    private String statusLabel(com.deepaudit.domain.AuditStatus status) {
        return switch (status) {
            case COMPLETED -> "已完成";
            case FAILED -> "失败";
            case CANCELLED -> "已取消";
            default -> "进行中";
        };
    }

    // 对动态报告文本进行 HTML 转义以阻断源码内容注入页面结构。
    private String escape(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    public record AuditReport(Project project, AuditTask task, AiReportSummary aiSummary,
                              List<Finding> findings, List<AgentRun> agentRuns,
                              List<AuditHypothesis> hypotheses) {
    }
}
