package com.deepaudit.report;

import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AiReportSummary;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.Project;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.agent.FindingLocationResolver;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.FindingMapper;
import com.deepaudit.mapper.ProjectMapper;
import com.deepaudit.mapper.AgentRunMapper;
import com.deepaudit.mapper.AiReportSummaryMapper;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.CodeChunkMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.UUID;

// 负责 ReportService 对应的业务编排和处理。
@Service
@RequiredArgsConstructor
public class ReportService {

    private final AuditTaskMapper taskMapper;
    private final ProjectMapper projectMapper;
    private final FindingMapper findingMapper;
    private final AgentRunMapper agentRunMapper;
    private final AuditHypothesisMapper hypothesisMapper;
    private final AiReportSummaryMapper summaryMapper;
    private final GitFileChangeMapper changeMapper;
    private final CodeChunkMapper chunkMapper;

    // 聚合任务、项目、确认发现、Agent 轨迹和假设为完整报告模型。
    public AuditReport report(UUID taskId) {
        AuditTask task = taskMapper.findById(taskId);
        if (task == null) throw new java.util.NoSuchElementException("扫描任务不存在: " + taskId);
        Project project = projectMapper.findById(task.getProjectId());
        if (project == null) throw new java.util.NoSuchElementException("项目不存在: " + task.getProjectId());
        return new AuditReport(project, task, summaryMapper.findByTaskId(taskId),
                findings(taskId), agentRunMapper.findByTaskId(taskId),
                hypothesisMapper.findByTaskId(taskId), changeMapper.findByTaskId(taskId));
    }

    // 查询风险排序后的发现，并移除不面向用户展示的内部证据段。
    public List<Finding> findings(UUID taskId) {
        List<Finding> findings = findingMapper.findByTaskIdOrderByRisk(taskId);
        AuditTask task = taskMapper.findById(taskId);
        Map<Long, CodeChunk> chunks = new LinkedHashMap<>();
        chunkMapper.findByTaskId(taskId).forEach(chunk -> chunks.put(chunk.getId(), chunk));
        findings.forEach(finding -> {
            if (task != null) {
                // 同时归一化历史记录，确保增量 API 和最终报告不再展示 BASELINE/REGRESSED/AFFECTED。
                finding.setDeltaStatus(FindingDeltaStatus.normalizeFor(
                        task.getScanMode(), finding.getDeltaStatus()));
            }
            finding.setEvidence(evidenceForDisplay(finding.getEvidence()));
            localizeLegacyEvidence(finding, chunks);
        });
        return findings;
    }

    // 历史 Finding 保存的是完整方法；读取时利用仍在任务索引中的代码块转换为局部上下文。
    private void localizeLegacyEvidence(Finding finding, Map<Long, CodeChunk> chunks) {
        if (finding.getEvidence().contains("[漏洞位置]")) return;
        List<Long> evidenceIds = evidenceChunkIds(finding.getEvidence());
        CodeChunk primary = evidenceIds.stream().map(chunks::get).filter(Objects::nonNull)
                .findFirst().orElseGet(() -> chunks.values().stream()
                        .filter(chunk -> Objects.equals(chunk.getFilePath(), finding.getFilePath()))
                        .filter(chunk -> finding.getStartLine() >= chunk.getStartLine()
                                && finding.getStartLine() <= chunk.getEndLine())
                        .findFirst().orElse(null));
        if (primary == null) return;
        if (evidenceIds.isEmpty()) evidenceIds = List.of(primary.getId());
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                finding.getType(), finding.getSeverity(), finding.getConfidence(), finding.getTitle(),
                finding.getDescription(), finding.getRemediation(), primary.getId(), evidenceIds);
        FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, primary);
        finding.setStartLine(location.startLine());
        finding.setEndLine(location.endLine());
        finding.setEvidence(FindingLocationResolver.formatEvidence(proposal, chunks));
    }

    // 执行 ReportService 中的 evidenceChunkIds 处理。
    private List<Long> evidenceChunkIds(String evidence) {
        Matcher matcher = Pattern.compile("\\[CHUNK (\\d+)]").matcher(evidence == null ? "" : evidence);
        java.util.ArrayList<Long> ids = new java.util.ArrayList<>();
        while (matcher.find()) ids.add(Long.parseLong(matcher.group(1)));
        return ids.stream().distinct().toList();
    }

    // 将结构化报告渲染为自包含的中文 HTML 页面。
    public String html(UUID taskId) {
        AuditReport report = report(taskId);
        StringBuilder rows = new StringBuilder();
        List<AuditHypothesis> unlocated = report.hypotheses().stream()
                .filter(hypothesis -> hypothesis.getStatus()
                        == com.deepaudit.domain.HypothesisStatus.CONFIRMED_UNLOCATED)
                .toList();
        StringBuilder unlocatedRows = new StringBuilder();
        for (AuditHypothesis hypothesis : unlocated) {
            unlocatedRows.append("<article class='unlocated-card'><h3>")
                    .append(escape(hypothesis.getClaim())).append("</h3><p class='badges'><span>")
                    .append(escape(hypothesis.getType().getDisplayName()))
                    .append("</span><span>可信度 ").append(confidenceLabel(hypothesis.getConfidence()))
                    .append("</span></p><p>").append(escape(hypothesis.getCriticReason()))
                    .append("</p><small>该漏洞结论已保留；由于精确源码位置尚未通过定位门禁，报告不标红任意代码行。</small></article>");
        }
        int findingNumber = 0;
        for (Finding finding : report.findings()) {
            findingNumber++;
            rows.append("<article class='finding-card'><header class='finding-head'>")
                    .append("<span class='finding-number'>")
                    .append(String.format(java.util.Locale.ROOT, "%02d", findingNumber)).append("</span>")
                    .append("<div><h2>").append(escape(finding.getTitle())).append("</h2><p class='badges'>")
                    .append("<span>").append(escape(finding.getType().getDisplayName())).append("</span>")
                    .append("<span>").append(severityLabel(finding.getSeverity())).append("</span>")
                    .append("<span>可信度 ").append(confidenceLabel(finding.getConfidence())).append("</span>")
                    .append("<span>").append(deltaLabel(finding.getDeltaStatus())).append("</span>")
                    .append("</p></div></header><div class='finding-body'>")
                    .append("<p class='vulnerability-location'><b>实际漏洞位置</b><span>")
                    .append(escape(finding.getFilePath())).append(":").append(finding.getStartLine())
                    .append(finding.getEndLine() == finding.getStartLine()
                            ? "" : "-" + finding.getEndLine()).append("</span></p>")
                    .append(descriptionHtml(finding.getDescription()))
                    .append(evidenceHtml(finding.getEvidence()))
                    .append("<section class='content-block remediation'><h3>修复建议</h3><p>")
                    .append(escape(finding.getRemediation())).append("</p></section></div></article>");
        }
        return "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>安全审计报告</title>"
                + "<meta name='viewport' content='width=device-width,initial-scale=1'><style>" + reportStyles()
                + "</style></head><body><main class='report-shell'>"
                + "<header class='report-hero'><p class='eyebrow'>DEEPAUDIT · SECURITY REVIEW</p>"
                + "<h1>代码安全审计报告</h1>"
                // "<p class='hero-copy'>基于代码事实、语义关系和多 Agent 复核生成的安全审计结果。</p>"
                + "<div class='report-meta'><article><small>项目</small><strong>" + escape(report.project().getName()) + "</strong></article>"
                + "<article><small>扫描范围</small><strong>" + escape(report.task().getScanMode().name()) + "</strong></article>"
                + "<article><small>目标提交</small><strong>" + escape(shortSha(report.task().getTargetCommitSha())) + "</strong></article>"
                + "<article><small>精确定位问题</small><strong>" + report.findings().size() + "</strong></article>"
                + "<article><small>定位待复核</small><strong>" + unlocated.size() + "</strong></article></div></header>"
                + "<section class='context-card'><div><small>版本范围</small><p>Target："
                + escape(shortSha(report.task().getTargetCommitSha()))
                + (report.task().getBaseCommitSha() == null ? "" : "　Base：" + escape(shortSha(report.task().getBaseCommitSha())))
                + (report.task().getMergeBaseSha() == null
                || report.task().getMergeBaseSha().equals(report.task().getBaseCommitSha()) ? ""
                : "　实际比较基线：" + escape(shortSha(report.task().getMergeBaseSha())))
                + "</p></div><div><small>任务状态</small><p>" + statusLabel(report.task().getStatus()) + "</p></div>"
                + "<div class='wide'><small>变更摘要</small><p>" + escape(report.task().getChangeSummary()) + "</p></div></section>"
                + "<section class='summary-card'><p class='section-label'>EXECUTIVE SUMMARY</p><h2>审计摘要</h2><p>"
                + escape(report.aiSummary() == null ? "暂无摘要" : report.aiSummary().getExecutiveSummary())
                + "</p><div class='coverage'><b>审计覆盖</b><span>"
                + escape(report.aiSummary() == null ? "暂无覆盖说明" : report.aiSummary().getCoverageSummary())
                + "</span></div></section><div class='findings-heading'><div><p class='section-label'>CONFIRMED FINDINGS</p>"
                + "<h2>确认漏洞</h2></div><span>" + report.findings().size() + "</span></div>"
                + (report.findings().isEmpty() ? "<div class='empty-report'>本轮审计没有产生已完成精确定位的问题。</div>" : rows)
                + (unlocated.isEmpty() ? "" : "<div class='findings-heading'><div><p class='section-label'>CONFIRMED · LOCATION PENDING</p>"
                + "<h2>已确认但定位待复核</h2></div><span>" + unlocated.size() + "</span></div>" + unlocatedRows)
                + "<footer>本报告基于静态代码事实生成，所有结果仍建议结合业务场景进行人工复核。</footer>"
                + "</main></body></html>";
    }

    // 隐藏 SEMANTIC_FLOW 和 CRITIC 内部段，防止实现细节泄露到报告证据。
    private String evidenceForDisplay(String value) {
        if (value == null) return "";
        int semanticFlow = sectionStart(value, "[SEMANTIC_FLOW]");
        int critic = sectionStart(value, "[CRITIC]");
        int hiddenSection = semanticFlow < 0 ? critic : critic < 0 ? semanticFlow : Math.min(semanticFlow, critic);
        return (hiddenSection < 0 ? value : value.substring(0, hiddenSection)).stripTrailing();
    }

    // 执行 ReportService 中的 sectionStart 处理。
    private int sectionStart(String value, String marker) {
        int index = value.indexOf("\n\n" + marker);
        if (index >= 0) return index;
        return value.startsWith(marker) ? 0 : -1;
    }

    // 面向报告读者只保留一份漏洞说明；Critic 仍参与确认，但不重复展示相近内容。
    private String descriptionHtml(String value) {
        String description = value == null ? "" : value.strip();
        String marker = "Critic Agent 复核：";
        int critic = description.indexOf(marker);
        if (critic < 0) return contentBlock("漏洞说明", description, "finding-description");
        String findingDescription = description.substring(0, critic).strip();
        String review = description.substring(critic + marker.length()).strip();
        return contentBlock("漏洞说明", findingDescription.isBlank() ? review : findingDescription,
                "finding-description");
    }

    // 将证据按 CHUNK 拆分为独立代码卡片，并移除旧的漏洞行红色标记。
    private String evidenceHtml(String value) {
        StringBuilder html = new StringBuilder("<section class='content-block'><h3>代码证据</h3>"
                + "<div class='evidence-list'>");
        List<EvidenceChunk> chunks = evidenceChunks(value);
        for (int index = 0; index < chunks.size(); index++) {
            EvidenceChunk chunk = chunks.get(index);
            html.append("<article class='evidence-chunk'><header><b>")
                    .append(escape(chunk.id().isBlank() ? "证据 " + (index + 1) : "CHUNK " + chunk.id()))
                    .append("</b><span>").append(escape(chunk.location().isBlank() ? "代码上下文" : chunk.location()))
                    .append("</span></header>").append(codeLinesHtml(chunk.code())).append("</article>");
        }
        return html.append("</div></section>").toString();
    }

    private List<EvidenceChunk> evidenceChunks(String value) {
        String evidence = value == null ? "" : value;
        Pattern header = Pattern.compile("^\\[CHUNK\\s+(\\d+)]\\s*(.*)$");
        List<EvidenceChunk> chunks = new ArrayList<>();
        String id = "";
        String location = "";
        StringBuilder code = new StringBuilder();
        for (String line : evidence.split("\\R", -1)) {
            Matcher matcher = header.matcher(line);
            if (matcher.matches()) {
                addEvidenceChunk(chunks, id, location, code);
                id = matcher.group(1);
                location = matcher.group(2).strip();
                code = new StringBuilder();
            } else {
                code.append(line).append('\n');
            }
        }
        addEvidenceChunk(chunks, id, location, code);
        if (chunks.isEmpty()) chunks.add(new EvidenceChunk("", "", "暂无代码证据"));
        return List.copyOf(chunks);
    }

    private String codeLinesHtml(String value) {
        String source = value == null || value.isBlank() ? "暂无代码证据" : value;
        Pattern numberedLine = Pattern.compile("^(>>> |\\s{4})(\\s*\\d+)\\s*\\|\\s?(.*)$");
        StringBuilder html = new StringBuilder("<div class='evidence-code'>");
        for (String line : source.split("\\R", -1)) {
            Matcher matcher = numberedLine.matcher(line);
            boolean vulnerable = line.startsWith(">>> ");
            html.append("<div class='evidence-code-line")
                    .append(vulnerable ? " vulnerable" : line.strip().equals("…") ? " ellipsis" : "")
                    .append("'>");
            if (matcher.matches()) {
                html.append("<span class='evidence-line-number'>").append(escape(matcher.group(2).strip()))
                        .append("</span><code>").append(escape(matcher.group(3).isEmpty() ? " " : matcher.group(3)))
                        .append("</code>");
            } else if (line.strip().equals("…")) {
                html.append("<span class='evidence-line-number'>…</span><code> </code>");
            } else {
                html.append("<span class='evidence-line-number'></span><code>")
                        .append(escape(line.isEmpty() ? " " : line)).append("</code>");
            }
            html.append("</div>");
        }
        return html.append("</div>").toString();
    }

    private void addEvidenceChunk(List<EvidenceChunk> chunks, String id, String location, StringBuilder code) {
        String content = code.toString().strip();
        if (!id.isBlank() || !location.isBlank() || !content.isBlank()) {
            chunks.add(new EvidenceChunk(id, location, content));
        }
    }

    private String contentBlock(String title, String content, String className) {
        if (content == null || content.isBlank()) return "";
        return "<section class='content-block'><h3>" + escape(title) + "</h3><p class='" + className + "'>"
                + escape(content) + "</p></section>";
    }

    private String reportStyles() {
        return """
                :root{color-scheme:light;--ink:#172033;--muted:#667187;--line:#dfe5ee;--soft:#f5f7fa;--blue:#356ae6;--nav:#111a2b;--cyan:#38b7a3}
                *{box-sizing:border-box}body{margin:0;background:#eef2f7;color:var(--ink);font:14px/1.7 Inter,"Segoe UI","Microsoft YaHei",sans-serif}
                .report-shell{width:min(1080px,calc(100% - 32px));margin:32px auto 56px}.report-hero{padding:34px 38px;color:white;background:linear-gradient(135deg,#111a2b 0%,#182846 70%,#204e75 100%);border-radius:18px;box-shadow:0 18px 42px rgba(18,33,59,.16)}
                .eyebrow,.section-label{margin:0;color:#7de2d1;font-size:10px;font-weight:800;letter-spacing:.14em}.report-hero h1{margin:8px 0 4px;font-size:34px;line-height:1.2}.hero-copy{margin:0;color:#b8c4d7}
                .report-meta{margin-top:28px;display:grid;grid-template-columns:1.6fr repeat(3,1fr);gap:10px}.report-meta article{min-width:0;padding:13px 15px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:10px}.report-meta small,.report-meta strong{display:block}.report-meta small{color:#91a0b7;font-size:9px}.report-meta strong{margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
                .context-card,.summary-card,.finding-card,.unlocated-card,.empty-report{margin-top:18px;background:white;border:1px solid var(--line);border-radius:14px;box-shadow:0 7px 24px rgba(22,35,57,.05)}.context-card{padding:19px 22px;display:grid;grid-template-columns:2fr 1fr;gap:14px 28px}.context-card .wide{grid-column:1/-1}.context-card small{color:var(--muted);font-size:9px;font-weight:700}.context-card p{margin:3px 0 0;overflow-wrap:anywhere}.unlocated-card{padding:19px 22px;border-color:#e5b96b;background:#fffaf0}.unlocated-card h3{margin:0;font-size:16px}.unlocated-card>p{white-space:pre-wrap}.unlocated-card>small{color:#805b1f}
                .summary-card{padding:26px 28px}.summary-card h2,.findings-heading h2{margin:5px 0 8px;font-size:23px}.summary-card>p:not(.section-label){margin:0;white-space:pre-wrap}.coverage{margin-top:18px;padding:13px 15px;display:grid;grid-template-columns:100px 1fr;gap:12px;background:var(--soft);border-radius:9px}.coverage span{color:#536075}
                .findings-heading{margin:32px 2px 10px;display:flex;justify-content:space-between;align-items:end}.findings-heading>span{min-width:34px;height:34px;padding:0 10px;display:grid;place-items:center;color:var(--blue);background:#eaf0ff;border-radius:9px;font-weight:800}.finding-card{overflow:hidden}.finding-head{padding:18px 22px;display:grid;grid-template-columns:38px 1fr;gap:14px;align-items:start}.finding-number{width:36px;height:36px;display:grid;place-items:center;color:white;background:var(--nav);border-radius:9px;font:800 10px monospace}.finding-head h2{margin:0;font-size:17px;line-height:1.4}.badges{margin:7px 0 0;display:flex;flex-wrap:wrap;gap:6px}.badges span{padding:3px 7px;color:#536075;background:var(--soft);border:1px solid var(--line);border-radius:5px;font-size:9px;font-weight:700}
                .finding-body{padding:20px 24px 24px 74px;border-top:1px solid var(--line)}.vulnerability-location{margin:0;padding:10px 12px;display:flex;gap:14px;align-items:baseline;color:#2557be;background:#edf3ff;border:1px solid #cbd9fb;border-radius:8px;font:700 12px/1.6 monospace}.vulnerability-location b{flex:0 0 auto;color:#234b9e;font:700 10px/1.6 Inter,"Segoe UI",sans-serif}.vulnerability-location span{overflow-wrap:anywhere}
                .content-block{margin-top:18px}.content-block h3{margin:0 0 8px;font-size:12px}.finding-description,.remediation p{margin:0;white-space:pre-wrap}.finding-description{padding:14px 16px;background:#f8fafd;border-left:3px solid var(--blue);border-radius:0 9px 9px 0}.remediation{padding:14px 16px;background:#eef9f7;border:1px solid #ccebe5;border-radius:9px}.remediation h3{color:#197d70}
                .evidence-list{display:grid;gap:11px}.evidence-chunk{min-width:0;overflow:hidden;background:var(--nav);border:1px solid #2a3750;border-radius:10px}.evidence-chunk header{min-height:40px;padding:9px 13px;display:flex;justify-content:space-between;align-items:center;gap:14px;border-bottom:1px solid #2a3750}.evidence-chunk header b{flex:0 0 auto;color:#7de2d1;font:800 9px monospace;letter-spacing:.06em}.evidence-chunk header span{min-width:0;overflow:hidden;color:#93a0b5;text-overflow:ellipsis;white-space:nowrap;font:10px monospace}.evidence-code{max-height:380px;padding:11px 0;overflow:auto;color:#dbe3ef;font:11px/1.7 "SFMono-Regular",Consolas,monospace}.evidence-code-line{min-width:max-content;display:grid;grid-template-columns:62px minmax(620px,1fr)}.evidence-line-number{padding:0 13px 0 8px;color:#728097;border-right:1px solid #2a3750;text-align:right;user-select:none}.evidence-code-line code{padding:0 16px;color:inherit;white-space:pre;font:inherit}.evidence-code-line.vulnerable{color:#dffaf5;background:rgba(56,183,163,.16);box-shadow:inset 3px 0 var(--cyan)}.evidence-code-line.vulnerable .evidence-line-number{color:#7de2d1;font-weight:800}.evidence-code-line.ellipsis{color:#65748b}
                .empty-report{padding:42px;text-align:center;color:var(--muted)}footer{padding:24px 4px 0;color:#7b8799;text-align:center;font-size:11px}
                @media(max-width:700px){.report-shell{width:min(100% - 18px,1080px);margin-top:9px}.report-hero{padding:25px 22px}.report-meta{grid-template-columns:1fr 1fr}.context-card{grid-template-columns:1fr}.context-card .wide{grid-column:auto}.finding-body{padding:17px}.finding-head{padding:16px}.coverage{grid-template-columns:1fr}.vulnerability-location{display:block}.vulnerability-location span{display:block;margin-top:4px}.evidence-chunk header{align-items:flex-start;flex-direction:column;gap:3px}.evidence-chunk header span{width:100%}}
                @media print{body{background:white}.report-shell{width:100%;margin:0}.report-hero,.context-card,.summary-card,.finding-card{box-shadow:none}.finding-card{break-inside:avoid}.evidence-code{max-height:none}}
                """;
    }

    private record EvidenceChunk(String id, String location, String code) {
    }

    // 执行 ReportService 中的 severityLabel 处理。
    private String severityLabel(com.deepaudit.domain.Severity severity) {
        return switch (severity) {
            case CRITICAL -> "严重";
            case HIGH -> "高危";
            case MEDIUM -> "中危";
            case LOW -> "低危";
        };
    }

    // 执行 ReportService 中的 confidenceLabel 处理。
    private String confidenceLabel(com.deepaudit.domain.Confidence confidence) {
        return switch (confidence) {
            case HIGH -> "高";
            case MEDIUM -> "中";
            case LOW -> "低";
        };
    }

    // 执行 ReportService 中的 statusLabel 处理。
    private String statusLabel(com.deepaudit.domain.AuditStatus status) {
        return switch (status) {
            case COMPLETED -> "已完成";
            case FAILED -> "失败";
            case CANCELLED -> "已取消";
            default -> "进行中";
        };
    }

    // 执行 ReportService 中的 deltaLabel 处理。
    private String deltaLabel(com.deepaudit.domain.FindingDeltaStatus status) {
        if (status == null) return "全量基线";
        return switch (status) {
            case BASELINE -> "全量基线";
            case NEW -> "变更新增";
            case REGRESSED -> "安全回归";
            case PERSISTING -> "持续存在";
            case AFFECTED -> "变更影响";
        };
    }

    // 执行 ReportService 中的 shortSha 处理。
    private String shortSha(String value) {
        return value == null ? "" : value.substring(0, Math.min(8, value.length()));
    }

    // 对动态报告文本进行 HTML 转义以阻断源码内容注入页面结构。
    private String escape(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    // 封装 AuditReport 使用的不可变结构化数据。
    public record AuditReport(Project project, AuditTask task, AiReportSummary aiSummary,
                              List<Finding> findings, List<AgentRun> agentRuns,
                              List<AuditHypothesis> hypotheses,
                              List<com.deepaudit.domain.GitFileChange> changes) {
    }
}
