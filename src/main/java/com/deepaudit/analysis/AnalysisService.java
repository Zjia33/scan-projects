package com.deepaudit.analysis;

import com.deepaudit.agent.AgentCandidate;
import com.deepaudit.agent.AgentCandidateConsolidator;
import com.deepaudit.agent.AgentTask;
import com.deepaudit.agent.AgentTraceService;
import com.deepaudit.agent.CriticAgentService;
import com.deepaudit.agent.OrchestratorAgentService;
import com.deepaudit.agent.ProfessionalAgentRunner;
import com.deepaudit.agent.ReconAgentService;
import com.deepaudit.agent.ReportAgentService;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.ai.AiResponseFormatException;
import com.deepaudit.ai.AiUnavailableException;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.mapper.AiReportSummaryMapper;
import com.deepaudit.mapper.FindingMapper;
import com.deepaudit.orchestrator.AuditCancellationService;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.semantic.SemanticAnalysisService;
import com.deepaudit.semantic.SemanticEvidenceService;
import com.deepaudit.semantic.IncrementalScopeService;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisService {
    private final List<VulnerabilityAnalyzer> hintProviders;
    private final CodeChunkMapper chunkMapper;
    private final FindingMapper findingMapper;
    private final AgentTraceService traceService;
    private final ReconAgentService reconAgent;
    private final OrchestratorAgentService orchestratorAgent;
    private final ProfessionalAgentRunner professionalAgentRunner;
    private final CriticAgentService criticAgent;
    private final ReportAgentService reportAgent;
    private final SemanticAnalysisService semanticAnalysisService;
    private final SemanticEvidenceService semanticEvidenceService;
    private final IncrementalScopeService incrementalScopeService;
    private final AiReportSummaryMapper reportSummaryMapper;
    private final AuditCancellationService cancellationService;

    // 执行从语义索引和调查线索到 Critic 确认、落库及报告生成的完整分析链。
    public AnalysisResult analyze(UUID taskId, Path projectRoot, ReconSummary reconSummary,
                                  String projectName, AuditTask task) {
        long analysisStarted = ExecutionTiming.start();
        long stageStarted = ExecutionTiming.start();
        cancellationService.throwIfCancellationRequested(taskId);
        // 清理旧发现和 Agent 轨迹，保证重跑结果不混入历史数据。
        findingMapper.deleteByTaskId(taskId);
        traceService.reset(taskId);
        cancellationService.throwIfCancellationRequested(taskId);
        // 初始只加载直接变更块，CodeGraph 命中的影响与上下文块在后续按需补入。
        List<CodeChunk> chunks = chunkMapper.findByTaskId(taskId);
        logTiming(taskId, "ANALYSIS_RESET_AND_LOAD", stageStarted, analysisStarted,
                "initialChunks=" + chunks.size());
        stageStarted = ExecutionTiming.start();
        IncrementalScopeService.ScopeResult incrementalScope = incrementalScopeService.determine(taskId, chunks);
        Set<Long> changedChunkIds = incrementalScope.changedChunkIds();
        if (changedChunkIds.isEmpty()) {
            throw new IllegalStateException("两次提交之间没有可供 Agent 审查的 CHANGED 代码块");
        }
        TimingDetailLog.info("任务 {} 增量范围：{} 个 CHANGED 审查目标；IMPACTED 源码将在专业调查时按需选择，"
                        + "全局配置变化={}", taskId, changedChunkIds.size(),
                incrementalScope.globalConfigurationChanged());
        TimingDetailLog.info("任务 {} 方法级语义变化：{}", taskId, incrementalScope.semanticChangeSummary());
        logTiming(taskId, "IMPACT_SCOPE", stageStarted, analysisStarted,
                "changed=" + changedChunkIds.size() + ",preloadedImpacted=0");

        // 轻量语义只分析 CHANGED，用于局部参数、Guard、Sink 和确定性提示；不扩张调用图。
        stageStarted = ExecutionTiming.start();
        SemanticAnalysisService.Summary semanticSummary = semanticAnalysisService.rebuild(
                taskId, projectRoot, chunks, changedChunkIds);
        cancellationService.throwIfCancellationRequested(taskId);
        logTiming(taskId, "SCOPED_SEMANTIC_ANALYSIS", stageStarted, analysisStarted,
                "scopeChunks=" + changedChunkIds.size() + ",relations=" + semanticSummary.callEdgeCount()
                        + ",securityFlows=" + semanticSummary.securityFlowCount());
        stageStarted = ExecutionTiming.start();
        HintIndex hintIndex = collectHints(taskId, projectRoot, chunks, changedChunkIds);
        mergeSemanticHints(taskId, hintIndex, changedChunkIds);
        cancellationService.throwIfCancellationRequested(taskId);
        TimingDetailLog.info("任务 {} 生成 {} 个规则调查目标，类型分布: {}", taskId,
                hintIndex.typesByChunk().size(), hintIndex.typesByChunk());
        TimingDetailLog.info("任务 {} CHANGED 检测索引：{} 个符号、{} 条局部关系边、{} 条安全数据流；"
                        + "框架语义边 {}，局部调用点 {}",
                taskId, semanticSummary.symbolCount(), semanticSummary.callEdgeCount(),
                semanticSummary.securityFlowCount(), semanticSummary.frameworkEdgeCount(),
                semanticSummary.localCallSiteCount());
        logTiming(taskId, "DETERMINISTIC_HINTS", stageStarted, analysisStarted,
                "changed=" + changedChunkIds.size() + ",hintTargets=" + hintIndex.typesByChunk().size());
        log.info("阶段耗时：taskId={}，阶段=变更范围与轻量语义分析，耗时={}ms，说明=只分析CHANGED并生成局部语义、安全流和确定性线索，变更块={}",
                taskId, ExecutionTiming.elapsedMillis(analysisStarted), changedChunkIds.size());
        // Recon Agent 先理解项目，再由 Orchestrator 只对 CHANGED 单元做二态分流。
        long reconAndTriageStarted = ExecutionTiming.start();
        stageStarted = ExecutionTiming.start();
        LlmGateway.ReconInsight recon = reconAgent.inspect(taskId, reconSummary);
        cancellationService.throwIfCancellationRequested(taskId);
        logTiming(taskId, "RECON_AGENT", stageStarted, analysisStarted,
                "sourceFiles=" + reconSummary.sourceFileCount()
                        + ",frameworkFiles=" + reconSummary.frameworkFiles().size());
        stageStarted = ExecutionTiming.start();
        List<AgentTask> plan = orchestratorAgent.plan(taskId, recon, chunks,
                hintIndex.typesByChunk(), hintIndex.descriptionsByChunk());
        cancellationService.throwIfCancellationRequested(taskId);
        logTiming(taskId, "TRIAGE_ORCHESTRATOR", stageStarted, analysisStarted,
                "changed=" + changedChunkIds.size() + ",plannedTasks=" + plan.size());
        log.info("阶段耗时：taskId={}，阶段=架构理解与增量分诊，耗时={}ms，说明=Recon归纳项目架构，Triage仅审查CHANGED并规划专业调查，专业任务数={}",
                taskId, ExecutionTiming.elapsedMillis(reconAndTriageStarted), plan.size());

        // 专业 Agent 并行调查并且只有证据充分时才形成候选假设。
        stageStarted = ExecutionTiming.start();
        ProfessionalAgentRunner.BatchResult investigation = professionalAgentRunner.investigate(
                taskId, plan, recon, chunks);
        cancellationService.throwIfCancellationRequested(taskId);
        // 专业 Agent 可能按需物化了 IMPACTED/CONTEXT，Critic 必须读取最新证据集合。
        chunks = chunkMapper.findByTaskId(taskId);
        int impactedCount = (int) chunks.stream()
                .filter(chunk -> chunk.getAnalysisScope() == com.deepaudit.domain.AnalysisScope.IMPACTED)
                .count();
        List<AgentCandidate> candidates = investigation.candidates();
        if (!plan.isEmpty() && investigation.formatFailures() == plan.size()) {
            throw new AiUnavailableException("所有专业 Agent 都未能返回合法结构化响应，无法形成可信审计结果");
        }
        if (!plan.isEmpty() && investigation.incompleteInvestigations() == plan.size()) {
            throw new AiUnavailableException("所有专业 Agent 调查均因响应、工具或覆盖限制未完成，不能生成误导性的空报告");
        }
        logTiming(taskId, "PROFESSIONAL_AGENTS", stageStarted, analysisStarted,
                "plannedTasks=" + plan.size() + ",candidates=" + candidates.size()
                        + ",formatFailures=" + investigation.formatFailures()
                        + ",incomplete=" + investigation.incompleteInvestigations());

        // Critic 前只合并同一主代码块、同一类型且建议行范围重叠的明确重复候选，
        // 减少重复模型调用；最终权威去重仍以 Critic 重定位后的真实位置为准。
        List<AgentCandidate> criticCandidates = AgentCandidateConsolidator.consolidate(candidates);
        if (criticCandidates.size() < candidates.size()) {
            TimingDetailLog.info("任务 {} 在 Critic 前合并了 {} 个位置完全重叠的专业 Agent 候选",
                    taskId, candidates.size() - criticCandidates.size());
        }
        List<Finding> reviewedFindings = new ArrayList<>();
        stageStarted = ExecutionTiming.start();
        for (AgentCandidate candidate : criticCandidates) {
            cancellationService.throwIfCancellationRequested(taskId);
            try {
                criticAgent.review(taskId, candidate, recon, chunks)
                        .filter(finding -> validateEvidence(projectRoot, finding))
                        .ifPresent(reviewedFindings::add);
            } catch (AiResponseFormatException exception) {
                log.warn("任务 {} 的 Critic 对候选 {} 返回不可解析 JSON，候选不进入最终报告",
                        taskId, candidate.proposal().primaryChunkId());
            }
        }
        logTiming(taskId, "CRITIC_REVIEW", stageStarted, analysisStarted,
                "candidates=" + criticCandidates.size() + ",reviewedFindings=" + reviewedFindings.size());
        log.info("阶段耗时：taskId={}，阶段=Critic独立复核，耗时={}ms，说明=验证漏洞因果、反证和精确位置，候选数={}，通过定位审查数={}",
                taskId, ExecutionTiming.elapsedMillis(stageStarted), criticCandidates.size(),
                reviewedFindings.size());
        // 不使用标题、endpoint 或证据链顺序判断身份。相同漏洞类型、文件、方法且最终
        // 行范围重叠的结果会合并，并基于合并后的真实源码锚点重新生成稳定指纹。
        List<Finding> confirmed = FindingConsolidator.consolidate(reviewedFindings, chunks);
        if (confirmed.size() < reviewedFindings.size()) {
            TimingDetailLog.info("任务 {} 在 Critic 后合并了 {} 个定位到同一代码位置的确认漏洞",
                    taskId, reviewedFindings.size() - confirmed.size());
        }
        // 批量持久化确认结果，最终报告只接收这一组经过证据门禁的发现。
        for (int start = 0; start < confirmed.size(); start += 200) {
            cancellationService.throwIfCancellationRequested(taskId);
            findingMapper.insertBatch(confirmed.subList(start, Math.min(start + 200, confirmed.size())));
        }
        String comparisonBaseSha = task.getMergeBaseSha() == null || task.getMergeBaseSha().isBlank()
                ? task.getBaseCommitSha() : task.getMergeBaseSha();
        String selectedBaseContext = task.getBaseCommitSha() != null
                && !task.getBaseCommitSha().equals(comparisonBaseSha)
                ? "；用户选择的基准分支提交 " + shortSha(task.getBaseCommitSha()) : "";
        String auditContext = "分支变更扫描 " + shortSha(comparisonBaseSha) + " → "
                + shortSha(task.getTargetCommitSha()) + "；" + task.getChangeSummary()
                + selectedBaseContext
                + "；深度范围 "
                + (incrementalScope.changedChunkIds().size() + impactedCount)
                + " 个代码块"
                + "（按需影响上下文 " + impactedCount + " 个）"
                + "；方法变化 " + incrementalScope.semanticChangeSummary();
        if (investigation.incompleteInvestigations() > 0) {
            auditContext += "；有 " + investigation.incompleteInvestigations()
                    + " 个专业调查因模型响应、工具错误、覆盖上限或预算耗尽未完成，结果覆盖不完整";
        }
        long confirmedUnlocated = candidates.stream()
                .filter(candidate -> candidate.hypothesis().getStatus()
                        == com.deepaudit.domain.HypothesisStatus.CONFIRMED_UNLOCATED)
                .count();
        if (confirmedUnlocated > 0) {
            auditContext += "；另有 " + confirmedUnlocated + " 个漏洞已由 Critic 确认但精确位置待复核";
        }
        long insufficientEvidence = candidates.stream()
                .filter(candidate -> candidate.hypothesis().getStatus()
                        == com.deepaudit.domain.HypothesisStatus.INSUFFICIENT_EVIDENCE)
                .count();
        if (insufficientEvidence > 0) {
            auditContext += "；另有 " + insufficientEvidence + " 个漏洞假设因 Critic 证据不足或响应异常保留待复核";
        }
        int rejectedHypotheses = (int) candidates.stream()
                .filter(candidate -> candidate.hypothesis().getStatus()
                        == com.deepaudit.domain.HypothesisStatus.REJECTED)
                .count();
        stageStarted = ExecutionTiming.start();
        cancellationService.throwIfCancellationRequested(taskId);
        reportAgent.generate(taskId, projectName, recon, confirmed, plan.size(),
                rejectedHypotheses, auditContext);
        cancellationService.throwIfCancellationRequested(taskId);
        logTiming(taskId, "REPORT_AGENT", stageStarted, analysisStarted,
                "confirmed=" + confirmed.size() + ",rejected=" + rejectedHypotheses);
        TimingDetailLog.info("阶段明细：taskId={}，阶段=智能审计分析总计，耗时={}ms，说明=完成范围分析、分诊、专业调查、Critic和报告，专业任务数={}，候选数={}，正式漏洞数={}",
                taskId, ExecutionTiming.elapsedMillis(analysisStarted), plan.size(), candidates.size(), confirmed.size());
        return new AnalysisResult(confirmed.size(), plan.size(), candidates.size(), recon.architectureSummary());
    }

    /** 取消任务不保留尚未完成证据门禁的正式漏洞和报告，但保留差异、语义与 Agent 调查轨迹。 */
    public void discardFinalResults(UUID taskId) {
        findingMapper.deleteByTaskId(taskId);
        reportSummaryMapper.deleteByTaskId(taskId);
    }

    private void logTiming(UUID taskId, String stage, long stageStarted, long analysisStarted, String details) {
        TimingDetailLog.info("执行耗时：taskId={}，stage={}，elapsedMs={}，analysisElapsedMs={}，details={}",
                taskId, stage, ExecutionTiming.elapsedMillis(stageStarted),
                ExecutionTiming.elapsedMillis(analysisStarted), details);
    }

    private HintIndex collectHints(UUID taskId, Path root, List<CodeChunk> chunks,
                                   Set<Long> changedChunkIds) {
        List<CodeChunk> changedChunks = chunks.stream()
                .filter(chunk -> chunk.getId() != null && changedChunkIds.contains(chunk.getId()))
                .toList();
        AnalysisContext context = new AnalysisContext(taskId, root, changedChunks);
        Map<Long, Set<VulnerabilityType>> types = new LinkedHashMap<>();
        Map<Long, String> descriptions = new LinkedHashMap<>();
        for (VulnerabilityAnalyzer provider : hintProviders) {
            if (provider.type() == null) continue;
            try {
                // 每个分析器只生成线索草稿，不能绕过专业 Agent 和 Critic 直接形成发现。
                for (FindingDraft draft : provider.analyze(context)) {
                    findChunk(changedChunks, draft).ifPresent(chunk -> {
                        types.computeIfAbsent(chunk.getId(), ignored -> new LinkedHashSet<>()).add(draft.type());
                        descriptions.merge(chunk.getId(), draft.title() + "：" + draft.description()
                                        + "\n规则定位到的代码证据：\n" + draft.evidence(),
                                (left, right) -> left + "\n" + right);
                    });
                }
            } catch (RuntimeException exception) {
                log.warn("规则提示提供器 {} 执行失败，Agent 仍会继续审查", provider.type(), exception);
            }
        }
        return new HintIndex(types, descriptions);
    }

    // 将跨过程安全流作为额外线索并入规则索引，而不是直接提升为漏洞。
    private void mergeSemanticHints(UUID taskId, HintIndex hints, Set<Long> changedChunkIds) {
        SemanticEvidenceService.SemanticHints semantic = semanticEvidenceService.hints(taskId);
        semantic.typesByChunk().forEach((chunkId, types) -> {
            if (changedChunkIds.contains(chunkId)) {
                hints.typesByChunk().computeIfAbsent(chunkId, ignored -> new LinkedHashSet<>()).addAll(types);
            }
        });
        semantic.descriptionsByChunk().forEach((chunkId, description) -> {
            if (changedChunkIds.contains(chunkId)) {
                hints.descriptionsByChunk().merge(chunkId, description,
                        (left, right) -> left + "\n\n" + right);
            }
        });
    }

    // 按文件与行号把规则草稿映射回模型可引用的真实代码块。
    private java.util.Optional<CodeChunk> findChunk(List<CodeChunk> chunks, FindingDraft draft) {
        return chunks.stream().filter(chunk -> chunk.getFilePath().equals(draft.filePath()))
                .filter(chunk -> draft.startLine() >= chunk.getStartLine() && draft.startLine() <= chunk.getEndLine())
                .findFirst().or(() -> chunks.stream().filter(chunk -> chunk.getFilePath().equals(draft.filePath())).findFirst());
    }

    private String shortSha(String value) {
        return value == null ? "" : value.substring(0, Math.min(8, value.length()));
    }

    // 在落库前确认主证据路径位于项目根目录且引用了真实有效行号。
    private boolean validateEvidence(Path root, Finding finding) {
        Path normalizedRoot = root.toAbsolutePath().normalize();
        Path evidenceFile = normalizedRoot.resolve(finding.getFilePath()).normalize();
        if (!evidenceFile.startsWith(normalizedRoot) || !Files.isRegularFile(evidenceFile)) return false;
        try (var lines = Files.lines(evidenceFile)) {
            long lineCount = lines.count();
            return finding.getStartLine() > 0 && finding.getStartLine() <= Math.max(1, lineCount);
        } catch (Exception exception) {
            return false;
        }
    }

    private record HintIndex(Map<Long, Set<VulnerabilityType>> typesByChunk,
                             Map<Long, String> descriptionsByChunk) {
    }

    public record AnalysisResult(int findingCount, int plannedAgentTasks,
                                 int supportedHypotheses, String architectureSummary) {
    }
}
