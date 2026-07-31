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
import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.mapper.FindingMapper;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.semantic.SemanticAnalysisService;
import com.deepaudit.semantic.SemanticEvidenceService;
import com.deepaudit.semantic.IncrementalScopeService;
import com.deepaudit.recon.ReconService;
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

// 负责 AnalysisService 对应的业务编排和处理。
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
    private final ReconService reconService;
    private final CodeGraphIntegrationService codeGraphIntegrationService;

    // 执行从语义索引和调查线索到 Critic 确认、落库及报告生成的完整分析链。
    public AnalysisResult analyze(UUID taskId, Path projectRoot, ReconSummary reconSummary,
                                  String projectName, AuditTask task) {
        // 清理旧发现和 Agent 轨迹，保证重跑结果不混入历史数据。
        findingMapper.deleteByTaskId(taskId);
        traceService.reset(taskId);
        // 加载 Recon 已持久化的全部代码块作为本次分析的事实边界。
        List<CodeChunk> chunks = chunkMapper.findByTaskId(taskId);
        if (chunks.isEmpty()) throw new IllegalStateException("项目中没有可供 Agent 审查的代码块");
        // CodeGraph 是可失败的辅助索引；初始化失败时后续流程继续使用内置语义分析。
        codeGraphIntegrationService.prepare(taskId, projectRoot);
        // 先生成跨文件语义索引，再合并规则与语义产生的调查线索。
        SemanticAnalysisService.Summary semanticSummary = semanticAnalysisService.rebuild(taskId, projectRoot, chunks);
        IncrementalScopeService.ScopeResult incrementalScope = null;
        if (task.getScanMode() == ScanMode.INCREMENTAL) {
            incrementalScope = incrementalScopeService.determine(taskId, chunks);
            CodeGraphIntegrationService.ImpactDecision codeGraphImpact = codeGraphIntegrationService.decideImpact(
                    taskId, chunks, incrementalScope.changedChunkIds(), incrementalScope.impactedChunkIds());
            incrementalScope = new IncrementalScopeService.ScopeResult(incrementalScope.changedChunkIds(),
                    codeGraphImpact.effectiveImpactedChunkIds(), incrementalScope.globalConfigurationChanged(),
                    incrementalScope.semanticChangeCounts());
            reconService.promoteImpactScope(taskId, incrementalScope.impactedChunkIds());
            chunks = chunkMapper.findByTaskId(taskId);
            reconSummary = reconService.refreshProjectStructure(projectRoot, reconSummary, chunks);
            log.info("任务 {} 增量范围：{} 个直接变更块、{} 个最终影响块、{} 个 CodeGraph 候选，"
                            + "全局配置变化={}",
                    taskId, incrementalScope.changedChunkIds().size(),
                    incrementalScope.impactedChunkIds().size(), codeGraphImpact.codeGraphImpactedChunkIds().size(),
                    incrementalScope.globalConfigurationChanged());
            log.info("任务 {} 方法级语义变化：{}", taskId, incrementalScope.semanticChangeSummary());
        }
        HintIndex hintIndex = collectHints(taskId, projectRoot, chunks);
        mergeSemanticHints(taskId, hintIndex);
        log.info("任务 {} 生成 {} 个规则调查目标，类型分布: {}", taskId,
                hintIndex.typesByChunk().size(), hintIndex.typesByChunk());
        log.info("任务 {} 语义索引：{} 个符号、{} 条调用边、{} 条安全数据流；调用点 {}，未解析 {}",
                taskId, semanticSummary.symbolCount(), semanticSummary.callEdgeCount(),
                semanticSummary.securityFlowCount(), semanticSummary.totalCallSites(),
                semanticSummary.unresolvedCallSites());
        // Recon Agent 先理解项目，再由 Orchestrator 对全部安全相关审计单元做轻量三态分流。
        LlmGateway.ReconInsight recon = reconAgent.inspect(taskId, reconSummary);
        List<AgentTask> plan = orchestratorAgent.plan(taskId, recon, chunks, task.getScanMode(),
                hintIndex.typesByChunk(), hintIndex.descriptionsByChunk());

        // 专业 Agent 并行调查并且只有证据充分时才形成候选假设。
        ProfessionalAgentRunner.BatchResult investigation = professionalAgentRunner.investigate(
                taskId, plan, recon, chunks);
        List<AgentCandidate> candidates = investigation.candidates();
        if (!plan.isEmpty() && investigation.formatFailures() == plan.size()) {
            throw new AiUnavailableException("所有专业 Agent 都未能返回合法结构化响应，无法形成可信审计结果");
        }

        // Critic 前只合并同一主代码块、同一类型且建议行范围重叠的明确重复候选，
        // 减少重复模型调用；最终权威去重仍以 Critic 重定位后的真实位置为准。
        List<AgentCandidate> criticCandidates = AgentCandidateConsolidator.consolidate(candidates);
        if (criticCandidates.size() < candidates.size()) {
            log.info("任务 {} 在 Critic 前合并了 {} 个位置完全重叠的专业 Agent 候选",
                    taskId, candidates.size() - criticCandidates.size());
        }
        List<Finding> reviewedFindings = new ArrayList<>();
        for (AgentCandidate candidate : criticCandidates) {
            try {
                criticAgent.review(taskId, candidate, recon, chunks, task.getScanMode())
                        .filter(finding -> validateEvidence(projectRoot, finding))
                        .ifPresent(reviewedFindings::add);
            } catch (AiResponseFormatException exception) {
                log.warn("任务 {} 的 Critic 对候选 {} 返回不可解析 JSON，候选不进入最终报告",
                        taskId, candidate.proposal().primaryChunkId());
            }
        }
        // 不使用标题、endpoint 或证据链顺序判断身份。相同漏洞类型、文件、方法且最终
        // 行范围重叠的结果会合并，并基于合并后的真实源码锚点重新生成稳定指纹。
        List<Finding> confirmed = FindingConsolidator.consolidate(reviewedFindings, chunks);
        if (confirmed.size() < reviewedFindings.size()) {
            log.info("任务 {} 在 Critic 后合并了 {} 个定位到同一代码位置的确认漏洞",
                    taskId, reviewedFindings.size() - confirmed.size());
        }
        // 批量持久化确认结果，最终报告只接收这一组经过证据门禁的发现。
        for (int start = 0; start < confirmed.size(); start += 200) {
            findingMapper.insertBatch(confirmed.subList(start, Math.min(start + 200, confirmed.size())));
        }
        String comparisonBaseSha = task.getMergeBaseSha() == null || task.getMergeBaseSha().isBlank()
                ? task.getBaseCommitSha() : task.getMergeBaseSha();
        String selectedBaseContext = task.getScanMode() == ScanMode.INCREMENTAL
                && task.getBaseCommitSha() != null
                && !task.getBaseCommitSha().equals(comparisonBaseSha)
                ? "；用户选择的基准分支提交 " + shortSha(task.getBaseCommitSha()) : "";
        String auditContext = task.getScanMode() == ScanMode.FULL
                ? "全量扫描目标提交 " + shortSha(task.getTargetCommitSha())
                : "分支变更扫描 " + shortSha(comparisonBaseSha) + " → "
                + shortSha(task.getTargetCommitSha()) + "；" + task.getChangeSummary()
                + selectedBaseContext
                + "；深度范围 " + (incrementalScope == null ? 0 : incrementalScope.totalDeepTargets()) + " 个代码块"
                + (incrementalScope == null ? "" : "；方法变化 " + incrementalScope.semanticChangeSummary());
        long confirmedUnlocated = candidates.stream()
                .filter(candidate -> candidate.hypothesis().getStatus()
                        == com.deepaudit.domain.HypothesisStatus.CONFIRMED_UNLOCATED)
                .count();
        if (confirmedUnlocated > 0) {
            auditContext += "；另有 " + confirmedUnlocated + " 个漏洞已由 Critic 确认但精确位置待复核";
        }
        int rejectedHypotheses = (int) candidates.stream()
                .filter(candidate -> candidate.hypothesis().getStatus()
                        == com.deepaudit.domain.HypothesisStatus.REJECTED)
                .count();
        reportAgent.generate(taskId, projectName, recon, confirmed, plan.size(),
                rejectedHypotheses, auditContext);
        return new AnalysisResult(confirmed.size(), plan.size(), candidates.size(), recon.architectureSummary());
    }

    // 运行所有确定性分析器并按代码块聚合“待调查”类型和证据说明。
    private HintIndex collectHints(UUID taskId, Path root, List<CodeChunk> chunks) {
        AnalysisContext context = new AnalysisContext(taskId, root, chunks);
        Map<Long, Set<VulnerabilityType>> types = new LinkedHashMap<>();
        Map<Long, String> descriptions = new LinkedHashMap<>();
        for (VulnerabilityAnalyzer provider : hintProviders) {
            if (provider.type() == null || !provider.type().isDetectable()) continue;
            try {
                // 每个分析器只生成线索草稿，不能绕过专业 Agent 和 Critic 直接形成发现。
                for (FindingDraft draft : provider.analyze(context)) {
                    findChunk(chunks, draft).ifPresent(chunk -> {
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
    private void mergeSemanticHints(UUID taskId, HintIndex hints) {
        SemanticEvidenceService.SemanticHints semantic = semanticEvidenceService.hints(taskId);
        semantic.typesByChunk().forEach((chunkId, types) ->
                hints.typesByChunk().computeIfAbsent(chunkId, ignored -> new LinkedHashSet<>()).addAll(types));
        semantic.descriptionsByChunk().forEach((chunkId, description) ->
                hints.descriptionsByChunk().merge(chunkId, description,
                        (left, right) -> left + "\n\n" + right));
    }

    // 按文件与行号把规则草稿映射回模型可引用的真实代码块。
    private java.util.Optional<CodeChunk> findChunk(List<CodeChunk> chunks, FindingDraft draft) {
        return chunks.stream().filter(chunk -> chunk.getFilePath().equals(draft.filePath()))
                .filter(chunk -> draft.startLine() >= chunk.getStartLine() && draft.startLine() <= chunk.getEndLine())
                .findFirst().or(() -> chunks.stream().filter(chunk -> chunk.getFilePath().equals(draft.filePath())).findFirst());
    }

    // 执行 AnalysisService 中的 shortSha 处理。
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

    // 封装 HintIndex 使用的不可变结构化数据。
    private record HintIndex(Map<Long, Set<VulnerabilityType>> typesByChunk,
                             Map<Long, String> descriptionsByChunk) {
    }

    // 封装 AnalysisResult 使用的不可变结构化数据。
    public record AnalysisResult(int findingCount, int plannedAgentTasks,
                                 int supportedHypotheses, String architectureSummary) {
    }
}
