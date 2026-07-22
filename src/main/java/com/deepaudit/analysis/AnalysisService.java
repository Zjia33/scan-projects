package com.deepaudit.analysis;

import com.deepaudit.agent.AgentCandidate;
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
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.mapper.FindingMapper;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.semantic.SemanticAnalysisService;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
public class AnalysisService {
    private static final Logger log = LoggerFactory.getLogger(AnalysisService.class);

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

    public AnalysisService(List<VulnerabilityAnalyzer> hintProviders,
                           CodeChunkMapper chunkMapper, FindingMapper findingMapper,
                           AgentTraceService traceService, ReconAgentService reconAgent,
                           OrchestratorAgentService orchestratorAgent,
                           ProfessionalAgentRunner professionalAgentRunner,
                           CriticAgentService criticAgent, ReportAgentService reportAgent,
                           SemanticAnalysisService semanticAnalysisService,
                           SemanticEvidenceService semanticEvidenceService) {
        this.hintProviders = hintProviders;
        this.chunkMapper = chunkMapper;
        this.findingMapper = findingMapper;
        this.traceService = traceService;
        this.reconAgent = reconAgent;
        this.orchestratorAgent = orchestratorAgent;
        this.professionalAgentRunner = professionalAgentRunner;
        this.criticAgent = criticAgent;
        this.reportAgent = reportAgent;
        this.semanticAnalysisService = semanticAnalysisService;
        this.semanticEvidenceService = semanticEvidenceService;
    }

    // 执行从语义索引和调查线索到 Critic 确认、落库及报告生成的完整分析链。
    public AnalysisResult analyze(UUID taskId, Path projectRoot, ReconSummary reconSummary, String projectName) {
        // 清理旧发现和 Agent 轨迹，保证重跑结果不混入历史数据。
        findingMapper.deleteByTaskId(taskId);
        traceService.reset(taskId);
        // 加载 Recon 已持久化的全部代码块作为本次分析的事实边界。
        List<CodeChunk> chunks = chunkMapper.findByTaskId(taskId);
        if (chunks.isEmpty()) throw new IllegalStateException("项目中没有可供 Agent 审查的代码块");
        // 先生成跨文件语义索引，再合并规则与语义产生的调查线索。
        SemanticAnalysisService.Summary semanticSummary = semanticAnalysisService.rebuild(taskId, projectRoot, chunks);
        HintIndex hintIndex = collectHints(taskId, projectRoot, chunks);
        mergeSemanticHints(taskId, hintIndex);
        log.info("任务 {} 生成 {} 个规则调查目标，类型分布: {}", taskId,
                hintIndex.typesByChunk().size(), hintIndex.typesByChunk());
        log.info("任务 {} 语义索引：{} 个符号、{} 条调用边、{} 条安全数据流；调用点 {}，未解析 {}",
                taskId, semanticSummary.symbolCount(), semanticSummary.callEdgeCount(),
                semanticSummary.securityFlowCount(), semanticSummary.totalCallSites(),
                semanticSummary.unresolvedCallSites());
        // 将有线索、接口和 Java 方法前置，以便规划器在目标预算内优先覆盖。
        List<CodeChunk> targets = selectTargets(chunks, hintIndex.typesByChunk());
        // Recon Agent 先理解项目，再由 Orchestrator 将目标拆给对应专业 Agent。
        LlmGateway.ReconInsight recon = reconAgent.inspect(taskId, reconSummary, chunks);
        List<AgentTask> plan = orchestratorAgent.plan(taskId, recon, targets,
                hintIndex.typesByChunk(), hintIndex.descriptionsByChunk());

        // 专业 Agent 并行调查并且只有证据充分时才形成候选假设。
        ProfessionalAgentRunner.BatchResult investigation = professionalAgentRunner.investigate(
                taskId, plan, recon, chunks);
        List<AgentCandidate> candidates = investigation.candidates();
        if (!plan.isEmpty() && investigation.formatFailures() == plan.size()) {
            throw new AiUnavailableException("所有专业 Agent 都未能返回合法结构化响应，无法形成可信审计结果");
        }

        // Critic 独立寻找反证，随后校验文件证据并按位置去重。
        List<Finding> confirmed = new ArrayList<>();
        Set<String> deduplication = new HashSet<>();
        for (AgentCandidate candidate : candidates) {
            try {
                criticAgent.review(taskId, candidate, recon, chunks)
                        .filter(finding -> validateEvidence(projectRoot, finding))
                        .filter(finding -> deduplication.add(finding.getType() + "|" + finding.getFilePath()
                                + "|" + finding.getStartLine()))
                        .ifPresent(confirmed::add);
            } catch (AiResponseFormatException exception) {
                log.warn("任务 {} 的 Critic 对候选 {} 返回不可解析 JSON，候选不进入最终报告",
                        taskId, candidate.proposal().primaryChunkId());
            }
        }
        // 批量持久化确认结果，最终报告只接收这一组经过证据门禁的发现。
        for (int start = 0; start < confirmed.size(); start += 200) {
            findingMapper.insertBatch(confirmed.subList(start, Math.min(start + 200, confirmed.size())));
        }
        reportAgent.generate(taskId, projectName, recon, confirmed, plan.size(), candidates.size() - confirmed.size());
        return new AnalysisResult(confirmed.size(), plan.size(), candidates.size(), recon.architectureSummary());
    }

    // 运行所有确定性分析器并按代码块聚合“待调查”类型和证据说明。
    private HintIndex collectHints(UUID taskId, Path root, List<CodeChunk> chunks) {
        AnalysisContext context = new AnalysisContext(taskId, root, chunks);
        Map<Long, Set<VulnerabilityType>> types = new LinkedHashMap<>();
        Map<Long, String> descriptions = new LinkedHashMap<>();
        for (VulnerabilityAnalyzer provider : hintProviders) {
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

    // 依次按线索、接口、Java 方法和源码位置确定 Agent 规划顺序。
    private List<CodeChunk> selectTargets(List<CodeChunk> chunks, Map<Long, Set<VulnerabilityType>> hints) {
        return chunks.stream().sorted(Comparator
                        .comparing((CodeChunk chunk) -> !hints.containsKey(chunk.getId()))
                        .thenComparing(chunk -> chunk.getEndpoint() == null)
                        .thenComparing(chunk -> !"JAVA_METHOD".equals(chunk.getChunkType()))
                        .thenComparing(CodeChunk::getFilePath)
                        .thenComparingInt(CodeChunk::getStartLine))
                .toList();
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
