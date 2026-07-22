package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class AgentRuntime {
    private final LlmGateway llmGateway;
    private final AiProperties properties;
    private final AuditToolService toolService;
    private final AgentTraceService traceService;
    private final AuditHypothesisMapper hypothesisMapper;
    private final SemanticEvidenceService semanticEvidenceService;

    public AgentRuntime(LlmGateway llmGateway, AiProperties properties, AuditToolService toolService,
                        AgentTraceService traceService, AuditHypothesisMapper hypothesisMapper,
                        SemanticEvidenceService semanticEvidenceService) {
        this.llmGateway = llmGateway;
        this.properties = properties;
        this.toolService = toolService;
        this.traceService = traceService;
        this.hypothesisMapper = hypothesisMapper;
        this.semanticEvidenceService = semanticEvidenceService;
    }

    // 驱动单个专业 Agent 的“推理—工具—观察”循环并执行证据准入。
    public Optional<AgentCandidate> investigate(UUID taskId, AgentTask task,
                                                LlmGateway.ReconInsight recon, List<CodeChunk> chunks) {
        // 当前目标和确定性语义流是初始允许引用的证据集合。
        Map<Long, CodeChunk> byId = chunks.stream().collect(Collectors.toMap(CodeChunk::getId, Function.identity()));
        CodeChunk target = byId.get(task.chunkId());
        if (target == null) return Optional.empty();
        AgentRun run = traceService.start(taskId, task.agentType(), target.getId(), target.getSymbolName());
        List<LlmGateway.Observation> observations = new ArrayList<>();
        Set<Long> allowedEvidence = new LinkedHashSet<>();
        Set<Long> candidateEvidence = new LinkedHashSet<>();
        allowedEvidence.add(target.getId());
        SemanticEvidenceService.EvidenceResult semanticEvidence = semanticEvidenceService.query(
                taskId, target.getId(), "trace_data_flow", 10, task.vulnerabilityType());
        allowedEvidence.addAll(semanticEvidence.evidenceChunkIds());
        try {
            int maxIterations = Math.max(1, properties.getMaxIterationsPerAgent());
            // 每轮只允许继续调用只读工具、提交发现或结束调查。
            for (int iteration = 1; iteration <= maxIterations; iteration++) {
                run.setStepCount(iteration);
                run.setModelCallCount(run.getModelCallCount() + 1);
                LlmGateway.AgentTurn turn = new LlmGateway.AgentTurn(taskId, task.agentType(),
                        task.vulnerabilityType(), AgentPromptSupport.target(target, Set.of(task.vulnerabilityType())),
                        task.ruleHint(), semanticEvidence.text(), recon, List.copyOf(observations), iteration);
                traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.MODEL_CALL,
                        "第 " + iteration + " 轮：结合 Recon 技术栈、语义调用链和 "
                                + observations.size() + " 条工具观察进行安全判断");
                LlmGateway.AgentDecision decision = llmGateway.decide(turn);
                traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.REASONING,
                        safe(decision.summary()));
                traceService.update(run);
                String action = decision.action() == null ? "" : decision.action().toUpperCase();
                if ("TOOL".equals(action)) {
                    // 工具返回分别标记为已验证证据或仍需关系验证的 RAG 候选。
                    if (run.getToolCallCount() >= properties.getMaxToolCallsPerAgent()) break;
                    run.setToolCallCount(run.getToolCallCount() + 1);
                    traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.TOOL_CALL,
                            decision.tool() + "：" + safe(decision.summary()));
                    AuditToolService.ToolResult result = toolService.execute(decision.tool(), decision.query(),
                            decision.limit(), target, chunks, task.vulnerabilityType());
                    allowedEvidence.addAll(result.evidenceChunkIds());
                    candidateEvidence.addAll(result.candidateChunkIds());
                    candidateEvidence.removeAll(result.evidenceChunkIds());
                    observations.add(new LlmGateway.Observation(decision.tool(), decision.query(), result.text()));
                    traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.OBSERVATION,
                            result.text());
                    continue;
                }
                if ("FINDING".equals(action)) {
                    // FINDING 必须匹配任务类型且只能引用当前已获准的代码块。
                    LlmGateway.FindingProposal proposal = validate(decision.finding(), task, allowedEvidence);
                    if (proposal == null) {
                        String feedback = invalidEvidenceFeedback(decision.finding(), allowedEvidence, candidateEvidence);
                        observations.add(new LlmGateway.Observation("evidence_validator", "验证漏洞证据引用", feedback));
                        traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.OBSERVATION, feedback);
                        traceService.update(run);
                        continue;
                    }
                    String evidence = buildEvidence(proposal, byId);
                    if (!semanticEvidence.evidenceChunkIds().isEmpty()) {
                        evidence += "\n\n[SEMANTIC_FLOW]\n" + semanticEvidence.text();
                    }
                    String evidenceIds = proposal.evidenceChunkIds().stream().map(String::valueOf)
                            .collect(Collectors.joining(","));
                    AuditHypothesis hypothesis = new AuditHypothesis(taskId, run.getId(), proposal.type(),
                            proposal.title() + "：" + proposal.description(), proposal.primaryChunkId(),
                            evidenceIds, proposal.confidence());
                    hypothesisMapper.insert(hypothesis);
                    traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.HYPOTHESIS,
                            safe(decision.summary()));
                    run.complete("已形成待 Critic 复核的漏洞假设");
                    traceService.update(run);
                    return Optional.of(new AgentCandidate(task.agentType(), proposal, evidence, hypothesis));
                }
                // 非工具、非发现动作视为专业 Agent 主动结束且没有充分证据。
                run.complete("Agent 未找到足够证据：" + safe(decision.summary()));
                traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.REJECTED,
                        safe(decision.summary()));
                traceService.update(run);
                return Optional.empty();
            }
            run.complete("达到调查预算，未形成证据充分的漏洞假设");
            traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.REJECTED, run.getSummary());
            traceService.update(run);
            return Optional.empty();
        } catch (RuntimeException exception) {
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
    }

    // 校验漏洞类型和所有证据 ID，并为缺省风险等级填入保守值。
    private LlmGateway.FindingProposal validate(LlmGateway.FindingProposal proposal, AgentTask task,
                                                Set<Long> allowedEvidence) {
        if (proposal == null || proposal.type() != task.vulnerabilityType()
                || proposal.primaryChunkId() == null || !allowedEvidence.contains(proposal.primaryChunkId())) {
            return null;
        }
        if (proposal.evidenceChunkIds().stream().anyMatch(id -> !allowedEvidence.contains(id))) return null;
        List<Long> ids = new ArrayList<>(proposal.evidenceChunkIds());
        if (!ids.contains(proposal.primaryChunkId())) ids.add(0, proposal.primaryChunkId());
        Severity severity = proposal.severity() == null ? Severity.HIGH : proposal.severity();
        Confidence confidence = proposal.confidence() == null ? Confidence.MEDIUM : proposal.confidence();
        return new LlmGateway.FindingProposal(proposal.type(), severity, confidence,
                proposal.title(), proposal.description(), proposal.remediation(), proposal.primaryChunkId(), ids);
    }

    // 向模型解释证据拒绝原因，引导其先验证 RAG 候选关系再重试。
    private String invalidEvidenceFeedback(LlmGateway.FindingProposal proposal, Set<Long> allowedEvidence,
                                           Set<Long> candidateEvidence) {
        if (proposal == null) return "[EVIDENCE_REJECTED] FINDING 缺少 finding 对象，请重新调查。";
        Set<Long> submitted = new LinkedHashSet<>(proposal.evidenceChunkIds());
        if (proposal.primaryChunkId() != null) submitted.add(proposal.primaryChunkId());
        Set<Long> unverifiedCandidates = submitted.stream().filter(candidateEvidence::contains)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!unverifiedCandidates.isEmpty()) {
            return "[EVIDENCE_REJECTED] 代码块 " + unverifiedCandidates
                    + " 仍是 RAG_CANDIDATE。必须逐个调用 verify_relation，验证通过后才能提交 FINDING。";
        }
        Set<Long> invalid = submitted.stream().filter(id -> !allowedEvidence.contains(id))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return "[EVIDENCE_REJECTED] 漏洞类型、主证据或证据引用无效"
                + (invalid.isEmpty() ? "" : "，未获准的代码块=" + invalid)
                + "。请只引用当前目标、SEMANTIC_EVIDENCE 或 VERIFIED_EVIDENCE。";
    }

    // 只从已加载的真实代码块构造带文件和行号的证据正文。
    private String buildEvidence(LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks) {
        return proposal.evidenceChunkIds().stream().distinct().map(chunks::get).filter(java.util.Objects::nonNull)
                .map(chunk -> "[CHUNK " + chunk.getId() + "] " + chunk.getFilePath() + ":"
                        + chunk.getStartLine() + " " + chunk.getSymbolName() + "\n"
                        + chunk.getContent().substring(0, Math.min(4_000, chunk.getContent().length())))
                .collect(Collectors.joining("\n\n"));
    }

    private String safe(String value) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), 2_000));
    }
}
