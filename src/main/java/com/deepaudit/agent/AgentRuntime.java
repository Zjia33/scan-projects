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
import com.deepaudit.orchestrator.AuditCancellationService;
import com.deepaudit.orchestrator.AuditCancelledException;
import com.deepaudit.semantic.SemanticEvidenceService;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class AgentRuntime {
    private final LlmGateway llmGateway;
    private final AiProperties properties;
    private final AuditToolService toolService;
    private final AgentTraceService traceService;
    private final AuditHypothesisMapper hypothesisMapper;
    private final SemanticEvidenceService semanticEvidenceService;
    private final AuditCancellationService cancellationService;

    // 驱动单个专业 Agent 的“推理—工具—观察”循环并执行证据准入。
    public Optional<AgentCandidate> investigate(UUID taskId, AgentTask task,
                                                LlmGateway.ReconInsight recon, List<CodeChunk> chunks) {
        cancellationService.throwIfCancellationRequested(taskId);
        // 当前目标和确定性语义流是初始允许引用的证据集合。
        Map<Long, CodeChunk> byId = chunkIndex(chunks);
        CodeChunk target = byId.get(task.chunkId());
        if (target == null) return Optional.empty();
        AgentRun run = traceService.start(taskId, task.agentType(), target.getId(), target.getSymbolName());
        List<RuntimeObservation> observations = new ArrayList<>();
        Set<Long> allowedEvidence = new LinkedHashSet<>();
        Set<Long> candidateEvidence = new LinkedHashSet<>();
        boolean incompleteCoverage = "OVERSIZED_FILE_CHANGE".equals(target.getChunkType());
        allowedEvidence.add(target.getId());
        SemanticEvidenceService.EvidenceResult semanticEvidence = semanticEvidenceService.query(
                taskId, target.getId(), 10, task.vulnerabilityType());
        allowedEvidence.addAll(semanticEvidence.evidenceChunkIds());
        try {
            int maxIterations = Math.max(1, properties.getMaxIterationsPerAgent());
            // 每轮只允许继续调用只读工具、提交发现或结束调查。
            // 额外保留一轮只用于消费最后一次工具观察并形成结论，避免最后一个工具结果永远不被模型看到。
            for (int iteration = 1; iteration <= maxIterations + 1; iteration++) {
                cancellationService.throwIfCancellationRequested(taskId);
                run.setStepCount(iteration);
                run.setModelCallCount(run.getModelCallCount() + 1);
                LlmGateway.AgentTurn turn = new LlmGateway.AgentTurn(taskId, task.agentType(),
                        task.vulnerabilityType(), AgentPromptSupport.target(target, Set.of(task.vulnerabilityType())),
                        task.ruleHint(), semanticEvidence.text(), recon,
                        promptObservations(observations), iteration);
                String observationContext = observations.isEmpty()
                        ? "结合 Recon 架构事实与 CHANGED 局部安全语义进行判断，必要时按需查询调用上下文"
                        : "结合 Recon 架构事实、CHANGED 局部安全语义和 " + observations.size()
                        + " 条工具观察进行安全判断";
                traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.MODEL_CALL,
                        "第 " + iteration + " 轮：" + observationContext);
                long modelStarted = ExecutionTiming.start();
                LlmGateway.AgentDecision decision = llmGateway.decide(turn);
                cancellationService.throwIfCancellationRequested(taskId);
                long modelElapsedMs = ExecutionTiming.elapsedMillis(modelStarted);
                TimingDetailLog.info("模型阶段结束：taskId={}，stage=PROFESSIONAL_AGENT_MODEL，agentType={}，chunkId={}，iteration={}，elapsedMs={}",
                        taskId, task.agentType(), task.chunkId(), iteration, modelElapsedMs);
                traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.REASONING,
                        "模型调用完成，耗时 " + modelElapsedMs + " ms；" + safe(decision.summary()));
                traceService.update(run);
                String action = decision.action() == null ? "" : decision.action().toUpperCase();
                if ("TOOL".equals(action)) {
                    // 工具返回分别标记为已验证证据或仍需关系验证的候选。
                    if (iteration > maxIterations
                            || run.getToolCallCount() >= properties.getMaxToolCallsPerAgent()) {
                        incompleteCoverage = true;
                        String budgetMessage = "调查工具或轮次预算已耗尽，当前结论不完整；"
                                + "不能把未继续查询解释为已经证明安全。";
                        observations.add(new RuntimeObservation("investigation_budget", Map.of(),
                                "[INCOMPLETE_INVESTIGATION] " + budgetMessage,
                                ToolResult.Status.ERROR, Set.of(), Set.of()));
                        traceService.event(taskId, run.getId(), task.agentType(),
                                AgentEventType.INSUFFICIENT_EVIDENCE, budgetMessage);
                        break;
                    }
                    run.setToolCallCount(run.getToolCallCount() + 1);
                    traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.TOOL_CALL,
                            decision.tool() + "：" + safe(decision.summary()));
                    ToolResult result = toolService.execute(decision.tool(), decision.arguments(),
                            target, chunks, task.vulnerabilityType(),
                            new ToolSessionContext(target.getId(), allowedEvidence, candidateEvidence));
                    allowedEvidence.addAll(result.evidenceChunkIds());
                    candidateEvidence.addAll(result.candidateChunkIds());
                    candidateEvidence.removeAll(result.evidenceChunkIds());
                    if (result.status() == ToolResult.Status.ERROR
                            || result.code().contains("PARTIAL")
                            || result.code().contains("COVERAGE_LIMIT")
                            || result.truncated() && result.nextCursor() == null) {
                        incompleteCoverage = true;
                    }
                    int remaining = Math.max(0,
                            properties.getMaxToolCallsPerAgent() - run.getToolCallCount());
                    String observationText = result.observationText()
                            + "\n[TOOL_BUDGET remaining=" + remaining + "]";
                    observations.add(new RuntimeObservation(decision.tool(), decision.arguments(),
                            observationText, result.status(), result.evidenceChunkIds(),
                            result.candidateChunkIds()));
                    traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.OBSERVATION,
                            observationText);
                    continue;
                }
                if ("FINDING".equals(action)) {
                    // FINDING 必须匹配任务类型且只能引用当前已获准的代码块。
                    byId = chunkIndex(chunks);
                    LlmGateway.FindingProposal proposal = validate(
                            decision.finding(), task, allowedEvidence, byId);
                    if (proposal == null) {
                        String feedback = invalidEvidenceFeedback(decision.finding(), allowedEvidence, candidateEvidence);
                        observations.add(new RuntimeObservation("evidence_validator",
                                Map.of("operation", "验证漏洞证据引用"), feedback,
                                ToolResult.Status.DENIED, Set.of(), Set.of()));
                        traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.OBSERVATION, feedback);
                        traceService.update(run);
                        continue;
                    }
                    String evidence = buildEvidence(taskId, proposal, byId);
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
                String rejectionReason = rejectionReason(decision.summary(), task, observations);
                if (incompleteCoverage) {
                    String message = "调查上下文或工具结果不完整，未形成可执行结论：" + rejectionReason;
                    run.complete(message);
                    traceService.event(taskId, run.getId(), task.agentType(),
                            AgentEventType.INSUFFICIENT_EVIDENCE, message);
                    traceService.update(run);
                    throw new IncompleteInvestigationException(message);
                }
                run.complete("Agent 未找到足够证据：" + rejectionReason);
                traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.REJECTED,
                        rejectionReason);
                traceService.update(run);
                return Optional.empty();
            }
            run.complete("达到调查预算或覆盖边界，未能完成当前漏洞假设验证");
            traceService.event(taskId, run.getId(), task.agentType(),
                    AgentEventType.INSUFFICIENT_EVIDENCE, run.getSummary());
            traceService.update(run);
            throw new IncompleteInvestigationException(run.getSummary());
        } catch (IncompleteInvestigationException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            if (exception instanceof AuditCancelledException
                    || cancellationService.isCancellationRequested(taskId)) {
                run.complete("审计任务已中断，停止专业调查");
                traceService.update(run);
                traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.CANCELLED,
                        "审计任务已中断，当前 Agent 停止执行");
                throw new AuditCancelledException(taskId);
            }
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
    }

    // 校验漏洞类型和所有证据 ID，并为缺省风险等级填入保守值。
    private LlmGateway.FindingProposal validate(LlmGateway.FindingProposal proposal, AgentTask task,
                                                Set<Long> allowedEvidence, Map<Long, CodeChunk> chunks) {
        if (proposal == null || proposal.type() != task.vulnerabilityType()
                || proposal.primaryChunkId() == null || !allowedEvidence.contains(proposal.primaryChunkId())) {
            return null;
        }
        if (proposal.evidenceChunkIds().stream().anyMatch(id -> !allowedEvidence.contains(id))) return null;
        List<Long> ids = new ArrayList<>(proposal.evidenceChunkIds());
        if (!ids.contains(proposal.primaryChunkId())) ids.add(0, proposal.primaryChunkId());
        if (!ids.contains(task.chunkId())) ids.add(task.chunkId());
        Severity severity = proposal.severity() == null ? Severity.HIGH : proposal.severity();
        Confidence confidence = proposal.confidence() == null ? Confidence.MEDIUM : proposal.confidence();
        CodeChunk primary = chunks.get(proposal.primaryChunkId());
        if (primary == null) return null;
        CodeChunk investigationTarget = chunks.get(task.chunkId());
        if (investigationTarget == null) return null;
        boolean incrementalTarget = investigationTarget.getAnalysisScope()
                == com.deepaudit.domain.AnalysisScope.CHANGED;
        boolean incrementalPrimary = primary.getAnalysisScope() == com.deepaudit.domain.AnalysisScope.CHANGED
                || primary.getAnalysisScope() == com.deepaudit.domain.AnalysisScope.IMPACTED;
        if (!incrementalTarget || !incrementalPrimary) return null;
        FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, primary);
        return new LlmGateway.FindingProposal(proposal.type(), severity, confidence,
                proposal.title(), proposal.description(), proposal.remediation(), proposal.primaryChunkId(), ids,
                location.startLine(), location.endLine());
    }

    // 向模型解释证据拒绝原因，引导其先验证候选关系再重试。
    private String invalidEvidenceFeedback(LlmGateway.FindingProposal proposal, Set<Long> allowedEvidence,
                                           Set<Long> candidateEvidence) {
        if (proposal == null) return "[EVIDENCE_REJECTED] FINDING 缺少 finding 对象，请重新调查。";
        Set<Long> submitted = new LinkedHashSet<>(proposal.evidenceChunkIds());
        if (proposal.primaryChunkId() != null) submitted.add(proposal.primaryChunkId());
        Set<Long> unverifiedCandidates = submitted.stream().filter(candidateEvidence::contains)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!unverifiedCandidates.isEmpty()) {
            return "[EVIDENCE_REJECTED] 代码块 " + unverifiedCandidates
                    + " 仍是未验证候选。必须逐个调用 verify_relation，验证通过后才能提交 FINDING。";
        }
        Set<Long> invalid = submitted.stream().filter(id -> !allowedEvidence.contains(id))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return "[EVIDENCE_REJECTED] 漏洞类型、主证据或证据引用无效"
                + (invalid.isEmpty() ? "" : "，未获准的代码块=" + invalid)
                + "。请只引用当前目标、SEMANTIC_EVIDENCE 或 VERIFIED_EVIDENCE。";
    }

    // 只从已加载的真实代码块构造带文件和行号的证据正文。
    private String buildEvidence(UUID taskId, LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks) {
        Set<Long> evidenceIds = new LinkedHashSet<>(proposal.evidenceChunkIds());
        evidenceIds.add(proposal.primaryChunkId());
        Map<Long, Integer> callSites = semanticEvidenceService.callSiteLines(
                taskId, proposal.primaryChunkId(), evidenceIds);
        return FindingLocationResolver.formatEvidence(proposal, chunks, callSites);
    }

    private List<LlmGateway.Observation> promptObservations(List<RuntimeObservation> observations) {
        int detailedCount = Math.max(1, properties.getMaxDetailedObservations());
        int maxChars = Math.max(500, properties.getMaxObservationChars());
        int detailedFrom = Math.max(0, observations.size() - detailedCount);
        List<LlmGateway.Observation> result = new ArrayList<>();
        for (int index = 0; index < observations.size(); index++) {
            RuntimeObservation observation = observations.get(index);
            String text = index >= detailedFrom
                    ? truncate(observation.result(), maxChars)
                    : compactObservation(observation);
            result.add(new LlmGateway.Observation(
                    observation.tool(), observation.arguments(), text));
        }
        return List.copyOf(result);
    }

    private Map<Long, CodeChunk> chunkIndex(List<CodeChunk> chunks) {
        return chunks.stream().filter(chunk -> chunk.getId() != null).collect(Collectors.toMap(
                CodeChunk::getId, Function.identity(), (left, right) -> right));
    }

    private String compactObservation(RuntimeObservation observation) {
        String firstLine = observation.result().lines().findFirst().orElse("");
        return "[COMPACT_OBSERVATION status=" + observation.status()
                + " evidenceChunkIds=" + observation.evidenceChunkIds()
                + " candidateChunkIds=" + observation.candidateChunkIds() + "] "
                + truncate(firstLine, 300);
    }

    private String truncate(String value, int maxChars) {
        if (value == null) return "";
        return value.substring(0, Math.min(value.length(), maxChars));
    }

    private String safe(String value) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), 2_000));
    }

    private String rejectionReason(String summary, AgentTask task,
                                   List<RuntimeObservation> observations) {
        String value = safe(summary).strip();
        if (!value.isBlank()) return value;
        if (observations.isEmpty()) {
            return "未发现能够支持 " + task.vulnerabilityType().getDisplayName()
                    + " 的具体危险操作、缺失安全控制或可利用数据流";
        }
        RuntimeObservation last = observations.get(observations.size() - 1);
        return "已检查 " + observations.size() + " 条工具观察，最后状态为 " + last.status()
                + "，仍未获得能够支持 " + task.vulnerabilityType().getDisplayName() + " 的已验证证据";
    }

    private record RuntimeObservation(String tool, Map<String, Object> arguments, String result,
                                      ToolResult.Status status,
                                      Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds) {
        private RuntimeObservation {
            arguments = arguments == null ? Map.of() : Map.copyOf(arguments);
            result = result == null ? "" : result;
            evidenceChunkIds = evidenceChunkIds == null ? Set.of() : Set.copyOf(evidenceChunkIds);
            candidateChunkIds = candidateChunkIds == null ? Set.of() : Set.copyOf(candidateChunkIds);
        }
    }
}
