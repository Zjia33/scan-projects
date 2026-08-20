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
import java.util.LinkedHashMap;
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
    private static final int MAX_LEDGER_CHARS = 6_000;
    private static final int MAX_LEDGER_ENTRY_CHARS = 700;
    private static final int MAX_LEDGER_SOURCE_LINES = 3;
    private static final int MAX_LEDGER_LINE_CHARS = 160;

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
        // 每个并行专业 Agent 维护独立、可按需补充的 Chunk 视图。
        List<CodeChunk> sessionChunks = new ArrayList<>(chunks);
        // 当前目标和确定性语义流是初始允许引用的证据集合。
        Map<Long, CodeChunk> byId = sessionChunks.stream().collect(Collectors.toMap(
                CodeChunk::getId, Function.identity(), (left, right) -> left, LinkedHashMap::new));
        CodeChunk target = byId.get(task.chunkId());
        if (target == null) return Optional.empty();
        AgentRun run = traceService.start(taskId, task.agentType(), target.getId(), target.getSymbolName());
        List<RuntimeObservation> observations = new ArrayList<>();
        Set<Long> allowedEvidence = new LinkedHashSet<>();
        Set<Long> candidateEvidence = new LinkedHashSet<>();
        allowedEvidence.add(target.getId());
        SemanticEvidenceService.EvidenceResult semanticEvidence = semanticEvidenceService.query(
                taskId, target.getId(), 10, task.vulnerabilityType());
        allowedEvidence.addAll(semanticEvidence.evidenceChunkIds());
        try {
            int maxIterations = Math.max(1, properties.getMaxIterationsPerAgent());
            traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.MODEL_CALL,
                    "开始专业调查：结合 Recon 架构事实、CodeGraph 调用关系和局部安全语义进行判断");
            // 每轮只允许继续调用只读工具、提交发现或结束调查。
            for (int iteration = 1; iteration <= maxIterations; iteration++) {
                cancellationService.throwIfCancellationRequested(taskId);
                run.setStepCount(iteration);
                run.setModelCallCount(run.getModelCallCount() + 1);
                LlmGateway.AgentTurn turn = new LlmGateway.AgentTurn(taskId, task.agentType(),
                        task.vulnerabilityType(), AgentPromptSupport.target(target, Set.of(task.vulnerabilityType())),
                        task.ruleHint(), semanticEvidence.text(), recon,
                        promptObservations(observations), iteration);
                long modelStarted = ExecutionTiming.start();
                LlmGateway.AgentDecision decision = llmGateway.decide(turn);
                cancellationService.throwIfCancellationRequested(taskId);
                long modelElapsedMs = ExecutionTiming.elapsedMillis(modelStarted);
                TimingDetailLog.info("模型阶段结束：taskId={}，stage=PROFESSIONAL_AGENT_MODEL，agentType={}，chunkId={}，iteration={}，elapsedMs={}",
                        taskId, task.agentType(), task.chunkId(), iteration, modelElapsedMs);
                String action = decision.action() == null ? "" : decision.action().toUpperCase();
                if ("TOOL".equals(action) || "FINDING".equals(action)) {
                    traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.REASONING,
                            "模型调用完成，耗时 " + modelElapsedMs + " ms；" + safe(decision.summary()));
                }
                traceService.update(run);
                if ("TOOL".equals(action)) {
                    // 工具返回分别标记为已验证证据或仍需关系验证的候选。
                    if (run.getToolCallCount() >= properties.getMaxToolCallsPerAgent()) break;
                    run.setToolCallCount(run.getToolCallCount() + 1);
                    traceService.event(taskId, run.getId(), task.agentType(), AgentEventType.TOOL_CALL,
                            decision.tool() + "：" + safe(decision.summary()));
                    ToolResult result = toolService.execute(decision.tool(), decision.arguments(),
                            target, sessionChunks, task.vulnerabilityType(),
                            new ToolSessionContext(target.getId(), allowedEvidence, candidateEvidence));
                    byId.clear();
                    sessionChunks.forEach(chunk -> byId.putIfAbsent(chunk.getId(), chunk));
                    allowedEvidence.addAll(result.evidenceChunkIds());
                    candidateEvidence.addAll(result.candidateChunkIds());
                    candidateEvidence.removeAll(result.evidenceChunkIds());
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
                    ? truncateObservation(observation.result(), maxChars)
                    : compactObservation(observation);
            result.add(new LlmGateway.Observation(
                    observation.tool(), observation.arguments(), text));
        }
        String ledger = evidenceLedger(observations);
        if (!ledger.isBlank()) {
            result.add(new LlmGateway.Observation("evidence_ledger", Map.of(), ledger));
        }
        return List.copyOf(result);
    }

    // 从完整运行时观察中重建有界账本，帮助模型记住旧证据；账本本身不改变证据资格。
    private String evidenceLedger(List<RuntimeObservation> observations) {
        if (observations.isEmpty()) return "";
        StringBuilder ledger = new StringBuilder("[EVIDENCE_LEDGER]\n"
                + "账本只用于保持调查记忆，不改变 evidenceChunkIds/candidateChunkIds 的证据资格。");
        for (int index = 0; index < observations.size(); index++) {
            RuntimeObservation observation = observations.get(index);
            String detail = limitLedgerDetail(ledgerDetail(observation));
            if (detail.isBlank()) continue;
            String entry = "\n\n[LEDGER_ENTRY step=" + (index + 1)
                    + " tool=" + observation.tool()
                    + " status=" + observation.status()
                    + " evidenceChunkIds=" + observation.evidenceChunkIds()
                    + " candidateChunkIds=" + observation.candidateChunkIds() + "]\n" + detail;
            if (ledger.length() + entry.length() > MAX_LEDGER_CHARS) {
                ledger.append("\n\n[LEDGER_TRUNCATED action=consult_recent_observations_or_repeat_precise_tool]");
                break;
            }
            ledger.append(entry);
        }
        return ledger.toString();
    }

    private String limitLedgerDetail(String value) {
        if (value == null || value.length() <= MAX_LEDGER_ENTRY_CHARS) return value == null ? "" : value;
        String openTag = "<UNTRUSTED_CODE>";
        String closeTag = "</UNTRUSTED_CODE>";
        String marker = "\n... [LEDGER_ENTRY_TRUNCATED] ...\n";
        int open = value.indexOf(openTag);
        int close = value.indexOf(closeTag, Math.max(0, open));
        if (open >= 0 && close >= 0 && open < MAX_LEDGER_ENTRY_CHARS && close >= MAX_LEDGER_ENTRY_CHARS) {
            int retained = MAX_LEDGER_ENTRY_CHARS - marker.length() - closeTag.length();
            if (retained <= open + openTag.length()) {
                return value.substring(0, open).stripTrailing() + marker.stripTrailing();
            }
            return value.substring(0, retained).stripTrailing() + marker + closeTag;
        }
        return truncate(value, MAX_LEDGER_ENTRY_CHARS);
    }

    private String ledgerDetail(RuntimeObservation observation) {
        String tool = observation.tool();
        if (tool == null || tool.isBlank()) return "";
        return switch (tool) {
            case AgentToolCatalog.READ_SOURCE -> sourceLedgerDetail(observation.result());
            case AgentToolCatalog.VERIFY_RELATION -> selectLedgerLines(observation.result(), 5,
                    "[VERIFIED_EVIDENCE]", "[RELATION_REJECTED]", "CHUNK_ID=", "[SOURCE_NOT_INCLUDED]");
            case AgentToolCatalog.SEARCH_SYMBOLS, AgentToolCatalog.SEARCH_CODE ->
                    "[DISCOVERY_ONLY] arguments=" + truncate(String.valueOf(observation.arguments()), 300)
                            + "；搜索命中仍按 candidateChunkIds 处理。";
            case AgentToolCatalog.EXPLORE_CALL_GRAPH -> callGraphLedgerDetail(observation.result());
            case AgentToolCatalog.GET_CHANGE_CONTEXT -> selectLedgerLines(observation.result(), 6,
                    "[CURRENT_CHANGE_SUMMARY]", "[CURRENT_FILE_CHANGE_SUMMARY]",
                    "[RELATED_METHOD_CHANGE]", "[FILE_CHANGE]", "[NO_TEXTUAL_CHANGE]");
            case AgentToolCatalog.RESOLVE_DATA_ACCESS -> dataAccessLedgerDetail(
                    observation.result(), observation.candidateChunkIds());
            case AgentToolCatalog.INSPECT_SECURITY_POLICY -> securityPolicyLedgerDetail(observation.result());
            case AgentToolCatalog.TRACE_VALUE -> selectLedgerLines(observation.result(), 10,
                    "[VALUE_TRACE]", "[FLOW ", "source=", "sink=", "guards=", "path=",
                    "[ARGUMENT_MAPPING]");
            case "evidence_validator" -> selectLedgerLines(observation.result(), 2,
                    "[EVIDENCE_REJECTED]");
            default -> "";
        };
    }

    private String sourceLedgerDetail(String result) {
        List<String> metadata = matchingLedgerLines(result,
                line -> line.startsWith("[SOURCE]"), 1);
        List<String> selected = matchingLedgerLines(result,
                line -> line.startsWith(">>> "), MAX_LEDGER_SOURCE_LINES);
        if (metadata.isEmpty() && selected.isEmpty()) return "";
        StringBuilder detail = new StringBuilder(String.join("\n", metadata));
        if (!selected.isEmpty()) {
            if (!detail.isEmpty()) detail.append('\n');
            detail.append("<UNTRUSTED_CODE>\n")
                    .append(String.join("\n", selected))
                    .append("\n</UNTRUSTED_CODE>");
        }
        return detail.toString();
    }

    private String callGraphLedgerDetail(String result) {
        if (result == null || result.isBlank()) return "";
        List<String> selected = new ArrayList<>();
        boolean verifiedPath = false;
        for (String rawLine : result.lines().toList()) {
            String line = rawLine.strip();
            if (line.startsWith("[CALL_GRAPH")) {
                addLedgerLine(selected, line, 1);
                continue;
            }
            if (line.startsWith("PATH ")) {
                verifiedPath = line.contains("verified=true");
                if (verifiedPath) addLedgerLine(selected, line, 8);
                continue;
            }
            if (verifiedPath && line.contains("[VERIFIED")) {
                addLedgerLine(selected, withoutUntrustedExpression(line), 8);
            }
        }
        return String.join("\n", selected);
    }

    private String dataAccessLedgerDetail(String result, Set<Long> candidateChunkIds) {
        if (result == null || result.isBlank()) return "";
        if (!result.contains("[SEMANTIC_EVIDENCE]")) {
            return "[CANDIDATE_ONLY] 数据访问回退结果尚未验证，candidateChunkIds="
                    + candidateChunkIds;
        }
        String metadata = selectLedgerLines(result, 5,
                "[DATA_ACCESS_ANALYSIS]", "CHUNK_ID=", "indicators=");
        return appendUntrustedLines(metadata, matchingLedgerLines(result,
                line -> line.startsWith(">>> "), MAX_LEDGER_SOURCE_LINES));
    }

    private String securityPolicyLedgerDetail(String result) {
        if (result == null || result.isBlank()) return "";
        List<String> selected = new ArrayList<>();
        List<String> sourceLines = new ArrayList<>();
        boolean verifiedPolicy = false;
        for (String rawLine : result.lines().toList()) {
            String line = rawLine.strip();
            if (line.startsWith("[SECURITY_POLICY]")) {
                addLedgerLine(selected, line, 8);
                continue;
            }
            if (line.startsWith("[VERIFIED_POLICY_RELATION]")) {
                verifiedPolicy = true;
                addLedgerLine(selected, line, 8);
                continue;
            }
            if (line.startsWith("[UNVERIFIED_CANDIDATE]")) {
                verifiedPolicy = false;
                continue;
            }
            if (verifiedPolicy && line.startsWith("CHUNK_ID=")) {
                addLedgerLine(selected, line, 8);
            } else if (verifiedPolicy && line.startsWith(">>> ")) {
                addLedgerLine(sourceLines, line, MAX_LEDGER_SOURCE_LINES);
            }
        }
        return appendUntrustedLines(String.join("\n", selected), sourceLines);
    }

    private String appendUntrustedLines(String metadata, List<String> sourceLines) {
        if (sourceLines.isEmpty()) return metadata;
        return metadata + (metadata.isBlank() ? "" : "\n")
                + "<UNTRUSTED_CODE>\n" + String.join("\n", sourceLines)
                + "\n</UNTRUSTED_CODE>";
    }

    private String withoutUntrustedExpression(String line) {
        String marker = ",expression=<UNTRUSTED_CODE>";
        int start = line.indexOf(marker);
        if (start < 0) return line;
        int end = line.indexOf("</UNTRUSTED_CODE>", start + marker.length());
        if (end < 0) return line.substring(0, start);
        return line.substring(0, start) + line.substring(end + "</UNTRUSTED_CODE>".length());
    }

    private String selectLedgerLines(String result, int limit, String... markers) {
        return String.join("\n", matchingLedgerLines(result, line ->
                java.util.Arrays.stream(markers).anyMatch(line::contains), limit));
    }

    private List<String> matchingLedgerLines(String result,
                                              java.util.function.Predicate<String> predicate,
                                              int limit) {
        if (result == null || result.isBlank()) return List.of();
        return result.lines().map(String::strip).filter(predicate)
                .map(line -> truncate(line, MAX_LEDGER_LINE_CHARS))
                .limit(limit).toList();
    }

    private void addLedgerLine(List<String> selected, String line, int limit) {
        if (selected.size() < limit) selected.add(truncate(line, MAX_LEDGER_LINE_CHARS));
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

    private String truncateObservation(String value, int maxChars) {
        if (value == null || value.length() <= maxChars) return value == null ? "" : value;
        String markerText = "[OBSERVATION_TRUNCATED originalChars=" + value.length()
                + " retainedChars=" + maxChars + " action=refine_query_or_use_cursor]";
        String marker = "\n... " + markerText + " ...\n";
        int available = Math.max(0, maxChars - marker.length());
        int headChars = available * 2 / 3;
        int tailChars = available - headChars;
        int headEnd = lineBoundaryBefore(value, headChars);
        int tailStart = lineBoundaryAfter(value, value.length() - tailChars);
        return value.substring(0, headEnd).stripTrailing() + marker
                + value.substring(tailStart).stripLeading();
    }

    private int lineBoundaryBefore(String value, int target) {
        int boundary = value.lastIndexOf('\n', Math.min(target, value.length()));
        return boundary < 0 ? Math.min(target, value.length()) : boundary;
    }

    private int lineBoundaryAfter(String value, int target) {
        int safeTarget = Math.max(0, Math.min(target, value.length()));
        int boundary = value.indexOf('\n', safeTarget);
        return boundary < 0 ? safeTarget : Math.min(value.length(), boundary + 1);
    }

    private String safe(String value) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), 2_000));
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
