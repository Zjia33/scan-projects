package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.AiResponseFormatException;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class OrchestratorAgentService {
    private static final int MAX_INCREMENTAL_BATCH_CHARS = 60_000;
    private final LlmGateway llmGateway;
    private final AiProperties properties;
    private final AgentTraceService traceService;
    private final IncrementalReviewService incrementalReviewService;

    // 先对紧凑审计单元执行三态分流，再仅为 INVESTIGATE 单元创建专业 Agent 任务。
    public List<AgentTask> plan(UUID taskId, LlmGateway.ReconInsight recon, List<CodeChunk> chunks,
                                Map<Long, Set<VulnerabilityType>> hints,
                                Map<Long, String> hintDescriptions) {
        AgentRun run = traceService.start(taskId, AgentType.ORCHESTRATOR, null, "轻量安全分流与调查编排");
        long planningStarted = ExecutionTiming.start();
        try {
            List<AgentTask> result = planIncremental(taskId, run, recon, chunks, hints, hintDescriptions);
            TimingDetailLog.info("阶段明细：taskId={}，阶段=增量分诊与任务规划，耗时={}ms，说明=仅审查CHANGED并按决定补充IMPACTED依据，专业任务数={}",
                    taskId, ExecutionTiming.elapsedMillis(planningStarted), result.size());
            return result;
        } catch (RuntimeException exception) {
            log.error("执行耗时：taskId={}，stage=TRIAGE_ORCHESTRATION，elapsedMs={}，status=FAILED，error={}",
                    taskId, ExecutionTiming.elapsedMillis(planningStarted), exception.getClass().getSimpleName());
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR,
                    AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
    }

    // 增量扫描只审查 CHANGED；仅在 NEED_CONTEXT 或 INVESTIGATE 后延迟附加对应 IMPACTED 代码。
    private List<AgentTask> planIncremental(
            UUID taskId, AgentRun run, LlmGateway.ReconInsight recon, List<CodeChunk> chunks,
            Map<Long, Set<VulnerabilityType>> hints, Map<Long, String> hintDescriptions) {
        List<IncrementalReviewUnit> units = incrementalReviewService.build(
                taskId, chunks, hints, hintDescriptions);
        TimingDetailLog.info("任务 {} 已构建 {} 个 CHANGED 审查单元；首次分流不附加 IMPACTED 源码",
                taskId, units.size());
        traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.REASONING,
                "首次三态分流仅审查 CHANGED 的 Base/Target；IMPACTED 将按决定延迟补充");
        Map<String, AgentTask> tasks = new LinkedHashMap<>();
        List<IncrementalReviewUnit> modelReview = new ArrayList<>();
        List<IncrementalReviewUnit> mandatoryReview = new ArrayList<>();
        for (IncrementalReviewUnit unit : units) {
            if (unit.mandatoryTypes().isEmpty()) {
                modelReview.add(unit);
                continue;
            }
            mandatoryReview.add(unit);
        }
        if (!mandatoryReview.isEmpty()) {
            List<IncrementalReviewUnit> enrichedMandatory = incrementalReviewService.enrichImpact(
                    taskId, mandatoryReview, chunks);
            TimingDetailLog.info("任务 {} 对 {} 个确定性直达 CHANGED 单元按需补充 IMPACTED 依据后进入专业调查",
                    taskId, mandatoryReview.size());
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.REASONING,
                    mandatoryReview.size() + " 个确定性直达位置已补充关联 IMPACTED 依据");
            Map<String, IncrementalReviewUnit> enrichedMandatoryById = enrichedMandatory == null ? Map.of()
                    : enrichedMandatory.stream().collect(Collectors.toMap(IncrementalReviewUnit::unitId,
                    Function.identity(), (first, ignored) -> first, LinkedHashMap::new));
            for (IncrementalReviewUnit original : mandatoryReview) {
                IncrementalReviewUnit unit = enrichedMandatoryById.getOrDefault(original.unitId(), original);
                for (VulnerabilityType type : unit.mandatoryTypes()) {
                    addTask(tasks, unit, type, "确定性规则、语义流或 Guard 变化要求直接调查",
                            unit.deterministicEvidence());
                }
            }
        }

        List<String> summaries = new ArrayList<>();
        Map<String, List<String>> decisionDiagnostics = new LinkedHashMap<>();
        Map<String, LlmGateway.TriageDecision> firstPass = triageIncrementalBatches(
                taskId, run, recon, modelReview, summaries, decisionDiagnostics, "初次增量变更审查");
        List<IncrementalReviewUnit> needContext = new ArrayList<>();
        List<IncrementalReviewUnit> investigate = new ArrayList<>();
        Map<String, LlmGateway.TriageDecision> investigateDecisions = new LinkedHashMap<>();
        int skipped = 0;
        for (IncrementalReviewUnit unit : modelReview) {
            LlmGateway.TriageDecision decision = firstPass.get(unit.unitId());
            if (decision == null || decision.disposition() == TriageDisposition.NEED_CONTEXT) {
                needContext.add(unit);
                if (decision != null) {
                    addDiagnostic(decisionDiagnostics, unit.unitId(),
                            "初次增量变更审查明确返回 NEED_CONTEXT");
                }
            } else if (decision.disposition() == TriageDisposition.INVESTIGATE) {
                investigate.add(unit);
                investigateDecisions.put(unit.unitId(), decision);
            } else {
                skipped++;
            }
        }
        if (!investigate.isEmpty()) {
            List<IncrementalReviewUnit> enrichedInvestigate = incrementalReviewService.enrichImpact(
                    taskId, investigate, chunks);
            TimingDetailLog.info("任务 {} 首次分流有 {} 个 CHANGED 单元进入 INVESTIGATE，现按需补充 IMPACTED 依据",
                    taskId, investigate.size());
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.REASONING,
                    investigate.size() + " 个 INVESTIGATE 位置已补充关联 IMPACTED 依据");
            Map<String, IncrementalReviewUnit> enrichedInvestigateById = enrichedInvestigate == null ? Map.of()
                    : enrichedInvestigate.stream().collect(Collectors.toMap(IncrementalReviewUnit::unitId,
                    Function.identity(), (first, ignored) -> first, LinkedHashMap::new));
            for (IncrementalReviewUnit original : investigate) {
                IncrementalReviewUnit enriched = enrichedInvestigateById.getOrDefault(
                        original.unitId(), original);
                addDecisionTasks(tasks, enriched, investigateDecisions.get(original.unitId()));
            }
        }

        // 缺失、无效或 NEED_CONTEXT 的决定补充一次受控上下文，并逐单元执行唯一一次明确复判。
        List<IncrementalReviewUnit> unresolved = new ArrayList<>();
        int conservativeFallbacks = 0;
        if (!needContext.isEmpty()) {
            List<IncrementalReviewUnit> enrichedResult =
                    incrementalReviewService.enrich(taskId, needContext, chunks);
            TimingDetailLog.info("任务 {} 首次分流有 {} 个 CHANGED 单元需要上下文，现补充 IMPACTED 依据并执行一次复判",
                    taskId, needContext.size());
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.REASONING,
                    needContext.size() + " 个 NEED_CONTEXT 位置已补充关联 IMPACTED 依据并准备复判");
            if (enrichedResult == null) enrichedResult = List.of();
            Map<String, IncrementalReviewUnit> enrichedById = enrichedResult.stream()
                    .collect(Collectors.toMap(IncrementalReviewUnit::unitId, Function.identity(),
                            (first, ignored) -> first, LinkedHashMap::new));
            List<IncrementalReviewUnit> enriched = new ArrayList<>();
            for (IncrementalReviewUnit original : needContext) {
                IncrementalReviewUnit candidate = enrichedById.get(original.unitId());
                if (candidate == null || candidate.primaryChunkId() != original.primaryChunkId()) {
                    String reason = candidate == null
                            ? "上下文补充结果缺少该单元，改用原始单元复判"
                            : "上下文补充结果篡改 primaryChunkId，改用原始单元复判";
                    addDiagnostic(decisionDiagnostics, original.unitId(), reason);
                    log.warn("任务 {} 的增量上下文补充异常：unitId={}，{}",
                            taskId, original.unitId(), reason);
                    enriched.add(original);
                } else {
                    enriched.add(candidate);
                }
            }
            Map<String, LlmGateway.TriageDecision> secondPass = triageIncrementalFinal(
                    taskId, run, recon, enriched, summaries, decisionDiagnostics);
            for (IncrementalReviewUnit unit : enriched) {
                LlmGateway.TriageDecision decision = secondPass.get(unit.unitId());
                if (decision != null && decision.disposition() == TriageDisposition.INVESTIGATE) {
                    addDecisionTasks(tasks, unit, decision);
                } else if (decision != null && decision.disposition() == TriageDisposition.SKIP) {
                    skipped++;
                } else {
                    unresolved.add(unit);
                    if (decision != null) {
                        rejectDecision(taskId, run, decisionDiagnostics, unit.unitId(),
                                "补充上下文后单位置明确复判",
                                "非法返回 NEED_CONTEXT");
                    }
                    List<VulnerabilityType> fallbackTypes = conservativeFallbackTypes(
                            unit, firstPass.get(unit.unitId()));
                    for (VulnerabilityType type : fallbackTypes) {
                        addTask(tasks, unit, type,
                                "增量分流复判未返回合法决定，按完整覆盖原则保守进入专业调查",
                                unit.deterministicEvidence());
                    }
                    conservativeFallbacks++;
                    String fallbackMessage = "增量分流复判不完整，已将 " + unit.unitId()
                            + " 保守升级为专业调查，类型=" + fallbackTypes;
                    log.warn("任务 {} {}", taskId, fallbackMessage);
                    traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR,
                            AgentEventType.FORMAT_ERROR, fallbackMessage);
                }
            }
        }
        if (!unresolved.isEmpty()) {
            log.warn("任务 {} 有 {} 个增量位置复判不完整，已全部保守调查：{}",
                    taskId, unresolved.size(), truncate(
                            unresolvedDescription(unresolved, decisionDiagnostics), 1_500));
        }

        String modelSummary = truncate(String.join("；", summaries), 2_000);
        long investigatedUnits = tasks.values().stream().map(AgentTask::chunkId).distinct().count();
        String summary = "增量变更审查覆盖 " + units.size() + " 个 CHANGED 位置；仅对 NEED_CONTEXT 或 INVESTIGATE "
                + "位置附加关联 IMPACTED 依据，其中 "
                + (units.size() - modelReview.size()) + " 个确定性直达、" + needContext.size()
                + " 个补充上下文并逐个明确复判、"
                + conservativeFallbacks + " 个复判异常后保守调查、"
                + skipped + " 个明确跳过、" + investigatedUnits
                + " 个进入调查，规划 " + tasks.size() + " 个专业 Agent 任务"
                + (modelSummary.isBlank() ? "" : "；" + modelSummary);
        traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.PLAN, summary);
        run.complete(summary);
        traceService.update(run);
        return List.copyOf(tasks.values());
    }

    // 按批次读取真实统一变更上下文，并严格校验单元 ID、主代码块、决定和漏洞类型。
    private Map<String, LlmGateway.TriageDecision> triageIncrementalBatches(
            UUID taskId, AgentRun run, LlmGateway.ReconInsight recon,
            List<IncrementalReviewUnit> units, List<String> summaries,
            Map<String, List<String>> diagnostics, String phase) {
        Map<String, LlmGateway.TriageDecision> accepted = new LinkedHashMap<>();
        int batchSize = Math.max(1, properties.getTriageBatchSize());
        int batchNumber = 0;
        for (int start = 0; start < units.size();) {
            int end = start;
            int estimatedChars = 0;
            while (end < units.size() && end - start < batchSize) {
                int nextSize = estimatedSize(units.get(end));
                if (end > start && estimatedChars + nextSize > MAX_INCREMENTAL_BATCH_CHARS) break;
                estimatedChars += nextSize;
                end++;
            }
            List<IncrementalReviewUnit> batch = units.subList(start, end);
            batchNumber++;
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.MODEL_CALL,
                    phase + "第 " + batchNumber + " 批，共 " + batch.size()
                            + " 个变更位置，输入约 " + estimatedChars + " 字符");
            LlmGateway.TriagePlan plan;
            long requestStarted = ExecutionTiming.start();
            TimingDetailLog.info("模型阶段开始：taskId={}，stage=TRIAGE_INITIAL，phase={}，batch={}，units={}，estimatedChars={}",
                    taskId, phase, batchNumber, batch.size(), estimatedChars);
            try {
                plan = llmGateway.triageIncremental(taskId, recon, batch);
            } catch (AiResponseFormatException exception) {
                long elapsedMs = ExecutionTiming.elapsedMillis(requestStarted);
                TimingDetailLog.warn("模型阶段结束：taskId={}，stage=TRIAGE_INITIAL，phase={}，batch={}，units={}，elapsedMs={}，status=FORMAT_ERROR",
                        taskId, phase, batchNumber, batch.size(), elapsedMs);
                traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.FORMAT_ERROR,
                        phase + "第 " + batchNumber + " 批模型调用在 " + elapsedMs + " ms 后返回格式异常");
                run.setModelCallCount(run.getModelCallCount() + 1);
                for (IncrementalReviewUnit unit : batch) {
                    rejectDecision(taskId, run, diagnostics, unit.unitId(), phase,
                            "模型响应无法解析：" + truncate(safeIdentifier(exception.getMessage()), 300));
                }
                start = end;
                continue;
            }
            long elapsedMs = ExecutionTiming.elapsedMillis(requestStarted);
            TimingDetailLog.info("模型阶段结束：taskId={}，stage=TRIAGE_INITIAL，phase={}，batch={}，units={}，elapsedMs={}，status=SUCCESS",
                    taskId, phase, batchNumber, batch.size(), elapsedMs);
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.REASONING,
                    phase + "第 " + batchNumber + " 批模型调用完成，耗时 " + elapsedMs + " ms");
            run.setModelCallCount(run.getModelCallCount() + 1);
            acceptIncrementalPlan(taskId, run, batch, plan, summaries, diagnostics, phase, accepted);
            start = end;
        }
        TriageCounts counts = incrementalTriageCounts(units, accepted);
        TimingDetailLog.info("任务 {} 增量变更三态统计（{}）：总数={}，INVESTIGATE={}，NEED_CONTEXT={}，SKIP={}",
                taskId, phase, counts.total(), counts.investigate(), counts.needContext(), counts.skip());
        return accepted;
    }

    private Map<String, LlmGateway.TriageDecision> triageIncrementalFinal(
            UUID taskId, AgentRun run, LlmGateway.ReconInsight recon,
            List<IncrementalReviewUnit> units, List<String> summaries,
            Map<String, List<String>> diagnostics) {
        Map<String, LlmGateway.TriageDecision> accepted = new LinkedHashMap<>();
        for (IncrementalReviewUnit unit : units) {
            String phase = "补充上下文后单位置明确复判 " + unit.unitId();
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.MODEL_CALL,
                    phase + "，必须明确返回 INVESTIGATE 或 SKIP");
            LlmGateway.TriagePlan plan;
            long requestStarted = ExecutionTiming.start();
            TimingDetailLog.info("模型阶段开始：taskId={}，stage=TRIAGE_FINAL，unitId={}，contextChars={}",
                    taskId, unit.unitId(), unit.relatedContext().length());
            try {
                plan = llmGateway.triageIncrementalFinal(taskId, recon, unit);
            } catch (AiResponseFormatException exception) {
                long elapsedMs = ExecutionTiming.elapsedMillis(requestStarted);
                TimingDetailLog.warn("模型阶段结束：taskId={}，stage=TRIAGE_FINAL，unitId={}，elapsedMs={}，status=FORMAT_ERROR",
                        taskId, unit.unitId(), elapsedMs);
                traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.FORMAT_ERROR,
                        phase + "模型调用在 " + elapsedMs + " ms 后返回格式异常");
                run.setModelCallCount(run.getModelCallCount() + 1);
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase,
                        "模型响应无法解析：" + truncate(safeIdentifier(exception.getMessage()), 300));
                continue;
            }
            long elapsedMs = ExecutionTiming.elapsedMillis(requestStarted);
            TimingDetailLog.info("模型阶段结束：taskId={}，stage=TRIAGE_FINAL，unitId={}，elapsedMs={}，status=SUCCESS",
                    taskId, unit.unitId(), elapsedMs);
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.REASONING,
                    phase + "模型调用完成，耗时 " + elapsedMs + " ms");
            run.setModelCallCount(run.getModelCallCount() + 1);
            acceptIncrementalPlan(taskId, run, List.of(unit), plan, summaries,
                    diagnostics, phase, accepted);
        }
        return accepted;
    }

    private void acceptIncrementalPlan(
            UUID taskId, AgentRun run, List<IncrementalReviewUnit> batch,
            LlmGateway.TriagePlan plan, List<String> summaries,
            Map<String, List<String>> diagnostics, String phase,
            Map<String, LlmGateway.TriageDecision> accepted) {
        if (plan == null) {
            for (IncrementalReviewUnit unit : batch) {
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase, "模型返回空计划");
            }
            return;
        }
        if (plan.summary() != null && !plan.summary().isBlank()) summaries.add(plan.summary());
        Map<String, IncrementalReviewUnit> batchById = batch.stream()
                .collect(Collectors.toMap(IncrementalReviewUnit::unitId, Function.identity()));
        Set<String> seen = new LinkedHashSet<>();
        Set<String> duplicated = new LinkedHashSet<>();
        for (LlmGateway.TriageDecision decision : plan.decisions()) {
            if (decision == null) {
                traceInvalidDecision(taskId, run, phase, "模型返回了 null 决定");
                continue;
            }
            IncrementalReviewUnit unit = batchById.get(decision.unitId());
            if (unit == null) {
                IncrementalReviewUnit matchingChunk = batch.stream()
                        .filter(candidate -> candidate.primaryChunkId() == decision.primaryChunkId())
                        .findFirst().orElse(null);
                if (matchingChunk != null) {
                    seen.add(matchingChunk.unitId());
                    rejectDecision(taskId, run, diagnostics, matchingChunk.unitId(), phase,
                            "unitId 不匹配，期望 " + matchingChunk.unitId()
                                    + "，实际 " + safeIdentifier(decision.unitId()));
                } else {
                    traceInvalidDecision(taskId, run, phase,
                            "返回批次外 unitId=" + safeIdentifier(decision.unitId())
                                    + "，primaryChunkId=" + decision.primaryChunkId());
                }
                continue;
            }
            if (!seen.add(unit.unitId())) {
                duplicated.add(unit.unitId());
                accepted.remove(unit.unitId());
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase, "同一单元返回了多个决定");
                continue;
            }
            if (decision.disposition() == null) {
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase, "disposition 为空");
                continue;
            }
            if (unit.primaryChunkId() != decision.primaryChunkId()) {
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase,
                        "primaryChunkId 不匹配，期望 " + unit.primaryChunkId()
                                + "，实际 " + decision.primaryChunkId());
                continue;
            }
            List<VulnerabilityType> safeTypes = decision.vulnerabilityTypes().stream()
                    .filter(java.util.Objects::nonNull)
                    .filter(unit.allowedTypes()::contains).distinct().toList();
            if (decision.disposition() == TriageDisposition.INVESTIGATE && safeTypes.isEmpty()) {
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase,
                        "INVESTIGATE 未提供允许范围内的漏洞类型");
                continue;
            }
            if (decision.disposition() == TriageDisposition.SKIP) safeTypes = List.of();
            accepted.put(unit.unitId(), new LlmGateway.TriageDecision(
                    decision.unitId(), decision.primaryChunkId(), decision.disposition(), safeTypes,
                    decision.reason()));
        }
        for (IncrementalReviewUnit unit : batch) {
            if (!seen.contains(unit.unitId())) {
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase, "模型响应缺少决定");
            } else if (duplicated.contains(unit.unitId())) {
                accepted.remove(unit.unitId());
            }
        }
    }

    private void rejectDecision(UUID taskId, AgentRun run, Map<String, List<String>> diagnostics,
                                String unitId, String phase, String reason) {
        addDiagnostic(diagnostics, unitId, phase + ": " + reason);
        log.warn("任务 {} 的 {} 拒绝增量分流决定：unitId={}，原因={}",
                taskId, phase, unitId, reason);
        traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR,
                AgentEventType.REASONING, phase + " 拒绝 " + unitId + "：" + reason);
    }

    private void traceInvalidDecision(UUID taskId, AgentRun run, String phase, String reason) {
        log.warn("任务 {} 的 {} 收到无法关联的增量分流决定：{}", taskId, phase, reason);
        traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR,
                AgentEventType.REASONING, phase + " 忽略无效决定：" + reason);
    }

    private void addDiagnostic(Map<String, List<String>> diagnostics, String unitId, String reason) {
        diagnostics.computeIfAbsent(unitId, ignored -> new ArrayList<>());
        List<String> reasons = diagnostics.get(unitId);
        if (!reasons.contains(reason)) reasons.add(reason);
    }

    private List<VulnerabilityType> conservativeFallbackTypes(
            IncrementalReviewUnit unit, LlmGateway.TriageDecision firstDecision) {
        LinkedHashSet<VulnerabilityType> types = new LinkedHashSet<>();
        if (firstDecision != null) {
            firstDecision.vulnerabilityTypes().stream()
                    .filter(unit.allowedTypes()::contains).forEach(types::add);
        }
        Set<String> facts = new LinkedHashSet<>(unit.facts());
        if (facts.contains("HAS_SECURITY_ANNOTATION") || facts.contains("HAS_SECURITY_CONFIGURATION")) {
            types.add(VulnerabilityType.AUTHORIZATION);
        }
        if (facts.contains("HAS_DATA_ACCESS")) {
            types.add(VulnerabilityType.AUTHORIZATION);
            types.add(VulnerabilityType.SQL_INJECTION);
        }
        if (facts.contains("HAS_OUTPUT_OPERATION")) {
            types.add(VulnerabilityType.STORED_XSS);
            types.add(VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE);
        }
        if (facts.contains("HAS_VALIDATION_OPERATION")) {
            types.add(VulnerabilityType.VALIDATION_BYPASS);
        }
        if (facts.contains("HAS_SENSITIVE_INFORMATION")) {
            types.add(VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE);
        }
        if (facts.contains("HAS_EXTERNAL_ENDPOINT")) {
            types.add(VulnerabilityType.AUTHORIZATION);
            types.add(VulnerabilityType.VALIDATION_BYPASS);
        }
        if (types.isEmpty()) types.addAll(unit.allowedTypes());
        return types.stream().filter(unit.allowedTypes()::contains).distinct().toList();
    }

    private String unresolvedDescription(List<IncrementalReviewUnit> units,
                                         Map<String, List<String>> diagnostics) {
        return units.stream().map(unit -> {
            String location = safeIdentifier(unit.filePath()) + " "
                    + safeIdentifier(unit.symbolName());
            List<String> reasons = diagnostics.getOrDefault(unit.unitId(), List.of("无诊断信息"));
            return unit.unitId() + "[" + location.strip() + "；"
                    + String.join("；", reasons) + "]";
        }).collect(Collectors.joining(","));
    }

    private String safeIdentifier(String value) {
        if (value == null) return "";
        return value.replace('\n', ' ').replace('\r', ' ').strip();
    }

    private int estimatedSize(IncrementalReviewUnit unit) {
        return unit.baseCodeExcerpt().length() + unit.targetCodeExcerpt().length()
                + unit.changeSummary().length() + unit.relatedContext().length()
                + unit.deterministicEvidence().length() + 1_000;
    }

    private TriageCounts incrementalTriageCounts(
            List<IncrementalReviewUnit> units, Map<String, LlmGateway.TriageDecision> decisions) {
        int investigate = 0;
        int needContext = 0;
        int skip = 0;
        for (IncrementalReviewUnit unit : units) {
            LlmGateway.TriageDecision decision = decisions.get(unit.unitId());
            TriageDisposition disposition = decision == null
                    ? TriageDisposition.NEED_CONTEXT : decision.disposition();
            switch (disposition) {
                case INVESTIGATE -> investigate++;
                case NEED_CONTEXT -> needContext++;
                case SKIP -> skip++;
            }
        }
        return new TriageCounts(units.size(), investigate, needContext, skip);
    }

    private void addDecisionTasks(Map<String, AgentTask> tasks, IncrementalReviewUnit unit,
                                  LlmGateway.TriageDecision decision) {
        for (VulnerabilityType type : decision.vulnerabilityTypes()) {
            addTask(tasks, unit, type, decision.reason(), unit.deterministicEvidence());
        }
    }

    private void addTask(Map<String, AgentTask> tasks, IncrementalReviewUnit unit,
                         VulnerabilityType type, String reason, String evidence) {
            if (type == null || !unit.allowedTypes().contains(type)) return;
        AgentTask task = new AgentTask(unit.primaryChunkId(), agentFor(type), type,
                reason == null || reason.isBlank() ? "增量变更审查确认需要深入调查" : reason,
                joinNonBlank(evidence, unit.changeSummary(), unit.relatedContext()));
        tasks.putIfAbsent(key(task), task);
    }

    private String truncate(String value, int maxLength) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), maxLength));
    }

    private String joinNonBlank(String... values) {
        return java.util.Arrays.stream(values).filter(java.util.Objects::nonNull).map(String::strip)
                .filter(value -> !value.isBlank()).collect(Collectors.joining("\n\n"));
    }

    // 用代码块和漏洞类型组成稳定键以合并重复规划任务。
    private String key(AgentTask task) {
        return task.chunkId() + "|" + task.vulnerabilityType();
    }

    private record TriageCounts(int total, int investigate, int needContext, int skip) {
    }

    // 将每类漏洞固定路由到具备相应提示词和工具策略的专业 Agent。
    public static AgentType agentFor(VulnerabilityType type) {
        return switch (type) {
            case SQL_INJECTION -> AgentType.SQL_INJECTION;
            case AUTHORIZATION -> AgentType.AUTHORIZATION;
            case SENSITIVE_INFORMATION_DISCLOSURE -> AgentType.SENSITIVE_INFORMATION;
            case STORED_XSS -> AgentType.STORED_XSS;
            case VALIDATION_BYPASS -> AgentType.VALIDATION_BYPASS;
        };
    }
}
