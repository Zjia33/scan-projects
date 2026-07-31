package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.AiResponseFormatException;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.domain.VulnerabilityType;
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

// 负责 OrchestratorAgentService 对应的业务编排和处理。
@Slf4j
@Service
@RequiredArgsConstructor
public class OrchestratorAgentService {
    private static final int MAX_INCREMENTAL_BATCH_CHARS = 60_000;
    private static final Set<String> MANDATORY_REASON_CODES = Set.of(
            "RULE_HINT", "SEMANTIC_FLOW", "GUARD_REMOVED");
    private static final Set<String> CONSERVATIVE_REASON_CODES = Set.of(
            "EXTERNAL_ENTRY", "SECURITY_CONFIGURATION", "DANGEROUS_DATA_ACCESS",
            "DANGEROUS_OUTPUT", "VALIDATION_BOUNDARY",
            "AUTHORIZATION_BOUNDARY", "UNRESOLVED_CALL", "SEMANTIC_CHANGE", "GUARD_REMOVED");

    private final LlmGateway llmGateway;
    private final AiProperties properties;
    private final AgentTraceService traceService;
    private final AuditUnitService auditUnitService;
    private final IncrementalReviewService incrementalReviewService;

    // 先对紧凑审计单元执行三态分流，再仅为 INVESTIGATE 单元创建专业 Agent 任务。
    public List<AgentTask> plan(UUID taskId, LlmGateway.ReconInsight recon, List<CodeChunk> chunks,
                                ScanMode scanMode, Map<Long, Set<VulnerabilityType>> hints,
                                Map<Long, String> hintDescriptions) {
        AgentRun run = traceService.start(taskId, AgentType.ORCHESTRATOR, null, "轻量安全分流与调查编排");
        try {
            if (scanMode == ScanMode.INCREMENTAL) {
                return planIncremental(taskId, run, recon, chunks, hints, hintDescriptions);
            }
            List<AuditUnit> units = auditUnitService.build(
                    taskId, chunks, scanMode, hints, hintDescriptions);
            Map<Long, AuditUnit> unitsByChunk = units.stream()
                    .collect(Collectors.toMap(AuditUnit::primaryChunkId, Function.identity()));
            Map<String, AgentTask> tasks = new LinkedHashMap<>();

            // 确定性规则和已形成的语义安全流属于必审事实，不能因模型漏返回而被静默跳过。
            for (Map.Entry<Long, Set<VulnerabilityType>> entry : hints.entrySet()) {
                AuditUnit unit = unitsByChunk.get(entry.getKey());
                if (unit == null || unit.reasonCodes().stream().noneMatch(MANDATORY_REASON_CODES::contains)) continue;
                for (VulnerabilityType type : entry.getValue()) {
                    if (!type.isDetectable()) continue;
                    addTask(tasks, unit, type, "确定性线索要求专业 Agent 深入核查",
                            hintDescriptions.get(entry.getKey()));
                }
            }
            // 删除权限或验证 Guard 是明确的安全退化，必须交给对应专业 Agent 复核。
            for (AuditUnit unit : units) {
                if (!unit.reasonCodes().contains("GUARD_REMOVED")) continue;
                addTask(tasks, unit, VulnerabilityType.AUTHORIZATION,
                        "Base/Target 语义差异发现安全 Guard 被删除", unit.contextSummary());
                addTask(tasks, unit, VulnerabilityType.VALIDATION_BYPASS,
                        "Base/Target 语义差异发现安全 Guard 被删除", unit.contextSummary());
            }

            List<String> summaries = new ArrayList<>();
            Map<String, LlmGateway.TriageDecision> firstPass = triageBatches(
                    taskId, run, recon, units, summaries, "初次轻量分流");
            List<AuditUnit> needContext = new ArrayList<>();
            int skipped = 0;
            for (AuditUnit unit : units) {
                LlmGateway.TriageDecision decision = firstPass.get(unit.unitId());
                if (decision == null || decision.disposition() == TriageDisposition.NEED_CONTEXT) {
                    needContext.add(unit);
                } else if (decision.disposition() == TriageDisposition.INVESTIGATE) {
                    addDecisionTasks(tasks, unit, decision, hintDescriptions.get(unit.primaryChunkId()));
                } else if (!hasTaskFor(tasks, unit.primaryChunkId())) {
                    skipped++;
                }
            }

            // NEED_CONTEXT 仅进行一次受控补充，避免无限扩张模型上下文。
            if (!needContext.isEmpty()) {
                List<AuditUnit> enriched = auditUnitService.enrich(taskId, needContext, chunks);
                Map<String, LlmGateway.TriageDecision> secondPass = triageBatches(
                        taskId, run, recon, enriched, summaries, "补充上下文后复判");
                for (AuditUnit unit : enriched) {
                    LlmGateway.TriageDecision decision = secondPass.get(unit.unitId());
                    if (decision != null && decision.disposition() == TriageDisposition.INVESTIGATE) {
                        addDecisionTasks(tasks, unit, decision, hintDescriptions.get(unit.primaryChunkId()));
                    } else if (decision != null && decision.disposition() == TriageDisposition.SKIP
                            && !hasTaskFor(tasks, unit.primaryChunkId())) {
                        skipped++;
                    } else if (shouldConservativelyInvestigate(unit)) {
                        // 安全相关事实仍无法排除时宁可交给会主动寻找反证的专业 Agent。
                        for (VulnerabilityType type : unit.candidateTypes()) {
                            addTask(tasks, unit, type, "补充上下文后仍无法排除安全相关性",
                                    hintDescriptions.get(unit.primaryChunkId()));
                        }
                    } else if (!hasTaskFor(tasks, unit.primaryChunkId())) {
                        skipped++;
                    }
                }
            }

            String modelSummary = truncate(String.join("；", summaries), 2_000);
            long investigatedUnits = tasks.values().stream().map(AgentTask::chunkId).distinct().count();
            String summary = "轻量分流 " + units.size() + " 个审计单元，其中 " + needContext.size()
                    + " 个补充上下文、" + skipped + " 个跳过、" + investigatedUnits
                    + " 个进入调查，规划 " + tasks.size() + " 个专业 Agent 任务"
                    + (modelSummary.isBlank() ? "" : "；" + modelSummary);
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.PLAN, summary);
            run.complete(summary);
            traceService.update(run);
            return List.copyOf(tasks.values());
        } catch (RuntimeException exception) {
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR,
                    AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
    }

    // 增量扫描直接覆盖全部 CHANGED/IMPACTED，审查资格不再由关键词审计单元决定。
    private List<AgentTask> planIncremental(
            UUID taskId, AgentRun run, LlmGateway.ReconInsight recon, List<CodeChunk> chunks,
            Map<Long, Set<VulnerabilityType>> hints, Map<Long, String> hintDescriptions) {
        List<IncrementalReviewUnit> units = incrementalReviewService.build(
                taskId, chunks, hints, hintDescriptions);
        Map<String, AgentTask> tasks = new LinkedHashMap<>();
        List<IncrementalReviewUnit> modelReview = new ArrayList<>();
        for (IncrementalReviewUnit unit : units) {
            if (unit.mandatoryTypes().isEmpty()) {
                modelReview.add(unit);
                continue;
            }
            for (VulnerabilityType type : unit.mandatoryTypes()) {
                addTask(tasks, unit, type, "确定性规则、语义流或 Guard 变化要求直接调查",
                        unit.deterministicEvidence());
            }
        }

        List<String> summaries = new ArrayList<>();
        Map<String, List<String>> decisionDiagnostics = new LinkedHashMap<>();
        Map<String, LlmGateway.TriageDecision> firstPass = triageIncrementalBatches(
                taskId, run, recon, modelReview, summaries, decisionDiagnostics, "初次增量变更审查");
        List<IncrementalReviewUnit> needContext = new ArrayList<>();
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
                addDecisionTasks(tasks, unit, decision);
            } else {
                skipped++;
            }
        }

        // 缺失、无效或 NEED_CONTEXT 的决定补充一次受控上下文，并逐单元执行唯一一次明确复判。
        List<IncrementalReviewUnit> unresolved = new ArrayList<>();
        if (!needContext.isEmpty()) {
            List<IncrementalReviewUnit> enrichedResult =
                    incrementalReviewService.enrich(taskId, needContext, chunks);
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
                }
            }
        }
        if (!unresolved.isEmpty()) {
            throw new AiResponseFormatException(truncate(
                    "增量分流复判失败，未对全部 CHANGED/IMPACTED 位置给出明确决定: "
                            + unresolvedDescription(unresolved, decisionDiagnostics), 1_900), null);
        }

        String modelSummary = truncate(String.join("；", summaries), 2_000);
        long investigatedUnits = tasks.values().stream().map(AgentTask::chunkId).distinct().count();
        String summary = "增量变更审查覆盖 " + units.size() + " 个 CHANGED/IMPACTED 位置，其中 "
                + (units.size() - modelReview.size()) + " 个确定性直达、" + needContext.size()
                + " 个补充上下文并逐个明确复判、"
                + skipped + " 个明确跳过、" + investigatedUnits
                + " 个进入调查，规划 " + tasks.size() + " 个专业 Agent 任务"
                + (modelSummary.isBlank() ? "" : "；" + modelSummary);
        traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.PLAN, summary);
        run.complete(summary);
        traceService.update(run);
        return List.copyOf(tasks.values());
    }

    // 按批次读取真实 Base/Target 差异，并严格校验单元 ID、主代码块、决定和漏洞类型。
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
                    phase + "第 " + batchNumber + " 批，共 " + batch.size() + " 个变更位置");
            LlmGateway.TriagePlan plan;
            try {
                plan = llmGateway.triageIncremental(taskId, recon, batch);
            } catch (AiResponseFormatException exception) {
                run.setModelCallCount(run.getModelCallCount() + 1);
                for (IncrementalReviewUnit unit : batch) {
                    rejectDecision(taskId, run, diagnostics, unit.unitId(), phase,
                            "模型响应无法解析：" + truncate(safeIdentifier(exception.getMessage()), 300));
                }
                start = end;
                continue;
            }
            run.setModelCallCount(run.getModelCallCount() + 1);
            acceptIncrementalPlan(taskId, run, batch, plan, summaries, diagnostics, phase, accepted);
            start = end;
        }
        TriageCounts counts = incrementalTriageCounts(units, accepted);
        log.info("任务 {} 增量变更三态统计（{}）：总数={}，INVESTIGATE={}，NEED_CONTEXT={}，SKIP={}",
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
            try {
                plan = llmGateway.triageIncrementalFinal(taskId, recon, unit);
            } catch (AiResponseFormatException exception) {
                run.setModelCallCount(run.getModelCallCount() + 1);
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase,
                        "模型响应无法解析：" + truncate(safeIdentifier(exception.getMessage()), 300));
                continue;
            }
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
                    .filter(VulnerabilityType::isDetectable)
                    .filter(unit.allowedTypes()::contains).distinct().toList();
            if (decision.disposition() == TriageDisposition.INVESTIGATE && safeTypes.isEmpty()) {
                rejectDecision(taskId, run, diagnostics, unit.unitId(), phase,
                        "INVESTIGATE 未提供允许范围内的漏洞类型");
                continue;
            }
            if (decision.disposition() != TriageDisposition.INVESTIGATE) safeTypes = List.of();
            accepted.put(unit.unitId(), new LlmGateway.TriageDecision(
                    decision.unitId(), decision.primaryChunkId(), decision.disposition(), safeTypes,
                    intersect(decision.reasonCodes(), unit.facts()), decision.requiredContext(), decision.reason()));
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

    // 按紧凑摘要批量调用轻量模型，并拒绝批次外或候选类型外的决定。
    private Map<String, LlmGateway.TriageDecision> triageBatches(
            UUID taskId, AgentRun run, LlmGateway.ReconInsight recon, List<AuditUnit> units,
            List<String> summaries, String phase) {
        Map<String, LlmGateway.TriageDecision> accepted = new LinkedHashMap<>();
        int batchSize = Math.max(1, properties.getTriageBatchSize());
        for (int start = 0; start < units.size(); start += batchSize) {
            List<AuditUnit> batch = units.subList(start, Math.min(start + batchSize, units.size()));
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.MODEL_CALL,
                    phase + "第 " + (start / batchSize + 1) + " 批，共 " + batch.size() + " 个审计单元");
            LlmGateway.TriagePlan plan = llmGateway.triage(taskId, recon, batch);
            run.setModelCallCount(run.getModelCallCount() + 1);
            if (plan.summary() != null && !plan.summary().isBlank()) summaries.add(plan.summary());
            Map<String, AuditUnit> batchById = batch.stream()
                    .collect(Collectors.toMap(AuditUnit::unitId, Function.identity()));
            for (LlmGateway.TriageDecision decision : plan.decisions()) {
                if (decision == null || decision.disposition() == null) continue;
                AuditUnit unit = batchById.get(decision.unitId());
                if (unit == null || unit.primaryChunkId() != decision.primaryChunkId()) continue;
                List<VulnerabilityType> safeTypes = decision.vulnerabilityTypes().stream()
                        .filter(java.util.Objects::nonNull)
                        .filter(VulnerabilityType::isDetectable)
                        .filter(unit.candidateTypes()::contains).distinct().toList();
                if (decision.disposition() == TriageDisposition.INVESTIGATE && safeTypes.isEmpty()) {
                    continue;
                }
                accepted.put(unit.unitId(), new LlmGateway.TriageDecision(
                        decision.unitId(), decision.primaryChunkId(), decision.disposition(), safeTypes,
                        intersect(decision.reasonCodes(), unit.reasonCodes()), decision.requiredContext(),
                        decision.reason()));
            }
        }
        TriageCounts counts = triageCounts(units, accepted);
        log.info("任务 {} 审计单元三态统计（{}）：总数={}，INVESTIGATE={}，NEED_CONTEXT={}，SKIP={}",
                taskId, phase, counts.total(), counts.investigate(), counts.needContext(), counts.skip());
        return accepted;
    }

    // 未返回或未通过服务端校验的决定会按现有流程补充上下文，因此统计为 NEED_CONTEXT。
    private TriageCounts triageCounts(List<AuditUnit> units,
                                      Map<String, LlmGateway.TriageDecision> decisions) {
        int investigate = 0;
        int needContext = 0;
        int skip = 0;
        for (AuditUnit unit : units) {
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

    // 向当前结果添加 addDecisionTasks 对应的数据。
    private void addDecisionTasks(Map<String, AgentTask> tasks, AuditUnit unit,
                                  LlmGateway.TriageDecision decision, String hintDescription) {
        for (VulnerabilityType type : decision.vulnerabilityTypes()) {
            addTask(tasks, unit, type, decision.reason(), hintDescription);
        }
    }

    private void addDecisionTasks(Map<String, AgentTask> tasks, IncrementalReviewUnit unit,
                                  LlmGateway.TriageDecision decision) {
        for (VulnerabilityType type : decision.vulnerabilityTypes()) {
            addTask(tasks, unit, type, decision.reason(), unit.deterministicEvidence());
        }
    }

    // 向当前结果添加 addTask 对应的数据。
    private void addTask(Map<String, AgentTask> tasks, AuditUnit unit, VulnerabilityType type,
                         String reason, String hintDescription) {
        if (type == null || !type.isDetectable() || !unit.candidateTypes().contains(type)) return;
        AgentTask task = new AgentTask(unit.primaryChunkId(), agentFor(type), type,
                reason == null || reason.isBlank() ? "轻量编排确认需要深入调查" : reason,
                hintDescription);
        tasks.putIfAbsent(key(task), task);
    }

    private void addTask(Map<String, AgentTask> tasks, IncrementalReviewUnit unit,
                         VulnerabilityType type, String reason, String evidence) {
        if (type == null || !type.isDetectable() || !unit.allowedTypes().contains(type)) return;
        AgentTask task = new AgentTask(unit.primaryChunkId(), agentFor(type), type,
                reason == null || reason.isBlank() ? "增量变更审查确认需要深入调查" : reason,
                joinNonBlank(evidence, unit.changeSummary(), unit.relatedContext()));
        tasks.putIfAbsent(key(task), task);
    }

    // 判断是否满足 shouldConservativelyInvestigate 对应的条件。
    private boolean shouldConservativelyInvestigate(AuditUnit unit) {
        return unit.reasonCodes().stream().anyMatch(CONSERVATIVE_REASON_CODES::contains);
    }

    // 判断是否满足 hasTaskFor 对应的条件。
    private boolean hasTaskFor(Map<String, AgentTask> tasks, long chunkId) {
        return tasks.values().stream().anyMatch(task -> task.chunkId() == chunkId);
    }

    // 执行 OrchestratorAgentService 中的 intersect 处理。
    private List<String> intersect(List<String> returned, List<String> allowed) {
        Set<String> allowedSet = new LinkedHashSet<>(allowed);
        return returned.stream().filter(allowedSet::contains).distinct().toList();
    }

    // 执行 OrchestratorAgentService 中的 truncate 处理。
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

    // 封装 TriageCounts 使用的不可变结构化数据。
    private record TriageCounts(int total, int investigate, int needContext, int skip) {
    }

    // 将每类漏洞固定路由到具备相应提示词和工具策略的专业 Agent。
    public static AgentType agentFor(VulnerabilityType type) {
        return switch (type) {
            case SQL_INJECTION -> AgentType.SQL_INJECTION;
            case AUTHORIZATION, UNAUTHORIZED_DISCLOSURE -> AgentType.AUTHORIZATION;
            case STORED_XSS -> AgentType.STORED_XSS;
            case VALIDATION_BYPASS -> AgentType.VALIDATION_BYPASS;
            case FINANCIAL_RISK -> throw new IllegalArgumentException("资金损失风险检测已停用");
        };
    }
}
