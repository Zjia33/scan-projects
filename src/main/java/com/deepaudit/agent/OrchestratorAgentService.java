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
    private static final int MAX_INVESTIGATION_QUESTIONS = 6;
    private final LlmGateway llmGateway;
    private final AiProperties properties;
    private final AgentTraceService traceService;
    private final IncrementalReviewService incrementalReviewService;

    /** Triage 只对 CHANGED 做逐行风险路由；跨方法上下文由专业 Agent 自主获取。 */
    public List<AgentTask> plan(UUID taskId, LlmGateway.ReconInsight recon, List<CodeChunk> chunks,
                                Map<Long, Set<VulnerabilityType>> hints,
                                Map<Long, String> hintDescriptions) {
        AgentRun run = traceService.start(taskId, AgentType.ORCHESTRATOR, null, "CHANGED 风险分诊与调查编排");
        long planningStarted = ExecutionTiming.start();
        try {
            List<AgentTask> result = planChangedUnits(taskId, run, recon, chunks, hints, hintDescriptions);
            TimingDetailLog.info("阶段明细：taskId={}，阶段=CHANGED分诊与任务规划，耗时={}ms，"
                            + "说明=Triage只定位可疑变更，不预载入IMPACTED源码，专业任务数={}",
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

    private List<AgentTask> planChangedUnits(
            UUID taskId, AgentRun run, LlmGateway.ReconInsight recon, List<CodeChunk> chunks,
            Map<Long, Set<VulnerabilityType>> hints, Map<Long, String> hintDescriptions) {
        List<IncrementalReviewUnit> units = incrementalReviewService.build(
                taskId, chunks, hints, hintDescriptions);
        TimingDetailLog.info("任务 {} 已构建 {} 个 CHANGED 审查单元；Triage不附加任何IMPACTED源码",
                taskId, units.size());
        traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.REASONING,
                "Triage 将逐行对比 CHANGED 的 Base/Target；上下文获取交由专业 Agent");

        Map<String, AgentTask> tasks = new LinkedHashMap<>();
        List<IncrementalReviewUnit> modelUnits = new ArrayList<>();
        int mandatoryUnits = 0;
        for (IncrementalReviewUnit unit : units) {
            modelUnits.add(unit);
            if (!unit.mandatoryTypes().isEmpty()) {
                mandatoryUnits++;
                for (VulnerabilityType type : unit.mandatoryTypes()) {
                    addTask(tasks, unit, type, "确定性规则、安全流或 Guard 变化要求直接调查",
                            unit.deterministicEvidence(), List.of(), List.of());
                }
            }
        }

        List<String> summaries = new ArrayList<>();
        Map<String, LlmGateway.TriageDecision> decisions = triageBatches(
                taskId, run, recon, modelUnits, summaries);
        int skipped = 0;
        int conservativeFallbacks = 0;
        for (IncrementalReviewUnit unit : modelUnits) {
            LlmGateway.TriageDecision decision = decisions.get(unit.unitId());
            if (decision == null) {
                List<VulnerabilityType> fallbackTypes = conservativeFallbackTypes(unit);
                for (VulnerabilityType type : fallbackTypes) {
                    addTask(tasks, unit, type,
                            "Triage 未返回合法决定，不将上下文不足解释为安全，保守进入专业调查",
                            unit.deterministicEvidence(), List.of(), List.of());
                }
                conservativeFallbacks++;
                continue;
            }
            if (decision.disposition() == TriageDisposition.SKIP) {
                skipped++;
                continue;
            }
            for (VulnerabilityType type : decision.vulnerabilityTypes()) {
                addTask(tasks, unit, type, decision.reason(), unit.deterministicEvidence(),
                        decision.focusRanges(), decision.investigationQuestions());
            }
        }

        long investigatedUnits = tasks.values().stream().map(AgentTask::chunkId).distinct().count();
        String modelSummary = truncate(String.join("；", summaries), 2_000);
        String summary = "CHANGED 变更分诊覆盖 " + units.size() + " 个位置；"
                + mandatoryUnits + " 个确定性直达，"
                + conservativeFallbacks + " 个响应异常后保守调查，"
                + skipped + " 个明确跳过，" + investigatedUnits
                + " 个进入调查，规划 " + tasks.size() + " 个专业 Agent 任务"
                + (modelSummary.isBlank() ? "" : "；" + modelSummary);
        traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.PLAN, summary);
        run.complete(summary);
        traceService.update(run);
        return List.copyOf(tasks.values());
    }

    private Map<String, LlmGateway.TriageDecision> triageBatches(
            UUID taskId, AgentRun run, LlmGateway.ReconInsight recon,
            List<IncrementalReviewUnit> units, List<String> summaries) {
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
                    "CHANGED 风险分诊第 " + batchNumber + " 批，共 " + batch.size()
                            + " 个变更位置，输入约 " + estimatedChars + " 字符");
            long requestStarted = ExecutionTiming.start();
            TimingDetailLog.info("模型阶段开始：taskId={}，stage=TRIAGE_CHANGED，batch={}，units={}，estimatedChars={}",
                    taskId, batchNumber, batch.size(), estimatedChars);
            try {
                LlmGateway.TriagePlan plan = llmGateway.triageIncremental(taskId, recon, batch);
                acceptPlan(taskId, run, batch, plan, summaries, accepted);
                TimingDetailLog.info("模型阶段结束：taskId={}，stage=TRIAGE_CHANGED，batch={}，elapsedMs={}，status=SUCCESS",
                        taskId, batchNumber, ExecutionTiming.elapsedMillis(requestStarted));
            } catch (AiResponseFormatException exception) {
                long elapsedMs = ExecutionTiming.elapsedMillis(requestStarted);
                TimingDetailLog.warn("模型阶段结束：taskId={}，stage=TRIAGE_CHANGED，batch={}，elapsedMs={}，status=FORMAT_ERROR",
                        taskId, batchNumber, elapsedMs);
                traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR,
                        AgentEventType.FORMAT_ERROR, "第 " + batchNumber
                                + " 批 Triage 响应格式异常，该批将保守调查");
            }
            run.setModelCallCount(run.getModelCallCount() + 1);
            start = end;
        }
        long investigate = accepted.values().stream()
                .filter(value -> value.disposition() == TriageDisposition.INVESTIGATE).count();
        long skip = accepted.values().stream()
                .filter(value -> value.disposition() == TriageDisposition.SKIP).count();
        TimingDetailLog.info("任务 {} CHANGED 二态分诊：总数={}，INVESTIGATE={}，SKIP={}，缺失或无效={}",
                taskId, units.size(), investigate, skip, units.size() - accepted.size());
        return accepted;
    }

    private void acceptPlan(UUID taskId, AgentRun run, List<IncrementalReviewUnit> batch,
                            LlmGateway.TriagePlan plan, List<String> summaries,
                            Map<String, LlmGateway.TriageDecision> accepted) {
        if (plan == null) return;
        if (plan.summary() != null && !plan.summary().isBlank()) summaries.add(plan.summary());
        Map<String, IncrementalReviewUnit> unitsById = batch.stream()
                .collect(Collectors.toMap(IncrementalReviewUnit::unitId, Function.identity()));
        Set<String> seen = new LinkedHashSet<>();
        for (LlmGateway.TriageDecision decision : plan.decisions()) {
            if (decision == null) continue;
            IncrementalReviewUnit unit = unitsById.get(decision.unitId());
            if (unit == null || !seen.add(unit.unitId())
                    || unit.primaryChunkId() != decision.primaryChunkId()
                    || decision.disposition() == null) {
                rejectDecision(taskId, run, decision.unitId(), "ID、主代码块、重复性或 disposition 无效");
                continue;
            }
            List<VulnerabilityType> safeTypes = decision.vulnerabilityTypes().stream()
                    .filter(unit.allowedTypes()::contains).distinct().toList();
            if (decision.disposition() == TriageDisposition.INVESTIGATE && safeTypes.isEmpty()) {
                rejectDecision(taskId, run, unit.unitId(), "INVESTIGATE 缺少允许范围内的漏洞类型");
                continue;
            }
            if (decision.disposition() == TriageDisposition.SKIP) safeTypes = List.of();
            List<LlmGateway.LineRange> focusRanges = validFocusRanges(unit, decision.focusRanges());
            List<String> questions = decision.investigationQuestions().stream()
                    .map(value -> truncate(value, 300)).limit(MAX_INVESTIGATION_QUESTIONS).toList();
            accepted.put(unit.unitId(), new LlmGateway.TriageDecision(
                    unit.unitId(), unit.primaryChunkId(), decision.disposition(), safeTypes,
                    decision.reason(), focusRanges, questions));
        }
        for (IncrementalReviewUnit unit : batch) {
            if (!seen.contains(unit.unitId())) {
                rejectDecision(taskId, run, unit.unitId(), "模型响应缺少决定");
            }
        }
    }

    private List<LlmGateway.LineRange> validFocusRanges(
            IncrementalReviewUnit unit, List<LlmGateway.LineRange> ranges) {
        if (ranges == null || ranges.isEmpty()) return List.of();
        return ranges.stream().filter(range -> range.startLine() > 0
                        && range.endLine() >= range.startLine())
                .filter(range -> unit.startLine() <= 0 || range.startLine() >= unit.startLine())
                .filter(range -> unit.endLine() <= 0 || range.endLine() <= unit.endLine())
                .distinct().limit(6).toList();
    }

    private void rejectDecision(UUID taskId, AgentRun run, String unitId, String reason) {
        log.warn("任务 {} 拒绝 Triage 决定：unitId={}，原因={}", taskId, safe(unitId), reason);
        traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR,
                AgentEventType.REASONING, "拒绝 " + safe(unitId) + "：" + reason);
    }

    private List<VulnerabilityType> conservativeFallbackTypes(IncrementalReviewUnit unit) {
        // 模型响应缺失时不能用关键词缩小漏洞类型，否则格式异常会转化为静默漏报。
        return unit.allowedTypes().stream().filter(java.util.Objects::nonNull).distinct().toList();
    }

    private void addTask(Map<String, AgentTask> tasks, IncrementalReviewUnit unit,
                         VulnerabilityType type, String reason, String evidence,
                         List<LlmGateway.LineRange> focusRanges, List<String> questions) {
        if (type == null || !unit.allowedTypes().contains(type)) return;
        String focus = focusRanges == null || focusRanges.isEmpty() ? ""
                : "Triage 可疑行：" + focusRanges.stream()
                .map(range -> range.startLine() + "-" + range.endLine())
                .collect(Collectors.joining(", "));
        String questionText = questions == null || questions.isEmpty() ? ""
                : "待验证问题：\n- " + String.join("\n- ", questions);
        AgentTask task = new AgentTask(unit.primaryChunkId(), agentFor(type), type,
                joinNonBlank(reason == null || reason.isBlank() ? "CHANGED 变更需要深入调查" : reason,
                        evidence, unit.changeSummary(), focus, questionText,
                        "Base 变更窗口：\n<UNTRUSTED_CODE_BASE>\n" + unit.baseCodeExcerpt()
                                + "\n</UNTRUSTED_CODE_BASE>",
                        "Target 变更窗口：\n<UNTRUSTED_CODE_TARGET>\n" + unit.targetCodeExcerpt()
                                + "\n</UNTRUSTED_CODE_TARGET>"));
        tasks.putIfAbsent(task.chunkId() + "|" + task.vulnerabilityType(), task);
    }

    private int estimatedSize(IncrementalReviewUnit unit) {
        return unit.baseCodeExcerpt().length() + unit.targetCodeExcerpt().length()
                + unit.changeSummary().length() + unit.deterministicEvidence().length() + 1_000;
    }

    private String joinNonBlank(String... values) {
        return java.util.Arrays.stream(values).filter(java.util.Objects::nonNull).map(String::strip)
                .filter(value -> !value.isBlank()).collect(Collectors.joining("\n\n"));
    }

    private String truncate(String value, int maxLength) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), maxLength));
    }

    private String safe(String value) {
        return value == null ? "" : value.replace('\n', ' ').replace('\r', ' ').strip();
    }

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
