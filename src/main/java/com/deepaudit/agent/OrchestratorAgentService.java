package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
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

@Slf4j
@Service
@RequiredArgsConstructor
public class OrchestratorAgentService {
    private static final Set<String> MANDATORY_REASON_CODES = Set.of(
            "RULE_HINT", "SEMANTIC_FLOW", "GUARD_REMOVED");
    private static final Set<String> CONSERVATIVE_REASON_CODES = Set.of(
            "EXTERNAL_ENTRY", "SECURITY_CONFIGURATION", "DANGEROUS_DATA_ACCESS",
            "DANGEROUS_OUTPUT", "VALIDATION_BOUNDARY", "SENSITIVE_FINANCIAL_OPERATION",
            "AUTHORIZATION_BOUNDARY", "UNRESOLVED_CALL", "SEMANTIC_CHANGE", "GUARD_REMOVED");

    private final LlmGateway llmGateway;
    private final AiProperties properties;
    private final AgentTraceService traceService;
    private final AuditUnitService auditUnitService;

    // 先对紧凑审计单元执行三态分流，再仅为 INVESTIGATE 单元创建专业 Agent 任务。
    public List<AgentTask> plan(UUID taskId, LlmGateway.ReconInsight recon, List<CodeChunk> chunks,
                                ScanMode scanMode, Map<Long, Set<VulnerabilityType>> hints,
                                Map<Long, String> hintDescriptions) {
        AgentRun run = traceService.start(taskId, AgentType.ORCHESTRATOR, null, "轻量安全分流与调查编排");
        try {
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
        return accepted;
    }

    private void addDecisionTasks(Map<String, AgentTask> tasks, AuditUnit unit,
                                  LlmGateway.TriageDecision decision, String hintDescription) {
        for (VulnerabilityType type : decision.vulnerabilityTypes()) {
            addTask(tasks, unit, type, decision.reason(), hintDescription);
        }
    }

    private void addTask(Map<String, AgentTask> tasks, AuditUnit unit, VulnerabilityType type,
                         String reason, String hintDescription) {
        if (type == null || !unit.candidateTypes().contains(type)) return;
        AgentTask task = new AgentTask(unit.primaryChunkId(), agentFor(type), type,
                reason == null || reason.isBlank() ? "轻量编排确认需要深入调查" : reason,
                hintDescription);
        tasks.putIfAbsent(key(task), task);
    }

    private boolean shouldConservativelyInvestigate(AuditUnit unit) {
        return unit.reasonCodes().stream().anyMatch(CONSERVATIVE_REASON_CODES::contains);
    }

    private boolean hasTaskFor(Map<String, AgentTask> tasks, long chunkId) {
        return tasks.values().stream().anyMatch(task -> task.chunkId() == chunkId);
    }

    private List<String> intersect(List<String> returned, List<String> allowed) {
        Set<String> allowedSet = new LinkedHashSet<>(allowed);
        return returned.stream().filter(allowedSet::contains).distinct().toList();
    }

    private String truncate(String value, int maxLength) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), maxLength));
    }

    // 用代码块和漏洞类型组成稳定键以合并重复规划任务。
    private String key(AgentTask task) {
        return task.chunkId() + "|" + task.vulnerabilityType();
    }

    // 将每类漏洞固定路由到具备相应提示词和工具策略的专业 Agent。
    public static AgentType agentFor(VulnerabilityType type) {
        return switch (type) {
            case SQL_INJECTION -> AgentType.SQL_INJECTION;
            case AUTHORIZATION, UNAUTHORIZED_DISCLOSURE -> AgentType.AUTHORIZATION;
            case STORED_XSS -> AgentType.STORED_XSS;
            case VALIDATION_BYPASS -> AgentType.VALIDATION_BYPASS;
            case FINANCIAL_RISK -> AgentType.FINANCIAL_RISK;
        };
    }
}
