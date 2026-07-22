package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
public class OrchestratorAgentService {
    private static final Logger log = LoggerFactory.getLogger(OrchestratorAgentService.class);

    private final LlmGateway llmGateway;
    private final AiProperties properties;
    private final AgentTraceService traceService;

    public OrchestratorAgentService(LlmGateway llmGateway, AiProperties properties,
                                    AgentTraceService traceService) {
        this.llmGateway = llmGateway;
        this.properties = properties;
        this.traceService = traceService;
    }

    // 将候选代码块分批规划为与漏洞类型严格匹配的专业 Agent 任务。
    public List<AgentTask> plan(UUID taskId, LlmGateway.ReconInsight recon,
                                List<CodeChunk> selectedChunks,
                                Map<Long, Set<VulnerabilityType>> hints,
                                Map<Long, String> hintDescriptions) {
        AgentRun run = traceService.start(taskId, AgentType.ORCHESTRATOR, null, "智能审计计划");
        try {
            // 按审计上限裁剪目标，并附带确定性线索类型供模型规划。
            List<LlmGateway.Target> targets = selectedChunks.stream()
                    .limit(properties.getMaxAuditTargets())
                    .map(chunk -> AgentPromptSupport.target(chunk, hints.getOrDefault(chunk.getId(), Set.of())))
                    .toList();
            Map<String, AgentTask> tasks = new LinkedHashMap<>();
            List<String> planSummaries = new ArrayList<>();
            int batchSize = Math.max(1, properties.getPlannerBatchSize());
            // 分批调用规划模型，避免大型项目一次性超过上下文窗口。
            for (int start = 0; start < targets.size(); start += batchSize) {
                List<LlmGateway.Target> batch = targets.subList(start, Math.min(start + batchSize, targets.size()));
                traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.MODEL_CALL,
                        "正在规划第 " + (start / batchSize + 1) + " 批审计目标，共 " + batch.size() + " 个代码块");
                LlmGateway.AuditPlan plan = llmGateway.createPlan(taskId, recon, batch);
                run.setModelCallCount(run.getModelCallCount() + 1);
                if (plan.summary() != null) planSummaries.add(plan.summary());
                for (LlmGateway.PlannedTask item : plan.tasks()) {
                    if (item == null || item.agentType() == null || item.vulnerabilityType() == null) {
                        log.warn("任务 {} 跳过模型返回的不受支持审计计划项: {}", taskId, item);
                        continue;
                    }
                    // 拒绝批次外目标及 Agent 类型不匹配项，限制模型扩大审计权限。
                    if (batch.stream().noneMatch(target -> target.chunkId() == item.chunkId())) continue;
                    AgentType expected = agentFor(item.vulnerabilityType());
                    if (expected != item.agentType()) continue;
                    AgentTask task = new AgentTask(item.chunkId(), expected, item.vulnerabilityType(),
                            item.reason(), hintDescriptions.get(item.chunkId()));
                    tasks.put(key(task), task);
                }
            }
            // 规则只能增加调查任务，不能直接产生漏洞；避免模型规划遗漏明确危险语法。
            for (Map.Entry<Long, Set<VulnerabilityType>> entry : hints.entrySet()) {
                for (VulnerabilityType type : entry.getValue()) {
                    AgentTask task = new AgentTask(entry.getKey(), agentFor(type), type,
                            "确定性规则提供了需要 AI 深入核查的线索", hintDescriptions.get(entry.getKey()));
                    tasks.putIfAbsent(key(task), task);
                }
            }
            String summary = "规划 " + tasks.size() + " 个专业 Agent 调查任务；"
                    + String.join("；", planSummaries).substring(0,
                    Math.min(String.join("；", planSummaries).length(), 4_000));
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.PLAN, summary);
            run.complete(summary);
            traceService.update(run);
            return List.copyOf(tasks.values());
        } catch (RuntimeException exception) {
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), AgentType.ORCHESTRATOR, AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
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
