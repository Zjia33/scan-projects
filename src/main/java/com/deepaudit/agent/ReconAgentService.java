package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.recon.ReconSummary;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

// 负责 ReconAgentService 对应的业务编排和处理。
@Service
@RequiredArgsConstructor
public class ReconAgentService {
    private final LlmGateway llmGateway;
    private final AgentTraceService traceService;

    // 用完整项目产生的结构化事实生成架构、攻击面及安全机制概览，不向模型发送业务源码正文。
    public LlmGateway.ReconInsight inspect(UUID taskId, ReconSummary summary) {
        AgentRun run = traceService.start(taskId, AgentType.RECON, null, "项目攻击面");
        try {
            run.setModelCallCount(1);
            traceService.event(taskId, run.getId(), AgentType.RECON, AgentEventType.MODEL_CALL,
                    "正在结合完整项目的技术栈、模块、入口与安全配置事实分析项目攻击面");
            // 将模型判断与确定性技术栈识别结果合并，避免模型覆盖真实扫描事实。
            LlmGateway.ReconInsight modelInsight = llmGateway.inspectProject(taskId, summary);
            LlmGateway.ReconInsight insight = new LlmGateway.ReconInsight(modelInsight.architectureSummary(),
                    List.of(), List.of(), List.of(),
                    summary.technologyProfile().withoutEvidence());
            // 将一个包含多个“框架名称”的集合，拼接成一个用中文顿号（、）分隔的单一字符串
            String frameworks = String.join("、", summary.technologyProfile().frameworks());
            String security = String.join("、", summary.technologyProfile().securityFrameworks());
            String event = insight.architectureSummary() + "；检测框架："
                    + (frameworks.isBlank() ? "未确定" : frameworks) + "；安全框架："
                    + (security.isBlank() ? "未确定" : security);
            traceService.event(taskId, run.getId(), AgentType.RECON, AgentEventType.OBSERVATION, event);
            run.complete("Recon Agent 已完成项目架构和攻击面分析");
            traceService.update(run);
            return insight;
        } catch (RuntimeException exception) {
            // 同步记录运行状态和错误事件后向上抛出，由任务编排器标记失败。
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), AgentType.RECON, AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
    }
}
