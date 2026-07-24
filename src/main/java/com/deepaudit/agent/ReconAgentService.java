package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.recon.ReconSummary;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReconAgentService {
    private final LlmGateway llmGateway;
    private final AgentTraceService traceService;

    // 用技术栈事实和代表性代码块生成项目架构、攻击面及安全机制概览。
    public LlmGateway.ReconInsight inspect(UUID taskId, ReconSummary summary, List<CodeChunk> chunks) {
        AgentRun run = traceService.start(taskId, AgentType.RECON, null, "项目攻击面");
        try {
            // 优先选择接口和 Java 方法，并限制样本规模以控制模型上下文。
            List<LlmGateway.Target> representatives = chunks.stream()
                    .sorted(java.util.Comparator
                            .comparing((CodeChunk chunk) -> chunk.getAnalysisScope()
                                    != com.deepaudit.domain.AnalysisScope.CHANGED)
                            .thenComparing((CodeChunk chunk) -> chunk.getEndpoint() == null)
                            .thenComparing(chunk -> !"JAVA_METHOD".equals(chunk.getChunkType())))
                    .limit(50).map(chunk -> AgentPromptSupport.target(chunk, Set.of())).toList();
            run.setModelCallCount(1);
            traceService.event(taskId, run.getId(), AgentType.RECON, AgentEventType.MODEL_CALL,
                    "正在结合技术栈事实、接口样本和配置文件分析项目攻击面");
            // 将模型判断与确定性技术栈识别结果合并，避免模型覆盖真实扫描事实。
            LlmGateway.ReconInsight modelInsight = llmGateway.inspectProject(taskId, summary, representatives);
            LlmGateway.ReconInsight insight = new LlmGateway.ReconInsight(modelInsight.architectureSummary(),
                    modelInsight.attackSurfaces(), modelInsight.securityMechanisms(), modelInsight.riskAreas(),
                    summary.technologyProfile());
            // 将一个包含多个“框架名称”的集合，拼接成一个用中文顿号（、）分隔的单一字符串
            String frameworks = String.join("、", summary.technologyProfile().frameworks());
            String security = String.join("、", summary.technologyProfile().securityFrameworks());
            String event = insight.architectureSummary() + "；检测框架："
                    + (frameworks.isBlank() ? "未确定" : frameworks) + "；安全框架："
                    + (security.isBlank() ? "未确定" : security) + "；重点风险："
                    + String.join("、", insight.riskAreas());
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
