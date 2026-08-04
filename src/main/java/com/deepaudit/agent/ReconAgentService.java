package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;

// 负责 ReconAgentService 对应的业务编排和处理。
@Service
@RequiredArgsConstructor
@Slf4j
public class ReconAgentService {
    private final LlmGateway llmGateway;
    private final AgentTraceService traceService;

    // 使用构建描述、应用配置和去计数后的框架事实生成技术架构概览，不执行安全结论判断。
    public LlmGateway.ReconInsight inspect(UUID taskId, ReconSummary summary) {
        long inspectStarted = ExecutionTiming.start();
        AgentRun run = traceService.start(taskId, AgentType.RECON, null, "项目框架与技术架构");
        try {
            run.setModelCallCount(1);
            traceService.event(taskId, run.getId(), AgentType.RECON, AgentEventType.MODEL_CALL,
                    "正在读取构建描述、配置与框架事实，归纳项目技术架构");
            // 将模型判断与确定性技术栈识别结果合并，避免模型覆盖真实扫描事实。
            LlmGateway.ReconInsight modelInsight = llmGateway.inspectProject(taskId, summary);
            long elapsedMs = ExecutionTiming.elapsedMillis(inspectStarted);
            LlmGateway.ReconInsight insight = new LlmGateway.ReconInsight(modelInsight.architectureSummary(),
                    summary.technologyProfile().withoutEvidence());
            // 将一个包含多个“框架名称”的集合，拼接成一个用中文顿号（、）分隔的单一字符串
            String frameworks = String.join("、", summary.technologyProfile().frameworks());
            String security = String.join("、", summary.technologyProfile().securityFrameworks());
            String event = insight.architectureSummary() + "；检测框架："
                    + (frameworks.isBlank() ? "未确定" : frameworks) + "；安全框架："
                    + (security.isBlank() ? "未确定" : security);
            traceService.event(taskId, run.getId(), AgentType.RECON, AgentEventType.OBSERVATION,
                    "模型调用完成，耗时 " + elapsedMs + " ms；" + event);
            TimingDetailLog.info("阶段明细：taskId={}，阶段=项目架构理解，耗时={}ms，说明=模型归纳构建配置、技术栈与框架事实，源码文件数={}，框架文件数={}",
                    taskId, elapsedMs, summary.sourceFileCount(), summary.frameworkFiles().size());
            run.complete("Recon Agent 已完成项目框架与技术架构解析");
            traceService.update(run);
            return insight;
        } catch (RuntimeException exception) {
            log.error("执行耗时：taskId={}，stage=RECON_AGENT，elapsedMs={}，status=FAILED，error={}",
                    taskId, ExecutionTiming.elapsedMillis(inspectStarted), exception.getClass().getSimpleName());
            // 同步记录运行状态和错误事件后向上抛出，由任务编排器标记失败。
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), AgentType.RECON, AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
    }
}
