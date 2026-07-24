package com.deepaudit.agent;

import com.deepaudit.domain.AgentEvent;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.mapper.AgentEventMapper;
import com.deepaudit.mapper.AgentRunMapper;
import com.deepaudit.mapper.AiReportSummaryMapper;
import com.deepaudit.mapper.AuditHypothesisMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AgentTraceService {
    private final AgentRunMapper runMapper;
    private final AgentEventMapper eventMapper;
    private final AuditHypothesisMapper hypothesisMapper;
    private final AiReportSummaryMapper reportSummaryMapper;
    private final AgentEventStreamService eventStreamService;

    // 创建 Agent 运行记录并同步发布启动事件。
    public AgentRun start(UUID taskId, AgentType type, Long targetChunkId, String targetSymbol) {
        AgentRun run = new AgentRun(taskId, type, targetChunkId, targetSymbol);
        runMapper.insert(run);
        event(taskId, run.getId(), type, AgentEventType.STARTED,
                targetSymbol == null ? type + " 已启动" : "开始审查 " + targetSymbol);
        return run;
    }

    // 持久化截断后的事件消息并实时推送给当前 SSE 订阅者。
    public void event(UUID taskId, UUID runId, AgentType type, AgentEventType eventType, String message) {
        String safe = message == null ? "" : message.substring(0, Math.min(message.length(), 12_000));
        AgentEvent event = new AgentEvent(taskId, runId, type, eventType, safe);
        eventMapper.insert(event);
        eventStreamService.publish(event);
    }

    // 保存 Agent 的步骤数、模型调用数、工具调用数和最终状态。
    public void update(AgentRun run) {
        runMapper.update(run);
    }

    // 按依赖顺序清理任务的旧报告、假设、事件和运行轨迹。
    @Transactional
    public void reset(UUID taskId) {
        reportSummaryMapper.deleteByTaskId(taskId);
        hypothesisMapper.deleteByTaskId(taskId);
        eventMapper.deleteByTaskId(taskId);
        runMapper.deleteByTaskId(taskId);
    }
}
