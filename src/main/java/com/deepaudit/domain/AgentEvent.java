package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

// 表示审计领域中的 AgentEvent 数据实体。
@Getter
@Setter
@NoArgsConstructor
public class AgentEvent {
    private Long id; // 事件记录的数据库自增主键
    private UUID taskId; // 事件所属的审计任务 ID
    private UUID runId; // 产生事件的 Agent 运行 ID，任务级事件可为空
    private AgentType agentType; // 产生事件的 Agent 类型
    private AgentEventType eventType; // Agent 生命周期中的事件类型
    private String message; // 事件的日志或过程说明
    private Instant createdAt; // 事件产生时间

    public AgentEvent(UUID taskId, UUID runId, AgentType agentType, AgentEventType eventType, String message) {
        this.taskId = taskId;
        this.runId = runId;
        this.agentType = agentType;
        this.eventType = eventType;
        this.message = message;
        this.createdAt = Instant.now();
    }

}
