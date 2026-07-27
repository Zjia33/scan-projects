package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class AgentRun {
    private UUID id; // 本次 Agent 运行的唯一标识
    private UUID taskId; // 运行所属的审计任务 ID
    private AgentType agentType; // 执行本次运行的 Agent 类型
    private Long targetChunkId; // 本次调查聚焦的主代码块 ID
    private String targetSymbol; // 本次调查聚焦的代码符号
    private AgentRunStatus status; // 当前运行状态
    private int stepCount; // Agent 已执行的推理步骤数
    private int toolCallCount; // Agent 已发起的工具调用次数
    private int modelCallCount; // Agent 已发起的模型调用次数
    private String summary; // 运行完成或失败后的结果摘要
    private Instant startedAt; // 运行开始时间
    private Instant completedAt; // 运行完成或失败时间

    public AgentRun(UUID taskId, AgentType agentType, Long targetChunkId, String targetSymbol) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.agentType = agentType;
        this.targetChunkId = targetChunkId;
        this.targetSymbol = targetSymbol;
        this.status = AgentRunStatus.RUNNING;
        this.startedAt = Instant.now();
    }

    public void complete(String summary) {
        this.status = AgentRunStatus.COMPLETED;
        this.summary = summary;
        this.completedAt = Instant.now();
    }

    public void fail(String summary) {
        this.status = AgentRunStatus.FAILED;
        this.summary = summary;
        this.completedAt = Instant.now();
    }

}
