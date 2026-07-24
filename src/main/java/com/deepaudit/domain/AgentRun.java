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
    private UUID id;
    private UUID taskId;
    private AgentType agentType;
    private Long targetChunkId;
    private String targetSymbol;
    private AgentRunStatus status;
    private int stepCount;
    private int toolCallCount;
    private int modelCallCount;
    private String summary;
    private Instant startedAt;
    private Instant completedAt;

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
