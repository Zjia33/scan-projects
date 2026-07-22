package com.deepaudit.domain;

import java.time.Instant;
import java.util.UUID;

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

    public AgentRun() {
    }

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

    public UUID getId() { return id; }
    public UUID getTaskId() { return taskId; }
    public AgentType getAgentType() { return agentType; }
    public Long getTargetChunkId() { return targetChunkId; }
    public String getTargetSymbol() { return targetSymbol; }
    public AgentRunStatus getStatus() { return status; }
    public int getStepCount() { return stepCount; }
    public int getToolCallCount() { return toolCallCount; }
    public int getModelCallCount() { return modelCallCount; }
    public String getSummary() { return summary; }
    public Instant getStartedAt() { return startedAt; }
    public Instant getCompletedAt() { return completedAt; }
    public void setId(UUID id) { this.id = id; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setAgentType(AgentType agentType) { this.agentType = agentType; }
    public void setTargetChunkId(Long targetChunkId) { this.targetChunkId = targetChunkId; }
    public void setTargetSymbol(String targetSymbol) { this.targetSymbol = targetSymbol; }
    public void setStatus(AgentRunStatus status) { this.status = status; }
    public void setStepCount(int stepCount) { this.stepCount = stepCount; }
    public void setToolCallCount(int toolCallCount) { this.toolCallCount = toolCallCount; }
    public void setModelCallCount(int modelCallCount) { this.modelCallCount = modelCallCount; }
    public void setSummary(String summary) { this.summary = summary; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }
}
