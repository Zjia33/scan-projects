package com.deepaudit.domain;

import java.time.Instant;
import java.util.UUID;

public class AgentEvent {
    private Long id;
    private UUID taskId;
    private UUID runId;
    private AgentType agentType;
    private AgentEventType eventType;
    private String message;
    private Instant createdAt;

    public AgentEvent() {
    }

    public AgentEvent(UUID taskId, UUID runId, AgentType agentType, AgentEventType eventType, String message) {
        this.taskId = taskId;
        this.runId = runId;
        this.agentType = agentType;
        this.eventType = eventType;
        this.message = message;
        this.createdAt = Instant.now();
    }

    public Long getId() { return id; }
    public UUID getTaskId() { return taskId; }
    public UUID getRunId() { return runId; }
    public AgentType getAgentType() { return agentType; }
    public AgentEventType getEventType() { return eventType; }
    public String getMessage() { return message; }
    public Instant getCreatedAt() { return createdAt; }
    public void setId(Long id) { this.id = id; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setRunId(UUID runId) { this.runId = runId; }
    public void setAgentType(AgentType agentType) { this.agentType = agentType; }
    public void setEventType(AgentEventType eventType) { this.eventType = eventType; }
    public void setMessage(String message) { this.message = message; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
