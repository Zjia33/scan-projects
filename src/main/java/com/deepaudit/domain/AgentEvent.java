package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class AgentEvent {
    private Long id;
    private UUID taskId;
    private UUID runId;
    private AgentType agentType;
    private AgentEventType eventType;
    private String message;
    private Instant createdAt;

    public AgentEvent(UUID taskId, UUID runId, AgentType agentType, AgentEventType eventType, String message) {
        this.taskId = taskId;
        this.runId = runId;
        this.agentType = agentType;
        this.eventType = eventType;
        this.message = message;
        this.createdAt = Instant.now();
    }

}
