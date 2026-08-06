package com.deepaudit.agent;

import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.VulnerabilityType;

public record AgentTask(long chunkId, AgentType agentType, VulnerabilityType vulnerabilityType,
                        String reason, String ruleHint) {
}
