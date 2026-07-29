package com.deepaudit.agent;

import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.VulnerabilityType;

// 封装 AgentTask 使用的不可变结构化数据。
public record AgentTask(long chunkId, AgentType agentType, VulnerabilityType vulnerabilityType,
                        String reason, String ruleHint) {
}
