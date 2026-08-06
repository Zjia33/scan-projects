package com.deepaudit.agent;

import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.VulnerabilityType;

public record AgentTask(long chunkId, AgentType agentType, VulnerabilityType vulnerabilityType,
                        String ruleHint, String baseChangeExcerpt, String targetChangeExcerpt) {

    public AgentTask(long chunkId, AgentType agentType, VulnerabilityType vulnerabilityType,
                     String ruleHint) {
        this(chunkId, agentType, vulnerabilityType, ruleHint, "", "");
    }

    public AgentTask {
        ruleHint = safe(ruleHint);
        baseChangeExcerpt = safe(baseChangeExcerpt);
        targetChangeExcerpt = safe(targetChangeExcerpt);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    public AgentTask withAdditionalRuleHint(String additionalHint) {
        String addition = safe(additionalHint).strip();
        if (addition.isBlank()) return this;
        String combined = ruleHint.isBlank() ? addition : ruleHint + "\n\n" + addition;
        return new AgentTask(chunkId, agentType, vulnerabilityType, combined,
                baseChangeExcerpt, targetChangeExcerpt);
    }
}
