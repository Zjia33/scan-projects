package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.AuditHypothesis;

public record AgentCandidate(AgentType sourceAgent, LlmGateway.FindingProposal proposal,
                             AuditHypothesis hypothesis) {
}
