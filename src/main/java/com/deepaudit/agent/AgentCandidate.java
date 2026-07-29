package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.AuditHypothesis;

// 封装 AgentCandidate 使用的不可变结构化数据。
public record AgentCandidate(AgentType sourceAgent, LlmGateway.FindingProposal proposal,
                             String evidence, AuditHypothesis hypothesis) {
}
