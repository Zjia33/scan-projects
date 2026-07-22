package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.HypothesisStatus;
import com.deepaudit.domain.Severity;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class CriticAgentService {
    private final LlmGateway llmGateway;
    private final AgentTraceService traceService;
    private final AuditHypothesisMapper hypothesisMapper;
    private final SemanticEvidenceService semanticEvidenceService;

    public CriticAgentService(LlmGateway llmGateway, AgentTraceService traceService,
                              AuditHypothesisMapper hypothesisMapper,
                              SemanticEvidenceService semanticEvidenceService) {
        this.llmGateway = llmGateway;
        this.traceService = traceService;
        this.hypothesisMapper = hypothesisMapper;
        this.semanticEvidenceService = semanticEvidenceService;
    }

    // 用独立语义证据和全局安全控制反证候选，仅确认项可转换为 Finding。
    public Optional<Finding> review(UUID taskId, AgentCandidate candidate,
                                    LlmGateway.ReconInsight recon, List<CodeChunk> chunks) {
        AgentRun run = traceService.start(taskId, AgentType.CRITIC,
                candidate.proposal().primaryChunkId(), candidate.proposal().title());
        try {
            run.setModelCallCount(1);
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.MODEL_CALL,
                    "正在结合 Recon 技术栈、独立语义证据和全局安全控制寻找反证");
            // Critic 直接读取持久化语义证据，避免只复述专业 Agent 的论证。
            String semanticEvidence = semanticEvidenceService.independentCriticEvidence(taskId,
                    candidate.proposal().primaryChunkId(), candidate.proposal().type());
            LlmGateway.CriticDecision decision = llmGateway.critique(new LlmGateway.CriticRequest(
                    taskId, candidate.sourceAgent(), candidate.proposal(), candidate.evidence(),
                    semanticEvidence, recon));
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.REASONING,
                    safe(decision.reason()));
            candidate.hypothesis().setCriticReason(decision.reason());
            candidate.hypothesis().setUpdatedAt(Instant.now());
            if (!decision.confirmed()) {
                // 发现反证时保留被拒假设和原因，但不创建最终漏洞。
                candidate.hypothesis().setStatus(HypothesisStatus.REJECTED);
                hypothesisMapper.update(candidate.hypothesis());
                traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.REJECTED,
                        "Critic 否决：" + safe(decision.reason()));
                run.complete("Critic Agent 找到反证并否决候选");
                traceService.update(run);
                return Optional.empty();
            }
            // 确认后以真实主代码块定位生成最终 Finding，并清理内部语义附录。
            Confidence confidence = decision.confidence() == null
                    ? fallbackConfidence(candidate.proposal().confidence()) : decision.confidence();
            candidate.hypothesis().setStatus(HypothesisStatus.CONFIRMED);
            candidate.hypothesis().setConfidence(confidence);
            hypothesisMapper.update(candidate.hypothesis());
            CodeChunk primary = chunks.stream()
                    .filter(chunk -> chunk.getId().equals(candidate.proposal().primaryChunkId()))
                    .findFirst().orElseThrow(() -> new IllegalStateException("Critic 引用的主证据不存在"));
            LlmGateway.FindingProposal proposal = candidate.proposal();
            Finding finding = new Finding(taskId, proposal.type(),
                    proposal.severity() == null ? Severity.HIGH : proposal.severity(), confidence,
                    truncate(proposal.title(), 500), primary.getFilePath(), primary.getStartLine(),
                    primary.getEndLine(), primary.getEndpoint(),
                    safeText(proposal.description()) + "\n\nCritic Agent 复核：" + safeText(decision.reason()),
                    reportEvidence(candidate.evidence()),
                    safeText(proposal.remediation()));
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.FINDING,
                    "确认 " + proposal.type().getDisplayName() + "：" + proposal.title());
            run.complete("Critic Agent 已确认漏洞证据链");
            traceService.update(run);
            return Optional.of(finding);
        } catch (RuntimeException exception) {
            run.fail(exception.getMessage());
            traceService.update(run);
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.ERROR, exception.getMessage());
            throw exception;
        }
    }

    private Confidence fallbackConfidence(Confidence value) {
        return value == null ? Confidence.MEDIUM : value;
    }

    private String truncate(String value, int length) {
        String result = value == null || value.isBlank() ? "AI Agent 发现潜在安全问题" : value.strip();
        return result.substring(0, Math.min(result.length(), length));
    }

    private String safe(String value) {
        return truncate(value, 2_000);
    }

    private String safeText(String value) {
        return value == null ? "" : value.strip();
    }

    // 从展示证据中移除只供内部复核使用的语义流附录。
    private String reportEvidence(String value) {
        if (value == null) return "";
        int semanticFlow = value.indexOf("\n\n[SEMANTIC_FLOW]\n");
        return (semanticFlow < 0 ? value : value.substring(0, semanticFlow)).stripTrailing();
    }
}
