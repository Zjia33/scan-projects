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
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

// 负责 CriticAgentService 对应的业务编排和处理。
@Service
@RequiredArgsConstructor
public class CriticAgentService {
    private final LlmGateway llmGateway;
    private final AgentTraceService traceService;
    private final AuditHypothesisMapper hypothesisMapper;
    private final SemanticEvidenceService semanticEvidenceService;

    // 用独立语义证据和全局安全控制反证候选，仅确认项可转换为 Finding。
    public Optional<Finding> review(UUID taskId, AgentCandidate candidate,
                                    LlmGateway.ReconInsight recon, List<CodeChunk> chunks,
                                    ScanMode scanMode) {
        AgentRun run = traceService.start(taskId, AgentType.CRITIC,
                candidate.proposal().primaryChunkId(), candidate.proposal().title());
        try {
            Map<Long, CodeChunk> chunksById = chunks.stream()
                    .collect(Collectors.toMap(CodeChunk::getId, Function.identity()));
            run.setModelCallCount(1);
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.MODEL_CALL,
                    "正在结合 Recon 技术栈、独立语义证据和全局安全控制寻找反证");
            // Critic 直接读取持久化语义证据，避免只复述专业 Agent 的论证。
            String semanticEvidence = semanticEvidenceService.independentCriticEvidence(taskId,
                    candidate.proposal().primaryChunkId(), candidate.proposal().type());
            CodeChunk originalPrimary = Optional.ofNullable(chunksById.get(candidate.proposal().primaryChunkId()))
                    .orElseThrow(() -> new IllegalStateException("Critic 引用的主证据不存在"));
            LlmGateway.CriticDecision decision = llmGateway.critique(new LlmGateway.CriticRequest(
                    taskId, candidate.sourceAgent(), candidate.proposal(), candidate.evidence(),
                    semanticEvidence, recon, originalPrimary.getChangeType().name(),
                    originalPrimary.getAnalysisScope().name(), originalPrimary.getBaseContent()));
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
            Optional<LlmGateway.FindingProposal> corrected = correctedProposal(
                    candidate.proposal(), decision, chunksById, scanMode);
            if (corrected.isEmpty()) {
                String invalidLocation = "Critic 虽确认候选，但未返回合法的最终漏洞代码块和精确行号";
                candidate.hypothesis().setStatus(HypothesisStatus.REJECTED);
                candidate.hypothesis().setCriticReason(safe(decision.reason()) + "；" + invalidLocation);
                hypothesisMapper.update(candidate.hypothesis());
                traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.REJECTED,
                        invalidLocation);
                run.complete(invalidLocation);
                traceService.update(run);
                return Optional.empty();
            }
            // Critic 对整条证据链重新选择实际漏洞点，最终报告不复用专业 Agent 的旧位置文本。
            Confidence confidence = decision.confidence() == null
                    ? fallbackConfidence(candidate.proposal().confidence()) : decision.confidence();
            LlmGateway.FindingProposal proposal = corrected.get();
            CodeChunk primary = chunksById.get(proposal.primaryChunkId());
            candidate.hypothesis().setStatus(HypothesisStatus.CONFIRMED);
            candidate.hypothesis().setConfidence(confidence);
            candidate.hypothesis().setPrimaryChunkId(proposal.primaryChunkId());
            candidate.hypothesis().setEvidenceChunkIds(proposal.evidenceChunkIds().stream()
                    .map(String::valueOf).collect(Collectors.joining(",")));
            hypothesisMapper.update(candidate.hypothesis());
            FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, primary);
            Set<Long> evidenceIds = new LinkedHashSet<>(proposal.evidenceChunkIds());
            Map<Long, Integer> callSites = semanticEvidenceService.callSiteLines(
                    taskId, proposal.primaryChunkId(), evidenceIds);
            String endpoint = affectedEndpoint(proposal, chunksById);
            Finding finding = new Finding(taskId, proposal.type(),
                    proposal.severity() == null ? Severity.HIGH : proposal.severity(), confidence,
                    truncate(proposal.title(), 500), primary.getFilePath(), location.startLine(),
                    location.endLine(), endpoint,
                    safeText(proposal.description()) + "\n\nCritic Agent 复核：" + safeText(decision.reason()),
                    FindingLocationResolver.formatEvidence(proposal, chunksById, callSites),
                    safeText(proposal.remediation()));
            finding.setDeltaStatus(FindingDeltaStatus.normalizeFor(scanMode, decision.deltaStatus()));
            finding.setFingerprint(fingerprint(proposal.type().name(), primary.getFilePath(),
                    primary.getSymbolName(), endpoint));
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

    // 执行 CriticAgentService 中的 fallbackConfidence 处理。
    private Confidence fallbackConfidence(Confidence value) {
        return value == null ? Confidence.MEDIUM : value;
    }

    // 执行 CriticAgentService 中的 truncate 处理。
    private String truncate(String value, int length) {
        String result = value == null || value.isBlank() ? "AI Agent 发现潜在安全问题" : value.strip();
        return result.substring(0, Math.min(result.length(), length));
    }

    // 执行 CriticAgentService 中的 safe 处理。
    private String safe(String value) {
        return truncate(value, 2_000);
    }

    // 执行 CriticAgentService 中的 safeText 处理。
    private String safeText(String value) {
        return value == null ? "" : value.strip();
    }

    // 执行 CriticAgentService 中的 correctedProposal 处理。
    private Optional<LlmGateway.FindingProposal> correctedProposal(
            LlmGateway.FindingProposal original, LlmGateway.CriticDecision decision,
            Map<Long, CodeChunk> chunks, ScanMode scanMode) {
        Long primaryChunkId = decision.primaryChunkId();
        Set<Long> allowed = new LinkedHashSet<>(original.evidenceChunkIds());
        allowed.add(original.primaryChunkId());
        if (primaryChunkId == null || !allowed.contains(primaryChunkId)) return Optional.empty();
        CodeChunk primary = chunks.get(primaryChunkId);
        if (primary == null) return Optional.empty();
        if (scanMode == ScanMode.INCREMENTAL
                && primary.getAnalysisScope() != com.deepaudit.domain.AnalysisScope.CHANGED
                && primary.getAnalysisScope() != com.deepaudit.domain.AnalysisScope.IMPACTED) {
            return Optional.empty();
        }
        Optional<FindingLocationResolver.Location> location = FindingLocationResolver.validateExplicit(
                decision.vulnerabilityStartLine(), decision.vulnerabilityEndLine(), primary);
        if (location.isEmpty()) return Optional.empty();
        List<Long> evidenceIds = new ArrayList<>(allowed);
        evidenceIds.remove(primaryChunkId);
        evidenceIds.add(0, primaryChunkId);
        return Optional.of(new LlmGateway.FindingProposal(original.type(), original.severity(),
                original.confidence(), original.title(), original.description(), original.remediation(),
                primaryChunkId, evidenceIds, location.get().startLine(), location.get().endLine()));
    }

    // 执行 CriticAgentService 中的 affectedEndpoint 处理。
    private String affectedEndpoint(LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks) {
        return proposal.evidenceChunkIds().stream().map(chunks::get).filter(java.util.Objects::nonNull)
                .map(CodeChunk::getEndpoint).filter(value -> value != null && !value.isBlank())
                .findFirst().orElse(null);
    }

    // 执行 CriticAgentService 中的 fingerprint 处理。
    private String fingerprint(String type, String path, String symbol, String endpoint) {
        String normalized = String.join("|", type, path == null ? "" : path.replace('\\', '/'),
                symbol == null ? "" : symbol, endpoint == null ? "" : endpoint);
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException("无法生成漏洞稳定指纹", exception);
        }
    }
}
