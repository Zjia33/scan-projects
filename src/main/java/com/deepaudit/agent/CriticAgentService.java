package com.deepaudit.agent;

import com.deepaudit.ai.AiResponseFormatException;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingLocationKind;
import com.deepaudit.domain.HypothesisStatus;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class CriticAgentService {
    private final LlmGateway llmGateway;
    private final AgentTraceService traceService;
    private final AuditHypothesisMapper hypothesisMapper;
    private final SemanticEvidenceService semanticEvidenceService;

    // 用独立语义证据和全局安全控制反证候选，仅确认项可转换为 Finding。
    public Optional<Finding> review(UUID taskId, AgentCandidate candidate,
                                    LlmGateway.ReconInsight recon, List<CodeChunk> chunks) {
        long reviewStarted = ExecutionTiming.start();
        AgentRun run = traceService.start(taskId, AgentType.CRITIC,
                candidate.proposal().primaryChunkId(), candidate.proposal().title());
        try {
            Map<Long, CodeChunk> chunksById = chunks.stream()
                    .collect(Collectors.toMap(CodeChunk::getId, Function.identity()));
            run.setModelCallCount(1);
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.MODEL_CALL,
                "正在结合 Recon 架构事实、CodeGraph 调用关系、局部安全语义和全局安全控制寻找反证");
            // Critic 直接读取持久化语义证据，避免只复述专业 Agent 的论证。
            SemanticEvidenceService.EvidenceResult independentEvidence =
                    semanticEvidenceService.independentCriticEvidenceResult(taskId,
                            candidate.proposal().primaryChunkId(), candidate.proposal().type());
            if (independentEvidence == null) {
                independentEvidence = new SemanticEvidenceService.EvidenceResult(
                        semanticEvidenceService.independentCriticEvidence(taskId,
                                candidate.proposal().primaryChunkId(), candidate.proposal().type()), Set.of());
            }
            CodeChunk originalPrimary = Optional.ofNullable(chunksById.get(candidate.proposal().primaryChunkId()))
                    .orElseThrow(() -> new IllegalStateException("Critic 引用的主证据不存在"));
            CodeChunk changeAnchor = candidate.proposal().evidenceChunkIds().stream()
                    .map(chunksById::get).filter(java.util.Objects::nonNull)
                    .filter(chunk -> chunk.getAnalysisScope()
                            == com.deepaudit.domain.AnalysisScope.CHANGED)
                    .findFirst().orElse(originalPrimary.getAnalysisScope()
                            == com.deepaudit.domain.AnalysisScope.CHANGED ? originalPrimary : null);
            String changeContext = changeAnchor == null
                    ? "" : AgentPromptSupport.changeContext(changeAnchor);
            Set<Long> allowedLocationChunks = allowedLocationChunks(
                    candidate.proposal(), independentEvidence.evidenceChunkIds(), chunksById);
            Set<Long> relatedReviewIds = Optional.ofNullable(semanticEvidenceService.criticReviewContextIds(
                    taskId, allowedLocationChunks, 3)).orElse(Set.of());
            LinkedHashSet<Long> verifiedLocationChunks = new LinkedHashSet<>(allowedLocationChunks);
            relatedReviewIds.stream().filter(chunksById::containsKey).forEach(verifiedLocationChunks::add);
            ReviewContext reviewContext = buildReviewContext(
                    candidate.proposal(), chunksById, verifiedLocationChunks, relatedReviewIds);
            List<LlmGateway.LocationCandidate> locationCandidates =
                    FindingLocationResolver.locationCandidates(
                            candidate.proposal().type(), chunksById, verifiedLocationChunks);
            Map<Long, Integer> criticCallSites = semanticEvidenceService.callSiteLines(
                    taskId, candidate.proposal().primaryChunkId(), verifiedLocationChunks);
            String criticEvidence = FindingLocationResolver.formatCriticEvidence(
                    candidate.proposal(), chunksById, verifiedLocationChunks, criticCallSites);
            TimingDetailLog.info("任务 {} Critic 证据包已构建：type={}，primaryChunk={}，verifiedChunks={}，"
                            + "semanticChunks={}，reviewContextChunks={}，reviewContextTruncated={}，"
                            + "locationCandidates={}，evidenceChars={}，evidenceBuildElapsedMs={}",
                    taskId, candidate.proposal().type(), candidate.proposal().primaryChunkId(),
                    verifiedLocationChunks.size(), independentEvidence.evidenceChunkIds().size(),
                    reviewContext.chunkCount(), reviewContext.truncated(),
                    locationCandidates.size(), criticEvidence.length(),
                    ExecutionTiming.elapsedMillis(reviewStarted));
            // Critic 只接收确定性技术栈，不携带 Recon 模型生成的架构意见。
            LlmGateway.ReconInsight criticRecon = new LlmGateway.ReconInsight("",
                    recon == null ? null : recon.technologyProfile());
            long modelStarted = ExecutionTiming.start();
            LlmGateway.CriticDecision decision = llmGateway.critique(new LlmGateway.CriticRequest(
                    taskId, candidate.sourceAgent(), candidate.proposal(), criticEvidence,
                    independentEvidence.text() + reviewContext.text(), criticRecon,
                    originalPrimary.getChangeType().name(),
                    originalPrimary.getAnalysisScope().name(), changeContext,
                    locationCandidates));
            long modelElapsedMs = ExecutionTiming.elapsedMillis(modelStarted);
            TimingDetailLog.info("模型阶段结束：taskId={}，stage=CRITIC_MODEL，type={}，primaryChunk={}，elapsedMs={}，reviewElapsedMs={}",
                    taskId, candidate.proposal().type(), candidate.proposal().primaryChunkId(),
                    modelElapsedMs, ExecutionTiming.elapsedMillis(reviewStarted));
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.REASONING,
                    "Critic 模型调用完成，耗时 " + modelElapsedMs + " ms");
            LinkedHashSet<Long> allowedCounterEvidenceIds = new LinkedHashSet<>(verifiedLocationChunks);
            allowedCounterEvidenceIds.addAll(reviewContext.chunkIds());
            if (!validDecisionEnvelope(decision, allowedCounterEvidenceIds)) {
                return markInsufficient(taskId, candidate, run, AgentEventType.FORMAT_ERROR,
                        "Critic 返回字段不完整、状态矛盾或引用了未验证反证，未执行漏洞否决");
            }
            candidate.hypothesis().setCriticReason(decision.reason());
            candidate.hypothesis().setUpdatedAt(Instant.now());
            TimingDetailLog.info("任务 {} Critic 判定完成：type={}，primaryChunk={}，verdict={}，confirmed={}，reasonChars={}",
                    taskId, candidate.proposal().type(), candidate.proposal().primaryChunkId(),
                    decision.verdict(), decision.confirmed(), decision.reason().length());
            if (decision.verdict() == LlmGateway.CriticVerdict.INSUFFICIENT_EVIDENCE) {
                return markInsufficient(taskId, candidate, run, AgentEventType.INSUFFICIENT_EVIDENCE,
                        "Critic 证据不足：" + decision.reason());
            }
            if (decision.verdict() == LlmGateway.CriticVerdict.REJECTED) {
                // 发现反证时保留被拒假设和原因，但不创建最终漏洞。
                candidate.hypothesis().setStatus(HypothesisStatus.REJECTED);
                hypothesisMapper.update(candidate.hypothesis());
                traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.REJECTED,
                        "Critic 否决：" + safe(decision.reason()));
                run.complete("Critic Agent 找到反证并否决候选");
                traceService.update(run);
                return Optional.empty();
            }
            Correction corrected = correctedProposal(candidate.proposal(), decision, chunksById,
                    verifiedLocationChunks, locationCandidates);
            if (corrected.proposal().isEmpty() && !locationCandidates.isEmpty()) {
                corrected = repairLocation(taskId, candidate.proposal(), decision, chunksById,
                        verifiedLocationChunks, locationCandidates, corrected.reason(), run);
            }
            if (corrected.proposal().isEmpty()) {
                String invalidLocation = "Critic 已确认漏洞，但精确位置仍待复核：" + corrected.reason();
                candidate.hypothesis().setStatus(HypothesisStatus.CONFIRMED_UNLOCATED);
                candidate.hypothesis().setConfidence(decision.confidence() == null
                        ? fallbackConfidence(candidate.proposal().confidence()) : decision.confidence());
                candidate.hypothesis().setCriticReason(safe(decision.reason()) + "；" + invalidLocation);
                hypothesisMapper.update(candidate.hypothesis());
                traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.LOCATION_UNRESOLVED,
                        invalidLocation);
                run.complete(invalidLocation);
                traceService.update(run);
                return Optional.empty();
            }
            // Critic 对整条证据链重新选择实际漏洞点，最终报告不复用专业 Agent 的旧位置文本。
            Confidence confidence = decision.confidence() == null
                    ? fallbackConfidence(candidate.proposal().confidence()) : decision.confidence();
            LlmGateway.FindingProposal correctedProposal = corrected.proposal().orElseThrow();
            Map<Long, Integer> callSites = Optional.ofNullable(semanticEvidenceService.callSiteLines(
                    taskId, correctedProposal.primaryChunkId(), verifiedLocationChunks)).orElse(Map.of());
            LlmGateway.FindingProposal proposal = reportProposal(
                    candidate.proposal(), correctedProposal, decision, chunksById, callSites,
                    locationCandidates);
            CodeChunk primary = chunksById.get(proposal.primaryChunkId());
            candidate.hypothesis().setStatus(HypothesisStatus.CONFIRMED);
            candidate.hypothesis().setConfidence(confidence);
            candidate.hypothesis().setPrimaryChunkId(proposal.primaryChunkId());
            candidate.hypothesis().setEvidenceChunkIds(proposal.evidenceChunkIds().stream()
                    .map(String::valueOf).collect(Collectors.joining(",")));
            hypothesisMapper.update(candidate.hypothesis());
            FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, primary);
            String endpoint = affectedEndpoint(proposal, chunksById);
            Finding finding = new Finding(taskId, proposal.type(),
                    proposal.severity() == null ? Severity.HIGH : proposal.severity(), confidence,
                    truncate(proposal.title(), 500), primary.getFilePath(), location.startLine(),
                    location.endLine(), endpoint,
                    safeText(proposal.description()) + "\n\nCritic Agent 复核：" + safeText(decision.reason()),
                    FindingLocationResolver.formatEvidence(
                            proposal, chunksById, callSites, corrected.locationKind(), decision.rootCauseKind()),
                    safeText(proposal.remediation()));
            finding.setLocationKind(corrected.locationKind() == null
                    ? FindingLocationKind.ROOT_CAUSE : corrected.locationKind());
            finding.setDeltaStatus(FindingDeltaStatus.normalize(decision.deltaStatus()));
            finding.setFingerprint(FindingFingerprint.create(
                    proposal.type(), primary, location.startLine(), location.endLine()));
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.REASONING,
                    safe(decision.reason()));
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.FINDING,
                    "确认 " + proposal.type().getDisplayName() + "：" + proposal.title());
            run.complete("Critic Agent 已确认漏洞证据链");
            traceService.update(run);
            return Optional.of(finding);
        } catch (AiResponseFormatException exception) {
            log.warn("任务 {} Critic 响应在纠正后仍不完整，候选保留为证据不足：type={}，primaryChunk={}，原因={}",
                    taskId, candidate.proposal().type(), candidate.proposal().primaryChunkId(),
                    compactError(exception.getMessage()));
            return markInsufficient(taskId, candidate, run, AgentEventType.FORMAT_ERROR,
                    "Critic 响应格式异常，未执行漏洞否决：" + compactError(exception.getMessage()));
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

    private Correction correctedProposal(
            LlmGateway.FindingProposal original, LlmGateway.CriticDecision decision,
            Map<Long, CodeChunk> chunks, Set<Long> allowed,
            List<LlmGateway.LocationCandidate> candidates) {
        if (!hasIncrementalAnchor(allowed, chunks)) {
            return Correction.unresolved("证据链中没有 CHANGED 变更因果锚点");
        }
        FindingLocationResolver.LocationResolution resolution =
                FindingLocationResolver.resolveCriticLocation(original, decision, chunks, allowed, candidates);
        if (resolution.resolved().isEmpty()) return Correction.unresolved(resolution.reason());
        Long primaryChunkId = resolution.resolved().orElseThrow().chunkId();
        FindingLocationResolver.Location location = resolution.resolved().orElseThrow().location();
        List<Long> evidenceIds = correctedEvidenceIds(original, primaryChunkId, allowed);
        return new Correction(Optional.of(new LlmGateway.FindingProposal(original.type(), original.severity(),
                original.confidence(), original.title(), original.description(), original.remediation(),
                primaryChunkId, evidenceIds, location.startLine(), location.endLine())),
                locationKind(resolution.resolved().orElseThrow()), resolution.reason());
    }

    private Correction repairLocation(UUID taskId, LlmGateway.FindingProposal original,
                                      LlmGateway.CriticDecision decision, Map<Long, CodeChunk> chunks,
                                      Set<Long> allowed, List<LlmGateway.LocationCandidate> candidates,
                                      String failureReason, AgentRun run) {
        try {
            run.setModelCallCount(run.getModelCallCount() + 1);
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.MODEL_CALL,
                    "漏洞结论已经确认，正在从真实源码候选中修复最终位置");
            String previous = String.valueOf(decision.primaryChunkId()) + ":"
                    + decision.vulnerabilityStartLine() + "-" + decision.vulnerabilityEndLine();
            LlmGateway.LocationDecision repaired = llmGateway.repairLocation(
                    new LlmGateway.LocationRepairRequest(taskId, original.type(), original.title(),
                            original.description(), decision.reason(), decision.rootCauseKind(), previous,
                            failureReason, candidates));
            Optional<FindingLocationResolver.ResolvedPrimary> resolved = FindingLocationResolver.resolveCandidate(
                    repaired == null ? null : repaired.locationCandidateId(), candidates,
                    original, decision, chunks, allowed);
            if (resolved.isEmpty()) return Correction.unresolved(
                    failureReason + "；定位修复未选择合法候选 ID");
            if (!hasIncrementalAnchor(allowed, chunks)) {
                return Correction.unresolved("定位已修复，但证据链中没有 CHANGED 变更因果锚点");
            }
            Long primaryChunkId = resolved.orElseThrow().chunkId();
            FindingLocationResolver.Location location = resolved.orElseThrow().location();
            List<Long> evidenceIds = correctedEvidenceIds(original, primaryChunkId, allowed);
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.REASONING,
                    "定位修复完成：" + safe(repaired.reason()));
            return new Correction(Optional.of(new LlmGateway.FindingProposal(original.type(), original.severity(),
                    original.confidence(), original.title(), original.description(), original.remediation(),
                    primaryChunkId, evidenceIds, location.startLine(), location.endLine())),
                    locationKind(resolved.orElseThrow()),
                    "已通过受约束候选完成位置修复");
        } catch (RuntimeException exception) {
            traceService.event(taskId, run.getId(), AgentType.CRITIC, AgentEventType.REASONING,
                    "定位修复调用失败，保留已确认但待定位状态：" + safe(exception.getMessage()));
            return Correction.unresolved(failureReason + "；定位修复调用失败");
        }
    }

    /**
     * Location candidates are intentionally wider than report evidence. A chunk being safe and
     * useful for Critic review does not make it evidence that should be displayed to users.
     */
    private List<Long> correctedEvidenceIds(LlmGateway.FindingProposal original,
                                            Long primaryChunkId, Set<Long> allowed) {
        LinkedHashSet<Long> evidenceIds = new LinkedHashSet<>();
        evidenceIds.add(primaryChunkId);
        original.evidenceChunkIds().stream()
                .filter(allowed::contains)
                .forEach(evidenceIds::add);
        return List.copyOf(evidenceIds);
    }

    private boolean validDecisionEnvelope(LlmGateway.CriticDecision decision,
                                          Set<Long> allowedCounterEvidenceIds) {
        if (decision == null || decision.verdict() == null || decision.confirmed() == null
                || decision.confidence() == null || decision.reason() == null
                || decision.reason().isBlank()) return false;
        if (Boolean.TRUE.equals(decision.confirmed())
                != (decision.verdict() == LlmGateway.CriticVerdict.CONFIRMED)) return false;
        if (decision.verdict() != LlmGateway.CriticVerdict.REJECTED) return true;
        return !decision.counterEvidenceChunkIds().isEmpty()
                && decision.counterEvidenceChunkIds().stream().allMatch(allowedCounterEvidenceIds::contains);
    }

    private Optional<Finding> markInsufficient(UUID taskId, AgentCandidate candidate, AgentRun run,
                                               AgentEventType eventType, String reason) {
        String message = reason == null || reason.isBlank() ? "Critic 证据不足，未执行漏洞否决" : reason.strip();
        candidate.hypothesis().setStatus(HypothesisStatus.INSUFFICIENT_EVIDENCE);
        candidate.hypothesis().setCriticReason(message);
        candidate.hypothesis().setUpdatedAt(Instant.now());
        hypothesisMapper.update(candidate.hypothesis());
        traceService.event(taskId, run.getId(), AgentType.CRITIC, eventType, message);
        run.complete("Critic Agent 未形成可执行的确认或反证结论");
        traceService.update(run);
        return Optional.empty();
    }

    private String compactError(String value) {
        if (value == null || value.isBlank()) return "未知响应错误";
        String compact = value.replaceAll("[\\r\\n\\t]", " ").strip();
        return compact.substring(0, Math.min(compact.length(), 500));
    }

    /**
     * Builds the narrow, server-verified evidence set used by the persisted finding.
     * The primary location and verified incoming call path are always retained. Context without a
     * verified call relation is retained only for security-control findings, where the protected
     * operation is necessary to explain the impact of the ineffective boundary/configuration.
     */
    private LlmGateway.FindingProposal reportProposal(
            LlmGateway.FindingProposal original, LlmGateway.FindingProposal corrected,
            LlmGateway.CriticDecision decision, Map<Long, CodeChunk> chunks,
            Map<Long, Integer> callSites, List<LlmGateway.LocationCandidate> locationCandidates) {
        LinkedHashSet<Long> reportEvidenceIds = new LinkedHashSet<>();
        reportEvidenceIds.add(corrected.primaryChunkId());
        corrected.evidenceChunkIds().stream()
                .filter(id -> !id.equals(corrected.primaryChunkId()))
                .filter(id -> callSites.containsKey(id) || hasReportPurpose(id, locationCandidates))
                .forEach(reportEvidenceIds::add);
        if (requiresImpactContext(decision)) {
            original.evidenceChunkIds().stream()
                    .filter(chunks::containsKey)
                    .forEach(reportEvidenceIds::add);
        }
        return new LlmGateway.FindingProposal(corrected.type(), corrected.severity(),
                corrected.confidence(), corrected.title(), corrected.description(),
                corrected.remediation(), corrected.primaryChunkId(), List.copyOf(reportEvidenceIds),
                corrected.vulnerabilityStartLine(), corrected.vulnerabilityEndLine());
    }

    private boolean hasReportPurpose(Long chunkId, List<LlmGateway.LocationCandidate> candidates) {
        return candidates.stream().filter(candidate -> candidate.chunkId() == chunkId)
                .flatMap(candidate -> candidate.purposes().stream())
                .anyMatch(purpose -> purpose.equals("IMPACT") || purpose.equals("ENTRY"));
    }

    private boolean requiresImpactContext(LlmGateway.CriticDecision decision) {
        if (decision == null) return false;
        return "INEFFECTIVE_SECURITY_CONTROL".equals(decision.rootCauseKind())
                || "MISSING_AUTHORIZATION_CHECK".equals(decision.rootCauseKind())
                || "SECURITY_BOUNDARY".equals(decision.locationRole())
                || "SECURITY_CONFIGURATION".equals(decision.locationRole());
    }

    private Set<Long> allowedLocationChunks(LlmGateway.FindingProposal proposal,
                                            Set<Long> independentEvidenceIds,
                                            Map<Long, CodeChunk> chunks) {
        LinkedHashSet<Long> allowed = new LinkedHashSet<>();
        allowed.add(proposal.primaryChunkId());
        allowed.addAll(proposal.evidenceChunkIds());
        allowed.addAll(independentEvidenceIds);
        allowed.removeIf(id -> id == null || !chunks.containsKey(id));
        return allowed;
    }

    private boolean hasIncrementalAnchor(Set<Long> allowed, Map<Long, CodeChunk> chunks) {
        return allowed.stream().map(chunks::get).filter(java.util.Objects::nonNull).anyMatch(chunk ->
                chunk.getAnalysisScope() == com.deepaudit.domain.AnalysisScope.CHANGED);
    }

    private ReviewContext buildReviewContext(LlmGateway.FindingProposal proposal,
                                             Map<Long, CodeChunk> chunks,
                                             Set<Long> evidenceIds, Set<Long> relatedIds) {
        LinkedHashSet<Long> selected = new LinkedHashSet<>(relatedIds);
        chunks.values().stream()
                .filter(chunk -> relevantGlobalContext(proposal.type(), chunk))
                .map(CodeChunk::getId).forEach(selected::add);
        selected.removeAll(evidenceIds);
        int maxChars = 24_000;
        StringBuilder text = new StringBuilder();
        LinkedHashSet<Long> includedIds = new LinkedHashSet<>();
        int included = 0;
        boolean truncated = false;
        for (Long id : selected) {
            CodeChunk chunk = chunks.get(id);
            if (chunk == null) continue;
            String content = safeText(chunk.getContent());
            String excerpt = content.substring(0, Math.min(content.length(), 2_400));
            String item = "\n\n[CRITIC_REVIEW_CONTEXT_ONLY] CHUNK_ID=" + id + " | "
                    + safeText(chunk.getFilePath()) + ":" + chunk.getStartLine() + " | "
                    + safeText(chunk.getSymbolName()) + "\n<UNTRUSTED_CODE>\n" + excerpt
                    + "\n</UNTRUSTED_CODE>";
            if (text.length() + item.length() > maxChars) {
                truncated = true;
                break;
            }
            text.append(item);
            includedIds.add(id);
            included++;
        }
        return new ReviewContext(text.toString(), included, truncated, Set.copyOf(includedIds));
    }

    private boolean relevantGlobalContext(com.deepaudit.domain.VulnerabilityType type, CodeChunk chunk) {
        String value = (safeText(chunk.getAnnotations()) + " " + safeText(chunk.getContent()))
                .toLowerCase(java.util.Locale.ROOT);
        if (type == com.deepaudit.domain.VulnerabilityType.AUTHORIZATION
                || type == com.deepaudit.domain.VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE) {
            return containsAny(value, "preauthorize", "secured", "rolesallowed", "securityfilterchain",
                    "requestmatchers", "authorizehttprequests", "permitall", "authenticated",
                    "enablemethodsecurity", "enableglobalmethodsecurity", "handlerinterceptor");
        }
        if (type == com.deepaudit.domain.VulnerabilityType.STORED_XSS) {
            return containsAny(value, "v-html", "innerhtml", "th:utext", "text/html",
                    "mediatype.text_html", "document.write", "dangerouslysetinnerhtml");
        }
        return false;
    }

    private boolean containsAny(String value, String... tokens) {
        for (String token : tokens) if (value.contains(token)) return true;
        return false;
    }

    private String affectedEndpoint(LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks) {
        return proposal.evidenceChunkIds().stream().map(chunks::get).filter(java.util.Objects::nonNull)
                .map(CodeChunk::getEndpoint).filter(value -> value != null && !value.isBlank())
                .findFirst().orElse(null);
    }

    private FindingLocationKind locationKind(FindingLocationResolver.ResolvedPrimary resolved) {
        return "RESPONSIBILITY_ANCHOR".equals(resolved.locationKind())
                ? FindingLocationKind.RESPONSIBILITY_ANCHOR : FindingLocationKind.ROOT_CAUSE;
    }

    private record Correction(Optional<LlmGateway.FindingProposal> proposal,
                              FindingLocationKind locationKind, String reason) {
        private static Correction unresolved(String reason) {
            return new Correction(Optional.empty(), null, reason == null ? "未知定位错误" : reason);
        }
    }

    private record ReviewContext(String text, int chunkCount, boolean truncated, Set<Long> chunkIds) {
    }
}
