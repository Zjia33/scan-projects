package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.HypothesisStatus;
import com.deepaudit.domain.Severity;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 将专业 Agent 的已验证提案转换为正式漏洞。这里只执行确定性证据、增量因果和位置门禁，
 * 不再调用第二个模型重新判断同一漏洞。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FindingGateService {
    private static final Pattern INTERNAL_CHUNK_REFERENCE = Pattern.compile(
            "(?i)\\[?\\s*chunk(?:\\s*id)?\\s*[:=#]?\\s*\\d+\\s*\\]?|代码块\\s*(?:id\\s*)?\\d+");
    private final AuditHypothesisMapper hypothesisMapper;
    private final SemanticEvidenceService semanticEvidenceService;
    private final CodeGraphIntegrationService codeGraphIntegrationService;
    private final AgentTraceService traceService;

    public List<Finding> evaluate(UUID taskId, List<AgentCandidate> candidates,
                                  List<CodeChunk> chunks) {
        if (candidates == null || candidates.isEmpty()) return List.of();
        Map<Long, CodeChunk> byId = chunks.stream()
                .filter(chunk -> chunk.getId() != null)
                .collect(Collectors.toMap(CodeChunk::getId, chunk -> chunk,
                        (left, right) -> right, LinkedHashMap::new));
        List<Finding> findings = new ArrayList<>();
        for (AgentCandidate original : candidates) {
            AgentCandidate candidate = normalizeLocation(taskId, original, byId, chunks);
            GateResult result = validate(candidate, byId);
            if (!result.accepted()) {
                markInsufficient(taskId, candidate, result.reason());
                continue;
            }
            LlmGateway.FindingProposal proposal = candidate.proposal();
            CodeChunk primary = byId.get(proposal.primaryChunkId());
            FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, primary);
            Set<Long> evidenceIds = new LinkedHashSet<>(proposal.evidenceChunkIds());
            Map<Long, Integer> callSites = new LinkedHashMap<>(semanticEvidenceService.callSiteLines(
                    taskId, proposal.primaryChunkId(), evidenceIds, byId));
            callSites.putAll(directCallSites(taskId, evidenceIds, byId, chunks));
            Finding finding = new Finding(taskId, proposal.type(),
                    proposal.severity() == null ? Severity.HIGH : proposal.severity(),
                    proposal.confidence() == null ? Confidence.MEDIUM : proposal.confidence(),
                    truncate(proposal.title(), 500), primary.getFilePath(),
                    location.startLine(), location.endLine(), affectedEndpoint(proposal, byId),
                     userText(proposal.description()),
                     FindingLocationResolver.formatEvidence(proposal, byId, callSites),
                     userText(proposal.remediation()));
            finding.setDeltaStatus(FindingDeltaStatus.NEW);
            finding.setFingerprint(FindingFingerprint.create(
                    proposal.type(), primary, location.startLine(), location.endLine()));
            confirm(taskId, candidate);
            findings.add(finding);
        }
        return List.copyOf(findings);
    }

    /**
     * 纠正一种可确定识别的错位：模型把纯转发调用行当作主位置，但已引用的直接 callee
     * 含有该类型的具体危险操作。缺少唯一调用点或具体危险操作时保持模型位置，不作猜测。
     */
    private AgentCandidate normalizeLocation(UUID taskId, AgentCandidate candidate,
                                             Map<Long, CodeChunk> byId, List<CodeChunk> chunks) {
        if (candidate == null || candidate.proposal() == null) return candidate;
        LlmGateway.FindingProposal proposal = candidate.proposal();
        CodeChunk primary = byId.get(proposal.primaryChunkId());
        if (primary == null) return candidate;
        FindingLocationResolver.Location proposedLocation = FindingLocationResolver.resolve(proposal, primary);
        CodeChunk bestChunk = null;
        FindingLocationResolver.SinkLocation bestSink = null;
        for (Long evidenceId : new LinkedHashSet<>(proposal.evidenceChunkIds())) {
            CodeChunk related = byId.get(evidenceId);
            if (related == null || related == primary
                    || !verifiedDirectRelation(taskId, primary, related, chunks)) continue;
            var callSite = FindingLocationResolver.uniqueCallSite(primary, related);
            if (callSite.isEmpty() || !overlaps(callSite.get(), proposedLocation)) continue;
            var sink = FindingLocationResolver.concreteSink(proposal, related);
            if (sink.isPresent() && (bestSink == null || sink.get().score() > bestSink.score())) {
                bestChunk = related;
                bestSink = sink.get();
            }
        }
        if (bestChunk == null) return candidate;
        List<Long> evidenceIds = new ArrayList<>();
        evidenceIds.add(bestChunk.getId());
        proposal.evidenceChunkIds().stream().filter(id -> !evidenceIds.contains(id)).forEach(evidenceIds::add);
        LlmGateway.FindingProposal normalized = new LlmGateway.FindingProposal(
                proposal.type(), proposal.severity(), proposal.confidence(), proposal.title(),
                proposal.description(), proposal.remediation(), bestChunk.getId(), evidenceIds,
                bestSink.location().startLine(), bestSink.location().endLine());
        TimingDetailLog.info("任务 {} 将纯转发位置 {}:{} 归一到直接被调用方法中的危险操作 {}:{}",
                taskId, primary.getFilePath(), proposedLocation.startLine(),
                bestChunk.getFilePath(), bestSink.location().startLine());
        return new AgentCandidate(candidate.sourceAgent(), normalized, candidate.hypothesis());
    }

    private Map<Long, Integer> directCallSites(UUID taskId, Set<Long> evidenceIds,
                                               Map<Long, CodeChunk> byId, List<CodeChunk> chunks) {
        List<Long> ids = evidenceIds.stream().filter(byId::containsKey).toList();
        Map<Long, Integer> result = new LinkedHashMap<>();
        for (int left = 0; left < ids.size(); left++) {
            for (int right = left + 1; right < ids.size(); right++) {
                CodeChunk first = byId.get(ids.get(left));
                CodeChunk second = byId.get(ids.get(right));
                if (!verifiedDirectRelation(taskId, first, second, chunks)) continue;
                FindingLocationResolver.uniqueCallSite(first, second)
                        .ifPresent(location -> result.putIfAbsent(first.getId(), location.startLine()));
                FindingLocationResolver.uniqueCallSite(second, first)
                        .ifPresent(location -> result.putIfAbsent(second.getId(), location.startLine()));
            }
        }
        return result;
    }

    private boolean verifiedDirectRelation(UUID taskId, CodeChunk first, CodeChunk second,
                                           List<CodeChunk> chunks) {
        try {
            CodeGraphIntegrationService.RelationCheck forward = codeGraphIntegrationService
                    .verifyDirectRelation(taskId, first, second, chunks);
            if (forward != null && forward.verified()) return true;
            CodeGraphIntegrationService.RelationCheck reverse = codeGraphIntegrationService
                    .verifyDirectRelation(taskId, second, first, chunks);
            return reverse != null && reverse.verified();
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private boolean overlaps(FindingLocationResolver.Location left,
                             FindingLocationResolver.Location right) {
        return left.startLine() <= right.endLine() && right.startLine() <= left.endLine();
    }

    private GateResult validate(AgentCandidate candidate, Map<Long, CodeChunk> chunks) {
        if (candidate == null || candidate.proposal() == null || candidate.hypothesis() == null) {
            return GateResult.reject("专业 Agent 没有提交结构化漏洞提案");
        }
        LlmGateway.FindingProposal proposal = candidate.proposal();
        if (proposal.type() == null || proposal.primaryChunkId() == null
                || proposal.title() == null || proposal.title().isBlank()
                || proposal.description() == null || proposal.description().isBlank()) {
            return GateResult.reject("漏洞类型、主位置、标题或说明不完整");
        }
        LinkedHashSet<Long> evidenceIds = new LinkedHashSet<>(proposal.evidenceChunkIds());
        if (!evidenceIds.contains(proposal.primaryChunkId())) {
            return GateResult.reject("主位置没有包含在已验证证据列表中");
        }
        if (evidenceIds.stream().anyMatch(id -> id == null || !chunks.containsKey(id))) {
            return GateResult.reject("证据列表引用了不存在的代码块");
        }
        CodeChunk primary = chunks.get(proposal.primaryChunkId());
        if (primary.getAnalysisScope() != AnalysisScope.CHANGED
                && primary.getAnalysisScope() != AnalysisScope.IMPACTED) {
            return GateResult.reject("主位置不是 CHANGED 或已验证 IMPACTED 代码块");
        }
        if (primary.getContent() == null || primary.getContent().isBlank()) {
            return GateResult.reject("主证据代码块没有可渲染源码");
        }
        boolean changedAnchor = evidenceIds.stream().map(chunks::get)
                .anyMatch(chunk -> chunk != null && chunk.getAnalysisScope() == AnalysisScope.CHANGED);
        if (!changedAnchor) return GateResult.reject("证据链缺少 CHANGED 增量因果锚点");
        FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, primary);
        if (location.startLine() < primary.getStartLine()
                || location.endLine() > primary.getEndLine()
                || location.startLine() > location.endLine()) {
            return GateResult.reject("漏洞位置不在主证据代码范围内");
        }
        return GateResult.accept();
    }

    private void confirm(UUID taskId, AgentCandidate candidate) {
        candidate.hypothesis().setStatus(HypothesisStatus.CONFIRMED);
        candidate.hypothesis().setConfidence(candidate.proposal().confidence() == null
                ? Confidence.MEDIUM : candidate.proposal().confidence());
        candidate.hypothesis().setPrimaryChunkId(candidate.proposal().primaryChunkId());
        candidate.hypothesis().setEvidenceChunkIds(candidate.proposal().evidenceChunkIds().stream()
                .map(String::valueOf).collect(Collectors.joining(",")));
        candidate.hypothesis().setValidationReason("已通过确定性证据、增量因果和源码位置门禁");
        candidate.hypothesis().setUpdatedAt(Instant.now());
        hypothesisMapper.update(candidate.hypothesis());
        traceService.event(taskId, candidate.hypothesis().getRunId(), candidate.sourceAgent(),
                AgentEventType.FINDING,
                "证据门禁通过：" + candidate.proposal().type().getDisplayName()
                        + "：" + candidate.proposal().title());
    }

    private void markInsufficient(UUID taskId, AgentCandidate candidate, String reason) {
        if (candidate == null || candidate.hypothesis() == null) return;
        candidate.hypothesis().setStatus(HypothesisStatus.INSUFFICIENT_EVIDENCE);
        candidate.hypothesis().setValidationReason("确定性证据门禁未通过：" + reason);
        candidate.hypothesis().setUpdatedAt(Instant.now());
        hypothesisMapper.update(candidate.hypothesis());
        traceService.event(taskId, candidate.hypothesis().getRunId(), candidate.sourceAgent(),
                AgentEventType.INSUFFICIENT_EVIDENCE, "确定性证据门禁未通过：" + reason);
        LlmGateway.FindingProposal proposal = candidate.proposal();
        log.warn("任务 {} 专业漏洞提案未通过确定性证据门禁：type={}，primaryChunk={}，reason={}",
                taskId, proposal == null ? null : proposal.type(),
                proposal == null ? null : proposal.primaryChunkId(), reason);
    }

    private String affectedEndpoint(LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks) {
        return proposal.evidenceChunkIds().stream().map(chunks::get)
                .filter(java.util.Objects::nonNull).map(CodeChunk::getEndpoint)
                .filter(value -> value != null && !value.isBlank()).findFirst().orElse(null);
    }

    private String truncate(String value, int maxLength) {
        String safe = value == null || value.isBlank() ? "专业 Agent 发现潜在安全问题" : value.strip();
        return safe.substring(0, Math.min(safe.length(), maxLength));
    }

    private String safe(String value) {
        return value == null ? "" : value.strip();
    }

    /** 删除只对 Agent 有意义的内部块编号，避免污染漏洞说明和修复建议。 */
    private String userText(String value) {
        return INTERNAL_CHUNK_REFERENCE.matcher(safe(value)).replaceAll("").replaceAll("[ \\t]{2,}", " ")
                .replaceAll("\\n{3,}", "\\n\\n").strip();
    }

    private record GateResult(boolean accepted, String reason) {
        private static GateResult accept() {
            return new GateResult(true, "");
        }

        private static GateResult reject(String reason) {
            return new GateResult(false, reason);
        }
    }
}
