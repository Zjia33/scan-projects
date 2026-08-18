package com.deepaudit.agent;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 为增量扫描构建 CHANGED 审查单元，并在分流决定需要时按需附加相关 IMPACTED 代码。
 */
@Service
@RequiredArgsConstructor
public class IncrementalReviewService {
    private static final int MAX_CONTEXT_CHARS = 12_000;
    private static final Set<String> SECURITY_ANNOTATIONS = Set.of(
            "preauthorize", "postauthorize", "secured", "rolesallowed", "permitall", "denyall");
    private static final Set<String> SECURITY_CONFIGURATION = Set.of(
            "securityfilterchain", "enablemethodsecurity", "enableglobalmethodsecurity",
            "authorizehttprequests", "requestmatchers", "antmatchers", "csrf", "cors");
    private static final Set<String> DATA_ACCESS = Set.of(
            "repository.", "mapper.", "dao.", "jdbctemplate", "entitymanager", "sqlsession",
            "executequery", "executeupdate", "preparestatement", "createstatement");
    private static final Set<String> OUTPUT = Set.of(
            "return ", ".body(", "response.", "getwriter", "printwriter", "innerhtml",
            "outerhtml", "document.write", "th:utext", "v-html");
    private static final Set<String> VALIDATION = Set.of(
            "validate", "isvalid", "verify", "captcha", "otp", "signature", "checktoken");
    private static final Set<String> SENSITIVE_INFORMATION = Set.of(
            "password", "passwd", "secret", "apikey", "api-key", "privatekey", "private-key",
            "client-secret", "access-token", "refresh-token", "idcard", "bankcard");

    private final SecurityFlowMapper flowMapper;
    private final SemanticCallEdgeMapper edgeMapper;
    private final SemanticMethodChangeMapper semanticChangeMapper;

    // 每个 CHANGED 代码块都是审查目标；IMPACTED 代码块只作为对应目标的影响证据。
    public List<IncrementalReviewUnit> build(UUID taskId, List<CodeChunk> chunks,
                                             Map<Long, Set<VulnerabilityType>> hints,
                                             Map<Long, String> hintDescriptions) {
        List<SemanticCallEdge> edges = safeList(edgeMapper.findByTaskId(taskId));
        List<SecurityFlow> flows = safeList(flowMapper.findByTaskId(taskId));
        List<SemanticMethodChange> changes = safeList(semanticChangeMapper.findByTaskId(taskId));
        List<VulnerabilityType> allowedTypes = java.util.Arrays.stream(VulnerabilityType.values()).sorted().toList();
        List<IncrementalReviewUnit> result = new ArrayList<>();
        for (CodeChunk chunk : chunks) {
            if (chunk.getId() == null || !insideIncrementalScope(chunk)) continue;
            List<SemanticCallEdge> relatedEdges = relatedEdges(chunk.getId(), edges);
            List<SecurityFlow> relatedFlows = flows.stream()
                    .filter(flow -> flow.getPrimaryChunkId() != null && flow.getPrimaryChunkId().equals(chunk.getId()))
                    .toList();
            List<SemanticMethodChange> relatedChanges = relatedChanges(chunk, changes, relatedEdges);
            Set<String> facts = facts(chunk, relatedEdges, relatedFlows, relatedChanges,
                    hints.getOrDefault(chunk.getId(), Set.of()));
            Set<VulnerabilityType> mandatoryTypes = mandatoryTypes(
                    hints.getOrDefault(chunk.getId(), Set.of()), relatedChanges, relatedFlows);
            if (isDtoOrEntityFile(chunk.getFilePath()) && mandatoryTypes.isEmpty()) continue;
            String deterministicEvidence = joinNonBlank(hintDescriptions.get(chunk.getId()),
                    flowSummary(relatedFlows));
            String changeContext = AgentPromptSupport.changeContext(chunk);
            result.add(new IncrementalReviewUnit("change-" + chunk.getId(), chunk.getId(),
                    chunk.getFilePath(), chunk.getSymbolName(), chunk.getEndpoint(), chunk.getChunkType(),
                    chunk.getChangeType().name(), allowedTypes,
                    mandatoryTypes.stream().sorted().toList(), List.copyOf(facts), chunk.getParameters(),
                    chunk.getAnnotations(), chunk.getCalledSymbols(), "", changeContext,
                    changeSummary(relatedChanges), edgeSummary(relatedEdges),
                    truncate(deterministicEvidence, 4_000)));
        }
        return List.copyOf(result);
    }

    // NEED_CONTEXT 后补充对应 IMPACTED 和少量直接相关 CONTEXT，再进行唯一一次复判。
    public List<IncrementalReviewUnit> enrich(UUID taskId, List<IncrementalReviewUnit> units,
                                              List<CodeChunk> chunks) {
        return enrichRelated(taskId, units, chunks, true);
    }

    // 只有已经决定 INVESTIGATE 的单元才在进入专业 Agent 前补充 IMPACTED 依据。
    public List<IncrementalReviewUnit> enrichImpact(UUID taskId, List<IncrementalReviewUnit> units,
                                                    List<CodeChunk> chunks) {
        return enrichRelated(taskId, units, chunks, false);
    }

    private List<IncrementalReviewUnit> enrichRelated(UUID taskId, List<IncrementalReviewUnit> units,
                                                      List<CodeChunk> chunks, boolean includeContext) {
        Map<Long, CodeChunk> chunksById = chunks.stream().filter(chunk -> chunk.getId() != null)
                .collect(Collectors.toMap(CodeChunk::getId, Function.identity()));
        List<SemanticCallEdge> edges = safeList(edgeMapper.findByTaskId(taskId));
        List<SecurityFlow> flows = safeList(flowMapper.findByTaskId(taskId));
        return units.stream().map(unit -> {
            List<SemanticCallEdge> related = relatedEdges(unit.primaryChunkId(), edges);
            Set<Long> impactedIds = impactedIds(unit.primaryChunkId(), edges, chunksById);
            List<CodeChunk> impactedChunks = impactedIds.stream().map(chunksById::get)
                    .filter(java.util.Objects::nonNull)
                    .sorted(Comparator.comparing(CodeChunk::getFilePath, Comparator.nullsLast(String::compareTo))
                            .thenComparingInt(CodeChunk::getStartLine))
                    .toList();
            Set<Long> impactScopeIds = new LinkedHashSet<>(impactedIds);
            impactScopeIds.add(unit.primaryChunkId());
            List<SecurityFlow> impactFlows = flows.stream()
                    .filter(flow -> flow.getPrimaryChunkId() != null
                            && impactScopeIds.contains(flow.getPrimaryChunkId()))
                    .toList();
            Set<Long> relatedIds = new LinkedHashSet<>();
            for (SemanticCallEdge edge : related) {
                if (edge.getCallerChunkId() != null) relatedIds.add(edge.getCallerChunkId());
                if (edge.getCalleeChunkId() != null) relatedIds.add(edge.getCalleeChunkId());
            }
            relatedIds.remove(unit.primaryChunkId());
            String codeContext = relatedIds.stream().map(chunksById::get)
                    .filter(java.util.Objects::nonNull)
                    .filter(chunk -> includeContext && chunk.getAnalysisScope() == AnalysisScope.CONTEXT)
                    .limit(8)
                    .map(chunk -> "[CONTEXT CHUNK_ID=" + chunk.getId() + "] "
                            + safe(chunk.getFilePath()) + ":" + chunk.getStartLine() + " "
                            + safe(chunk.getSymbolName()) + "\n<UNTRUSTED_CODE>\n"
                            + excerpt(chunk.getContent(), 1_200) + "\n</UNTRUSTED_CODE>")
                    .collect(Collectors.joining("\n\n"));
            return unit.withRelatedContext(truncate(joinNonBlank(unit.relatedContext(),
                    impactedCodeContext(impactedChunks), flowSummary(impactFlows), codeContext), MAX_CONTEXT_CHARS));
        }).toList();
    }

    private boolean insideIncrementalScope(CodeChunk chunk) {
        return chunk.getAnalysisScope() == AnalysisScope.CHANGED;
    }

    // 普通 DTO/Entity 变更保留在代码索引中但不作为独立审查目标；强制证据命中时仍须调查。
    private boolean isDtoOrEntityFile(String filePath) {
        if (filePath == null || filePath.isBlank()) return false;
        String normalized = filePath.replace('\\', '/');
        String fileName = normalized.substring(normalized.lastIndexOf('/') + 1);
        if (!fileName.toLowerCase(Locale.ROOT).endsWith(".java")) return false;
        String typeName = fileName.substring(0, fileName.length() - ".java".length())
                .toLowerCase(Locale.ROOT);
        return typeName.endsWith("dto") || typeName.endsWith("entity");
    }

    private Set<String> facts(CodeChunk chunk, List<SemanticCallEdge> edges, List<SecurityFlow> flows,
                              List<SemanticMethodChange> changes, Set<VulnerabilityType> hints) {
        Set<String> facts = new LinkedHashSet<>();
        facts.add("DIRECT_CHANGE");
        if (chunk.getEndpoint() != null && !chunk.getEndpoint().isBlank()) facts.add("HAS_EXTERNAL_ENDPOINT");
        String searchable = searchable(chunk);
        if (containsAny(searchable, SECURITY_ANNOTATIONS)) facts.add("HAS_SECURITY_ANNOTATION");
        if (containsAny(searchable, SECURITY_CONFIGURATION)) facts.add("HAS_SECURITY_CONFIGURATION");
        if (containsAny(searchable, DATA_ACCESS)) facts.add("HAS_DATA_ACCESS");
        if (containsAny(searchable, OUTPUT)) facts.add("HAS_OUTPUT_OPERATION");
        if (containsAny(searchable, VALIDATION)) facts.add("HAS_VALIDATION_OPERATION");
        if (containsAny(searchable, SENSITIVE_INFORMATION)) facts.add("HAS_SENSITIVE_INFORMATION");
        if (!edges.isEmpty()) facts.add("HAS_CALL_RELATIONS");
        if (edges.stream().anyMatch(edge -> "CODEGRAPH_CALL".equals(edge.getEdgeType())
                && edge.getConfidence() == com.deepaudit.domain.Confidence.MEDIUM)) {
            facts.add("HAS_CONSERVATIVE_ARGUMENT_MAPPING");
        }
        if (!flows.isEmpty()) facts.add("HAS_SEMANTIC_FLOW");
        if (!hints.isEmpty()) facts.add("HAS_DETERMINISTIC_HINT");
        changes.stream().map(SemanticMethodChange::getChangeKind).filter(java.util.Objects::nonNull)
                .map(Enum::name).forEach(facts::add);
        return facts;
    }

    private Set<VulnerabilityType> mandatoryTypes(Set<VulnerabilityType> hints,
                                                   List<SemanticMethodChange> changes,
                                                   List<SecurityFlow> flows) {
        Set<VulnerabilityType> result = EnumSet.noneOf(VulnerabilityType.class);
        hints.stream().filter(java.util.Objects::nonNull).forEach(result::add);
        flows.stream().map(SecurityFlow::getType).filter(java.util.Objects::nonNull)
                .forEach(result::add);
        if (changes.stream().anyMatch(change -> change.getChangeKind() == SemanticChangeKind.GUARD_REMOVED)) {
            result.add(VulnerabilityType.AUTHORIZATION);
            result.add(VulnerabilityType.VALIDATION_BYPASS);
        }
        return result;
    }

    private Set<Long> impactedIds(long changedChunkId, List<SemanticCallEdge> edges,
                                  Map<Long, CodeChunk> chunksById) {
        Map<Long, Set<Long>> adjacency = new LinkedHashMap<>();
        for (SemanticCallEdge edge : edges) {
            Long caller = edge.getCallerChunkId();
            Long callee = edge.getCalleeChunkId();
            if (caller == null || callee == null || edge.getConfidence() == Confidence.LOW) continue;
            adjacency.computeIfAbsent(caller, ignored -> new LinkedHashSet<>()).add(callee);
            adjacency.computeIfAbsent(callee, ignored -> new LinkedHashSet<>()).add(caller);
        }
        Set<Long> visited = new LinkedHashSet<>();
        Set<Long> result = new LinkedHashSet<>();
        ArrayDeque<Long> queue = new ArrayDeque<>();
        visited.add(changedChunkId);
        queue.add(changedChunkId);
        while (!queue.isEmpty()) {
            Long current = queue.removeFirst();
            for (Long candidateId : adjacency.getOrDefault(current, Set.of())) {
                if (!visited.add(candidateId)) continue;
                CodeChunk candidate = chunksById.get(candidateId);
                if (candidate == null || candidate.getAnalysisScope() != AnalysisScope.IMPACTED) continue;
                result.add(candidateId);
                queue.addLast(candidateId);
            }
        }
        return result;
    }

    private String impactedCodeContext(List<CodeChunk> impactedChunks) {
        if (impactedChunks.isEmpty()) return "";
        String chunks = impactedChunks.stream().map(chunk -> "[IMPACTED CHUNK_ID=" + chunk.getId() + "] "
                        + safe(chunk.getFilePath()) + ":" + chunk.getStartLine() + "-" + chunk.getEndLine()
                        + " | " + safe(chunk.getSymbolName()) + " | endpoint=" + safe(chunk.getEndpoint())
                        + "\n<UNTRUSTED_CODE>\n" + excerpt(chunk.getContent(), 1_200)
                        + "\n</UNTRUSTED_CODE>")
                .collect(Collectors.joining("\n\n"));
        return "[IMPACTED_CONTEXT] 以下未变更代码块受当前 CHANGED 代码影响，"
                + "仅作为本次变更的判断依据，不是独立审查目标。\n" + chunks;
    }

    private List<SemanticMethodChange> relatedChanges(CodeChunk chunk, List<SemanticMethodChange> changes,
                                                       List<SemanticCallEdge> relatedEdges) {
        Set<String> calledNames = relatedEdges.stream().map(SemanticCallEdge::getCalledName)
                .filter(java.util.Objects::nonNull).collect(Collectors.toSet());
        return changes.stream().filter(change -> {
            boolean sameTarget = safe(change.getTargetPath()).equals(safe(chunk.getFilePath()))
                    && (change.getTargetStartLine() == null
                    || change.getTargetStartLine() >= chunk.getStartLine()
                    && change.getTargetStartLine() <= chunk.getEndLine());
            boolean deletedDependency = change.getChangeKind() == SemanticChangeKind.METHOD_DELETED
                    && calledNames.contains(change.getMethodName());
            return sameTarget || deletedDependency;
        }).toList();
    }

    private List<SemanticCallEdge> relatedEdges(long chunkId, List<SemanticCallEdge> edges) {
        return edges.stream().filter(edge -> Long.valueOf(chunkId).equals(edge.getCallerChunkId())
                        || Long.valueOf(chunkId).equals(edge.getCalleeChunkId()))
                .limit(20).toList();
    }

    private String changeSummary(List<SemanticMethodChange> changes) {
        return changes.stream().map(change -> change.getChangeKind() + ": " + safe(change.getDetails()))
                .collect(Collectors.joining("\n"));
    }

    private String edgeSummary(List<SemanticCallEdge> edges) {
        return edges.stream().map(edge -> "callerChunk=" + edge.getCallerChunkId()
                        + " -> " + safe(edge.getCalledName()) + "@" + edge.getCallSiteLine()
                        + " -> calleeChunk=" + edge.getCalleeChunkId() + " [" + safe(edge.getEdgeType()) + "]")
                .collect(Collectors.joining("\n"));
    }

    private String flowSummary(List<SecurityFlow> flows) {
        return flows.stream().map(flow -> "source=" + safe(flow.getSourceDescription())
                        + " | sink=" + safe(flow.getSinkDescription()) + " | guard="
                        + safe(flow.getGuardSummary()) + " | path=" + safe(flow.getPathText()))
                .collect(Collectors.joining("\n"));
    }

    private String searchable(CodeChunk chunk) {
        return String.join(" ", safe(chunk.getFilePath()), safe(chunk.getSymbolName()),
                safe(chunk.getEndpoint()), safe(chunk.getAnnotations()), safe(chunk.getCalledSymbols()),
                safe(chunk.getContent())).toLowerCase(Locale.ROOT);
    }

    private boolean containsAny(String value, Set<String> markers) {
        return markers.stream().anyMatch(value::contains);
    }

    private String excerpt(String value, int limit) {
        String safe = safe(value);
        return safe.substring(0, Math.min(limit, safe.length()));
    }

    private String truncate(String value, int maxLength) {
        String safe = safe(value);
        return safe.substring(0, Math.min(maxLength, safe.length()));
    }

    private String joinNonBlank(String... values) {
        return java.util.Arrays.stream(values).filter(java.util.Objects::nonNull).map(String::strip)
                .filter(value -> !value.isBlank()).collect(Collectors.joining("\n\n"));
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }
}
