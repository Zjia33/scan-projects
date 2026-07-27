package com.deepaudit.agent;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
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

@Service
@RequiredArgsConstructor
public class AuditUnitService {
    private static final Set<String> SECURITY_CONFIG_MARKERS = Set.of(
            "securityfilterchain", "websecurityconfigureradapter", "enablemethodsecurity",
            "enableglobalmethodsecurity", "authorizehttprequests", "requestmatchers",
            "oauth2", "jwt", "csrf", "cors", "authenticationmanager", "accessdecisionmanager");
    private static final Set<String> EXTERNAL_ENTRY_MARKERS = Set.of(
            "mapping", "kafkalistener", "jmslistener", "rabbitlistener", "scheduled",
            "messagemapping", "webserviceref");
    private static final Set<String> SQL_MARKERS = Set.of(
            "execute(", "executequery", "executeupdate", "createstatement", "preparestatement",
            "jdbctemplate", "entitymanager", "select ", "insert ", "update ", "delete ",
            "findby", "save(", "deleteby");
    private static final Set<String> XSS_MARKERS = Set.of(
            "v-html", "innerhtml", "outerhtml", "document.write", "th:utext", "<%=",
            "render(", "template", "response.getwriter", "printwriter");
    private static final Set<String> VALIDATION_MARKERS = Set.of(
            "validate", "verify", "captcha", "otp", "token", "signature", "skipverify",
            "bypass", "isvalid", "check");
    private static final Set<String> FINANCIAL_MARKERS = Set.of(
            "payment", "refund", "transfer", "balance", "amount", "price", "money",
            "withdraw", "deposit", "settlement", "order");
    private static final Set<String> AUTHORIZATION_MARKERS = Set.of(
            "preauthorize", "secured", "rolesallowed", "permitall", "hasrole", "hasauthority",
            "tenant", "owner", "userid", "accountid", "deletebyid", "findbyid");

    private final SecurityFlowMapper flowMapper;
    private final SemanticCallEdgeMapper edgeMapper;
    private final SemanticMethodChangeMapper semanticChangeMapper;

    // 从全部项目事实中构建安全相关审计单元
    public List<AuditUnit> build(UUID taskId, List<CodeChunk> chunks, ScanMode scanMode,
                                 Map<Long, Set<VulnerabilityType>> hints,
                                 Map<Long, String> hintDescriptions) {
        Map<Long, List<SecurityFlow>> flowsByChunk = flowMapper.findByTaskId(taskId).stream()
                .filter(flow -> flow.getPrimaryChunkId() != null)
                .collect(Collectors.groupingBy(SecurityFlow::getPrimaryChunkId,
                        LinkedHashMap::new, Collectors.toList()));
        Map<Long, List<SemanticCallEdge>> edgesByCaller = edgeMapper.findByTaskId(taskId).stream()
                .filter(edge -> edge.getCallerChunkId() != null)
                .collect(Collectors.groupingBy(SemanticCallEdge::getCallerChunkId,
                        LinkedHashMap::new, Collectors.toList()));
        Map<String, List<SemanticMethodChange>> semanticChangesByPath = semanticChangeMapper.findByTaskId(taskId)
                .stream().filter(change -> change.getTargetPath() != null)
                .collect(Collectors.groupingBy(SemanticMethodChange::getTargetPath,
                        LinkedHashMap::new, Collectors.toList()));

        List<AuditUnit> units = new ArrayList<>();
        for (CodeChunk chunk : chunks) {
            if (chunk.getId() == null || !insideDeepScope(chunk, scanMode)) continue;
            List<SecurityFlow> flows = flowsByChunk.getOrDefault(chunk.getId(), List.of());
            List<SemanticCallEdge> edges = edgesByCaller.getOrDefault(chunk.getId(), List.of());
            List<SemanticMethodChange> semanticChanges = semanticChangesByPath
                    .getOrDefault(chunk.getFilePath(), List.of()).stream()
                    .filter(change -> change.getTargetStartLine() == null
                            || change.getTargetStartLine() >= chunk.getStartLine()
                            && change.getTargetStartLine() <= chunk.getEndLine())
                    .toList();
            Set<VulnerabilityType> candidateTypes = EnumSet.noneOf(VulnerabilityType.class);
            Set<String> reasonCodes = new LinkedHashSet<>();
            Set<VulnerabilityType> chunkHints = hints.getOrDefault(chunk.getId(), Set.of());

            if (!chunkHints.isEmpty()) {
                reasonCodes.add("RULE_HINT");
                candidateTypes.addAll(chunkHints);
            }
            if (!flows.isEmpty()) {
                reasonCodes.add("SEMANTIC_FLOW");
                flows.stream().map(SecurityFlow::getType).forEach(candidateTypes::add);
            }
            if (!semanticChanges.isEmpty()) {
                reasonCodes.add("SEMANTIC_CHANGE");
                if (semanticChanges.stream().anyMatch(change ->
                        change.getChangeKind() == SemanticChangeKind.GUARD_REMOVED)) {
                    reasonCodes.add("GUARD_REMOVED");
                    candidateTypes.add(VulnerabilityType.AUTHORIZATION);
                    candidateTypes.add(VulnerabilityType.VALIDATION_BYPASS);
                }
            }

            String searchable = searchable(chunk);
            if (hasExternalEntry(chunk, searchable)) {
                reasonCodes.add("EXTERNAL_ENTRY");
                candidateTypes.add(VulnerabilityType.AUTHORIZATION);
                candidateTypes.add(VulnerabilityType.UNAUTHORIZED_DISCLOSURE);
                candidateTypes.add(VulnerabilityType.VALIDATION_BYPASS);
            }
            if (isSecurityConfiguration(chunk, searchable)) {
                reasonCodes.add("SECURITY_CONFIGURATION");
                candidateTypes.add(VulnerabilityType.AUTHORIZATION);
                candidateTypes.add(VulnerabilityType.VALIDATION_BYPASS);
            }
            addMarkerFacts(searchable, candidateTypes, reasonCodes);
            if (edges.stream().anyMatch(this::isUnresolved)) {
                reasonCodes.add("UNRESOLVED_CALL");
            }
            if (scanMode == ScanMode.INCREMENTAL && chunk.getAnalysisScope() == AnalysisScope.CHANGED) {
                reasonCodes.add("DIRECT_CHANGE");
            } else if (scanMode == ScanMode.INCREMENTAL
                    && chunk.getAnalysisScope() == AnalysisScope.IMPACTED) {
                reasonCodes.add("IMPACTED_BY_CHANGE");
            }
            if (candidateTypes.isEmpty() && scanMode == ScanMode.INCREMENTAL
                    && (reasonCodes.contains("DIRECT_CHANGE") || reasonCodes.contains("IMPACTED_BY_CHANGE"))) {
                candidateTypes.addAll(EnumSet.allOf(VulnerabilityType.class));
            }
            if (reasonCodes.isEmpty() || candidateTypes.isEmpty()) continue;

            String context = joinNonBlank(hintDescriptions.get(chunk.getId()), flowSummary(flows),
                    methodChangeSummary(semanticChanges));
            units.add(new AuditUnit("chunk-" + chunk.getId(), chunk.getId(), chunk.getFilePath(),
                    chunk.getSymbolName(), chunk.getEndpoint(), unitType(reasonCodes),
                    chunk.getChangeType().name(), chunk.getAnalysisScope().name(),
                    List.copyOf(candidateTypes), List.copyOf(reasonCodes), chunk.getParameters(),
                    chunk.getAnnotations(), callSummary(edges), truncate(context, 1_800),
                    outline(chunk.getContent())));
        }
        return List.copyOf(units);
    }

    // 为 NEED_CONTEXT 单元批量补入双向调用边、语义流和相关代码块位置。
    public List<AuditUnit> enrich(UUID taskId, List<AuditUnit> units, List<CodeChunk> chunks) {
        Map<Long, CodeChunk> chunksById = chunks.stream().filter(chunk -> chunk.getId() != null)
                .collect(Collectors.toMap(CodeChunk::getId, Function.identity()));
        List<SemanticCallEdge> allEdges = edgeMapper.findByTaskId(taskId);
        Map<Long, List<SecurityFlow>> flowsByChunk = flowMapper.findByTaskId(taskId).stream()
                .filter(flow -> flow.getPrimaryChunkId() != null)
                .collect(Collectors.groupingBy(SecurityFlow::getPrimaryChunkId));
        return units.stream().map(unit -> {
            List<SemanticCallEdge> relatedEdges = allEdges.stream()
                    .filter(edge -> unit.primaryChunkId() == value(edge.getCallerChunkId())
                            || unit.primaryChunkId() == value(edge.getCalleeChunkId()))
                    .limit(20).toList();
            Set<Long> relatedChunkIds = new LinkedHashSet<>();
            for (SemanticCallEdge edge : relatedEdges) {
                if (edge.getCallerChunkId() != null) relatedChunkIds.add(edge.getCallerChunkId());
                if (edge.getCalleeChunkId() != null) relatedChunkIds.add(edge.getCalleeChunkId());
            }
            String locations = relatedChunkIds.stream().map(chunksById::get).filter(java.util.Objects::nonNull)
                    .map(chunk -> "CHUNK " + chunk.getId() + " " + chunk.getFilePath() + ":"
                            + chunk.getStartLine() + " " + chunk.getSymbolName())
                    .collect(Collectors.joining("\n"));
            String expanded = joinNonBlank(unit.contextSummary(),
                    "补充调用关系：\n" + callSummary(relatedEdges),
                    "相关代码位置：\n" + locations,
                    "补充安全流：\n" + flowSummary(flowsByChunk.getOrDefault(
                            unit.primaryChunkId(), List.of())));
            return unit.withContext(truncate(expanded, 6_000));
        }).toList();
    }

    private boolean insideDeepScope(CodeChunk chunk, ScanMode scanMode) {
        return scanMode == ScanMode.FULL || chunk.getAnalysisScope() == AnalysisScope.CHANGED
                || chunk.getAnalysisScope() == AnalysisScope.IMPACTED;
    }

    private void addMarkerFacts(String searchable, Set<VulnerabilityType> types, Set<String> reasons) {
        if (containsAny(searchable, SQL_MARKERS)) {
            reasons.add("DANGEROUS_DATA_ACCESS");
            types.add(VulnerabilityType.SQL_INJECTION);
            types.add(VulnerabilityType.AUTHORIZATION);
        }
        if (containsAny(searchable, XSS_MARKERS)) {
            reasons.add("DANGEROUS_OUTPUT");
            types.add(VulnerabilityType.STORED_XSS);
        }
        if (containsAny(searchable, VALIDATION_MARKERS)) {
            reasons.add("VALIDATION_BOUNDARY");
            types.add(VulnerabilityType.VALIDATION_BYPASS);
        }
        if (containsAny(searchable, FINANCIAL_MARKERS)) {
            reasons.add("SENSITIVE_FINANCIAL_OPERATION");
            types.add(VulnerabilityType.FINANCIAL_RISK);
        }
        if (containsAny(searchable, AUTHORIZATION_MARKERS)) {
            reasons.add("AUTHORIZATION_BOUNDARY");
            types.add(VulnerabilityType.AUTHORIZATION);
            types.add(VulnerabilityType.UNAUTHORIZED_DISCLOSURE);
        }
    }

    private boolean hasExternalEntry(CodeChunk chunk, String searchable) {
        if (chunk.getEndpoint() != null && !chunk.getEndpoint().isBlank()) return true;
        return containsAny(searchable, EXTERNAL_ENTRY_MARKERS);
    }

    private boolean isSecurityConfiguration(CodeChunk chunk, String searchable) {
        String path = chunk.getFilePath() == null ? "" : chunk.getFilePath().toLowerCase(Locale.ROOT);
        boolean configurationFile = path.endsWith(".yml") || path.endsWith(".yaml")
                || path.endsWith(".properties") || path.endsWith(".xml")
                || path.endsWith("pom.xml") || searchable.contains("@configuration");
        return configurationFile && containsAny(searchable, SECURITY_CONFIG_MARKERS);
    }

    private boolean isUnresolved(SemanticCallEdge edge) {
        return "UNRESOLVED".equals(edge.getEdgeType()) || edge.getCalleeChunkId() == null;
    }

    private String searchable(CodeChunk chunk) {
        return String.join(" ", safe(chunk.getFilePath()), safe(chunk.getSymbolName()),
                safe(chunk.getEndpoint()), safe(chunk.getParameters()), safe(chunk.getAnnotations()),
                safe(chunk.getCalledSymbols()), safe(chunk.getContent())).toLowerCase(Locale.ROOT);
    }

    private boolean containsAny(String value, Set<String> markers) {
        String normalized = value.toLowerCase(Locale.ROOT);
        return markers.stream().map(marker -> marker.toLowerCase(Locale.ROOT))
                .anyMatch(normalized::contains);
    }

    private String unitType(Set<String> reasonCodes) {
        if (reasonCodes.contains("SEMANTIC_FLOW")) return "SECURITY_FLOW";
        if (reasonCodes.contains("EXTERNAL_ENTRY")) return "EXTERNAL_ENTRY";
        if (reasonCodes.contains("SECURITY_CONFIGURATION")) return "SECURITY_CONFIGURATION";
        if (reasonCodes.contains("DIRECT_CHANGE")) return "CHANGED_CODE";
        return "SECURITY_RELEVANT_CODE";
    }

    private String callSummary(List<SemanticCallEdge> edges) {
        if (edges.isEmpty()) return "没有已解析调用边";
        return edges.stream().limit(20).map(edge ->
                edge.getCalledName() + "@" + edge.getCallSiteLine() + " -> "
                        + (edge.getCalleeChunkId() == null ? "UNRESOLVED" : "CHUNK " + edge.getCalleeChunkId())
                        + " [" + edge.getEdgeType() + "/" + edge.getConfidence() + "]")
                .collect(Collectors.joining("\n"));
    }

    private String flowSummary(List<SecurityFlow> flows) {
        return flows.stream().limit(10).map(flow ->
                flow.getType() + " | source=" + safe(flow.getSourceDescription())
                        + " | sink=" + safe(flow.getSinkDescription())
                        + " | guard=" + safe(flow.getGuardSummary())
                        + " | confidence=" + flow.getConfidence())
                .collect(Collectors.joining("\n"));
    }

    private String methodChangeSummary(List<SemanticMethodChange> changes) {
        return changes.stream().limit(20)
                .map(change -> change.getChangeKind() + " | " + change.getDetails()
                        + (change.getBaseStartLine() == null ? "" : " | base=" + change.getBasePath()
                        + ":" + change.getBaseStartLine())
                        + (change.getTargetStartLine() == null ? "" : " | target=" + change.getTargetPath()
                        + ":" + change.getTargetStartLine()))
                .collect(Collectors.joining("\n"));
    }

    private String outline(String content) {
        if (content == null || content.isBlank()) return "";
        return truncate(content.replaceAll("\\s+", " ").strip(), 1_200);
    }

    private String joinNonBlank(String... values) {
        return java.util.Arrays.stream(values).filter(java.util.Objects::nonNull)
                .map(String::strip).filter(value -> !value.isBlank())
                .collect(Collectors.joining("\n\n"));
    }

    private String truncate(String value, int maxLength) {
        return value == null ? "" : value.substring(0, Math.min(maxLength, value.length()));
    }

    private long value(Long value) {
        return value == null ? Long.MIN_VALUE : value;
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }
}
