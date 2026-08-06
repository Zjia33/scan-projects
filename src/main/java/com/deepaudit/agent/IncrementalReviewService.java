package com.deepaudit.agent;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import com.deepaudit.mapper.GitFileChangeMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 为增量扫描构建只包含 CHANGED 事实的轻量审查单元。
 */
@Service
@RequiredArgsConstructor
public class IncrementalReviewService {
    private static final int MAX_CODE_CHARS = 4_000;
    private static final int CHANGE_CONTEXT_LINES = 10;
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
    private final GitFileChangeMapper fileChangeMapper;

    // 每个 CHANGED 代码块都是分诊目标；跨方法上下文由专业 Agent 后续按需获取。
    public List<IncrementalReviewUnit> build(UUID taskId, List<CodeChunk> chunks,
                                             Map<Long, Set<VulnerabilityType>> hints,
                                             Map<Long, String> hintDescriptions) {
        List<SemanticCallEdge> edges = safeList(edgeMapper.findByTaskId(taskId));
        List<SecurityFlow> flows = safeList(flowMapper.findByTaskId(taskId));
        List<SemanticMethodChange> changes = safeList(semanticChangeMapper.findByTaskId(taskId));
        Map<String, GitFileChange> fileChanges = safeList(fileChangeMapper.findByTaskId(taskId)).stream()
                .filter(change -> change.getNewPath() != null || change.getOldPath() != null)
                .collect(Collectors.toMap(change -> normalizePath(change.getNewPath() == null
                                ? change.getOldPath() : change.getNewPath()), change -> change,
                        (left, right) -> left));
        List<VulnerabilityType> allowedTypes = java.util.Arrays.stream(VulnerabilityType.values()).sorted().toList();
        List<IncrementalReviewUnit> result = new ArrayList<>();
        for (CodeChunk chunk : chunks) {
            if (chunk.getId() == null || !insideIncrementalScope(chunk)) continue;
            List<SemanticCallEdge> relatedEdges = relatedEdges(chunk.getId(), edges);
            List<SecurityFlow> relatedFlows = flows.stream()
                    .filter(flow -> flow.getPrimaryChunkId() != null && flow.getPrimaryChunkId().equals(chunk.getId()))
                    .toList();
            List<SemanticMethodChange> relatedChanges = relatedChanges(chunk, changes, relatedEdges);
            GitFileChange fileChange = fileChanges.get(normalizePath(chunk.getFilePath()));
            Set<String> facts = facts(chunk, relatedEdges, relatedFlows, relatedChanges,
                    hints.getOrDefault(chunk.getId(), Set.of()));
            Set<VulnerabilityType> mandatoryTypes = mandatoryTypes(
                    hints.getOrDefault(chunk.getId(), Set.of()), relatedChanges, relatedFlows);
            String deterministicEvidence = joinNonBlank(hintDescriptions.get(chunk.getId()),
                    flowSummary(relatedFlows));
            result.add(new IncrementalReviewUnit("change-" + chunk.getId(), chunk.getId(),
                    chunk.getFilePath(), chunk.getSymbolName(), chunk.getEndpoint(), chunk.getChunkType(),
                    chunk.getChangeType().name(), allowedTypes,
                    mandatoryTypes.stream().sorted().toList(), List.copyOf(facts), chunk.getParameters(),
                    chunk.getAnnotations(), chunk.getCalledSymbols(), baseExcerpt(chunk, relatedChanges, fileChange),
                    targetExcerpt(chunk, fileChange), joinNonBlank(changeSummary(relatedChanges),
                            fileChangeSummary(fileChange), edgeSummary(relatedEdges)),
                    truncate(deterministicEvidence, 4_000), chunk.getStartLine(), chunk.getEndLine()));
        }
        return List.copyOf(result);
    }

    private boolean insideIncrementalScope(CodeChunk chunk) {
        return chunk.getAnalysisScope() == AnalysisScope.CHANGED;
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
        boolean deletedSecurityBoundary = changes.stream()
                .filter(change -> change.getChangeKind() == SemanticChangeKind.METHOD_DELETED)
                .map(SemanticMethodChange::getBaseContent).map(this::safe)
                .map(value -> value.toLowerCase(Locale.ROOT))
                .anyMatch(value -> containsAny(value, SECURITY_ANNOTATIONS)
                        || containsAny(value, VALIDATION)
                        || value.contains("checkowner") || value.contains("checkpermission")
                        || value.contains("hasauthority") || value.contains("hasrole"));
        if (deletedSecurityBoundary) {
            result.add(VulnerabilityType.AUTHORIZATION);
            result.add(VulnerabilityType.VALIDATION_BYPASS);
        }
        return result;
    }


    private List<SemanticMethodChange> relatedChanges(CodeChunk chunk, List<SemanticMethodChange> changes,
                                                       List<SemanticCallEdge> relatedEdges) {
        Set<String> calledNames = relatedEdges.stream().map(SemanticCallEdge::getCalledName)
                .filter(java.util.Objects::nonNull).collect(Collectors.toSet());
        return changes.stream().filter(change -> {
            boolean samePath = safe(change.getTargetPath()).equals(safe(chunk.getFilePath()))
                    || change.getTargetPath() == null
                    && safe(change.getBasePath()).equals(safe(chunk.getFilePath()));
            boolean sameTarget = samePath && (change.getTargetStartLine() != null
                    ? change.getTargetStartLine() >= chunk.getStartLine()
                    && change.getTargetStartLine() <= chunk.getEndLine()
                    : safe(chunk.getSymbolName()).toLowerCase(Locale.ROOT)
                    .contains(safe(change.getMethodName()).toLowerCase(Locale.ROOT)));
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
                safe(chunk.getContent()), safe(chunk.getBaseContent())).toLowerCase(Locale.ROOT);
    }

    private boolean containsAny(String value, Set<String> markers) {
        return markers.stream().anyMatch(value::contains);
    }

    private String targetExcerpt(CodeChunk chunk, GitFileChange change) {
        if (chunk.getContent() == null || chunk.getContent().isBlank()) return "";
        String ranges = change == null ? "" : change.getNewRanges();
        return changedWindow(chunk.getContent(), chunk.getStartLine(), ranges, MAX_CODE_CHARS);
    }

    private String baseExcerpt(CodeChunk chunk, List<SemanticMethodChange> changes,
                               GitFileChange fileChange) {
        String base = safe(chunk.getBaseContent());
        if (base.isBlank()) return "";
        // 文本/config 块的基线内容是带 +/- 标记的真实 Git 差异，不伪装成完整 Base 源码。
        if (base.stripLeading().startsWith("@@ base")) return truncate(base, MAX_CODE_CHARS);
        int baseStart = changes.stream().map(SemanticMethodChange::getBaseStartLine)
                .filter(java.util.Objects::nonNull).findFirst().orElse(chunk.getStartLine());
        String ranges = fileChange == null ? "" : fileChange.getOldRanges();
        return changedWindow(base, baseStart, ranges, MAX_CODE_CHARS);
    }

    private String changedWindow(String content, int contentStartLine, String ranges, int limit) {
        String[] lines = safe(content).split("\\R", -1);
        List<ChangeWindow> selected = new ArrayList<>();
        int contentEndLine = contentStartLine + lines.length - 1;
        if (ranges != null && !ranges.isBlank()) {
            for (String value : ranges.split(",")) {
                String[] bounds = value.split(":", 2);
                if (bounds.length != 2) continue;
                try {
                    int changedStart = Integer.parseInt(bounds[0]);
                    int changedEnd = Integer.parseInt(bounds[1]);
                    int coreStart = Math.max(contentStartLine, Math.min(changedStart, changedEnd));
                    int coreEnd = Math.min(contentEndLine, Math.max(changedStart, changedEnd));
                    if (coreStart > coreEnd) continue;
                    selected.add(new ChangeWindow(
                            Math.max(contentStartLine, coreStart - CHANGE_CONTEXT_LINES),
                            Math.min(contentEndLine, coreEnd + CHANGE_CONTEXT_LINES),
                            coreStart, coreEnd));
                } catch (NumberFormatException ignored) {
                }
            }
        }
        if (selected.isEmpty()) {
            return renderContiguousWindow(lines, contentStartLine, contentStartLine,
                    Math.min(contentEndLine, contentStartLine + 40), limit);
        }

        // 每个 Git 变更区间独立分配剩余预算，避免前面的长区间吞掉全部源码窗口。
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < selected.size(); index++) {
            String separator = result.isEmpty() ? "" : "\n...\n";
            int available = limit - result.length() - separator.length();
            int remainingWindows = selected.size() - index;
            if (available <= 0) break;
            int windowBudget = Math.max(1, available / remainingWindows);
            String windowText = renderChangeWindow(lines, contentStartLine,
                    selected.get(index), windowBudget);
            if (windowText.isBlank()) continue;
            result.append(separator).append(windowText);
        }
        return result.toString().strip();
    }

    private String renderChangeWindow(String[] lines, int contentStartLine,
                                      ChangeWindow window, int limit) {
        String header = "[CHANGE_RANGE " + window.coreStart() + ":" + window.coreEnd() + "]\n";
        if (header.length() >= limit) return header.substring(0, limit).stripTrailing();

        java.util.SortedSet<Integer> selectedLines = new java.util.TreeSet<>();
        selectedLines.add(window.coreStart());
        String rendered = renderSelectedLines(lines, contentStartLine, window, selectedLines, header);
        if (rendered.length() > limit) {
            return truncateSourceLine(header, window.coreStart(),
                    lines[window.coreStart() - contentStartLine], limit);
        }

        for (int line : prioritizedLines(window)) {
            if (selectedLines.contains(line)) continue;
            selectedLines.add(line);
            String candidate = renderSelectedLines(lines, contentStartLine, window, selectedLines, header);
            if (candidate.length() <= limit) {
                rendered = candidate;
            } else {
                selectedLines.remove(line);
            }
        }
        return rendered.stripTrailing();
    }

    private List<Integer> prioritizedLines(ChangeWindow window) {
        List<Integer> result = new ArrayList<>();
        if (window.coreEnd() != window.coreStart()) result.add(window.coreEnd());
        for (int line = window.coreStart() + 1; line < window.coreEnd(); line++) result.add(line);
        for (int distance = 1; distance <= CHANGE_CONTEXT_LINES; distance++) {
            int before = window.coreStart() - distance;
            int after = window.coreEnd() + distance;
            if (before >= window.from()) result.add(before);
            if (after <= window.to()) result.add(after);
        }
        return result;
    }

    private String renderSelectedLines(String[] lines, int contentStartLine, ChangeWindow window,
                                       java.util.SortedSet<Integer> selectedLines, String header) {
        StringBuilder result = new StringBuilder(header);
        int previous = Integer.MIN_VALUE;
        for (int line : selectedLines) {
            if (previous != Integer.MIN_VALUE && line > previous + 1) result.append("...\n");
            result.append(line).append(" | ").append(lines[line - contentStartLine]).append('\n');
            previous = line;
        }
        if (selectedLines.first() > window.from() || selectedLines.last() < window.to()) {
            result.append("[WINDOW_TRUNCATED]\n");
        }
        return result.toString();
    }

    private String truncateSourceLine(String header, int line, String source, int limit) {
        String prefix = header + line + " | ";
        if (prefix.length() >= limit) return prefix.substring(0, limit).stripTrailing();
        int sourceLimit = Math.max(0, limit - prefix.length());
        return prefix + source.substring(0, Math.min(source.length(), sourceLimit));
    }

    private String renderContiguousWindow(String[] lines, int contentStartLine,
                                          int from, int to, int limit) {
        StringBuilder result = new StringBuilder();
        for (int line = from; line <= to; line++) {
            String numbered = (result.isEmpty() ? "" : "\n")
                    + line + " | " + lines[line - contentStartLine];
            if (result.length() + numbered.length() > limit) break;
            result.append(numbered);
        }
        return result.toString().strip();
    }

    private record ChangeWindow(int from, int to, int coreStart, int coreEnd) {
    }

    private String fileChangeSummary(GitFileChange change) {
        if (change == null) return "";
        return "Git文件变化=" + safe(change.getChangeType()) + "，Base范围="
                + safe(change.getOldRanges()) + "，Target范围=" + safe(change.getNewRanges())
                + "\n" + truncate(change.getContextText(), 4_000);
    }

    private String normalizePath(String value) {
        return value == null ? "" : value.replace('\\', '/');
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
