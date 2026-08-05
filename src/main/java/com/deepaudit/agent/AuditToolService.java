package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.recon.ReconService;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuditToolService {
    private final SemanticEvidenceService semanticEvidenceService;
    private final CodeGraphIntegrationService codeGraphIntegrationService;
    private final ProfessionalToolService professionalToolService;
    private final ReconService reconService;
    private final CodeChunkMapper chunkMapper;

    public AuditToolService(SemanticEvidenceService semanticEvidenceService,
                            CodeGraphIntegrationService codeGraphIntegrationService,
                            ProfessionalToolService professionalToolService,
                            ReconService reconService, CodeChunkMapper chunkMapper) {
        this.semanticEvidenceService = semanticEvidenceService;
        this.codeGraphIntegrationService = codeGraphIntegrationService;
        this.professionalToolService = professionalToolService;
        this.reconService = reconService;
        this.chunkMapper = chunkMapper;
    }

    // 使用当前 Agent 工具会话中的证据状态执行只读工具。
    public ToolResult execute(String tool, Map<String, Object> rawArguments,
                              CodeChunk current, List<CodeChunk> chunks,
                              VulnerabilityType vulnerabilityType, ToolSessionContext session) {
        ToolArguments arguments = ToolArguments.of(rawArguments);
        int limit = arguments.integer("limit", 6, 1, 10);
        if (tool == null || tool.isBlank()) {
            return ToolResult.invalid("TOOL 动作必须提供明确的工具名称。");
        }
        String normalizedTool = tool.toLowerCase(Locale.ROOT);
        AgentToolCatalog.ToolSpec spec = AgentToolCatalog.find(normalizedTool);
        if (spec == null) {
            return ToolResult.invalid("不允许的 Agent 工具: " + tool);
        }
        Set<String> unknownArguments = arguments.unknownKeys(spec.allowedArguments());
        if (!unknownArguments.isEmpty()) {
            return ToolResult.invalid(normalizedTool + " 包含未知参数: " + unknownArguments);
        }
        AnchorResolution anchorResolution = resolveAnchor(arguments, current, chunks, session);
        if (anchorResolution.error() != null) return anchorResolution.error();
        CodeChunk anchor = anchorResolution.chunk();
        return switch (normalizedTool) {
            case AgentToolCatalog.READ_SOURCE -> readSource(arguments, chunks, session);
            case AgentToolCatalog.VERIFY_RELATION -> verifyRelation(reference(arguments, "candidateChunkId"),
                    anchor, chunks, session);
            case AgentToolCatalog.SEARCH_SYMBOLS -> professionalToolService.searchSymbols(
                    anchor.getTaskId(), anchor, chunks, arguments, limit);
            case AgentToolCatalog.SEARCH_CODE -> searchCode(arguments, anchor, chunks, limit);
            case AgentToolCatalog.EXPLORE_CALL_GRAPH -> exploreCallGraph(arguments, anchor, chunks, limit);
            case AgentToolCatalog.READ_IMPACT_SOURCE -> readImpactSource(arguments, anchor, chunks);
            case AgentToolCatalog.GET_CHANGE_CONTEXT -> professionalToolService.getChangeContext(
                    anchor.getTaskId(), anchor, chunks, arguments, limit);
            case AgentToolCatalog.RESOLVE_DATA_ACCESS -> {
                ToolResult result = professionalToolService.resolveDataAccess(
                        anchor.getTaskId(), anchor, chunks, arguments, limit);
                yield explainPartialScope(result, "数据访问实现尚未物化；可先用 explore_call_graph 选择被调用符号，"
                        + "再用 read_impact_source 和 verify_relation 验证。 ");
            }
            case AgentToolCatalog.INSPECT_SECURITY_POLICY -> {
                materializeGlobalContext(anchor, chunks);
                yield professionalToolService.inspectSecurityPolicy(
                        anchor.getTaskId(), anchor, chunks, arguments, limit);
            }
            case AgentToolCatalog.TRACE_VALUE -> explainPartialScope(
                    professionalToolService.traceValue(anchor.getTaskId(), anchor, chunks,
                            arguments, limit, vulnerabilityType),
                    "当前值流索引只覆盖已物化范围；需要跨方法时应先按需载入并验证调用上下文。 ");
            default -> ToolResult.invalid("不允许的 Agent 工具: " + tool);
        };
    }

    private String reference(ToolArguments arguments, String name) {
        Long value = arguments.longValue(name);
        return value == null ? null : String.valueOf(value);
    }

    private AnchorResolution resolveAnchor(ToolArguments arguments, CodeChunk current,
                                           List<CodeChunk> chunks, ToolSessionContext session) {
        Long requested = arguments.longValue("anchorChunkId");
        if (requested == null) return new AnchorResolution(current, null);
        if (!session.allowedEvidenceChunkIds().contains(requested)) {
            return new AnchorResolution(null, ToolResult.forbidden(
                    "anchorChunkId=" + requested + " 尚未成为已验证证据；"
                            + "请先调用 verify_relation，候选代码块不能直接作为新的探索锚点。"));
        }
        CodeChunk anchor = chunks.stream().filter(chunk -> requested.equals(chunk.getId()))
                .findFirst().orElse(null);
        if (anchor == null) {
            return new AnchorResolution(null, ToolResult.notFound(
                    "当前任务不存在 anchorChunkId=" + requested));
        }
        return new AnchorResolution(anchor, null);
    }

    private ToolResult exploreCallGraph(ToolArguments arguments, CodeChunk anchor,
                                        List<CodeChunk> chunks, int limit) {
        ToolResult local = professionalToolService.exploreCallGraph(
                anchor.getTaskId(), anchor, chunks, arguments, limit);
        if (codeGraphIntegrationService == null) return local;
        CodeGraphIntegrationService.Direction direction;
        try {
            String requested = arguments.string("direction");
            direction = requested.isBlank() ? CodeGraphIntegrationService.Direction.BOTH
                    : CodeGraphIntegrationService.Direction.valueOf(requested.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            return ToolResult.invalid("direction 只能是 CALLERS、CALLEES 或 BOTH。");
        }
        int cursor = arguments.integer("cursor", 0, 0, Integer.MAX_VALUE);
        CodeGraphIntegrationService.CandidatePage page = codeGraphIntegrationService.relatedCandidates(
                anchor.getTaskId(), anchor, direction, cursor, limit);
        if (page.error() != null) {
            return new ToolResult(ToolResult.Status.ERROR, "CODEGRAPH_QUERY_FAILED", page.error(),
                    local.evidenceChunkIds(), local.candidateChunkIds(), false, null);
        }
        if (page.candidates().isEmpty() && page.truncated() && page.nextCursor() == null) {
            return new ToolResult(ToolResult.Status.ERROR, "CODEGRAPH_COVERAGE_LIMIT_REACHED",
                    "[PARTIAL_SCOPE] CodeGraph 关系数量达到后端安全上限，仍可能存在未返回的调用关系。",
                    local.evidenceChunkIds(), local.candidateChunkIds(), true, null);
        }
        if (page.candidates().isEmpty()) return local;
        String candidates = page.candidates().stream().map(candidate -> {
            var location = candidate.location();
            return "candidateId=" + candidate.candidateId() + " | direction=" + candidate.direction()
                    + " | symbol=" + location.name() + " | kind=" + location.kind()
                    + " | file=" + location.filePath() + ":" + location.startLine();
        }).collect(Collectors.joining("\n"));
        String text = local.text() + "\n\n[UNVERIFIED_SYMBOL_CANDIDATES] 仅含符号位置，尚未读取源码：\n"
                + candidates + (page.truncated() && page.nextCursor() == null
                ? "\n[PARTIAL_SCOPE] 已达到 CodeGraph 最大关系读取范围，候选集合可能不完整。" : "");
        return new ToolResult(ToolResult.Status.OK, "CODEGRAPH_SYMBOL_CANDIDATES", text,
                local.evidenceChunkIds(), local.candidateChunkIds(), page.truncated(), page.nextCursor());
    }

    private ToolResult searchCode(ToolArguments arguments, CodeChunk anchor,
                                  List<CodeChunk> chunks, int limit) {
        ReconService.ProjectSearchMaterialization coverage = null;
        String scope = arguments.string("scope").toUpperCase(Locale.ROOT);
        if (scope.isBlank()) scope = "RELATED";
        if ("PROJECT".equals(scope) && reconService != null && codeGraphIntegrationService != null) {
            var root = codeGraphIntegrationService.targetRoot(anchor.getTaskId());
            String query = arguments.string("query");
            boolean caseSensitive = arguments.bool("caseSensitive", false);
            String filePattern = arguments.string("filePattern");
            String searchKey = query + "|" + caseSensitive + "|" + filePattern;
            if (root != null && !query.isBlank()) {
                synchronized (materializationLock(anchor)) {
                    if (codeGraphIntegrationService.markProjectSearchIfNew(anchor.getTaskId(), searchKey)) {
                        coverage = reconService.materializeProjectSearch(anchor.getTaskId(), root,
                                query, caseSensitive, filePattern, 500);
                    }
                    refreshChunks(anchor.getTaskId(), chunks);
                }
            }
        }
        ToolResult base = professionalToolService.searchCode(
                anchor.getTaskId(), anchor, chunks, arguments, limit);
        if (coverage == null || !coverage.truncated() && coverage.skippedOversizedFiles() == 0) return base;
        String note = "\n[PARTIAL_SCOPE] 项目搜索按需物化达到安全上限或跳过超大文件：matched="
                + coverage.matchedLocations() + "，skippedOversizedFiles="
                + coverage.skippedOversizedFiles() + "。未返回结果不能证明项目中不存在匹配代码。";
        return new ToolResult(base.status(), "PROJECT_SEARCH_PARTIAL", base.text() + note,
                base.evidenceChunkIds(), base.candidateChunkIds(), true, base.nextCursor());
    }

    private ToolResult explainPartialScope(ToolResult result, String guidance) {
        if (result.status() != ToolResult.Status.EMPTY) return result;
        return new ToolResult(ToolResult.Status.EMPTY, "PARTIAL_SCOPE", result.text()
                + "\n[PARTIAL_SCOPE] " + guidance + "未找到不等于已证明不存在。",
                result.evidenceChunkIds(), result.candidateChunkIds(), false, null);
    }

    private ToolResult readImpactSource(ToolArguments arguments, CodeChunk anchor,
                                        List<CodeChunk> chunks) {
        if (codeGraphIntegrationService == null || reconService == null || chunkMapper == null) {
            return ToolResult.notFound("CodeGraph 按需源码读取不可用。");
        }
        String candidateId = arguments.string("candidateId");
        if (candidateId.isBlank()) return ToolResult.invalid("read_impact_source 需要 candidateId。");
        CodeGraphIntegrationService.ImpactCandidate candidate = codeGraphIntegrationService.candidate(
                anchor.getTaskId(), candidateId);
        if (candidate == null || !Objects.equals(candidate.anchorChunkId(), anchor.getId())) {
            return ToolResult.forbidden("candidateId 不属于当前已验证锚点的 CodeGraph 查询结果。");
        }
        var root = codeGraphIntegrationService.targetRoot(anchor.getTaskId());
        if (root == null) return ToolResult.notFound("当前任务没有可读取的 Target 工作区。");
        CodeChunk selected;
        synchronized (materializationLock(anchor)) {
            reconService.materializeCodeGraphLocations(anchor.getTaskId(), root, List.of(candidate.location()));
            refreshChunks(anchor.getTaskId(), chunks);
            selected = codeGraphIntegrationService.mapCandidate(chunks, candidate);
            if (selected != null && Objects.equals(selected.getId(), anchor.getId())) {
                return ToolResult.invalid("CodeGraph 候选指向当前锚点自身，无需作为 IMPACTED 上下文读取。");
            }
            if (selected != null && selected.getId() != null) {
                reconService.promoteImpactScope(anchor.getTaskId(), Set.of(selected.getId()));
                selected.setAnalysisScope(com.deepaudit.domain.AnalysisScope.IMPACTED);
            }
        }
        if (selected == null || selected.getId() == null) {
            return ToolResult.notFound("CodeGraph 候选无法严格映射到唯一源码块。");
        }
        return new ToolResult(ToolResult.Status.OK, "IMPACT_SOURCE_LOADED",
                "[UNVERIFIED_CANDIDATE][IMPACT_SOURCE] 候选源码已按需载入，必须继续 verify_relation。\n"
                        + format(selected, "CodeGraph 候选位置"),
                Set.of(), Set.of(selected.getId()), false, null);
    }

    private void materializeGlobalContext(CodeChunk anchor, List<CodeChunk> chunks) {
        if (codeGraphIntegrationService == null || reconService == null || chunkMapper == null) return;
        var root = codeGraphIntegrationService.targetRoot(anchor.getTaskId());
        if (root == null) return;
        synchronized (materializationLock(anchor)) {
            if (!codeGraphIntegrationService.isGlobalContextMaterialized(anchor.getTaskId())) {
                reconService.materializeGlobalSecurityContext(anchor.getTaskId(), root);
                codeGraphIntegrationService.markGlobalContextMaterialized(anchor.getTaskId());
            }
            refreshChunks(anchor.getTaskId(), chunks);
        }
    }

    private void refreshChunks(java.util.UUID taskId, List<CodeChunk> chunks) {
        Set<Long> existing = chunks.stream().map(CodeChunk::getId).filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        for (CodeChunk chunk : chunkMapper.findByTaskId(taskId)) {
            if (chunk.getId() != null && existing.add(chunk.getId())) chunks.add(chunk);
        }
    }

    private boolean hasUniqueDirectCallRelation(CodeChunk current, CodeChunk candidate,
                                                List<CodeChunk> chunks, Set<String> currentCalls,
                                                String currentMethod) {
        String candidateMethod = methodName(candidate.getSymbolName());
        boolean outgoing = currentCalls.contains(candidateMethod)
                && uniqueMethod(chunks, candidateMethod, candidate.getId());
        Set<String> candidateCalls = splitSymbols(candidate.getCalledSymbols());
        boolean incoming = candidateCalls.contains(currentMethod)
                && uniqueMethod(chunks, currentMethod, current.getId());
        return outgoing || incoming;
    }

    private boolean uniqueMethod(List<CodeChunk> chunks, String method, Long expectedId) {
        if (method == null || method.isBlank()) return false;
        List<Long> matches = chunks.stream()
                .filter(chunk -> method.equals(methodName(chunk.getSymbolName())))
                .map(CodeChunk::getId).distinct().limit(2).toList();
        return matches.size() == 1 && matches.get(0).equals(expectedId);
    }

    // 读取完整代码块或按行精读；候选代码仍需 verify_relation 才能成为证据。
    private ToolResult readSource(ToolArguments arguments, List<CodeChunk> chunks,
                                  ToolSessionContext session) {
        Long id = arguments.longValue("chunkId");
        if (id == null) return ToolResult.invalid("read_source 需要有效的 chunkId。");
        CodeChunk chunk = chunks.stream().filter(value -> id.equals(value.getId())).findFirst().orElse(null);
        if (chunk == null) return ToolResult.notFound("当前任务不存在 CHUNK " + id);
        if (!session.canRead(id)) {
            return ToolResult.forbidden("CHUNK " + id + " 尚未通过搜索或语义工具进入当前会话候选集合。");
        }
        String[] contentLines = chunk.getContent() == null ? new String[0] : chunk.getContent().split("\\R", -1);
        if (contentLines.length == 0) return ToolResult.empty("CHUNK " + id + " 没有可读取的源码。");
        int chunkStart = Math.max(1, chunk.getStartLine());
        int chunkEnd = chunkStart + contentLines.length - 1;
        boolean ranged = arguments.has("startLine") || arguments.has("endLine");
        int requestedStart = arguments.integer("startLine", chunkStart, chunkStart, chunkEnd);
        int requestedEnd = arguments.integer("endLine", ranged ? requestedStart : chunkEnd,
                chunkStart, chunkEnd);
        if (requestedEnd < requestedStart) {
            return ToolResult.invalid("endLine 不能小于 startLine。");
        }
        int contextLines = arguments.integer("contextLines", 2, 0, 10);
        int first = Math.max(chunkStart, requestedStart - contextLines);
        int last = Math.min(chunkEnd, requestedEnd + contextLines);
        boolean truncated = last - first + 1 > 80;
        if (truncated) last = first + 79;
        StringBuilder body = new StringBuilder();
        for (int line = first; line <= last; line++) {
            boolean selected = line >= requestedStart && line <= requestedEnd;
            body.append(selected ? ">>> " : "    ")
                    .append(String.format(Locale.ROOT, "%5d | ", line))
                    .append(contentLines[line - chunkStart]).append('\n');
        }
        String text = "[SOURCE] CHUNK_ID=" + id + " | " + chunk.getFilePath() + ":"
                + first + "-" + last + " | " + chunk.getSymbolName()
                + "\n<UNTRUSTED_CODE>\n" + body.toString().stripTrailing() + "\n</UNTRUSTED_CODE>";
        Set<Long> evidence = session.allowedEvidenceChunkIds().contains(id) ? Set.of(id) : Set.of();
        Set<Long> candidates = evidence.isEmpty() ? Set.of(id) : Set.of();
        return new ToolResult(ToolResult.Status.OK, text, evidence, candidates, truncated, null);
    }

    // 通过语义图或确定性结构关系把候选提升为已验证证据。
    private ToolResult verifyRelation(String candidateReference, CodeChunk current,
                                      List<CodeChunk> chunks, ToolSessionContext session) {
        Long candidateId = parseChunkId(candidateReference);
        if (candidateId == null) {
            return ToolResult.invalid("verify_relation 需要提供候选 candidateChunkId。");
        }
        CodeChunk candidate = chunks.stream().filter(chunk -> candidateId.equals(chunk.getId())).findFirst().orElse(null);
        if (candidate == null) {
            return ToolResult.notFound("候选代码块不存在: " + candidateId);
        }
        if (!session.canRead(candidateId)) {
            return ToolResult.forbidden("CHUNK " + candidateId
                    + " 尚未通过搜索、语义流或调用图进入当前会话，不能直接验证猜测的代码块 ID。");
        }
        SemanticEvidenceService.RelationVerification semantic = semanticEvidenceService.verifyRelation(
                current.getTaskId(), current.getId(), candidateId);
        CodeGraphIntegrationService.RelationCheck codeGraph = codeGraphIntegrationService == null
                ? null : codeGraphIntegrationService.verifyDirectRelation(
                current.getTaskId(), current, candidate, chunks);
        RelationAssessment structural = structuralRelation(current, candidate, chunks);
        if (semantic != null && semantic.verified()) {
            return new ToolResult("[VERIFIED_EVIDENCE][SEMANTIC_RELATION] " + semantic.reason() + "\n"
                    + format(candidate, "语义关系验证通过"), Set.of(candidateId), Set.of());
        }
        if (codeGraph != null && codeGraph.verified() && hasLocalCallSite(current, candidate)) {
            return new ToolResult("[VERIFIED_EVIDENCE][CODEGRAPH_RELATION][LOCAL_CALL_SITE] "
                    + codeGraph.reason() + "；本地源码存在对应调用点\n"
                    + format(candidate, "CodeGraph 与本地调用点共同复验通过"), Set.of(candidateId), Set.of());
        }
        if (!structural.verified()) {
            String semanticReason = semantic == null || semantic.reason() == null ? "" : semantic.reason() + "；";
            String codeGraphReason = codeGraph == null || codeGraph.reason() == null
                    ? "" : codeGraph.reason() + "；";
            return new ToolResult(ToolResult.Status.DENIED, "RELATION_REJECTED",
                    "[RELATION_REJECTED][" + structural.code() + "] " + semanticReason + codeGraphReason
                            + structural.reason() + "。该候选仍只能作为上下文，不能作为漏洞证据。",
                    Set.of(), Set.of(candidateId), false, null);
        }
        return new ToolResult("[VERIFIED_EVIDENCE][" + structural.code() + "] "
                + structural.reason() + "\n"
                + format(candidate, "确定性关系验证通过"), Set.of(candidateId), Set.of());
    }

    // 只有唯一方法调用或明确安全策略匹配可以提升证据；同路由、同名方法仅保留为候选。
    private RelationAssessment structuralRelation(CodeChunk current, CodeChunk candidate,
                                                  List<CodeChunk> chunks) {
        String currentMethod = methodName(current.getSymbolName());
        Set<String> currentCalls = splitSymbols(current.getCalledSymbols());
        if (hasUniqueDirectCallRelation(current, candidate, chunks, currentCalls, currentMethod)) {
            return new RelationAssessment(true, "CALL_EDGE_VERIFIED",
                    "代码块之间存在唯一方法符号调用关系");
        }
        if (securityPolicyMatches(current.getEndpoint(), candidate.getContent())) {
            return new RelationAssessment(true, "POLICY_MATCH_VERIFIED",
                    "候选安全配置能够匹配当前接口路径");
        }
        if (current.getEndpoint() != null && current.getEndpoint().equals(candidate.getEndpoint())) {
            return new RelationAssessment(false, "SAME_ROUTE_CONTEXT_ONLY",
                    "代码块仅属于同一接口路由，尚未证明调用或数据流关系");
        }
        String candidateMethod = methodName(candidate.getSymbolName());
        if (currentCalls.contains(candidateMethod)
                || splitSymbols(candidate.getCalledSymbols()).contains(currentMethod)) {
            return new RelationAssessment(false, "NAME_MATCH_ONLY",
                    "存在方法名匹配，但项目中无法唯一解析到该代码块");
        }
        return new RelationAssessment(false, "NO_VERIFIED_RELATION",
                "未找到可靠的调用、数据流或安全策略关系");
    }

    private Object materializationLock(CodeChunk anchor) {
        Object lock = codeGraphIntegrationService.materializationLock(anchor.getTaskId());
        return lock == null ? this : lock;
    }

    private boolean hasLocalCallSite(CodeChunk current, CodeChunk candidate) {
        String currentMethod = methodName(current.getSymbolName());
        String candidateMethod = methodName(candidate.getSymbolName());
        return splitSymbols(current.getCalledSymbols()).contains(candidateMethod)
                || splitSymbols(candidate.getCalledSymbols()).contains(currentMethod);
    }

    private boolean securityPolicyMatches(String endpoint, String content) {
        if (endpoint == null || content == null) return false;
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
                "requestMatchers\\s*\\(([^)]*)\\)", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(content);
        while (matcher.find()) {
            java.util.regex.Matcher quoted = java.util.regex.Pattern.compile("[\\\"']([^\\\"']+)[\\\"']")
                    .matcher(matcher.group(1));
            while (quoted.find()) {
                if (endpointMatches(endpoint, quoted.group(1))) return true;
            }
        }
        return false;
    }

    private boolean endpointMatches(String endpoint, String antPattern) {
        StringBuilder regex = new StringBuilder("^");
        for (int index = 0; index < antPattern.length(); index++) {
            char current = antPattern.charAt(index);
            if (current == '*' && index + 1 < antPattern.length() && antPattern.charAt(index + 1) == '*') {
                regex.append(".*");
                index++;
            } else if (current == '*') {
                regex.append("[^/]*");
            } else if (current == '{') {
                int end = antPattern.indexOf('}', index + 1);
                if (end > index) {
                    regex.append("[^/]+");
                    index = end;
                } else {
                    regex.append(java.util.regex.Pattern.quote(String.valueOf(current)));
                }
            } else {
                regex.append(java.util.regex.Pattern.quote(String.valueOf(current)));
            }
        }
        return endpoint.matches(regex.append('$').toString());
    }

    private Long parseChunkId(String chunkReference) {
        if (chunkReference == null) return null;
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\\d+").matcher(chunkReference);
        if (!matcher.find()) return null;
        try { return Long.parseLong(matcher.group()); } catch (NumberFormatException exception) { return null; }
    }

    // 将源码包裹为不可信代码片段，避免其文本被当作 Agent 指令执行。
    private String format(CodeChunk chunk, String reason) {
        String content = chunk.getContent() == null ? "" : chunk.getContent();
        String code = content.substring(0, Math.min(content.length(), 4_000));
        return "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":" + chunk.getStartLine()
                + " | " + chunk.getSymbolName() + " | reason=" + reason
                + "\n<UNTRUSTED_CODE>\n" + code
                + "\n</UNTRUSTED_CODE>"
                + (content.length() > 4_000
                ? "\n[CONTENT_TRUNCATED] 请使用 read_source 精读目标行。" : "");
    }

    private Set<String> splitSymbols(String value) {
        if (value == null || value.isBlank()) return Set.of();
        return Arrays.stream(value.split(",")).map(String::strip).filter(item -> !item.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private String methodName(String symbol) {
        if (symbol == null) return "";
        int hash = symbol.lastIndexOf('#');
        return hash < 0 ? symbol : symbol.substring(hash + 1);
    }

    private record AnchorResolution(CodeChunk chunk, ToolResult error) {
    }

    private record RelationAssessment(boolean verified, String code, String reason) {
    }
}
