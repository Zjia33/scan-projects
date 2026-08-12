package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AuditToolService {
    static final int DEFAULT_RESULT_LIMIT = 10;
    static final int MAX_RESULT_LIMIT = 20;
    static final int MAX_READ_SOURCE_LINES = 160;
    static final int MAX_READ_SOURCE_CONTEXT_LINES = 20;

    private final SemanticEvidenceService semanticEvidenceService;
    private final CodeGraphIntegrationService codeGraphIntegrationService;
    private final ProfessionalToolService professionalToolService;
    private final CodeGraphSymbolSearchService codeGraphSymbolSearchService;
    private final CallGraphExplorerService callGraphExplorerService;

    @Autowired
    public AuditToolService(SemanticEvidenceService semanticEvidenceService,
                            CodeGraphIntegrationService codeGraphIntegrationService,
                            ProfessionalToolService professionalToolService,
                            CodeGraphSymbolSearchService codeGraphSymbolSearchService,
                            CallGraphExplorerService callGraphExplorerService) {
        this.semanticEvidenceService = semanticEvidenceService;
        this.codeGraphIntegrationService = codeGraphIntegrationService;
        this.professionalToolService = professionalToolService;
        this.codeGraphSymbolSearchService = codeGraphSymbolSearchService;
        this.callGraphExplorerService = callGraphExplorerService;
    }

    AuditToolService(SemanticEvidenceService semanticEvidenceService,
                     CodeGraphIntegrationService codeGraphIntegrationService,
                     ProfessionalToolService professionalToolService,
                     CodeGraphSymbolSearchService codeGraphSymbolSearchService) {
        this(semanticEvidenceService, codeGraphIntegrationService, professionalToolService,
                codeGraphSymbolSearchService, null);
    }

    AuditToolService(SemanticEvidenceService semanticEvidenceService,
                     CodeGraphIntegrationService codeGraphIntegrationService,
                     ProfessionalToolService professionalToolService) {
        this(semanticEvidenceService, codeGraphIntegrationService, professionalToolService, null, null);
    }

    // 使用当前 Agent 工具会话中的证据状态执行只读工具。
    public ToolResult execute(String tool, Map<String, Object> rawArguments,
                              CodeChunk current, List<CodeChunk> chunks,
                              VulnerabilityType vulnerabilityType, ToolSessionContext session) {
        try {
            ToolArguments arguments = ToolArguments.of(rawArguments);
            int limit = arguments.integer("limit", DEFAULT_RESULT_LIMIT, 1, MAX_RESULT_LIMIT);
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
                case AgentToolCatalog.SEARCH_SYMBOLS -> searchSymbols(
                        anchor.getTaskId(), anchor, chunks, arguments, limit);
                case AgentToolCatalog.SEARCH_CODE -> professionalToolService.searchCode(
                        anchor.getTaskId(), anchor, chunks, arguments, limit);
                case AgentToolCatalog.EXPLORE_CALL_GRAPH -> callGraphExplorerService == null
                        ? addCodeGraphRelations(professionalToolService.exploreCallGraph(
                                anchor.getTaskId(), anchor, chunks, arguments, limit), anchor, chunks, limit)
                        : callGraphExplorerService.explore(
                                anchor.getTaskId(), anchor, chunks, arguments, limit);
                case AgentToolCatalog.GET_CHANGE_CONTEXT -> professionalToolService.getChangeContext(
                        anchor.getTaskId(), anchor, chunks, arguments, limit);
                case AgentToolCatalog.RESOLVE_DATA_ACCESS -> professionalToolService.resolveDataAccess(
                        anchor.getTaskId(), anchor, chunks, arguments, limit);
                case AgentToolCatalog.INSPECT_SECURITY_POLICY -> professionalToolService.inspectSecurityPolicy(
                        anchor.getTaskId(), anchor, chunks, arguments, limit);
                case AgentToolCatalog.TRACE_VALUE -> professionalToolService.traceValue(
                        anchor.getTaskId(), anchor, chunks, arguments, limit, vulnerabilityType);
                default -> ToolResult.invalid("不允许的 Agent 工具: " + tool);
            };
        } catch (ToolArguments.InvalidArgumentException exception) {
            return ToolResult.invalid(exception.getMessage());
        }
    }

    private ToolResult searchSymbols(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                     ToolArguments arguments, int limit) {
        CodeGraphSymbolSearchService.Expansion expansion = codeGraphSymbolSearchService == null
                ? CodeGraphSymbolSearchService.Expansion.skipped()
                : codeGraphSymbolSearchService.expand(taskId, arguments, chunks);
        ToolResult local = professionalToolService.searchSymbols(
                taskId, current, chunks, arguments, limit);
        return expansion.merge(local);
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

    // 兼容旧调用入口：未经本地调用点验证的 CodeGraph 邻居只能作为候选。
    private ToolResult addCodeGraphRelations(ToolResult base, CodeChunk current,
                                             List<CodeChunk> chunks, int limit) {
        if (codeGraphIntegrationService == null) return base;
        CodeGraphIntegrationService.RelationContext context = codeGraphIntegrationService.relationContext(
                current.getTaskId(), current, chunks, limit);
        if (context.relatedChunkIds().isEmpty()) return base;
        Set<Long> evidence = new LinkedHashSet<>(base.evidenceChunkIds());
        Set<Long> candidates = new LinkedHashSet<>(base.candidateChunkIds());
        candidates.addAll(context.relatedChunkIds());
        candidates.removeAll(evidence);
        String text = base.text() + "\n\n" + context.text();
        return new ToolResult(base.status(), base.code(), text, evidence, candidates,
                base.truncated(), base.nextCursor());
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
        int contextLines = arguments.integer("contextLines", 2, 0, MAX_READ_SOURCE_CONTEXT_LINES);
        int first = Math.max(chunkStart, requestedStart - contextLines);
        int last = Math.min(chunkEnd, requestedEnd + contextLines);
        boolean truncated = last - first + 1 > MAX_READ_SOURCE_LINES;
        if (truncated) last = first + MAX_READ_SOURCE_LINES - 1;
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
                    + formatMetadata(candidate, "语义关系验证通过"), Set.of(candidateId), Set.of());
        }
        if (codeGraph != null && codeGraph.verified()) {
            return new ToolResult("[VERIFIED_EVIDENCE][CODEGRAPH_RELATION] " + codeGraph.reason() + "\n"
                    + formatMetadata(candidate, "CodeGraph 直接关系复验通过"), Set.of(candidateId), Set.of());
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
                + formatMetadata(candidate, "确定性关系验证通过"), Set.of(candidateId), Set.of());
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

    private String formatMetadata(CodeChunk chunk, String reason) {
        return "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":" + chunk.getStartLine()
                + " | " + chunk.getSymbolName() + " | reason=" + reason
                + " | kind=" + chunk.getChunkType() + " | endpoint=" + safe(chunk.getEndpoint())
                + " | annotations=" + safe(chunk.getAnnotations())
                + "\n[SOURCE_NOT_INCLUDED] 请使用 read_source 精读该代码块。";
    }

    private String safe(String value) {
        return value == null ? "" : value;
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
