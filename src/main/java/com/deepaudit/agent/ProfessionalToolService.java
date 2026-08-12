package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.SemanticSymbol;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.git.UnifiedChangeContext;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import com.deepaudit.mapper.SemanticSymbolMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ProfessionalToolService {
    private static final int KEY_STATEMENT_CONTEXT_LINES = 5;
    private static final int CHANGE_DIFF_CONTEXT_LINES = 5;
    private static final int MAX_RELATED_CHANGE_CHARS = 20_000;
    private static final int MAX_SEARCH_QUERY_CHARS = 500;
    private static final int MAX_FILE_DIFF_HUNKS = 3;
    private static final Pattern REQUEST_MATCHERS = Pattern.compile(
            "requestMatchers\\s*\\(([^)]*)\\)", Pattern.CASE_INSENSITIVE);
    private static final Pattern QUOTED_VALUE = Pattern.compile("[\\\"']([^\\\"']+)[\\\"']");
    private static final Pattern SQL_KEYWORD = Pattern.compile(
            "\\b(select|insert|update|delete|merge|where|from|join)\\b", Pattern.CASE_INSENSITIVE);

    private final SemanticSymbolMapper symbolMapper;
    private final SemanticCallEdgeMapper edgeMapper;
    private final SecurityFlowMapper flowMapper;
    private final SemanticMethodChangeMapper methodChangeMapper;
    private final GitFileChangeMapper fileChangeMapper;
    private final AiProperties aiProperties;

    public ToolResult searchSymbols(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                ToolArguments arguments, int limit) {
        String symbol = arguments.string("symbol");
        String kind = arguments.string("kind");
        String annotation = arguments.string("annotation");
        String filePath = arguments.string("filePath");
        String endpoint = arguments.string("endpoint");
        if (symbol.isBlank() && kind.isBlank() && annotation.isBlank() && filePath.isBlank()
                && endpoint.isBlank()) {
            return ToolResult.empty("search_symbols 至少需要 symbol、kind、annotation、filePath 或 endpoint 参数之一。");
        }

        Map<Long, SemanticSymbol> metadata = symbolMapper.findByTaskId(taskId).stream()
                .filter(item -> item.getChunkId() != null)
                .collect(Collectors.toMap(SemanticSymbol::getChunkId, item -> item, (left, right) -> left));
        List<ScoredChunk> allMatches = chunks.stream()
                .filter(chunk -> matches(chunk, metadata.get(chunk.getId()), symbol, kind, annotation,
                        filePath, endpoint))
                .map(chunk -> new ScoredChunk(chunk, searchScore(chunk, metadata.get(chunk.getId()),
                        symbol, kind, annotation, filePath, endpoint)))
                .sorted(Comparator.comparingInt(ScoredChunk::score).reversed()
                        .thenComparing(item -> item.chunk().getFilePath())
                        .thenComparingInt(item -> item.chunk().getStartLine()))
                .toList();
        int offset = cursorOffset(arguments);
        if (offset >= allMatches.size()) {
            return ToolResult.empty("[SEARCH_RESULT] 没有更多满足结构化条件的代码符号。");
        }
        SerializedPage<ScoredChunk> page = serializePage(allMatches, offset, limit,
                "[SEARCH_RESULT][UNVERIFIED_CANDIDATE]", item -> formatChunkMetadata(item.chunk(),
                        "deterministicScore=" + item.score()));
        List<ScoredChunk> matches = page.items();

        Set<Long> candidates = matches.stream().map(ScoredChunk::chunk).map(CodeChunk::getId)
                .filter(id -> !id.equals(current.getId()))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return new ToolResult(ToolResult.Status.OK, page.text(), Set.of(current.getId()), candidates,
                page.truncated(), page.nextCursor());
    }

    // 在不可变任务源码块上执行受控文本搜索；结果只作为候选线索。
    public ToolResult searchCode(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                             ToolArguments arguments, int limit) {
        String query = arguments.string("query");
        if (query.isBlank()) return ToolResult.invalid("search_code 需要非空 query。");
        if (query.length() > MAX_SEARCH_QUERY_CHARS) {
            return ToolResult.invalid("search_code query 最长为 " + MAX_SEARCH_QUERY_CHARS + " 个字符。");
        }
        boolean caseSensitive = arguments.bool("caseSensitive", false);

        String scope = arguments.string("scope").toUpperCase(Locale.ROOT);
        if (scope.isBlank()) scope = "RELATED";
        if (!Set.of("CURRENT_FILE", "RELATED", "PROJECT").contains(scope)) {
            return ToolResult.invalid("search_code scope 只能是 CURRENT_FILE、RELATED 或 PROJECT。");
        }
        int depth = arguments.integer("depth", 2, 1, 5);
        Set<Long> related = "RELATED".equals(scope)
                ? reachableChunks(taskId, current.getId(), depth) : Set.of();
        String filePattern = arguments.string("filePattern");
        boolean includeTests = arguments.bool("includeTests", false);
        int contextLines = arguments.integer("contextLines", 2, 0, 5);
        String normalizedQuery = caseSensitive ? query : lower(query);
        String selectedScope = scope;
        List<CodeMatch> allMatches = new ArrayList<>();
        for (CodeChunk chunk : chunks) {
            if (!inSearchScope(chunk, current, selectedScope, related)) continue;
            if (!includeTests && isTestPath(chunk.getFilePath())) continue;
            if (!filePattern.isBlank() && !globMatches(chunk.getFilePath(), filePattern)) continue;
            String[] lines = chunk.getContent() == null ? new String[0] : chunk.getContent().split("\\R", -1);
            List<Integer> matchedIndexes = new ArrayList<>();
            for (int index = 0; index < lines.length; index++) {
                String line = lines[index];
                boolean matched = (caseSensitive ? line : lower(line)).contains(normalizedQuery);
                if (matched) matchedIndexes.add(index);
            }
            allMatches.addAll(mergeCodeMatches(chunk, matchedIndexes, contextLines, lines.length));
        }
        allMatches.sort(Comparator.comparing((CodeMatch match) -> match.chunk().getFilePath())
                .thenComparingInt(CodeMatch::lineNumber));
        int offset = cursorOffset(arguments);
        if (offset >= allMatches.size()) return ToolResult.empty("[CODE_SEARCH] 没有更多匹配结果。");
        String prefix = "[CODE_SEARCH][UNVERIFIED_CANDIDATE] scope=" + scope;
        SerializedPage<CodeMatch> page = serializePage(allMatches, offset, limit, prefix, CodeMatch::format);
        List<CodeMatch> matches = page.items();
        Set<Long> evidence = matches.stream().map(CodeMatch::chunk).map(CodeChunk::getId)
                .filter(current.getId()::equals)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<Long> candidates = matches.stream().map(CodeMatch::chunk).map(CodeChunk::getId)
                .filter(id -> !evidence.contains(id))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return new ToolResult(ToolResult.Status.OK, page.text(), evidence, candidates,
                page.truncated(), page.nextCursor());
    }

    public ToolResult exploreCallGraph(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                   ToolArguments arguments, int limit) {
        String direction = arguments.string("direction").toUpperCase(Locale.ROOT);
        if (direction.isBlank()) direction = "BOTH";
        if (!Set.of("CALLERS", "CALLEES", "BOTH").contains(direction)) {
            return ToolResult.invalid("explore_call_graph direction 只能是 CALLERS、CALLEES 或 BOTH。");
        }
        int depth = arguments.integer("depth", 2, 1, 3);
        Long targetId = arguments.longValue("targetChunkId");

        List<SemanticCallEdge> allEdges = edgeMapper.findByTaskId(taskId);
        Map<Long, List<GraphStep>> graph = directedGraph(allEdges, direction);
        List<GraphPath> paths = breadthFirstPaths(current.getId(), targetId, graph, depth, limit);
        if (paths.isEmpty()) {
            String target = targetId == null ? "" : "，目标代码块=" + targetId;
            return ToolResult.empty("[CALL_GRAPH] 在方向=" + direction + "、深度=" + depth + target
                    + " 的范围内没有找到 CodeGraph/框架关系路径。局部语义缺口=" + localSemanticGapCount(allEdges));
        }

        Set<Long> evidence = new LinkedHashSet<>();
        evidence.add(current.getId());
        paths.forEach(path -> path.steps().forEach(step -> evidence.add(step.to())));
        String body = paths.stream().map(this::formatPath).collect(Collectors.joining("\n\n"));
        return new ToolResult("[CALL_GRAPH] direction=" + direction + " depth=" + depth
                + " localSemanticGaps=" + localSemanticGapCount(allEdges) + "\n" + body, evidence, Set.of());
    }

    public ToolResult getChangeContext(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                   ToolArguments arguments, int limit) {
        String selector = arguments.string("selector");
        boolean includeConfiguration = arguments.bool("includeConfiguration", false);
        List<SemanticMethodChange> allMethodChanges = methodChangeMapper.findByTaskId(taskId);
        List<GitFileChange> allFileChanges = fileChangeMapper.findByTaskId(taskId);
        List<ChangeItem> items = new ArrayList<>();
        Set<String> itemKeys = new LinkedHashSet<>();

        if (selector.isBlank()) {
            addCurrentChangeSummaries(current, chunks, allMethodChanges, items, itemKeys, limit);
            if (items.isEmpty()) {
                allFileChanges.stream().filter(change -> fileChangeMatchesCurrent(change, current))
                        .sorted(fileChangeOrder()).forEach(change -> addChangeItem(items, itemKeys,
                                fileChangeKey(change), formatCurrentFileSummary(change), Set.of(), limit));
            }
            if (includeConfiguration) {
                allFileChanges.stream().filter(GitFileChange::isConfigurationChange)
                        .filter(change -> !fileChangeMatchesCurrent(change, current))
                        .sorted(fileChangeOrder()).forEach(change -> addChangeItem(items, itemKeys,
                                fileChangeKey(change), formatFileChangeIndex(change),
                                mapFileChangeChunks(change, chunks, current.getId()), limit));
            }
        } else {
            List<SemanticMethodChange> selectedMethods = allMethodChanges.stream()
                    .filter(change -> changeMatches(change, current, selector))
                    .sorted(methodChangeOrder()).toList();
            Set<String> methodCoveredPaths = new LinkedHashSet<>();
            for (SemanticMethodChange change : selectedMethods) {
                Set<Long> mappedIds = mapChangeChunks(change, chunks);
                boolean currentChange = mappedIds.contains(current.getId());
                Set<Long> candidates = mappedIds.stream().filter(id -> !id.equals(current.getId()))
                        .collect(Collectors.toCollection(LinkedHashSet::new));
                addChangeItem(items, itemKeys, methodChangeKey(change),
                        currentChange ? formatCurrentChangeSummary(change)
                                : formatRelatedMethodChange(change, mappedIds),
                        candidates, limit);
                methodCoveredPaths.add(normalizedChangePath(change));
            }
            allFileChanges.stream().filter(change -> fileChangeMatches(change, current, selector))
                    .filter(change -> !methodCoveredPaths.contains(normalizedFileChangePath(change)))
                    .sorted(fileChangeOrder()).forEach(change -> addChangeItem(items, itemKeys,
                            fileChangeKey(change), formatFileChangeDetail(change, selector),
                            mapFileChangeChunks(change, chunks, current.getId()), limit));
        }

        if (items.isEmpty()) {
            return ToolResult.empty("[CHANGE_CONTEXT] 当前目标没有直接方法级或文件级变化，可能仅由影响范围纳入。");
        }
        Set<Long> candidates = new LinkedHashSet<>();
        items.forEach(item -> candidates.addAll(item.candidateChunkIds()));
        candidates.remove(current.getId());
        return new ToolResult("[CHANGE_CONTEXT]\n" + items.stream().map(ChangeItem::text)
                .collect(Collectors.joining("\n\n")), Set.of(current.getId()), candidates);
    }

    public ToolResult resolveDataAccess(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                    ToolArguments arguments, int limit) {
        int depth = arguments.integer("depth", 3, 1, 5);
        String selector = arguments.string("selector");
        String discoverySelector = selector;
        Set<Long> reachable = reachableChunks(taskId, current.getId(), depth);
        reachable.add(current.getId());
        List<CodeChunk> connected = chunks.stream()
                .filter(chunk -> reachable.contains(chunk.getId()))
                .filter(this::isDataAccess)
                .filter(chunk -> selector.isBlank() || matchesAnyToken(searchable(chunk), selector))
                .limit(limit).toList();
        List<CodeChunk> discovered = connected.isEmpty() ? chunks.stream()
                .filter(this::isDataAccess)
                .filter(chunk -> discoverySelector.isBlank()
                        || matchesAnyToken(searchable(chunk), discoverySelector))
                .limit(limit).toList() : List.of();
        List<CodeChunk> results = connected.isEmpty() ? discovered : connected;
        if (results.isEmpty()) return ToolResult.empty("[DATA_ACCESS] 未找到与当前目标或选择条件关联的数据访问代码。");

        Set<Long> evidence = results.stream().filter(chunk -> reachable.contains(chunk.getId()))
                .map(CodeChunk::getId).collect(Collectors.toCollection(LinkedHashSet::new));
        evidence.add(current.getId());
        Set<Long> candidates = results.stream().map(CodeChunk::getId)
                .filter(id -> !evidence.contains(id)).collect(Collectors.toCollection(LinkedHashSet::new));
        String body = results.stream().map(this::formatDataAccess).collect(Collectors.joining("\n\n"));
        String evidenceLabel = connected.isEmpty() ? "[UNVERIFIED_CANDIDATE]" : "[SEMANTIC_EVIDENCE]";
        return new ToolResult("[DATA_ACCESS_ANALYSIS]" + evidenceLabel
                + " 仅报告确定性语法指标，不以单一指标直接判定漏洞。\n"
                + body, evidence, candidates);
    }

    public ToolResult inspectSecurityPolicy(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                        ToolArguments arguments, int limit) {
        String endpoint = arguments.string("endpoint");
        if (endpoint.isBlank()) endpoint = current.getEndpoint() == null ? "" : current.getEndpoint();
        String selectedEndpoint = endpoint;
        List<SemanticCallEdge> edges = edgeMapper.findByTaskId(taskId);
        List<PolicyAssessment> policies = chunks.stream().filter(this::hasSecurityPolicySignal)
                .filter(chunk -> !chunk.getId().equals(current.getId()))
                .map(chunk -> new PolicyAssessment(chunk,
                        !selectedEndpoint.isBlank() && matchesEndpointPolicy(selectedEndpoint, chunk.getContent()),
                        directlyRelated(edges, current.getId(), chunk.getId())))
                .sorted(Comparator.comparing(PolicyAssessment::verified, Comparator.reverseOrder())
                        .thenComparing(PolicyAssessment::endpointMatched, Comparator.reverseOrder())
                        .thenComparing(item -> item.chunk().getFilePath())
                        .thenComparingInt(item -> item.chunk().getStartLine()))
                .toList();
        Set<Long> evidence = new LinkedHashSet<>();
        evidence.add(current.getId());
        Set<Long> candidates = new LinkedHashSet<>();
        List<String> details = new ArrayList<>();
        if (hasMethodSecuritySignal(current)) {
            details.add(formatPolicy(current, "当前方法或类型上的安全注解", true));
        }
        for (PolicyAssessment policy : policies) {
            if (details.size() >= limit) break;
            if (policy.verified()) {
                evidence.add(policy.chunk().getId());
                details.add(formatPolicy(policy.chunk(), policy.endpointMatched()
                        ? "安全规则匹配 endpoint=" + endpoint
                        : "调用图直接关联的安全控制", true));
            } else {
                candidates.add(policy.chunk().getId());
                details.add(formatPolicy(policy.chunk(), "项目级安全配置候选，尚未证明适用于当前入口", false));
            }
        }
        candidates.removeAll(evidence);
        if (details.isEmpty()) {
            return new ToolResult("[SECURITY_POLICY] 未发现方法级或项目级安全策略；这不等于已证明入口无保护。",
                    evidence, Set.of());
        }
        return new ToolResult("[SECURITY_POLICY] endpoint=" + (endpoint.isBlank() ? "未知" : endpoint)
                + "。配置顺序和框架启用状态仍需结合 Recon 事实判断。\n"
                + String.join("\n\n", details), evidence, candidates);
    }

    public ToolResult traceValue(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                             ToolArguments arguments, int limit, VulnerabilityType vulnerabilityType) {
        String source = arguments.string("source");
        String sink = arguments.string("sink");
        String variable = arguments.string("variable");
        List<SecurityFlow> flows = flowMapper.findByTaskAndChunk(taskId, current.getId()).stream()
                .filter(flow -> vulnerabilityType == null || flow.getType() == vulnerabilityType)
                .filter(flow -> flowContains(flow, source, sink, variable))
                .limit(limit).toList();
        if (!flows.isEmpty()) {
            Set<Long> evidence = flows.stream().flatMap(flow -> parseIds(flow.getEvidenceChunkIds()).stream())
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            evidence.add(current.getId());
            String body = flows.stream().map(this::formatValueFlow).collect(Collectors.joining("\n\n"));
            return new ToolResult("[VALUE_TRACE][SEMANTIC_EVIDENCE]\n" + body, evidence, Set.of());
        }

        String token = firstNonBlank(variable, source, sink);
        int depth = arguments.integer("depth", 3, 1, 5);
        Set<Long> reachable = reachableChunks(taskId, current.getId(), depth);
        List<SemanticCallEdge> mappings = edgeMapper.findByTaskId(taskId).stream()
                .filter(edge -> reachable.contains(edge.getCallerChunkId())
                        && reachable.contains(edge.getCalleeChunkId()))
                .filter(this::reliable)
                .filter(edge -> token.isBlank() || matchesAnyToken(
                        lower(edge.getArgumentMapping() + " " + edge.getExpression()), token))
                .limit(limit).toList();
        if (mappings.isEmpty()) {
            return ToolResult.empty("[VALUE_TRACE] 没有找到满足变量、来源或终点条件的已解析数据流或参数映射。");
        }
        Set<Long> evidence = new LinkedHashSet<>();
        evidence.add(current.getId());
        mappings.forEach(edge -> {
            if (edge.getCallerChunkId() != null) evidence.add(edge.getCallerChunkId());
            if (edge.getCalleeChunkId() != null) evidence.add(edge.getCalleeChunkId());
        });
        Map<Long, CodeChunk> chunksById = chunks.stream().filter(chunk -> chunk.getId() != null)
                .collect(Collectors.toMap(CodeChunk::getId, chunk -> chunk, (left, right) -> left));
        String body = mappings.stream().map(edge -> formatArgumentMapping(
                edge, chunksById.get(edge.getCallerChunkId()))).collect(Collectors.joining("\n"));
        return new ToolResult("[VALUE_TRACE][ARGUMENT_MAPPING]\n" + body, evidence, Set.of());
    }

    private boolean matches(CodeChunk chunk, SemanticSymbol metadata, String symbol, String kind,
                            String annotation, String filePath, String endpoint) {
        if (!symbol.isBlank() && !contains(chunk.getSymbolName(), symbol)
                && (metadata == null || !contains(metadata.getQualifiedName() + " " + metadata.getSignature(), symbol))) {
            return false;
        }
        if (!kind.isBlank() && !contains(chunk.getChunkType(), kind)
                && (metadata == null || !contains(metadata.getKind(), kind))) return false;
        if (!annotation.isBlank() && !contains(chunk.getAnnotations(), annotation)) return false;
        if (!filePath.isBlank() && !contains(chunk.getFilePath(), filePath)) return false;
        if (!endpoint.isBlank() && !contains(chunk.getEndpoint(), endpoint)) return false;
        return true;
    }

    private int searchScore(CodeChunk chunk, SemanticSymbol metadata, String symbol, String kind,
                            String annotation, String filePath, String endpoint) {
        int score = 0;
        if (!symbol.isBlank()) score += equalsIgnoreCase(chunk.getSymbolName(), symbol) ? 40 : 20;
        if (!kind.isBlank()) score += 10;
        if (!annotation.isBlank()) score += 15;
        if (!filePath.isBlank()) score += equalsIgnoreCase(chunk.getFilePath(), filePath) ? 25 : 10;
        if (!endpoint.isBlank()) score += equalsIgnoreCase(chunk.getEndpoint(), endpoint) ? 30 : 15;
        if (metadata != null) score += 3;
        return score;
    }

    private Map<Long, List<GraphStep>> directedGraph(List<SemanticCallEdge> edges, String direction) {
        Map<Long, List<GraphStep>> graph = new LinkedHashMap<>();
        for (SemanticCallEdge edge : edges) {
            if (!reliable(edge) || edge.getCallerChunkId() == null || edge.getCalleeChunkId() == null) continue;
            if ("CALLEES".equals(direction) || "BOTH".equals(direction)) {
                graph.computeIfAbsent(edge.getCallerChunkId(), ignored -> new ArrayList<>())
                        .add(new GraphStep(edge.getCallerChunkId(), edge.getCalleeChunkId(), edge));
            }
            if ("CALLERS".equals(direction) || "BOTH".equals(direction)) {
                graph.computeIfAbsent(edge.getCalleeChunkId(), ignored -> new ArrayList<>())
                        .add(new GraphStep(edge.getCalleeChunkId(), edge.getCallerChunkId(), edge));
            }
        }
        return graph;
    }

    private List<GraphPath> breadthFirstPaths(Long start, Long target, Map<Long, List<GraphStep>> graph,
                                              int maxDepth, int limit) {
        ArrayDeque<GraphPath> queue = new ArrayDeque<>();
        queue.add(new GraphPath(start, List.of()));
        List<GraphPath> result = new ArrayList<>();
        while (!queue.isEmpty() && result.size() < limit) {
            GraphPath path = queue.removeFirst();
            if (path.steps().size() >= maxDepth) continue;
            for (GraphStep step : graph.getOrDefault(path.end(), List.of())) {
                if (path.contains(step.to())) continue;
                List<GraphStep> nextSteps = new ArrayList<>(path.steps());
                nextSteps.add(step);
                GraphPath next = new GraphPath(step.to(), List.copyOf(nextSteps));
                if (target == null || target.equals(step.to())) result.add(next);
                if (target != null && target.equals(step.to())) return result;
                queue.addLast(next);
                if (result.size() >= limit) break;
            }
        }
        return result;
    }

    private String formatPath(GraphPath path) {
        return "PATH depth=" + path.steps().size() + " " + path.steps().stream().map(step ->
                step.from() + " -[" + step.edge().getEdgeType() + "," + step.edge().getConfidence()
                        + ",line=" + step.edge().getCallSiteLine() + ",args="
                        + safe(step.edge().getArgumentMapping(), 300) + "]-> " + step.to())
                .collect(Collectors.joining(" | "));
    }

    private Set<Long> reachableChunks(UUID taskId, Long start, int depth) {
        Map<Long, List<GraphStep>> graph = directedGraph(edgeMapper.findByTaskId(taskId), "BOTH");
        Set<Long> result = new LinkedHashSet<>();
        result.add(start);
        ArrayDeque<NodeDepth> queue = new ArrayDeque<>();
        queue.add(new NodeDepth(start, 0));
        while (!queue.isEmpty()) {
            NodeDepth node = queue.removeFirst();
            if (node.depth() >= depth) continue;
            for (GraphStep step : graph.getOrDefault(node.id(), List.of())) {
                if (result.add(step.to())) queue.addLast(new NodeDepth(step.to(), node.depth() + 1));
            }
        }
        return result;
    }

    private boolean directlyRelated(List<SemanticCallEdge> edges, Long left, Long right) {
        return edges.stream().filter(this::reliable).anyMatch(edge ->
                left.equals(edge.getCallerChunkId()) && right.equals(edge.getCalleeChunkId())
                        || right.equals(edge.getCallerChunkId()) && left.equals(edge.getCalleeChunkId()));
    }

    private boolean reliable(SemanticCallEdge edge) {
        return edge.getConfidence() != Confidence.LOW;
    }

    // 统计已确认 CodeGraph 关系中未由局部 AST 唯一定位调用现场的数量。
    private long localSemanticGapCount(List<SemanticCallEdge> edges) {
        return edges.stream().filter(edge -> "CODEGRAPH_CALL".equals(edge.getEdgeType())
                && edge.getConfidence() == Confidence.MEDIUM).count();
    }

    private boolean changeMatches(SemanticMethodChange change, CodeChunk current, String selector) {
        String target = selector.isBlank() ? current.getFilePath() + " " + current.getSymbolName() : selector;
        String value = lower(change.getBasePath() + " " + change.getTargetPath() + " "
                + change.getBaseSymbol() + " " + change.getTargetSymbol() + " " + change.getMethodName());
        return List.of(lower(target).split("\\s+")).stream().filter(token -> !token.isBlank())
                .anyMatch(value::contains);
    }

    private boolean fileChangeMatches(GitFileChange change, CodeChunk current, String selector) {
        String target = selector.isBlank() ? current.getFilePath() : selector;
        String searchableChange = lower(change.getOldPath() + " " + change.getNewPath() + " "
                + change.getChangeType() + " " + change.getOldRanges() + " " + change.getNewRanges()
                + " " + change.getContextText());
        return contains(change.getOldPath(), target) || contains(change.getNewPath(), target)
                || matchesAnyToken(searchableChange, target);
    }

    private void addCurrentChangeSummaries(CodeChunk current, List<CodeChunk> chunks,
                                           List<SemanticMethodChange> changes,
                                           List<ChangeItem> items, Set<String> itemKeys, int limit) {
        changes.stream().filter(change -> mapChangeChunks(change, chunks).contains(current.getId()))
                .sorted(methodChangeOrder()).forEach(change -> addChangeItem(items, itemKeys,
                        methodChangeKey(change), formatCurrentChangeSummary(change), Set.of(), limit));
    }

    private void addChangeItem(List<ChangeItem> items, Set<String> itemKeys, String key,
                               String text, Set<Long> candidateChunkIds, int limit) {
        if (items.size() >= limit || !itemKeys.add(key)) return;
        items.add(new ChangeItem(text, Set.copyOf(candidateChunkIds)));
    }

    private Comparator<SemanticMethodChange> methodChangeOrder() {
        return Comparator.comparing(this::normalizedChangePath)
                .thenComparing(change -> change.getTargetStartLine() == null
                        ? Integer.MAX_VALUE : change.getTargetStartLine())
                .thenComparing(change -> safeValue(change.getMethodName()));
    }

    private Comparator<GitFileChange> fileChangeOrder() {
        return Comparator.comparing(this::normalizedFileChangePath)
                .thenComparing(change -> safeValue(change.getChangeType()));
    }

    private String methodChangeKey(SemanticMethodChange change) {
        return "METHOD|" + normalizedChangePath(change) + "|" + safeValue(change.getMethodName())
                + "|" + change.getBaseStartLine() + "|" + change.getTargetStartLine();
    }

    private String fileChangeKey(GitFileChange change) {
        return "FILE|" + normalizedFileChangePath(change) + "|" + safeValue(change.getChangeType());
    }

    private String normalizedChangePath(SemanticMethodChange change) {
        return lower(firstNonBlank(change.getTargetPath(), change.getBasePath())).replace('\\', '/');
    }

    private String normalizedFileChangePath(GitFileChange change) {
        return lower(firstNonBlank(change.getNewPath(), change.getOldPath())).replace('\\', '/');
    }

    private boolean fileChangeMatchesCurrent(GitFileChange change, CodeChunk current) {
        return samePath(change.getNewPath(), current.getFilePath())
                || samePath(change.getOldPath(), current.getFilePath());
    }

    private Set<Long> mapChangeChunks(SemanticMethodChange change, List<CodeChunk> chunks) {
        return chunks.stream().filter(chunk -> samePath(change.getTargetPath(), chunk.getFilePath())
                        || samePath(change.getBasePath(), chunk.getFilePath()))
                .filter(chunk -> overlaps(chunk.getStartLine(), chunk.getEndLine(), change.getTargetStartLine(),
                        change.getTargetEndLine()) || overlaps(chunk.getStartLine(), chunk.getEndLine(),
                        change.getBaseStartLine(), change.getBaseEndLine())
                        || contains(chunk.getSymbolName(), change.getMethodName()))
                .map(CodeChunk::getId).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private boolean overlaps(int start, int end, Integer otherStart, Integer otherEnd) {
        return otherStart != null && otherEnd != null && start <= otherEnd && otherStart <= end;
    }

    private Set<Long> mapFileChangeChunks(GitFileChange change, List<CodeChunk> chunks, Long currentId) {
        return chunks.stream().filter(chunk -> samePath(change.getNewPath(), chunk.getFilePath())
                        || samePath(change.getOldPath(), chunk.getFilePath()))
                .map(CodeChunk::getId).filter(id -> id != null && !id.equals(currentId))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private String formatCurrentChangeSummary(SemanticMethodChange change) {
        return "[CURRENT_CHANGE_SUMMARY] currentDiffProvidedInTarget=true kind=" + change.getChangeKind()
                + " method=" + change.getMethodName()
                + " base=" + change.getBasePath() + ":" + change.getBaseStartLine()
                + " target=" + change.getTargetPath() + ":" + change.getTargetStartLine()
                + " details=" + safe(change.getDetails(), 800)
                + "\n当前统一差异已经位于 target.codeExcerpt；如需调查其他变更，请使用 selector。";
    }

    private String formatCurrentFileSummary(GitFileChange change) {
        return "[CURRENT_FILE_CHANGE_SUMMARY] currentDiffProvidedInTarget=true type="
                + change.getChangeType() + " old=" + change.getOldPath()
                + " new=" + change.getNewPath() + " additions=" + change.getAdditions()
                + " deletions=" + change.getDeletions() + " configuration=" + change.isConfigurationChange()
                + " ranges=" + change.getOldRanges() + " -> " + change.getNewRanges()
                + "\n当前统一差异已经位于 target.codeExcerpt；如需查看其他文件，请使用 selector。";
    }

    private String formatRelatedMethodChange(SemanticMethodChange change, Set<Long> chunkIds) {
        int targetStartLine = change.getTargetStartLine() == null
                ? firstNonNull(change.getBaseStartLine(), 1) : change.getTargetStartLine();
        String diff = UnifiedChangeContext.render(change.getBaseContent(), change.getTargetContent(),
                change.getBaseStartLine(), targetStartLine, CHANGE_DIFF_CONTEXT_LINES,
                MAX_RELATED_CHANGE_CHARS, true);
        String metadata = "[RELATED_METHOD_CHANGE] CHUNK_IDS=" + chunkIds + " kind="
                + change.getChangeKind() + " method=" + change.getMethodName()
                + " base=" + change.getBasePath() + ":" + change.getBaseStartLine()
                + " target=" + change.getTargetPath() + ":" + change.getTargetStartLine()
                + " details=" + safe(change.getDetails(), 800);
        if (diff.isBlank()) return metadata + "\n[NO_TEXTUAL_CHANGE]";
        return metadata + "\n<UNTRUSTED_DIFF>\n" + diff + "\n</UNTRUSTED_DIFF>";
    }

    private String formatFileChangeIndex(GitFileChange change) {
        return "[FILE_CHANGE_INDEX] type=" + change.getChangeType() + " old=" + change.getOldPath()
                + " new=" + change.getNewPath() + " additions=" + change.getAdditions()
                + " deletions=" + change.getDeletions() + " configuration=" + change.isConfigurationChange()
                + " ranges=" + change.getOldRanges() + " -> " + change.getNewRanges()
                + "\n未返回文件差异；请使用 selector 指定需要查看的文件或变更关键词。";
    }

    private String formatFileChangeDetail(GitFileChange change, String selector) {
        DiffSelection selection = selectDiffHunks(change.getContextText(), selector, MAX_FILE_DIFF_HUNKS);
        String metadata = "[FILE_CHANGE] type=" + change.getChangeType() + " old=" + change.getOldPath()
                + " new=" + change.getNewPath() + " additions=" + change.getAdditions()
                + " deletions=" + change.getDeletions() + " configuration=" + change.isConfigurationChange()
                + " ranges=" + change.getOldRanges() + " -> " + change.getNewRanges()
                + " returnedHunks=" + selection.returnedHunks() + " totalHunks=" + selection.totalHunks();
        if (selection.text().isBlank()) return metadata + "\n[NO_TEXTUAL_CHANGE]";
        return metadata + "\n<UNTRUSTED_DIFF>\n" + selection.text() + "\n</UNTRUSTED_DIFF>"
                + (selection.returnedHunks() < selection.totalHunks()
                ? "\n[MORE_FILE_HUNKS] 请使用更具体的 selector 查询其余变化。" : "");
    }

    private DiffSelection selectDiffHunks(String contextText, String selector, int maxHunks) {
        if (contextText == null || contextText.isBlank()) return new DiffSelection("", 0, 0);
        List<String> hunks = java.util.Arrays.stream(contextText.strip().split("(?m)(?=^@@ )"))
                .map(String::strip).filter(value -> !value.isBlank()).toList();
        if (hunks.isEmpty()) return new DiffSelection("", 0, 0);
        List<String> ordered = new ArrayList<>(hunks);
        if (!selector.isBlank()) {
            ordered.sort(Comparator.comparing((String hunk) -> !matchesAnyToken(lower(hunk), selector)));
        }
        List<String> selected = ordered.stream().limit(maxHunks).toList();
        return new DiffSelection(String.join("\n\n", selected), selected.size(), hunks.size());
    }

    private int firstNonNull(Integer value, int fallback) {
        return value == null ? fallback : value;
    }

    private boolean isDataAccess(CodeChunk chunk) {
        String value = searchable(chunk);
        return value.contains("mybatis") || value.contains("mapper") || value.contains("repository")
                || value.contains("@query") || value.contains("select ") || value.contains("insert ")
                || value.contains("update ") || value.contains("delete ") || value.contains("jdbc")
                || value.contains("preparestatement") || value.contains("statement.execute")
                || value.contains("#{") || value.contains("${");
    }

    private String formatDataAccess(CodeChunk chunk) {
        String content = lower(chunk.getContent());
        List<String> indicators = new ArrayList<>();
        if (content.contains("${")) indicators.add("RAW_SUBSTITUTION_${}");
        if (content.contains("#{")) indicators.add("BOUND_PARAMETER_#{}");
        if (content.contains("preparestatement") || content.contains("namedparameterjdbctemplate")) {
            indicators.add("PARAMETERIZED_API");
        }
        if (content.contains("statement.execute") || content.matches("(?s).*(select|insert|update|delete).*[+].*")) {
            indicators.add("DYNAMIC_SQL_INDICATOR");
        }
        if (content.matches("(?s).*(tenant|owner|user_id|userid|account_id|accountid).*")) {
            indicators.add("OWNERSHIP_OR_TENANT_CONSTRAINT_INDICATOR");
        }
        if (indicators.isEmpty()) indicators.add("DATA_ACCESS_LOCATION");
        return formatMatchedChunk(chunk, "indicators=" + indicators,
                matchingLineIndexes(chunk, this::isDataAccessKeyLine));
    }

    private boolean hasSecurityPolicySignal(CodeChunk chunk) {
        String value = lower(chunk.getAnnotations() + " " + chunk.getContent());
        return value.contains("preauthorize") || value.contains("secured") || value.contains("rolesallowed")
                || value.contains("securityfilterchain") || value.contains("requestmatchers")
                || value.contains("authorizehttprequests") || value.contains("permitall")
                || value.contains("authenticated") || value.contains("access(")
                || value.contains("handlerinterceptor") || value.contains("addinterceptors")
                || value.contains("onceperrequestfilter") || value.contains("enablemethodsecurity");
    }

    private boolean hasMethodSecuritySignal(CodeChunk chunk) {
        String value = lower(chunk.getAnnotations() + " " + chunk.getContent());
        return value.contains("preauthorize") || value.contains("secured") || value.contains("rolesallowed");
    }

    private boolean matchesEndpointPolicy(String endpoint, String content) {
        Matcher matcher = REQUEST_MATCHERS.matcher(content == null ? "" : content);
        while (matcher.find()) {
            Matcher quoted = QUOTED_VALUE.matcher(matcher.group(1));
            while (quoted.find()) if (endpointMatches(endpoint, quoted.group(1))) return true;
        }
        return false;
    }

    private String formatPolicy(CodeChunk chunk, String relation, boolean verified) {
        String value = lower(chunk.getAnnotations() + " " + chunk.getContent());
        List<String> indicators = new ArrayList<>();
        if (value.contains("permitall")) indicators.add("PERMIT_ALL");
        if (value.contains("authenticated")) indicators.add("AUTHENTICATED");
        if (value.contains("hasrole") || value.contains("hasauthority")) indicators.add("ROLE_OR_AUTHORITY");
        if (value.contains("preauthorize") || value.contains("secured") || value.contains("rolesallowed")) {
            indicators.add("METHOD_SECURITY");
        }
        if (value.contains("enablemethodsecurity")) indicators.add("METHOD_SECURITY_ENABLED");
        return (verified ? "[VERIFIED_POLICY_RELATION] " : "[UNVERIFIED_CANDIDATE] ")
                + relation + " indicators=" + indicators + "\n"
                + formatMatchedChunk(chunk, relation,
                matchingLineIndexes(chunk, this::isSecurityPolicyKeyLine));
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
                } else regex.append(Pattern.quote(String.valueOf(current)));
            } else regex.append(Pattern.quote(String.valueOf(current)));
        }
        return endpoint.matches(regex.append('$').toString());
    }

    private boolean flowContains(SecurityFlow flow, String source, String sink, String variable) {
        if (!source.isBlank() && !contains(flow.getSourceDescription(), source)) return false;
        if (!sink.isBlank() && !contains(flow.getSinkDescription(), sink)) return false;
        if (!variable.isBlank()) {
            String value = lower(flow.getSourceDescription() + " " + flow.getSinkDescription() + " "
                    + flow.getPathText() + " " + flow.getGuardSummary());
            if (!matchesAnyToken(value, variable)) return false;
        }
        return true;
    }

    private String formatValueFlow(SecurityFlow flow) {
        return "[FLOW " + flow.getId() + "] type=" + flow.getType() + " confidence=" + flow.getConfidence()
                + " confirmedRelationEdges=" + flow.getConfirmedRelationEdges()
                + " localSemanticGaps=" + flow.getLocalSemanticGaps()
                + "\nsource=" + flow.getSourceDescription() + "\nsink=" + flow.getSinkDescription()
                + "\nguards=" + flow.getGuardSummary() + "\npath=" + flow.getPathText();
    }

    private String formatArgumentMapping(SemanticCallEdge edge, CodeChunk caller) {
        String header = "[ARGUMENT_MAPPING] " + edge.getCallerChunkId() + " -> " + edge.getCalleeChunkId()
                + " line=" + edge.getCallSiteLine() + " confidence=" + edge.getConfidence()
                + " mapping=" + safe(edge.getArgumentMapping(), 600);
        if (caller == null) {
            return header + "\n[KEY_STATEMENT_NOT_LOCATED] 调用方代码块不可用，请使用 read_source 精读证据代码块。";
        }
        return header + "\n" + formatMatchedChunk(caller, "调用现场",
                callSiteLineIndexes(caller, edge));
    }

    private List<CodeMatch> mergeCodeMatches(CodeChunk chunk, List<Integer> matchedIndexes,
                                             int contextLines, int totalLines) {
        if (matchedIndexes.isEmpty()) return List.of();
        List<CodeMatch> matches = new ArrayList<>();
        int windowStart = Math.max(0, matchedIndexes.get(0) - contextLines);
        int windowEnd = Math.min(totalLines - 1, matchedIndexes.get(0) + contextLines);
        List<Integer> windowMatches = new ArrayList<>(List.of(matchedIndexes.get(0)));
        for (int index = 1; index < matchedIndexes.size(); index++) {
            int matched = matchedIndexes.get(index);
            int nextStart = Math.max(0, matched - contextLines);
            int nextEnd = Math.min(totalLines - 1, matched + contextLines);
            if (nextStart <= windowEnd + 1) {
                windowEnd = Math.max(windowEnd, nextEnd);
                windowMatches.add(matched);
            } else {
                matches.add(new CodeMatch(chunk, windowStart, windowEnd, List.copyOf(windowMatches)));
                windowStart = nextStart;
                windowEnd = nextEnd;
                windowMatches = new ArrayList<>(List.of(matched));
            }
        }
        matches.add(new CodeMatch(chunk, windowStart, windowEnd, List.copyOf(windowMatches)));
        return matches;
    }

    private <T> SerializedPage<T> serializePage(List<T> allItems, int offset, int limit,
                                                String prefix, Function<T, String> formatter) {
        int textBudget = searchResultTextBudget();
        StringBuilder text = new StringBuilder(prefix);
        List<T> selected = new ArrayList<>();
        int index = offset;
        while (index < allItems.size() && selected.size() < limit) {
            T item = allItems.get(index);
            String separator = text.isEmpty() ? "" : "\n\n";
            int remaining = textBudget - text.length() - separator.length();
            if (remaining < 160 && !selected.isEmpty()) break;
            String formatted = limitSearchItem(formatter.apply(item), Math.max(1, remaining));
            text.append(separator).append(formatted);
            selected.add(item);
            index++;
            if (text.length() >= textBudget) break;
        }
        if (selected.isEmpty() && offset < allItems.size()) {
            T item = allItems.get(offset);
            String separator = text.isEmpty() ? "" : "\n\n";
            int remaining = Math.max(1, textBudget - text.length() - separator.length());
            text.append(separator).append(limitSearchItem(formatter.apply(item), remaining));
            selected.add(item);
            index = offset + 1;
        }
        boolean truncated = index < allItems.size();
        return new SerializedPage<>(List.copyOf(selected), text.toString(), truncated,
                truncated ? String.valueOf(index) : null);
    }

    private int searchResultTextBudget() {
        int observationChars = Math.max(500, aiProperties.getMaxObservationChars());
        int observationBudget = Math.max(160, observationChars - 700);
        return Math.min(ToolResult.MAX_TEXT_CHARS - 500, observationBudget);
    }

    private String limitSearchItem(String value, int maxChars) {
        String safe = value == null ? "" : value;
        if (safe.length() <= maxChars) return safe;
        String markerText = "[ITEM_TRUNCATED originalChars=" + safe.length()
                + " retainedChars=" + maxChars + " action=use_read_source]";
        String marker = "\n... " + markerText + " ...\n";
        if (marker.length() >= maxChars) return safe.substring(0, maxChars);
        int available = maxChars - marker.length();
        int headChars = available * 2 / 3;
        int tailChars = available - headChars;
        return safe.substring(0, headChars).stripTrailing() + marker
                + safe.substring(safe.length() - tailChars).stripLeading();
    }

    private int cursorOffset(ToolArguments arguments) {
        Long cursor = arguments.longValue("cursor");
        if (cursor == null || cursor < 0) return 0;
        return (int) Math.min(cursor, Integer.MAX_VALUE);
    }

    private boolean inSearchScope(CodeChunk chunk, CodeChunk current, String scope, Set<Long> related) {
        if ("PROJECT".equals(scope)) return true;
        if (samePath(chunk.getFilePath(), current.getFilePath())) return true;
        return "RELATED".equals(scope) && related.contains(chunk.getId());
    }

    private boolean isTestPath(String filePath) {
        String normalized = lower(filePath).replace('\\', '/');
        return normalized.contains("/src/test/") || normalized.startsWith("src/test/")
                || normalized.contains("/test/") || normalized.endsWith("test.java");
    }

    private boolean globMatches(String filePath, String glob) {
        String normalizedPath = filePath == null ? "" : filePath.replace('\\', '/');
        String normalizedGlob = glob.replace('\\', '/');
        StringBuilder regex = new StringBuilder("^");
        for (int index = 0; index < normalizedGlob.length(); index++) {
            char value = normalizedGlob.charAt(index);
            if (value == '*' && index + 1 < normalizedGlob.length()
                    && normalizedGlob.charAt(index + 1) == '*') {
                regex.append(".*");
                index++;
            } else if (value == '*') {
                regex.append("[^/]*");
            } else if (value == '?') {
                regex.append("[^/]");
            } else {
                regex.append(Pattern.quote(String.valueOf(value)));
            }
        }
        String expression = regex.append('$').toString();
        return Pattern.compile(expression, Pattern.CASE_INSENSITIVE).matcher(normalizedPath).matches()
                || !normalizedGlob.contains("/")
                && Pattern.compile(expression, Pattern.CASE_INSENSITIVE)
                .matcher(normalizedPath.substring(normalizedPath.lastIndexOf('/') + 1)).matches();
    }

    private Set<Long> parseIds(String value) {
        if (value == null || value.isBlank()) return Set.of();
        Set<Long> ids = new LinkedHashSet<>();
        for (String item : value.split(",")) {
            try {
                ids.add(Long.parseLong(item.strip()));
            } catch (NumberFormatException ignored) {
                // 忽略持久化数据中的无效 ID。
            }
        }
        return ids;
    }

    private String formatChunkMetadata(CodeChunk chunk, String reason) {
        return "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":" + chunk.getStartLine()
                + " | " + chunk.getSymbolName() + " | kind=" + chunk.getChunkType()
                + " | endpoint=" + safeValue(chunk.getEndpoint())
                + " | parameters=" + safeValue(chunk.getParameters())
                + " | annotations=" + safeValue(chunk.getAnnotations()) + " | " + reason;
    }

    private String formatMatchedChunk(CodeChunk chunk, String reason, List<Integer> matchedIndexes) {
        String metadata = formatChunkMetadata(chunk, reason);
        String[] lines = sourceLines(chunk);
        if (matchedIndexes.isEmpty() || lines.length == 0) {
            return metadata + "\n[KEY_STATEMENT_NOT_LOCATED] 请使用 read_source 精读该代码块。";
        }

        boolean[] matched = new boolean[lines.length];
        boolean[] included = new boolean[lines.length];
        for (int matchedIndex : matchedIndexes) {
            if (matchedIndex < 0 || matchedIndex >= lines.length) continue;
            matched[matchedIndex] = true;
            int first = Math.max(0, matchedIndex - KEY_STATEMENT_CONTEXT_LINES);
            int last = Math.min(lines.length - 1, matchedIndex + KEY_STATEMENT_CONTEXT_LINES);
            for (int index = first; index <= last; index++) included[index] = true;
        }

        StringBuilder source = new StringBuilder();
        int previous = -1;
        int firstLine = Math.max(1, chunk.getStartLine());
        for (int index = 0; index < lines.length; index++) {
            if (!included[index]) continue;
            if (previous >= 0 && index > previous + 1) source.append("    ...\n");
            source.append(matched[index] ? ">>> " : "    ")
                    .append(String.format(Locale.ROOT, "%5d | ", firstLine + index))
                    .append(lines[index]).append('\n');
            previous = index;
        }
        return metadata + "\n<UNTRUSTED_CODE>\n" + source.toString().stripTrailing()
                + "\n</UNTRUSTED_CODE>";
    }

    private List<Integer> matchingLineIndexes(CodeChunk chunk, Predicate<String> predicate) {
        String[] lines = sourceLines(chunk);
        List<Integer> indexes = new ArrayList<>();
        for (int index = 0; index < lines.length; index++) {
            if (predicate.test(lines[index])) indexes.add(index);
        }
        return indexes;
    }

    private List<Integer> callSiteLineIndexes(CodeChunk chunk, SemanticCallEdge edge) {
        String[] lines = sourceLines(chunk);
        int index = edge.getCallSiteLine() - Math.max(1, chunk.getStartLine());
        if (index >= 0 && index < lines.length) return List.of(index);
        String expression = safeValue(edge.getExpression()).strip();
        if (expression.isEmpty()) return List.of();
        for (int current = 0; current < lines.length; current++) {
            if (lines[current].contains(expression)) return List.of(current);
        }
        return List.of();
    }

    private String[] sourceLines(CodeChunk chunk) {
        return chunk.getContent() == null || chunk.getContent().isEmpty()
                ? new String[0] : chunk.getContent().split("\\R", -1);
    }

    private boolean isDataAccessKeyLine(String line) {
        String value = lower(line);
        return value.contains("${") || value.contains("#{") || value.contains("@query")
                || value.contains("preparestatement") || value.contains("namedparameterjdbctemplate")
                || value.contains("jdbctemplate") || value.contains("statement.execute")
                || value.contains("executequery") || value.contains("executeupdate")
                || value.contains("mapper") || value.contains("repository") || value.contains("dao")
                || value.contains("tenant") || value.contains("owner") || value.contains("user_id")
                || value.contains("userid") || value.contains("account_id") || value.contains("accountid")
                || SQL_KEYWORD.matcher(value).find();
    }

    private boolean isSecurityPolicyKeyLine(String line) {
        String value = lower(line);
        return value.contains("preauthorize") || value.contains("secured") || value.contains("rolesallowed")
                || value.contains("securityfilterchain") || value.contains("requestmatchers")
                || value.contains("authorizehttprequests") || value.contains("permitall")
                || value.contains("authenticated") || value.contains("hasrole")
                || value.contains("hasauthority") || value.contains("access(")
                || value.contains("handlerinterceptor") || value.contains("addinterceptors")
                || value.contains("onceperrequestfilter") || value.contains("enablemethodsecurity");
    }

    private String safeValue(String value) {
        return value == null ? "" : value;
    }

    private String searchable(CodeChunk chunk) {
        return lower(chunk.getFilePath() + " " + chunk.getSymbolName() + " " + chunk.getEndpoint() + " "
                + chunk.getChunkType() + " " + chunk.getParameters() + " " + chunk.getAnnotations() + " "
                + chunk.getCalledSymbols() + " " + chunk.getContent());
    }

    private String firstNonBlank(String... values) {
        for (String value : values) if (value != null && !value.isBlank()) return value;
        return "";
    }

    private boolean matchesAnyToken(String haystack, String query) {
        return java.util.Arrays.stream(lower(query).split("[^a-z0-9_$#{}./-]+"))
                .map(String::strip).filter(token -> token.length() >= 2).anyMatch(haystack::contains);
    }

    private boolean contains(String value, String expected) {
        return !expected.isBlank() && lower(value).contains(lower(expected));
    }

    private boolean equalsIgnoreCase(String left, String right) {
        return left != null && right != null && left.equalsIgnoreCase(right);
    }

    private boolean samePath(String left, String right) {
        return left != null && right != null && left.replace('\\', '/').equalsIgnoreCase(right.replace('\\', '/'));
    }

    private String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private String safe(String value, int maxChars) {
        if (value == null) return "";
        return value.substring(0, Math.min(value.length(), maxChars));
    }

    private record ScoredChunk(CodeChunk chunk, int score) {}
    private record SerializedPage<T>(List<T> items, String text, boolean truncated, String nextCursor) {}
    private record PolicyAssessment(CodeChunk chunk, boolean endpointMatched, boolean directCall) {
        boolean verified() {
            return endpointMatched || directCall;
        }
    }
    private record ChangeItem(String text, Set<Long> candidateChunkIds) {}
    private record DiffSelection(String text, int returnedHunks, int totalHunks) {}
    private record CodeMatch(CodeChunk chunk, int firstIndex, int lastIndex, List<Integer> matchedIndexes) {
        int lineNumber() {
            return Math.max(1, chunk.getStartLine()) + matchedIndexes.get(0);
        }

        String format() {
            String[] lines = chunk.getContent() == null ? new String[0] : chunk.getContent().split("\\R", -1);
            StringBuilder source = new StringBuilder();
            for (int index = firstIndex; index <= lastIndex; index++) {
                source.append(matchedIndexes.contains(index) ? ">>> " : "    ")
                        .append(String.format(Locale.ROOT, "%5d | ",
                                Math.max(1, chunk.getStartLine()) + index))
                        .append(lines[index]).append('\n');
            }
            return "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":"
                    + lineNumber() + " | " + chunk.getSymbolName()
                    + "\n<UNTRUSTED_CODE>\n" + source.toString().stripTrailing()
                    + "\n</UNTRUSTED_CODE>";
        }
    }
    private record GraphStep(Long from, Long to, SemanticCallEdge edge) {}
    private record GraphPath(Long end, List<GraphStep> steps) {
        boolean contains(Long chunkId) {
            if (end.equals(chunkId)) return true;
            return steps.stream().anyMatch(step -> step.from().equals(chunkId));
        }
    }
    private record NodeDepth(Long id, int depth) {}
}
