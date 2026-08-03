package com.deepaudit.agent;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.SemanticSymbol;
import com.deepaudit.domain.VulnerabilityType;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

// 负责 ProfessionalToolService 对应的业务编排和处理。
@Service
@RequiredArgsConstructor
public class ProfessionalToolService {
    private static final Pattern REQUEST_MATCHERS = Pattern.compile(
            "requestMatchers\\s*\\(([^)]*)\\)", Pattern.CASE_INSENSITIVE);
    private static final Pattern QUOTED_VALUE = Pattern.compile("[\\\"']([^\\\"']+)[\\\"']");

    private final SemanticSymbolMapper symbolMapper;
    private final SemanticCallEdgeMapper edgeMapper;
    private final SecurityFlowMapper flowMapper;
    private final SemanticMethodChangeMapper methodChangeMapper;
    private final GitFileChangeMapper fileChangeMapper;

    // 查询并返回 searchSymbols 对应的数据。
    public ToolResult searchSymbols(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                ToolArguments arguments, int limit) {
        String symbol = arguments.string("symbol");
        String kind = arguments.string("kind");
        String annotation = arguments.string("annotation");
        String filePath = arguments.string("filePath");
        String endpoint = arguments.string("endpoint");
        String text = arguments.string("text");
        if (symbol.isBlank() && kind.isBlank() && annotation.isBlank() && filePath.isBlank()
                && endpoint.isBlank() && text.isBlank()) {
            return ToolResult.empty("search_symbols 至少需要 symbol、kind、annotation、filePath、endpoint 或 text 参数之一。");
        }

        Map<Long, SemanticSymbol> metadata = symbolMapper.findByTaskId(taskId).stream()
                .filter(item -> item.getChunkId() != null)
                .collect(Collectors.toMap(SemanticSymbol::getChunkId, item -> item, (left, right) -> left));
        List<ScoredChunk> allMatches = chunks.stream()
                .filter(chunk -> matches(chunk, metadata.get(chunk.getId()), symbol, kind, annotation,
                        filePath, endpoint, text))
                .map(chunk -> new ScoredChunk(chunk, searchScore(chunk, metadata.get(chunk.getId()),
                        symbol, kind, annotation, filePath, endpoint, text)))
                .sorted(Comparator.comparingInt(ScoredChunk::score).reversed()
                        .thenComparing(item -> item.chunk().getFilePath())
                        .thenComparingInt(item -> item.chunk().getStartLine()))
                .toList();
        int offset = cursorOffset(arguments);
        if (offset >= allMatches.size()) {
            return ToolResult.empty("[SEARCH_RESULT] 没有更多满足结构化条件的代码符号。");
        }
        List<ScoredChunk> matches = allMatches.stream().skip(offset).limit(limit).toList();
        if (matches.isEmpty()) return ToolResult.empty("[SEARCH_RESULT] 没有找到满足结构化条件的代码符号。");

        Set<Long> candidates = matches.stream().map(ScoredChunk::chunk).map(CodeChunk::getId)
                .filter(id -> !id.equals(current.getId()))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        String body = matches.stream().map(item -> formatChunk(item.chunk(),
                        "deterministicScore=" + item.score(), 1_600))
                .collect(Collectors.joining("\n\n"));
        boolean truncated = offset + matches.size() < allMatches.size();
        String nextCursor = truncated ? String.valueOf(offset + matches.size()) : null;
        return new ToolResult(ToolResult.Status.OK, "[SEARCH_RESULT][UNVERIFIED_CANDIDATE]\n" + body,
                Set.of(current.getId()), candidates, truncated, nextCursor);
    }

    // 在不可变任务源码块上执行受控文本搜索；结果只作为候选线索。
    public ToolResult searchCode(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                             ToolArguments arguments, int limit) {
        String query = arguments.string("query");
        if (query.isBlank()) return ToolResult.invalid("search_code 需要非空 query。");
        if (query.length() > 200) return ToolResult.invalid("search_code query 最长为 200 个字符。");
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
            for (int index = 0; index < lines.length; index++) {
                String line = lines[index];
                boolean matched = (caseSensitive ? line : lower(line)).contains(normalizedQuery);
                if (matched) {
                    allMatches.add(new CodeMatch(chunk, index, contextLines));
                }
            }
        }
        allMatches.sort(Comparator.comparing((CodeMatch match) -> match.chunk().getFilePath())
                .thenComparingInt(CodeMatch::lineNumber));
        int offset = cursorOffset(arguments);
        if (offset >= allMatches.size()) return ToolResult.empty("[CODE_SEARCH] 没有更多匹配结果。");
        List<CodeMatch> matches = allMatches.stream().skip(offset).limit(limit).toList();
        if (matches.isEmpty()) return ToolResult.empty("[CODE_SEARCH] 没有找到匹配源码。");
        Set<Long> evidence = matches.stream().map(CodeMatch::chunk).map(CodeChunk::getId)
                .filter(current.getId()::equals)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<Long> candidates = matches.stream().map(CodeMatch::chunk).map(CodeChunk::getId)
                .filter(id -> !evidence.contains(id))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        String body = matches.stream().map(CodeMatch::format).collect(Collectors.joining("\n\n"));
        boolean truncated = offset + matches.size() < allMatches.size();
        String nextCursor = truncated ? String.valueOf(offset + matches.size()) : null;
        return new ToolResult(ToolResult.Status.OK, "[CODE_SEARCH][UNVERIFIED_CANDIDATE] scope="
                + scope + "\n" + body, evidence, candidates, truncated, nextCursor);
    }

    // 执行 ProfessionalToolService 中的 exploreCallGraph 处理。
    public ToolResult exploreCallGraph(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                   ToolArguments arguments, int limit) {
        String direction = arguments.string("direction").toUpperCase(Locale.ROOT);
        if (!Set.of("CALLERS", "CALLEES", "BOTH").contains(direction)) direction = "BOTH";
        int depth = arguments.integer("depth", 3, 1, 5);
        Long targetId = arguments.longValue("targetChunkId");
        String targetSymbol = arguments.string("targetSymbol");
        if (targetId == null && !targetSymbol.isBlank()) {
            targetId = chunks.stream().filter(chunk -> contains(chunk.getSymbolName(), targetSymbol))
                    .map(CodeChunk::getId).findFirst().orElse(null);
        }

        List<SemanticCallEdge> allEdges = edgeMapper.findByTaskId(taskId);
        Map<Long, List<GraphStep>> graph = directedGraph(allEdges, direction);
        List<GraphPath> paths = breadthFirstPaths(current.getId(), targetId, graph, depth, limit);
        if (paths.isEmpty()) {
            String target = targetId == null ? "" : "，目标代码块=" + targetId;
            return ToolResult.empty("[CALL_GRAPH] 在方向=" + direction + "、深度=" + depth + target
                    + " 的范围内没有找到高/中可信调用路径。未解析边=" + unresolvedCount(allEdges));
        }

        Set<Long> evidence = new LinkedHashSet<>();
        evidence.add(current.getId());
        paths.forEach(path -> path.steps().forEach(step -> evidence.add(step.to())));
        String body = paths.stream().map(this::formatPath).collect(Collectors.joining("\n\n"));
        return new ToolResult("[CALL_GRAPH] direction=" + direction + " depth=" + depth
                + " unresolvedEdges=" + unresolvedCount(allEdges) + "\n" + body, evidence, Set.of());
    }

    // 读取并返回 getChangeContext 对应的信息。
    public ToolResult getChangeContext(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                   ToolArguments arguments, int limit) {
        String selector = arguments.string("selector");
        boolean includeConfiguration = arguments.bool("includeConfiguration", true);
        List<SemanticMethodChange> methodChanges = methodChangeMapper.findByTaskId(taskId).stream()
                .filter(change -> changeMatches(change, current, selector))
                .limit(limit).toList();
        List<GitFileChange> fileChanges = fileChangeMapper.findByTaskId(taskId).stream()
                .filter(change -> fileChangeMatches(change, current, selector)
                        || includeConfiguration && change.isConfigurationChange())
                .limit(limit).toList();
        if (methodChanges.isEmpty() && fileChanges.isEmpty()) {
            return ToolResult.empty("[CHANGE_CONTEXT] 当前目标没有方法级或文件级增量变更记录，可能是全量审计任务。");
        }

        Set<Long> evidence = new LinkedHashSet<>();
        evidence.add(current.getId());
        Set<Long> candidates = new LinkedHashSet<>();
        for (SemanticMethodChange change : methodChanges) {
            mapChangeChunks(change, chunks).forEach(id -> {
                if (samePath(change.getTargetPath(), current.getFilePath())
                        || samePath(change.getBasePath(), current.getFilePath())) evidence.add(id);
                else candidates.add(id);
            });
        }
        for (GitFileChange change : fileChanges) {
            chunks.stream().filter(chunk -> samePath(change.getNewPath(), chunk.getFilePath())
                            || samePath(change.getOldPath(), chunk.getFilePath()))
                    .map(CodeChunk::getId).forEach(id -> {
                        if (samePath(change.getNewPath(), current.getFilePath())
                                || samePath(change.getOldPath(), current.getFilePath())) evidence.add(id);
                        else candidates.add(id);
                    });
        }
        candidates.removeAll(evidence);

        String methods = methodChanges.stream().map(this::formatMethodChange).collect(Collectors.joining("\n\n"));
        String files = fileChanges.stream().map(this::formatFileChange).collect(Collectors.joining("\n\n"));
        return new ToolResult("[CHANGE_CONTEXT]\n" + methods
                + (methods.isBlank() || files.isBlank() ? "" : "\n\n") + files, evidence, candidates);
    }

    // 解析并确定 resolveDataAccess 对应的目标。
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

    // 分析并提取 inspectSecurityPolicy 对应的事实。
    public ToolResult inspectSecurityPolicy(UUID taskId, CodeChunk current, List<CodeChunk> chunks,
                                        ToolArguments arguments, int limit) {
        String endpoint = arguments.string("endpoint");
        if (endpoint.isBlank()) endpoint = current.getEndpoint() == null ? "" : current.getEndpoint();
        List<CodeChunk> policies = chunks.stream().filter(this::hasSecurityPolicySignal)
                .sorted(Comparator.comparing((CodeChunk chunk) -> !chunk.getId().equals(current.getId()))
                        .thenComparing(CodeChunk::getFilePath).thenComparingInt(CodeChunk::getStartLine))
                .limit(Math.max(limit * 3L, limit)).toList();
        Set<Long> evidence = new LinkedHashSet<>();
        evidence.add(current.getId());
        Set<Long> candidates = new LinkedHashSet<>();
        List<String> details = new ArrayList<>();
        if (hasMethodSecuritySignal(current)) {
            details.add(formatPolicy(current, "当前方法或类型上的安全注解", true));
        }
        for (CodeChunk policy : policies) {
            if (policy.getId().equals(current.getId())) continue;
            boolean endpointMatched = !endpoint.isBlank() && matchesEndpointPolicy(endpoint, policy.getContent());
            boolean directCall = directlyRelated(taskId, current.getId(), policy.getId());
            if (endpointMatched || directCall) {
                evidence.add(policy.getId());
                details.add(formatPolicy(policy, endpointMatched ? "安全规则匹配 endpoint=" + endpoint
                        : "调用图直接关联的安全控制", true));
            } else if (candidates.size() < limit) {
                candidates.add(policy.getId());
                details.add(formatPolicy(policy, "项目级安全配置候选，尚未证明适用于当前入口", false));
            }
            if (details.size() >= limit) break;
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

    // 执行 ProfessionalToolService 中的 traceValue 处理。
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
        String body = mappings.stream().map(this::formatArgumentMapping).collect(Collectors.joining("\n"));
        return new ToolResult("[VALUE_TRACE][ARGUMENT_MAPPING]\n" + body, evidence, Set.of());
    }

    // 判断是否满足 matches 对应的条件。
    private boolean matches(CodeChunk chunk, SemanticSymbol metadata, String symbol, String kind,
                            String annotation, String filePath, String endpoint, String text) {
        if (!symbol.isBlank() && !contains(chunk.getSymbolName(), symbol)
                && (metadata == null || !contains(metadata.getQualifiedName() + " " + metadata.getSignature(), symbol))) {
            return false;
        }
        if (!kind.isBlank() && !contains(chunk.getChunkType(), kind)
                && (metadata == null || !contains(metadata.getKind(), kind))) return false;
        if (!annotation.isBlank() && !contains(chunk.getAnnotations(), annotation)) return false;
        if (!filePath.isBlank() && !contains(chunk.getFilePath(), filePath)) return false;
        if (!endpoint.isBlank() && !contains(chunk.getEndpoint(), endpoint)) return false;
        if (!text.isBlank()) {
            String haystack = searchable(chunk);
            boolean found = java.util.Arrays.stream(lower(text).split("\\s+"))
                    .filter(token -> !token.isBlank()).allMatch(haystack::contains);
            if (!found) return false;
        }
        return true;
    }

    // 查询并返回 searchScore 对应的数据。
    private int searchScore(CodeChunk chunk, SemanticSymbol metadata, String symbol, String kind,
                            String annotation, String filePath, String endpoint, String text) {
        int score = 0;
        if (!symbol.isBlank()) score += equalsIgnoreCase(chunk.getSymbolName(), symbol) ? 40 : 20;
        if (!kind.isBlank()) score += 10;
        if (!annotation.isBlank()) score += 15;
        if (!filePath.isBlank()) score += equalsIgnoreCase(chunk.getFilePath(), filePath) ? 25 : 10;
        if (!endpoint.isBlank()) score += equalsIgnoreCase(chunk.getEndpoint(), endpoint) ? 30 : 15;
        if (!text.isBlank()) score += Math.min(20, lower(text).split("\\s+").length * 4);
        if (metadata != null) score += 3;
        return score;
    }

    // 执行 ProfessionalToolService 中的 directedGraph 处理。
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

    // 执行 ProfessionalToolService 中的 breadthFirstPaths 处理。
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

    // 格式化并输出 formatPath 对应的展示内容。
    private String formatPath(GraphPath path) {
        return "PATH depth=" + path.steps().size() + " " + path.steps().stream().map(step ->
                step.from() + " -[" + step.edge().getEdgeType() + "," + step.edge().getConfidence()
                        + ",line=" + step.edge().getCallSiteLine() + ",args="
                        + safe(step.edge().getArgumentMapping(), 300) + "]-> " + step.to())
                .collect(Collectors.joining(" | "));
    }

    // 执行 ProfessionalToolService 中的 reachableChunks 处理。
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

    // 执行 ProfessionalToolService 中的 directlyRelated 处理。
    private boolean directlyRelated(UUID taskId, Long left, Long right) {
        return edgeMapper.findByTaskId(taskId).stream().filter(this::reliable).anyMatch(edge ->
                left.equals(edge.getCallerChunkId()) && right.equals(edge.getCalleeChunkId())
                        || right.equals(edge.getCallerChunkId()) && left.equals(edge.getCalleeChunkId()));
    }

    // 执行 ProfessionalToolService 中的 reliable 处理。
    private boolean reliable(SemanticCallEdge edge) {
        return edge.getConfidence() != Confidence.LOW && !"UNRESOLVED".equals(edge.getEdgeType());
    }

    // 执行 ProfessionalToolService 中的 unresolvedCount 处理。
    private long unresolvedCount(List<SemanticCallEdge> edges) {
        return edges.stream().filter(edge -> edge.getCalleeChunkId() == null
                || "UNRESOLVED".equals(edge.getEdgeType())).count();
    }

    // 执行 ProfessionalToolService 中的 changeMatches 处理。
    private boolean changeMatches(SemanticMethodChange change, CodeChunk current, String selector) {
        String target = selector.isBlank() ? current.getFilePath() + " " + current.getSymbolName() : selector;
        String value = lower(change.getBasePath() + " " + change.getTargetPath() + " "
                + change.getBaseSymbol() + " " + change.getTargetSymbol() + " " + change.getMethodName());
        return List.of(lower(target).split("\\s+")).stream().filter(token -> !token.isBlank())
                .anyMatch(value::contains);
    }

    // 执行 ProfessionalToolService 中的 fileChangeMatches 处理。
    private boolean fileChangeMatches(GitFileChange change, CodeChunk current, String selector) {
        String target = selector.isBlank() ? current.getFilePath() : selector;
        return contains(change.getOldPath(), target) || contains(change.getNewPath(), target);
    }

    // 转换并返回 mapChangeChunks 对应的数据表示。
    private Set<Long> mapChangeChunks(SemanticMethodChange change, List<CodeChunk> chunks) {
        return chunks.stream().filter(chunk -> samePath(change.getTargetPath(), chunk.getFilePath())
                        || samePath(change.getBasePath(), chunk.getFilePath()))
                .filter(chunk -> overlaps(chunk.getStartLine(), chunk.getEndLine(), change.getTargetStartLine(),
                        change.getTargetEndLine()) || overlaps(chunk.getStartLine(), chunk.getEndLine(),
                        change.getBaseStartLine(), change.getBaseEndLine())
                        || contains(chunk.getSymbolName(), change.getMethodName()))
                .map(CodeChunk::getId).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    // 执行 ProfessionalToolService 中的 overlaps 处理。
    private boolean overlaps(int start, int end, Integer otherStart, Integer otherEnd) {
        return otherStart != null && otherEnd != null && start <= otherEnd && otherStart <= end;
    }

    // 格式化并输出 formatMethodChange 对应的展示内容。
    private String formatMethodChange(SemanticMethodChange change) {
        return "[METHOD_CHANGE] kind=" + change.getChangeKind() + " method=" + change.getMethodName()
                + " base=" + change.getBasePath() + ":" + change.getBaseStartLine()
                + " target=" + change.getTargetPath() + ":" + change.getTargetStartLine()
                + " details=" + safe(change.getDetails(), 800)
                + "\n<UNTRUSTED_CODE_BASE>\n" + safe(change.getBaseContent(), 1_200)
                + "\n</UNTRUSTED_CODE_BASE>\n<UNTRUSTED_CODE_TARGET>\n"
                + safe(change.getTargetContent(), 1_200) + "\n</UNTRUSTED_CODE_TARGET>";
    }

    // 格式化并输出 formatFileChange 对应的展示内容。
    private String formatFileChange(GitFileChange change) {
        return "[FILE_CHANGE] type=" + change.getChangeType() + " old=" + change.getOldPath()
                + " new=" + change.getNewPath() + " additions=" + change.getAdditions()
                + " deletions=" + change.getDeletions() + " configuration=" + change.isConfigurationChange()
                + " ranges=" + change.getOldRanges() + " -> " + change.getNewRanges()
                + "\n<UNTRUSTED_DIFF>\n" + safe(change.getContextText(), 1_600) + "\n</UNTRUSTED_DIFF>";
    }

    // 判断是否满足 isDataAccess 对应的条件。
    private boolean isDataAccess(CodeChunk chunk) {
        String value = searchable(chunk);
        return value.contains("mybatis") || value.contains("mapper") || value.contains("repository")
                || value.contains("@query") || value.contains("select ") || value.contains("insert ")
                || value.contains("update ") || value.contains("delete ") || value.contains("jdbc")
                || value.contains("preparestatement") || value.contains("statement.execute")
                || value.contains("#{") || value.contains("${");
    }

    // 格式化并输出 formatDataAccess 对应的展示内容。
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
        return formatChunk(chunk, "indicators=" + indicators, 2_000);
    }

    // 判断是否满足 hasSecurityPolicySignal 对应的条件。
    private boolean hasSecurityPolicySignal(CodeChunk chunk) {
        String value = lower(chunk.getAnnotations() + " " + chunk.getContent());
        return value.contains("preauthorize") || value.contains("secured") || value.contains("rolesallowed")
                || value.contains("securityfilterchain") || value.contains("requestmatchers")
                || value.contains("authorizehttprequests") || value.contains("permitall")
                || value.contains("authenticated") || value.contains("access(")
                || value.contains("handlerinterceptor") || value.contains("addinterceptors")
                || value.contains("onceperrequestfilter") || value.contains("enablemethodsecurity");
    }

    // 判断是否满足 hasMethodSecuritySignal 对应的条件。
    private boolean hasMethodSecuritySignal(CodeChunk chunk) {
        String value = lower(chunk.getAnnotations() + " " + chunk.getContent());
        return value.contains("preauthorize") || value.contains("secured") || value.contains("rolesallowed");
    }

    // 判断是否满足 matchesEndpointPolicy 对应的条件。
    private boolean matchesEndpointPolicy(String endpoint, String content) {
        Matcher matcher = REQUEST_MATCHERS.matcher(content == null ? "" : content);
        while (matcher.find()) {
            Matcher quoted = QUOTED_VALUE.matcher(matcher.group(1));
            while (quoted.find()) if (endpointMatches(endpoint, quoted.group(1))) return true;
        }
        return false;
    }

    // 格式化并输出 formatPolicy 对应的展示内容。
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
                + relation + " indicators=" + indicators + "\n" + formatChunk(chunk, relation, 1_600);
    }

    // 执行 ProfessionalToolService 中的 endpointMatches 处理。
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

    // 执行 ProfessionalToolService 中的 flowContains 处理。
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

    // 格式化并输出 formatValueFlow 对应的展示内容。
    private String formatValueFlow(SecurityFlow flow) {
        return "[FLOW " + flow.getId() + "] type=" + flow.getType() + " confidence=" + flow.getConfidence()
                + " resolvedEdges=" + flow.getResolvedEdges() + " unresolvedEdges=" + flow.getUnresolvedEdges()
                + "\nsource=" + flow.getSourceDescription() + "\nsink=" + flow.getSinkDescription()
                + "\nguards=" + flow.getGuardSummary() + "\npath=" + flow.getPathText();
    }

    // 格式化并输出 formatArgumentMapping 对应的展示内容。
    private String formatArgumentMapping(SemanticCallEdge edge) {
        return "[ARGUMENT_MAPPING] " + edge.getCallerChunkId() + " -> " + edge.getCalleeChunkId()
                + " line=" + edge.getCallSiteLine() + " confidence=" + edge.getConfidence()
                + " mapping=" + safe(edge.getArgumentMapping(), 600)
                + "\n<UNTRUSTED_CODE>" + safe(edge.getExpression(), 600) + "</UNTRUSTED_CODE>";
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

    // 解析输入并生成 parseIds 对应的结构化结果。
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

    // 格式化并输出 formatChunk 对应的展示内容。
    private String formatChunk(CodeChunk chunk, String reason, int maxChars) {
        return "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":" + chunk.getStartLine()
                + " | " + chunk.getSymbolName() + " | " + reason + "\n<UNTRUSTED_CODE>\n"
                + safe(chunk.getContent(), maxChars) + "\n</UNTRUSTED_CODE>";
    }

    // 查询并返回 searchable 对应的数据。
    private String searchable(CodeChunk chunk) {
        return lower(chunk.getFilePath() + " " + chunk.getSymbolName() + " " + chunk.getEndpoint() + " "
                + chunk.getChunkType() + " " + chunk.getParameters() + " " + chunk.getAnnotations() + " "
                + chunk.getCalledSymbols() + " " + chunk.getContent());
    }

    // 执行 ProfessionalToolService 中的 firstNonBlank 处理。
    private String firstNonBlank(String... values) {
        for (String value : values) if (value != null && !value.isBlank()) return value;
        return "";
    }

    // 判断是否满足 matchesAnyToken 对应的条件。
    private boolean matchesAnyToken(String haystack, String query) {
        return java.util.Arrays.stream(lower(query).split("[^a-z0-9_$#{}./-]+"))
                .map(String::strip).filter(token -> token.length() >= 2).anyMatch(haystack::contains);
    }

    // 判断是否满足 contains 对应的条件。
    private boolean contains(String value, String expected) {
        return !expected.isBlank() && lower(value).contains(lower(expected));
    }

    // 执行 ProfessionalToolService 中的 equalsIgnoreCase 处理。
    private boolean equalsIgnoreCase(String left, String right) {
        return left != null && right != null && left.equalsIgnoreCase(right);
    }

    // 执行 ProfessionalToolService 中的 samePath 处理。
    private boolean samePath(String left, String right) {
        return left != null && right != null && left.replace('\\', '/').equalsIgnoreCase(right.replace('\\', '/'));
    }

    // 执行 ProfessionalToolService 中的 lower 处理。
    private String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    // 执行 ProfessionalToolService 中的 safe 处理。
    private String safe(String value, int maxChars) {
        if (value == null) return "";
        return value.substring(0, Math.min(value.length(), maxChars));
    }

    // 封装 ScoredChunk 使用的不可变结构化数据。
    private record ScoredChunk(CodeChunk chunk, int score) {}
    private record CodeMatch(CodeChunk chunk, int lineIndex, int contextLines) {
        int lineNumber() {
            return Math.max(1, chunk.getStartLine()) + lineIndex;
        }

        String format() {
            String[] lines = chunk.getContent() == null ? new String[0] : chunk.getContent().split("\\R", -1);
            int first = Math.max(0, lineIndex - contextLines);
            int last = Math.min(lines.length - 1, lineIndex + contextLines);
            StringBuilder source = new StringBuilder();
            for (int index = first; index <= last; index++) {
                source.append(index == lineIndex ? ">>> " : "    ")
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
    // 封装 GraphStep 使用的不可变结构化数据。
    private record GraphStep(Long from, Long to, SemanticCallEdge edge) {}
    // 封装 GraphPath 使用的不可变结构化数据。
    private record GraphPath(Long end, List<GraphStep> steps) {
        boolean contains(Long chunkId) {
            if (end.equals(chunkId)) return true;
            return steps.stream().anyMatch(step -> step.from().equals(chunkId));
        }
    }
    // 封装 NodeDepth 使用的不可变结构化数据。
    private record NodeDepth(Long id, int depth) {}
}
