package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphClient;
import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.codegraph.CodeGraphResultMapper;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.recon.ReconService;
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
import java.util.stream.Collectors;

/** Explores one coherent graph while retaining the evidence boundary of every discovered edge. */
@Service
@RequiredArgsConstructor
public class CallGraphExplorerService {
    private static final int MAX_GRAPH_NODES = 200;
    private static final int MAX_CODEGRAPH_NEIGHBORS = 100;
    private final Object[] materializationLocks = locks();

    private final SemanticCallEdgeMapper edgeMapper;
    private final CodeGraphIntegrationService codeGraph;
    private final CodeGraphResultMapper resultMapper;
    private final ReconService reconService;
    private final CodeChunkMapper chunkMapper;

    public ToolResult explore(UUID taskId, CodeChunk anchor, List<CodeChunk> sessionChunks,
                              ToolArguments arguments, int limit) {
        String requestedDirection = arguments.string("direction").toUpperCase(Locale.ROOT);
        if (requestedDirection.isBlank()) requestedDirection = "BOTH";
        if (!Set.of("CALLERS", "CALLEES", "BOTH").contains(requestedDirection)) {
            return ToolResult.invalid("explore_call_graph direction 只能是 CALLERS、CALLEES 或 BOTH。");
        }
        int depth = arguments.integer("depth", 2, 1, 3);
        Long targetId = arguments.longValue("targetChunkId");
        List<CodeChunk> workingChunks = new ArrayList<>(sessionChunks);
        if (targetId != null && workingChunks.stream().noneMatch(chunk -> targetId.equals(chunk.getId()))) {
            return ToolResult.notFound("当前任务不存在 targetChunkId=" + targetId);
        }

        List<SemanticCallEdge> semanticEdges = edgeMapper.findByTaskId(taskId);
        SearchState state = new SearchState(taskId, anchor, targetId, depth, limit,
                semanticEdges, workingChunks);
        List<String> directions = "BOTH".equals(requestedDirection)
                ? List.of("CALLERS", "CALLEES") : List.of(requestedDirection);
        int remaining = limit;
        for (int index = 0; index < directions.size(); index++) {
            if (targetId == null && remaining <= 0) break;
            int directionsLeft = directions.size() - index;
            int quota = targetId == null ? Math.max(1, remaining / directionsLeft) : limit;
            int before = state.paths.size();
            searchDirection(state, directions.get(index), before + quota);
            remaining -= state.paths.size() - before;
            if (targetId != null && !state.paths.isEmpty()) break;
        }
        if (state.materializedChunks > 0) refreshSessionChunks(sessionChunks, workingChunks);

        List<GraphEdge> returnedEdges = state.paths.stream().flatMap(path -> path.edges().stream())
                .distinct().toList();
        Set<Long> evidence = state.paths.isEmpty()
                ? new LinkedHashSet<>(Set.of(anchor.getId()))
                : verifiedReachable(anchor.getId(), returnedEdges);
        Set<Long> returnedNodes = new LinkedHashSet<>();
        for (GraphPath path : state.paths) {
            returnedNodes.add(anchor.getId());
            path.edges().forEach(edge -> returnedNodes.add(edge.to()));
        }
        if (state.paths.isEmpty()) state.discoveredEdges.stream().map(GraphEdge::to)
                .distinct().limit(20).forEach(returnedNodes::add);
        Set<Long> candidates = returnedNodes.stream().filter(id -> !evidence.contains(id))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        candidates.remove(anchor.getId());

        String header = "[CALL_GRAPH direction=" + requestedDirection + " depth=" + depth
                + " engine=LOCAL+CODEGRAPH codeGraphQueries=" + state.codeGraphQueries
                + " materializedChunks=" + state.materializedChunks
                + " verifiedEdges=" + returnedEdges.stream().filter(GraphEdge::verified).count()
                + " candidateEdges=" + returnedEdges.stream().filter(edge -> !edge.verified()).count()
                + " truncated=" + state.truncated + "]";
        if (state.paths.isEmpty()) {
            String target = targetId == null ? "" : "，目标代码块=" + targetId;
            String text = header + "\n在指定方向和深度内没有找到可返回路径" + target
                    + frontier(candidates);
            if (state.codeGraphFailures > 0) {
                return new ToolResult(ToolResult.Status.EMPTY, "PARTIAL_RESULT", text,
                        Set.of(), candidates, state.truncated, null);
            }
            return new ToolResult(ToolResult.Status.EMPTY, "NO_RESULTS", text,
                    Set.of(), candidates, state.truncated, null);
        }

        Map<Long, CodeChunk> resultChunks = byId(state.workingChunks);
        String body = state.paths.stream().limit(limit).map(path -> formatPath(path, resultChunks))
                .collect(Collectors.joining("\n\n"));
        String failures = state.codeGraphFailures == 0 ? ""
                : "\n[PARTIAL_RESULT] CodeGraph 邻居查询失败 " + state.codeGraphFailures
                + " 次；已保留本地语义图和成功查询的结果。";
        return new ToolResult(ToolResult.Status.OK,
                state.codeGraphFailures == 0 ? "OK" : "PARTIAL_RESULT",
                header + "\n" + body + failures, evidence, candidates, state.truncated, null);
    }

    private void searchDirection(SearchState state, String direction, int pathLimit) {
        ArrayDeque<GraphPath> queue = new ArrayDeque<>();
        queue.add(new GraphPath(direction, state.anchor.getId(), List.of()));
        while (!queue.isEmpty() && state.paths.size() < pathLimit && !state.truncated) {
            GraphPath path = queue.removeFirst();
            if (path.edges().size() >= state.depth) continue;
            List<GraphEdge> neighbors = neighbors(state, path.end(), direction);
            for (GraphEdge edge : neighbors) {
                if (path.contains(edge.to())) continue;
                if (state.visitedNodes.add(edge.to()) && state.visitedNodes.size() > MAX_GRAPH_NODES) {
                    state.truncated = true;
                    break;
                }
                List<GraphEdge> nextEdges = new ArrayList<>(path.edges());
                nextEdges.add(edge);
                GraphPath next = new GraphPath(direction, edge.to(), List.copyOf(nextEdges));
                if (state.targetId == null || state.targetId.equals(edge.to())) state.paths.add(next);
                if (state.targetId != null && state.targetId.equals(edge.to())) return;
                queue.addLast(next);
                if (state.paths.size() >= pathLimit) break;
            }
        }
    }

    private List<GraphEdge> neighbors(SearchState state, Long currentId, String direction) {
        String cacheKey = direction + ":" + currentId;
        List<GraphEdge> cached = state.neighborCache.get(cacheKey);
        if (cached != null) return cached;
        Map<String, GraphEdge> result = new LinkedHashMap<>();
        Map<Long, CodeChunk> byId = byId(state.workingChunks);
        CodeChunk current = byId.get(currentId);
        if (current == null) return List.of();

        for (SemanticCallEdge semantic : state.semanticEdges) {
            if (semantic.getCallerChunkId() == null || semantic.getCalleeChunkId() == null
                    || semantic.getConfidence() == Confidence.LOW) continue;
            Long nextId;
            if ("CALLEES".equals(direction) && currentId.equals(semantic.getCallerChunkId())) {
                nextId = semantic.getCalleeChunkId();
            } else if ("CALLERS".equals(direction) && currentId.equals(semantic.getCalleeChunkId())) {
                nextId = semantic.getCallerChunkId();
            } else continue;
            CodeChunk caller = byId.get(semantic.getCallerChunkId());
            CodeChunk callee = byId.get(semantic.getCalleeChunkId());
            if (caller == null || callee == null) continue;
            GraphEdge edge = edge(direction, currentId, nextId, caller, callee,
                    "LOCAL_SEMANTIC", state.workingChunks, state.semanticEdges);
            merge(result, edge);
        }

        CodeGraphIntegrationService.CallGraphNeighbors query = codeGraph.queryCallGraphNeighbors(
                state.taskId, current, direction, MAX_CODEGRAPH_NEIGHBORS);
        if (query.attempted()) state.codeGraphQueries++;
        if (query.failed()) state.codeGraphFailures++;
        if (!query.locations().isEmpty()) {
            materializeIfRequired(state, query);
            byId = byId(state.workingChunks);
            current = byId.get(currentId);
            if (current != null) {
                for (CodeGraphClient.CodeGraphLocation location : query.callers()) {
                    CodeChunk caller = resultMapper.mapLocation(state.workingChunks, location);
                    if (caller == null || caller.getId() == null || caller.getId().equals(currentId)) continue;
                    merge(result, edge(direction, currentId, caller.getId(), caller, current,
                            "CODEGRAPH_CALLERS", state.workingChunks, state.semanticEdges));
                }
                for (CodeGraphClient.CodeGraphLocation location : query.callees()) {
                    CodeChunk callee = resultMapper.mapLocation(state.workingChunks, location);
                    if (callee == null || callee.getId() == null || callee.getId().equals(currentId)) continue;
                    merge(result, edge(direction, currentId, callee.getId(), current, callee,
                            "CODEGRAPH_CALLEES", state.workingChunks, state.semanticEdges));
                }
            }
        }
        List<GraphEdge> ordered = result.values().stream()
                .sorted(Comparator.comparing(GraphEdge::verified).reversed()
                        .thenComparing(GraphEdge::to)).toList();
        state.discoveredEdges.addAll(ordered);
        state.neighborCache.put(cacheKey, ordered);
        return ordered;
    }

    private GraphEdge edge(String direction, Long from, Long to, CodeChunk caller, CodeChunk callee,
                           String source, List<CodeChunk> chunks, List<SemanticCallEdge> semanticEdges) {
        CallSiteVerifier.Verification verification = CallSiteVerifier.verify(
                caller, callee, chunks, semanticEdges);
        return new GraphEdge(direction, from, to, caller.getId(), callee.getId(), source,
                verification.verified(), verification.callSiteLine(), verification.expression(),
                verification.type(), verification.reason());
    }

    private void materializeIfRequired(SearchState state,
                                       CodeGraphIntegrationService.CallGraphNeighbors query) {
        CodeGraphResultMapper.MappingResult mapping = resultMapper.map(state.workingChunks, query.locations());
        if (mapping.unmappedLocations() == 0 || query.targetRoot() == null) return;
        synchronized (lock(state.taskId)) {
            int additions = reconService.materializeCodeGraphLocations(
                    state.taskId, query.targetRoot(), query.locations());
            state.materializedChunks += additions;
            if (additions > 0) {
                List<CodeChunk> refreshed = chunkMapper.findByTaskId(state.taskId);
                state.workingChunks.clear();
                state.workingChunks.addAll(refreshed);
            }
        }
    }

    private Set<Long> verifiedReachable(Long anchorId, List<GraphEdge> edges) {
        Map<Long, Set<Long>> graph = new LinkedHashMap<>();
        for (GraphEdge edge : edges) {
            if (!edge.verified()) continue;
            graph.computeIfAbsent(edge.from(), ignored -> new LinkedHashSet<>()).add(edge.to());
        }
        Set<Long> result = new LinkedHashSet<>();
        result.add(anchorId);
        ArrayDeque<Long> queue = new ArrayDeque<>();
        queue.add(anchorId);
        while (!queue.isEmpty()) {
            for (Long next : graph.getOrDefault(queue.removeFirst(), Set.of())) {
                if (result.add(next)) queue.addLast(next);
            }
        }
        return result;
    }

    private String formatPath(GraphPath path, Map<Long, CodeChunk> chunks) {
        boolean verified = path.edges().stream().allMatch(GraphEdge::verified);
        return "PATH direction=" + path.direction() + " depth=" + path.edges().size()
                + " verified=" + verified + "\n" + path.edges().stream().map(edge -> {
            String relation = edge.verified() ? "VERIFIED" : "CANDIDATE";
            String arrow = "CALLERS".equals(path.direction()) ? " <-[" : " -[";
            String close = "CALLERS".equals(path.direction()) ? "]- " : "]-> ";
            return formatNode(edge.from(), chunks) + arrow + relation + ",source=" + edge.source()
                    + ",type=" + edge.verificationType()
                    + (edge.callSiteLine() > 0 ? ",line=" + edge.callSiteLine() : "")
                    + formatExpression(edge.expression())
                    + close + formatNode(edge.to(), chunks)
                    + (edge.reason().isBlank() ? "" : " | " + edge.reason());
        }).collect(Collectors.joining("\n"));
    }

    private String formatNode(Long chunkId, Map<Long, CodeChunk> chunks) {
        CodeChunk chunk = chunks.get(chunkId);
        if (chunk == null) return "CHUNK_ID=" + chunkId + " | symbol=? | location=?";
        return "CHUNK_ID=" + chunkId + " | symbol=" + oneLine(chunk.getSymbolName(), 180)
                + " | location=" + oneLine(chunk.getFilePath(), 300) + ":"
                + Math.max(1, chunk.getStartLine());
    }

    private String formatExpression(String expression) {
        String value = oneLine(expression, 300);
        if (value.isBlank()) return "";
        String escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("<", "\\u003c").replace(">", "\\u003e");
        return ",expression=<UNTRUSTED_CODE>\"" + escaped + "\"</UNTRUSTED_CODE>";
    }

    private String oneLine(String value, int maxChars) {
        if (value == null) return "";
        String normalized = value.replaceAll("\\s+", " ").strip();
        if (normalized.length() <= maxChars) return normalized;
        return normalized.substring(0, Math.max(0, maxChars - 1)) + "…";
    }

    private String frontier(Set<Long> candidates) {
        if (candidates.isEmpty()) return "";
        return "\n[UNVERIFIED_FRONTIER] candidateChunkIds=" + candidates;
    }

    private void merge(Map<String, GraphEdge> edges, GraphEdge candidate) {
        String key = candidate.direction() + ":" + candidate.from() + "->" + candidate.to();
        GraphEdge existing = edges.get(key);
        if (existing == null || !existing.verified() && candidate.verified()) edges.put(key, candidate);
    }

    private Map<Long, CodeChunk> byId(List<CodeChunk> chunks) {
        return chunks.stream().filter(chunk -> chunk.getId() != null)
                .collect(Collectors.toMap(CodeChunk::getId, chunk -> chunk,
                        (left, right) -> left, LinkedHashMap::new));
    }

    private void refreshSessionChunks(List<CodeChunk> sessionChunks, List<CodeChunk> refreshed) {
        try {
            sessionChunks.clear();
            sessionChunks.addAll(refreshed);
        } catch (UnsupportedOperationException ignored) {
            // Unit callers may pass immutable views; persisted chunks remain available to subsequent requests.
        }
    }

    private Object lock(UUID taskId) {
        return materializationLocks[Math.floorMod(taskId.hashCode(), materializationLocks.length)];
    }

    private static Object[] locks() {
        Object[] values = new Object[32];
        java.util.Arrays.setAll(values, ignored -> new Object());
        return values;
    }

    private static final class SearchState {
        private final UUID taskId;
        private final CodeChunk anchor;
        private final Long targetId;
        private final int depth;
        private final int limit;
        private final List<SemanticCallEdge> semanticEdges;
        private final List<CodeChunk> workingChunks;
        private final Map<String, List<GraphEdge>> neighborCache = new LinkedHashMap<>();
        private final List<GraphEdge> discoveredEdges = new ArrayList<>();
        private final List<GraphPath> paths = new ArrayList<>();
        private final Set<Long> visitedNodes = new LinkedHashSet<>();
        private int codeGraphQueries;
        private int codeGraphFailures;
        private int materializedChunks;
        private boolean truncated;

        private SearchState(UUID taskId, CodeChunk anchor, Long targetId, int depth, int limit,
                            List<SemanticCallEdge> semanticEdges, List<CodeChunk> workingChunks) {
            this.taskId = taskId;
            this.anchor = anchor;
            this.targetId = targetId;
            this.depth = depth;
            this.limit = limit;
            this.semanticEdges = semanticEdges;
            this.workingChunks = workingChunks;
            this.visitedNodes.add(anchor.getId());
        }
    }

    private record GraphEdge(String direction, Long from, Long to, Long callerId, Long calleeId,
                             String source, boolean verified, int callSiteLine, String expression,
                             String verificationType, String reason) {
    }

    private record GraphPath(String direction, Long end, List<GraphEdge> edges) {
        private boolean contains(Long chunkId) {
            if (end.equals(chunkId)) return true;
            return edges.stream().anyMatch(edge -> edge.from().equals(chunkId));
        }
    }
}
