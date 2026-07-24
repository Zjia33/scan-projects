package com.deepaudit.semantic;

import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticSymbol;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticSymbolMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class SemanticEvidenceService {
    private final SecurityFlowMapper flowMapper;
    private final SemanticCallEdgeMapper edgeMapper;
    private final SemanticSymbolMapper symbolMapper;

    // 将语义安全流转换为只供 Orchestrator 调查的线索索引。
    public SemanticHints hints(UUID taskId) {
        Map<Long, Set<VulnerabilityType>> types = new LinkedHashMap<>();
        Map<Long, String> descriptions = new LinkedHashMap<>();
        for (SecurityFlow flow : flowMapper.findByTaskId(taskId)) {
            types.computeIfAbsent(flow.getPrimaryChunkId(), ignored -> new LinkedHashSet<>()).add(flow.getType());
            String hint = "语义分析调查线索（不是最终漏洞结论）：\n" + flow.getPathText();
            descriptions.merge(flow.getPrimaryChunkId(), hint, (left, right) -> left + "\n\n" + right);
        }
        return new SemanticHints(types, descriptions);
    }

    public EvidenceResult query(UUID taskId, Long currentChunkId, String tool, int requestedLimit) {
        return query(taskId, currentChunkId, tool, requestedLimit, null);
    }

    // 按当前代码块和漏洞类型查询 Agent 可引用的语义路径或调用边。
    public EvidenceResult query(UUID taskId, Long currentChunkId, String tool, int requestedLimit,
                                VulnerabilityType vulnerabilityType) {
        int limit = Math.max(1, Math.min(requestedLimit <= 0 ? 6 : requestedLimit, 10));
        List<SecurityFlow> flows = flowMapper.findByTaskAndChunk(taskId, currentChunkId).stream()
                .filter(flow -> vulnerabilityType == null || flow.getType() == vulnerabilityType)
                .limit(limit).toList();
        Set<Long> evidence = flows.stream().flatMap(flow -> parseIds(flow.getEvidenceChunkIds()).stream())
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!flows.isEmpty()) {
            String text = flows.stream().map(flow -> formatFlow(flow, tool)).collect(Collectors.joining("\n\n"));
            return new EvidenceResult(text, evidence);
        }
        if ("get_call_chain".equals(tool)) return callEdges(taskId, currentChunkId, limit);
        return new EvidenceResult("语义分析未找到与当前代码块关联的可验证路径；应继续使用 RAG 检索源码。", Set.of());
    }

    // 为 Critic 提供独立于专业 Agent 工具观察的原始语义证据。
    public String independentCriticEvidence(UUID taskId, Long chunkId, VulnerabilityType type) {
        return flowMapper.findByTaskAndChunk(taskId, chunkId).stream()
                .filter(flow -> flow.getType() == type)
                .map(flow -> "[独立语义证据 " + flow.getId() + "]\n" + flow.getPathText())
                .collect(Collectors.joining("\n\n"));
    }

    // 在安全流或高/中可信调用图中验证两个代码块是否确有关系。
    public RelationVerification verifyRelation(UUID taskId, Long sourceChunkId, Long candidateChunkId) {
        if (sourceChunkId == null || candidateChunkId == null) {
            return new RelationVerification(false, "代码块 ID 不能为空");
        }
        if (sourceChunkId.equals(candidateChunkId)) {
            return new RelationVerification(true, "候选就是当前审计目标");
        }
        for (SecurityFlow flow : flowMapper.findByTaskId(taskId)) {
            Set<Long> ids = parseIds(flow.getEvidenceChunkIds());
            if (ids.contains(sourceChunkId) && ids.contains(candidateChunkId)) {
                return new RelationVerification(true, "两个代码块位于同一条已验证语义安全路径 " + flow.getId());
            }
        }

        // 将可靠调用边视作无向关系图，并以十层上限执行广度优先搜索。
        Map<Long, Set<Long>> graph = new LinkedHashMap<>();
        for (SemanticCallEdge edge : edgeMapper.findByTaskId(taskId)) {
            Long caller = edge.getCallerChunkId();
            Long callee = edge.getCalleeChunkId();
            if (caller == null || callee == null || edge.getConfidence() == com.deepaudit.domain.Confidence.LOW
                    || "UNRESOLVED".equals(edge.getEdgeType())) continue;
            graph.computeIfAbsent(caller, ignored -> new LinkedHashSet<>()).add(callee);
            graph.computeIfAbsent(callee, ignored -> new LinkedHashSet<>()).add(caller);
        }
        ArrayDeque<Long> queue = new ArrayDeque<>();
        Map<Long, Integer> depth = new LinkedHashMap<>();
        queue.add(sourceChunkId);
        depth.put(sourceChunkId, 0);
        while (!queue.isEmpty()) {
            Long current = queue.removeFirst();
            int currentDepth = depth.get(current);
            if (currentDepth >= 10) continue;
            for (Long next : graph.getOrDefault(current, Set.of())) {
                if (depth.containsKey(next)) continue;
                if (next.equals(candidateChunkId)) {
                    return new RelationVerification(true,
                            "两个代码块通过 " + (currentDepth + 1) + " 条高/中可信调用边连接");
                }
                depth.put(next, currentDepth + 1);
                queue.addLast(next);
            }
        }
        return new RelationVerification(false, "调用图和安全数据流中未确认两个代码块存在关系");
    }

    // 将当前块的已解析调用边格式化为带目标位置和参数流的证据。
    private EvidenceResult callEdges(UUID taskId, Long chunkId, int limit) {
        Map<UUID, SemanticSymbol> symbols = symbolMapper.findByTaskId(taskId).stream()
                .collect(Collectors.toMap(SemanticSymbol::getId, value -> value));
        List<SemanticCallEdge> edges = edgeMapper.findByCallerChunkId(taskId, chunkId).stream().limit(limit).toList();
        if (edges.isEmpty()) return new EvidenceResult("当前代码块没有已解析的跨文件调用边。", Set.of());
        Set<Long> evidence = new LinkedHashSet<>();
        evidence.add(chunkId);
        String text = edges.stream().map(edge -> {
            SemanticSymbol target = symbols.get(edge.getCalleeSymbolId());
            if (edge.getCalleeChunkId() != null) evidence.add(edge.getCalleeChunkId());
            return "[CALL_EDGE " + edge.getId() + "] " + edge.getCalledName() + " @ line "
                    + edge.getCallSiteLine() + " -> "
                    + (target == null ? "UNRESOLVED" : target.getQualifiedName() + " " + target.getFilePath()
                    + ":" + target.getStartLine()) + " | " + edge.getEdgeType() + " | "
                    + edge.getConfidence() + " | 参数流=" + edge.getArgumentMapping()
                    + " | " + edge.getResolutionReason();
        }).collect(Collectors.joining("\n"));
        return new EvidenceResult(text, evidence);
    }

    // 根据工具意图输出完整安全路径或聚焦 Guard 的覆盖摘要。
    private String formatFlow(SecurityFlow flow, String tool) {
        StringBuilder text = new StringBuilder("[SECURITY_FLOW ").append(flow.getId()).append("]\n");
        if ("find_security_guards".equals(tool)) {
            text.append("漏洞类型: ").append(flow.getType()).append('\n')
                    .append("安全控制检查: ").append(flow.getGuardSummary()).append('\n')
                    .append("覆盖情况: 已解析边=").append(flow.getResolvedEdges())
                    .append("，未解析边=").append(flow.getUnresolvedEdges());
        } else {
            text.append(flow.getPathText());
        }
        return text.toString();
    }

    private Set<Long> parseIds(String value) {
        if (value == null || value.isBlank()) return Set.of();
        Set<Long> result = new LinkedHashSet<>();
        Arrays.stream(value.split(",")).map(String::strip).filter(item -> !item.isBlank()).forEach(item -> {
            try { result.add(Long.parseLong(item)); } catch (NumberFormatException ignored) { }
        });
        return result;
    }

    public record SemanticHints(Map<Long, Set<VulnerabilityType>> typesByChunk,
                                Map<Long, String> descriptionsByChunk) {}
    public record EvidenceResult(String text, Set<Long> evidenceChunkIds) {
        public EvidenceResult {
            text = text == null || text.isBlank() ? "没有语义证据" : text;
            evidenceChunkIds = evidenceChunkIds == null ? Set.of() : Set.copyOf(evidenceChunkIds);
        }
    }

    public record RelationVerification(boolean verified, String reason) {}
}
