package com.deepaudit.semantic;

import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

// 负责 SemanticEvidenceService 对应的业务编排和处理。
@Service
@RequiredArgsConstructor
public class SemanticEvidenceService {
    private final SecurityFlowMapper flowMapper;
    private final SemanticCallEdgeMapper edgeMapper;

    // 将语义安全流转换为只供 Orchestrator 调查的线索索引。
    public SemanticHints hints(UUID taskId) {
        Map<Long, Set<VulnerabilityType>> types = new LinkedHashMap<>();
        Map<Long, String> descriptions = new LinkedHashMap<>();
        for (SecurityFlow flow : flowMapper.findByTaskId(taskId)) {
            if (flow.getType() == null) continue;
            types.computeIfAbsent(flow.getPrimaryChunkId(), ignored -> new LinkedHashSet<>()).add(flow.getType());
            String hint = "语义分析调查线索（不是最终漏洞结论）：\n" + flow.getPathText();
            descriptions.merge(flow.getPrimaryChunkId(), hint, (left, right) -> left + "\n\n" + right);
        }
        return new SemanticHints(types, descriptions);
    }

    // 按当前代码块和漏洞类型查询 Agent 可引用的语义路径或调用边。
    public EvidenceResult query(UUID taskId, Long currentChunkId, int requestedLimit,
                                VulnerabilityType vulnerabilityType) {
        int limit = Math.max(1, Math.min(requestedLimit <= 0 ? 6 : requestedLimit, 10));
        List<SecurityFlow> flows = flowMapper.findByTaskAndChunk(taskId, currentChunkId).stream()
                .filter(flow -> vulnerabilityType == null || flow.getType() == vulnerabilityType)
                .limit(limit).toList();
        Set<Long> evidence = flows.stream().flatMap(flow -> parseIds(flow.getEvidenceChunkIds()).stream())
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!flows.isEmpty()) {
            String text = flows.stream().map(this::formatFlow).collect(Collectors.joining("\n\n"));
            return new EvidenceResult(text, evidence);
        }
        return new EvidenceResult("语义分析未找到与当前代码块关联的可验证路径；应继续读取相关代码块和调用上下文。", Set.of());
    }

    // 为 Critic 提供独立于专业 Agent 工具观察的原始语义证据。
    public String independentCriticEvidence(UUID taskId, Long chunkId, VulnerabilityType type) {
        return independentCriticEvidenceResult(taskId, chunkId, type).text();
    }

    // 同时返回独立语义证据涉及的真实代码块 ID，供 Critic 扩展合法定位候选范围。
    public EvidenceResult independentCriticEvidenceResult(UUID taskId, Long chunkId, VulnerabilityType type) {
        List<SecurityFlow> flows = flowMapper.findByTaskAndChunk(taskId, chunkId).stream()
                .filter(flow -> flow.getType() == type).toList();
        Set<Long> evidence = flows.stream().flatMap(flow -> parseIds(flow.getEvidenceChunkIds()).stream())
                .collect(Collectors.toCollection(LinkedHashSet::new));
        String text = flows.stream()
                .map(flow -> "[独立语义证据 " + flow.getId() + "]\n" + flow.getPathText())
                .collect(Collectors.joining("\n\n"));
        return new EvidenceResult(text.isBlank() ? "没有独立语义证据" : text, evidence);
    }

    // 为 Critic 补充已验证调用图邻域。它只用于寻找 Guard 和反证，不会自动成为最终报告证据。
    public Set<Long> criticReviewContextIds(UUID taskId, Set<Long> seedChunkIds, int requestedDepth) {
        if (seedChunkIds == null || seedChunkIds.isEmpty()) return Set.of();
        int maxDepth = Math.max(1, Math.min(requestedDepth <= 0 ? 3 : requestedDepth, 5));
        Map<Long, Set<Long>> graph = new LinkedHashMap<>();
        for (SemanticCallEdge edge : edgeMapper.findByTaskId(taskId)) {
            Long caller = edge.getCallerChunkId();
            Long callee = edge.getCalleeChunkId();
            if (caller == null || callee == null
                    || edge.getConfidence() == com.deepaudit.domain.Confidence.LOW) continue;
            graph.computeIfAbsent(caller, ignored -> new LinkedHashSet<>()).add(callee);
            graph.computeIfAbsent(callee, ignored -> new LinkedHashSet<>()).add(caller);
        }
        Set<Long> visited = new LinkedHashSet<>(seedChunkIds);
        ArrayDeque<Long> queue = new ArrayDeque<>();
        Map<Long, Integer> depth = new LinkedHashMap<>();
        seedChunkIds.forEach(id -> {
            if (id != null) {
                queue.add(id);
                depth.put(id, 0);
            }
        });
        while (!queue.isEmpty()) {
            Long current = queue.removeFirst();
            int currentDepth = depth.getOrDefault(current, 0);
            if (currentDepth >= maxDepth) continue;
            for (Long next : graph.getOrDefault(current, Set.of())) {
                if (!visited.add(next)) continue;
                depth.put(next, currentDepth + 1);
                queue.addLast(next);
            }
        }
        visited.removeAll(seedChunkIds);
        return Set.copyOf(visited);
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
            if (caller == null || callee == null
                    || edge.getConfidence() == com.deepaudit.domain.Confidence.LOW) continue;
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

    // 从最终漏洞代码块沿可靠调用边反向追踪，返回每个证据调用方的真实调用表达式行号。
    public Map<Long, Integer> callSiteLines(UUID taskId, Long primaryChunkId, Set<Long> evidenceChunkIds) {
        if (primaryChunkId == null || evidenceChunkIds == null || evidenceChunkIds.isEmpty()) return Map.of();
        Map<Long, List<SemanticCallEdge>> incoming = edgeMapper.findByTaskId(taskId).stream()
                .filter(edge -> edge.getCallerChunkId() != null && edge.getCalleeChunkId() != null)
                .filter(edge -> evidenceChunkIds.contains(edge.getCallerChunkId())
                        && evidenceChunkIds.contains(edge.getCalleeChunkId()))
                .filter(edge -> edge.getConfidence() != com.deepaudit.domain.Confidence.LOW)
                .collect(Collectors.groupingBy(SemanticCallEdge::getCalleeChunkId,
                        LinkedHashMap::new, Collectors.toList()));
        Map<Long, Integer> callSites = new LinkedHashMap<>();
        Set<Long> visited = new LinkedHashSet<>();
        ArrayDeque<Long> queue = new ArrayDeque<>();
        visited.add(primaryChunkId);
        queue.add(primaryChunkId);
        while (!queue.isEmpty()) {
            Long callee = queue.removeFirst();
            for (SemanticCallEdge edge : incoming.getOrDefault(callee, List.of())) {
                Long caller = edge.getCallerChunkId();
                callSites.putIfAbsent(caller, edge.getCallSiteLine());
                if (visited.add(caller)) queue.addLast(caller);
            }
        }
        return Map.copyOf(callSites);
    }

    // 同时输出安全路径和 Guard 摘要，避免为同一条流调用多个重叠工具。
    private String formatFlow(SecurityFlow flow) {
        StringBuilder text = new StringBuilder("[SECURITY_FLOW ").append(flow.getId()).append("]\n");
        text.append(flow.getPathText()).append('\n')
                .append("安全控制检查: ").append(flow.getGuardSummary()).append('\n')
                .append("覆盖情况: 已确认关系边=").append(flow.getConfirmedRelationEdges())
                .append("，局部语义缺口=").append(flow.getLocalSemanticGaps());
        return text.toString();
    }

    // 解析输入并生成 parseIds 对应的结构化结果。
    private Set<Long> parseIds(String value) {
        if (value == null || value.isBlank()) return Set.of();
        Set<Long> result = new LinkedHashSet<>();
        Arrays.stream(value.split(",")).map(String::strip).filter(item -> !item.isBlank()).forEach(item -> {
            try { result.add(Long.parseLong(item)); } catch (NumberFormatException ignored) { }
        });
        return result;
    }

    // 封装 SemanticHints 使用的不可变结构化数据。
    public record SemanticHints(Map<Long, Set<VulnerabilityType>> typesByChunk,
                                Map<Long, String> descriptionsByChunk) {}
    // 封装 EvidenceResult 使用的不可变结构化数据。
    public record EvidenceResult(String text, Set<Long> evidenceChunkIds) {
        // 校验并规范化 EvidenceResult 的构造参数。
        public EvidenceResult {
            text = text == null || text.isBlank() ? "没有语义证据" : text;
            evidenceChunkIds = evidenceChunkIds == null ? Set.of() : Set.copyOf(evidenceChunkIds);
        }
    }

    // 封装 RelationVerification 使用的不可变结构化数据。
    public record RelationVerification(boolean verified, String reason) {}
}
