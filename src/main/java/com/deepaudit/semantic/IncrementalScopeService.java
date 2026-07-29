package com.deepaudit.semantic;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import com.deepaudit.source.AuditSourceFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.EnumMap;
import java.util.Set;
import java.util.UUID;

// 负责 IncrementalScopeService 对应的业务编排和处理。
@Service
@RequiredArgsConstructor
public class IncrementalScopeService {
    private static final int CALL_GRAPH_DEPTH = 2;

    private final SemanticCallEdgeMapper edgeMapper;
    private final GitFileChangeMapper changeMapper;
    private final SemanticMethodChangeMapper semanticChangeMapper;

    // 以直接变更块为种子，沿调用图双向扩展两层，并补充同文件和全局配置影响目标。
    public ScopeResult determine(UUID taskId, List<CodeChunk> chunks) {
        Set<Long> changed = new LinkedHashSet<>();
        for (CodeChunk chunk : chunks) {
            if (chunk.getAnalysisScope() == AnalysisScope.CHANGED && chunk.getId() != null) {
                changed.add(chunk.getId());
            }
        }
        Set<Long> impacted = new LinkedHashSet<>(changed);
        List<SemanticCallEdge> edges = edgeMapper.findByTaskId(taskId);
        List<SemanticMethodChange> semanticChanges = semanticChangeMapper.findByTaskId(taskId);
        // 语义差异提供比 Git 新增行更稳定的方法定位，尤其覆盖纯删除和签名变化。
        for (SemanticMethodChange change : semanticChanges) {
            if (change.getTargetPath() != null && change.getTargetStartLine() != null) {
                chunks.stream().filter(chunk -> change.getTargetPath().equals(chunk.getFilePath()))
                        .filter(chunk -> change.getTargetStartLine() >= chunk.getStartLine()
                                && change.getTargetStartLine() <= chunk.getEndLine())
                        .map(CodeChunk::getId).filter(java.util.Objects::nonNull).findFirst()
                        .ifPresent(changed::add);
            }
        }
        ArrayDeque<NodeDepth> queue = new ArrayDeque<>();
        changed.forEach(id -> queue.add(new NodeDepth(id, 0)));
        while (!queue.isEmpty()) {
            NodeDepth current = queue.removeFirst();
            if (current.depth() >= CALL_GRAPH_DEPTH) continue;
            for (SemanticCallEdge edge : edges) {
                Long next = null;
                if (current.chunkId().equals(edge.getCallerChunkId())) next = edge.getCalleeChunkId();
                else if (current.chunkId().equals(edge.getCalleeChunkId())) next = edge.getCallerChunkId();
                if (next != null && impacted.add(next)) queue.add(new NodeDepth(next, current.depth() + 1));
            }
        }

        Set<String> changedFiles = new LinkedHashSet<>();
        chunks.stream().filter(chunk -> changed.contains(chunk.getId()))
                .forEach(chunk -> changedFiles.add(chunk.getFilePath()));
        chunks.stream().filter(chunk -> changedFiles.contains(chunk.getFilePath()))
                .map(CodeChunk::getId).filter(java.util.Objects::nonNull).forEach(impacted::add);

        // 被删除方法没有 Target Chunk：优先补充仍在调用该方法的调用者，并补充其原文件剩余方法。
        semanticChanges.stream().filter(change -> change.getChangeKind() == SemanticChangeKind.METHOD_DELETED)
                .forEach(change -> {
                    edges.stream().filter(edge -> change.getMethodName().equals(edge.getCalledName()))
                            .map(SemanticCallEdge::getCallerChunkId).filter(java.util.Objects::nonNull)
                            .forEach(impacted::add);
                    if (change.getTargetPath() != null) {
                        chunks.stream().filter(chunk -> change.getTargetPath().equals(chunk.getFilePath()))
                                .map(CodeChunk::getId).filter(java.util.Objects::nonNull).forEach(impacted::add);
                    }
                });

        List<GitFileChange> fileChanges = changeMapper.findByTaskId(taskId);
        boolean globalConfigurationChanged = fileChanges.stream().anyMatch(GitFileChange::isConfigurationChange);
        if (globalConfigurationChanged) {
            chunks.stream().filter(this::globalSecurityContext)
                    .map(CodeChunk::getId).filter(java.util.Objects::nonNull).forEach(impacted::add);
        }

        boolean deletedAnalyzableSource = fileChanges.stream()
                .filter(change -> "DELETE".equals(change.getChangeType()))
                .map(GitFileChange::getOldPath).anyMatch(this::analyzableSource);
        // 删除源码后 Target 中没有对应代码块，即使同批还有其他修改也要补充剩余入口和安全方法。
        if (deletedAnalyzableSource || (changed.isEmpty() && globalConfigurationChanged)) {
            chunks.stream().filter(this::globalSecurityContext)
                    .map(CodeChunk::getId).filter(java.util.Objects::nonNull).forEach(impacted::add);
        }
        impacted.removeAll(changed);
        Map<SemanticChangeKind, Long> semanticCounts = new EnumMap<>(SemanticChangeKind.class);
        for (SemanticMethodChange change : semanticChanges) {
            semanticCounts.merge(change.getChangeKind(), 1L, Long::sum);
        }
        return new ScopeResult(Set.copyOf(changed), Set.copyOf(impacted), globalConfigurationChanged,
                Map.copyOf(semanticCounts));
    }

    // 执行 IncrementalScopeService 中的 globalSecurityContext 处理。
    private boolean globalSecurityContext(CodeChunk chunk) {
        if (chunk.getEndpoint() != null) return true;
        String text = (chunk.getAnnotations() + " " + chunk.getSymbolName() + " "
                + chunk.getFilePath()).toLowerCase(Locale.ROOT);
        return "JAVA_METHOD".equals(chunk.getChunkType()) && (text.contains("security")
                || text.contains("authorize") || text.contains("permission") || text.contains("filter")
                || text.contains("interceptor") || text.contains("controller") || text.contains("mapper"));
    }

    // 执行 IncrementalScopeService 中的 analyzableSource 处理。
    private boolean analyzableSource(String path) {
        if (!AuditSourceFilter.shouldAnalyze(path)) return false;
        String normalized = path.toLowerCase(Locale.ROOT);
        return normalized.endsWith(".java") || normalized.endsWith(".xml") || normalized.endsWith(".yml")
                || normalized.endsWith(".yaml") || normalized.endsWith(".properties")
                || normalized.endsWith(".sql") || normalized.endsWith(".jsp")
                || normalized.endsWith(".html") || normalized.endsWith(".js")
                || normalized.endsWith(".ts") || normalized.endsWith(".vue");
    }

    // 封装 NodeDepth 使用的不可变结构化数据。
    private record NodeDepth(Long chunkId, int depth) {
    }

    // 封装 ScopeResult 使用的不可变结构化数据。
    public record ScopeResult(Set<Long> changedChunkIds, Set<Long> impactedChunkIds,
                              boolean globalConfigurationChanged,
                              Map<SemanticChangeKind, Long> semanticChangeCounts) {
        // 转换并返回 totalDeepTargets 对应的数据表示。
        public int totalDeepTargets() {
            return changedChunkIds.size() + impactedChunkIds.size();
        }

        // 执行 ScopeResult 中的 semanticChangeSummary 处理。
        public String semanticChangeSummary() {
            if (semanticChangeCounts.isEmpty()) return "无方法级语义变化";
            return semanticChangeCounts.entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(java.util.stream.Collectors.joining("，"));
        }
    }
}
