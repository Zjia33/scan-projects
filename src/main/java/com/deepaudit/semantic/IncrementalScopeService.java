package com.deepaudit.semantic;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.source.AuditSourceFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class IncrementalScopeService {
    private static final int MAX_IMPACTED_CHUNKS = 600;
    private static final int CALL_GRAPH_DEPTH = 2;

    private final SemanticCallEdgeMapper edgeMapper;
    private final GitFileChangeMapper changeMapper;

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
        ArrayDeque<NodeDepth> queue = new ArrayDeque<>();
        changed.forEach(id -> queue.add(new NodeDepth(id, 0)));
        while (!queue.isEmpty() && impacted.size() < MAX_IMPACTED_CHUNKS) {
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

        List<GitFileChange> fileChanges = changeMapper.findByTaskId(taskId);
        boolean globalConfigurationChanged = fileChanges.stream().anyMatch(GitFileChange::isConfigurationChange);
        if (globalConfigurationChanged) {
            chunks.stream().filter(this::globalSecurityContext)
                    .map(CodeChunk::getId).filter(java.util.Objects::nonNull)
                    .limit(250).forEach(impacted::add);
        }

        boolean deletedAnalyzableSource = fileChanges.stream()
                .filter(change -> "DELETE".equals(change.getChangeType()))
                .map(GitFileChange::getOldPath).anyMatch(this::analyzableSource);
        // 删除源码后 Target 中没有对应代码块，即使同批还有其他修改也要补充剩余入口和安全方法。
        if (deletedAnalyzableSource || (changed.isEmpty() && globalConfigurationChanged)) {
            chunks.stream().filter(this::globalSecurityContext)
                    .map(CodeChunk::getId).filter(java.util.Objects::nonNull)
                    .limit(150).forEach(impacted::add);
        }
        impacted.removeAll(changed);
        if (impacted.size() > MAX_IMPACTED_CHUNKS) {
            impacted = new LinkedHashSet<>(impacted.stream().limit(MAX_IMPACTED_CHUNKS).toList());
        }
        return new ScopeResult(Set.copyOf(changed), Set.copyOf(impacted), globalConfigurationChanged);
    }

    private boolean globalSecurityContext(CodeChunk chunk) {
        if (chunk.getEndpoint() != null) return true;
        String text = (chunk.getAnnotations() + " " + chunk.getSymbolName() + " "
                + chunk.getFilePath()).toLowerCase(Locale.ROOT);
        return "JAVA_METHOD".equals(chunk.getChunkType()) && (text.contains("security")
                || text.contains("authorize") || text.contains("permission") || text.contains("filter")
                || text.contains("interceptor") || text.contains("controller") || text.contains("mapper"));
    }

    private boolean analyzableSource(String path) {
        if (!AuditSourceFilter.shouldAnalyze(path)) return false;
        String normalized = path.toLowerCase(Locale.ROOT);
        return normalized.endsWith(".java") || normalized.endsWith(".xml") || normalized.endsWith(".yml")
                || normalized.endsWith(".yaml") || normalized.endsWith(".properties")
                || normalized.endsWith(".sql") || normalized.endsWith(".jsp")
                || normalized.endsWith(".html") || normalized.endsWith(".js")
                || normalized.endsWith(".ts") || normalized.endsWith(".vue");
    }

    private record NodeDepth(Long chunkId, int depth) {
    }

    public record ScopeResult(Set<Long> changedChunkIds, Set<Long> impactedChunkIds,
                              boolean globalConfigurationChanged) {
        public int totalDeepTargets() {
            return changedChunkIds.size() + impactedChunkIds.size();
        }
    }
}
