package com.deepaudit.semantic;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import com.deepaudit.source.AuditSourceFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.EnumMap;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class IncrementalScopeService {
    private final GitFileChangeMapper changeMapper;
    private final SemanticMethodChangeMapper semanticChangeMapper;

    // 只确定直接变化和确定性上下文；跨文件调用拓扑由 CodeGraph 负责。
    public ScopeResult determine(UUID taskId, List<CodeChunk> chunks) {
        Set<Long> changed = new LinkedHashSet<>();
        for (CodeChunk chunk : chunks) {
            if (chunk.getAnalysisScope() == AnalysisScope.CHANGED && chunk.getId() != null) {
                changed.add(chunk.getId());
            }
        }
        Set<Long> impacted = new LinkedHashSet<>(changed);
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
        Set<String> changedFiles = new LinkedHashSet<>();
        chunks.stream().filter(chunk -> changed.contains(chunk.getId()))
                .forEach(chunk -> changedFiles.add(chunk.getFilePath()));
        chunks.stream().filter(chunk -> changedFiles.contains(chunk.getFilePath()))
                .map(CodeChunk::getId).filter(java.util.Objects::nonNull).forEach(impacted::add);

        // 被删除方法没有 Target Chunk；这里只补充原文件剩余方法，历史调用者由 Base CodeGraph 查询。
        semanticChanges.stream().filter(change -> change.getChangeKind() == SemanticChangeKind.METHOD_DELETED)
                .forEach(change -> {
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

    private boolean globalSecurityContext(CodeChunk chunk) {
        if (chunk.getEndpoint() != null) return true;
        String text = (chunk.getAnnotations() + " " + chunk.getSymbolName() + " "
                + chunk.getFilePath()).toLowerCase(Locale.ROOT);
        return "JAVA_METHOD".equals(chunk.getChunkType()) && (text.contains("security")
                || text.contains("authorize") || text.contains("permission") || text.contains("filter")
                || text.contains("interceptor") || text.contains("controller") || text.contains("mapper"));
    }

    private boolean analyzableSource(String path) {
        return AuditSourceFilter.classify(path).createChunks();
    }

    public record ScopeResult(Set<Long> changedChunkIds, Set<Long> impactedChunkIds,
                              boolean globalConfigurationChanged,
                              Map<SemanticChangeKind, Long> semanticChangeCounts) {
        public String semanticChangeSummary() {
            if (semanticChangeCounts.isEmpty()) return "无方法级语义变化";
            return semanticChangeCounts.entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(java.util.stream.Collectors.joining("，"));
        }
    }
}
