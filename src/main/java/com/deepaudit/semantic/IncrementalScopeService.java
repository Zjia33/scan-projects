package com.deepaudit.semantic;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.EnumMap;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class IncrementalScopeService {
    private final GitFileChangeMapper changeMapper;
    private final SemanticMethodChangeMapper semanticChangeMapper;

    // 只确定直接变化；上下文完全由专业 Agent 在调查时按需选择。
    public ScopeResult determine(UUID taskId, List<CodeChunk> chunks) {
        Set<Long> changed = new LinkedHashSet<>();
        for (CodeChunk chunk : chunks) {
            if (chunk.getAnalysisScope() == AnalysisScope.CHANGED && chunk.getId() != null) {
                changed.add(chunk.getId());
            }
        }
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
        boolean globalConfigurationChanged = changeMapper.findByTaskId(taskId).stream()
                .anyMatch(com.deepaudit.domain.GitFileChange::isConfigurationChange);
        Map<SemanticChangeKind, Long> semanticCounts = new EnumMap<>(SemanticChangeKind.class);
        for (SemanticMethodChange change : semanticChanges) {
            semanticCounts.merge(change.getChangeKind(), 1L, Long::sum);
        }
        return new ScopeResult(Set.copyOf(changed), globalConfigurationChanged,
                Map.copyOf(semanticCounts));
    }

    public record ScopeResult(Set<Long> changedChunkIds, boolean globalConfigurationChanged,
                              Map<SemanticChangeKind, Long> semanticChangeCounts) {
        public String semanticChangeSummary() {
            if (semanticChangeCounts.isEmpty()) return "无方法级语义变化";
            return semanticChangeCounts.entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(java.util.stream.Collectors.joining("，"));
        }
    }
}
