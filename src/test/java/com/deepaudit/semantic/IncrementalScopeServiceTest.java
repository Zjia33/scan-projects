package com.deepaudit.semantic;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IncrementalScopeServiceTest {
    @Test
    void deletedMethodUsesChangedDiffAnchorWithoutPreloadingSiblingMethods() {
        UUID taskId = UUID.randomUUID();
        String servicePath = "src/main/java/demo/OrderService.java";
        CodeChunk caller = chunk(1L, "src/main/java/demo/OrderController.java", "OrderController#load");
        CodeChunk sibling = chunk(2L, servicePath, "OrderService#remaining");
        CodeChunk deletionAnchor = chunk(3L, servicePath, "demo.OrderService.removed()");
        deletionAnchor.setChunkType("JAVA_METHOD_DELETED");
        deletionAnchor.setAnalysisScope(AnalysisScope.CHANGED);
        SemanticMethodChange deleted = new SemanticMethodChange(taskId, SemanticChangeKind.METHOD_DELETED,
                "removed", servicePath, servicePath, "demo.OrderService.removed()", null,
                10, 12, null, null, "void removed() {}", "", "方法已删除");
        GitFileChange fileChange = new GitFileChange(taskId, servicePath, servicePath,
                "MODIFY", 0, 3, "10:12", "", "", false);

        GitFileChangeMapper fileChangeMapper = mock(GitFileChangeMapper.class);
        SemanticMethodChangeMapper semanticChangeMapper = mock(SemanticMethodChangeMapper.class);
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of(fileChange));
        when(semanticChangeMapper.findByTaskId(taskId)).thenReturn(List.of(deleted));

        IncrementalScopeService.ScopeResult result = new IncrementalScopeService(
                fileChangeMapper, semanticChangeMapper).determine(taskId,
                List.of(caller, sibling, deletionAnchor));

        assertThat(result.changedChunkIds()).containsExactly(3L);
        assertThat(result.semanticChangeCounts()).containsEntry(SemanticChangeKind.METHOD_DELETED, 1L);
    }

    private CodeChunk chunk(long id, String path, String symbol) {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), path, symbol, null,
                1, 20, "method", "JAVA_METHOD", "", "", "");
        chunk.setId(id);
        chunk.setAnalysisScope(AnalysisScope.CONTEXT);
        return chunk;
    }
}
