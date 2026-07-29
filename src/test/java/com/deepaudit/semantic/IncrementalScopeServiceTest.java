package com.deepaudit.semantic;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IncrementalScopeServiceTest {
    @Test
    void deletedMethodImpactsRemainingCallersAndMethodsInItsTargetFile() {
        UUID taskId = UUID.randomUUID();
        String servicePath = "src/main/java/demo/OrderService.java";
        CodeChunk caller = chunk(1L, "src/main/java/demo/OrderController.java", "OrderController#load");
        CodeChunk sibling = chunk(2L, servicePath, "OrderService#remaining");
        SemanticCallEdge unresolved = new SemanticCallEdge(taskId, UUID.randomUUID(), null,
                1L, null, 8, "removed", "service.removed()", "UNRESOLVED",
                Confidence.LOW, "目标已删除", "");
        SemanticMethodChange deleted = new SemanticMethodChange(taskId, SemanticChangeKind.METHOD_DELETED,
                "removed", servicePath, servicePath, "demo.OrderService.removed()", null,
                10, 12, null, null, "void removed() {}", "", "方法已删除");
        GitFileChange fileChange = new GitFileChange(taskId, servicePath, servicePath,
                "MODIFY", 0, 3, "10:12", "", "", false);

        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        GitFileChangeMapper fileChangeMapper = mock(GitFileChangeMapper.class);
        SemanticMethodChangeMapper semanticChangeMapper = mock(SemanticMethodChangeMapper.class);
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(unresolved));
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of(fileChange));
        when(semanticChangeMapper.findByTaskId(taskId)).thenReturn(List.of(deleted));

        IncrementalScopeService.ScopeResult result = new IncrementalScopeService(
                edgeMapper, fileChangeMapper, semanticChangeMapper).determine(taskId, List.of(caller, sibling));

        assertThat(result.impactedChunkIds()).containsExactlyInAnyOrder(1L, 2L);
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
