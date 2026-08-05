package com.deepaudit.agent;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import com.deepaudit.mapper.GitFileChangeMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IncrementalReviewServiceTest {

    @Test
    void buildsOnlyChangedUnitsWithoutEmbeddingImpactedSource() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper changeMapper = mock(SemanticMethodChangeMapper.class);
        GitFileChangeMapper fileChangeMapper = mock(GitFileChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        SemanticCallEdge impactEdge = new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                1L, 2L, 2, "detail", "service.detail(id)", "CODEGRAPH_CALL",
                Confidence.HIGH, "CodeGraph confirmed", "id -> id");
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(impactEdge));
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of());
        IncrementalReviewService service = new IncrementalReviewService(
                flowMapper, edgeMapper, changeMapper, fileChangeMapper);
        CodeChunk changed = chunk(taskId, 1L, "Formatter#format", "return repository.findById(id);");
        changed.setAnalysisScope(AnalysisScope.CHANGED);
        changed.setBaseContent("return cache.get(id);");
        CodeChunk impacted = chunk(taskId, 2L, "Controller#detail", "return service.detail(id);");
        impacted.setAnalysisScope(AnalysisScope.IMPACTED);
        CodeChunk context = chunk(taskId, 3L, "Dto#value", "return value;");
        context.setAnalysisScope(AnalysisScope.CONTEXT);

        List<IncrementalReviewUnit> units = service.build(
                taskId, List.of(changed, impacted, context), Map.of(), Map.of());

        assertThat(units).extracting(IncrementalReviewUnit::primaryChunkId)
                .containsExactly(1L);
        assertThat(units.get(0).facts()).contains("DIRECT_CHANGE", "HAS_DATA_ACCESS", "HAS_CALL_RELATIONS");
        assertThat(units).allSatisfy(unit -> {
            assertThat(unit.allowedTypes()).containsExactlyInAnyOrderElementsOf(
                java.util.Set.of(VulnerabilityType.values()));
            assertThat(unit.mandatoryTypes()).isEmpty();
        });
        assertThat(units.get(0).baseCodeExcerpt()).contains("cache.get");
        assertThat(units.get(0).targetCodeExcerpt()).contains("repository.findById");
        assertThat(units.get(0).changeSummary()).contains("CODEGRAPH_CALL");
        assertThat(units.get(0).targetCodeExcerpt()).doesNotContain("return service.detail(id)");
    }

    @Test
    void exposesGuardRemovalAsMandatoryTypesWithoutClassifyingOrdinaryFacts() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper changeMapper = mock(SemanticMethodChangeMapper.class);
        GitFileChangeMapper fileChangeMapper = mock(GitFileChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        SemanticMethodChange removed = new SemanticMethodChange(taskId, SemanticChangeKind.GUARD_REMOVED,
                "load", "OrderService.java", "OrderService.java", "demo.OrderService.load",
                "demo.OrderService.load", 10, 13, 10, 12, "checkOwner(id);", "return repository.findById(id);",
                "删除对象归属校验");
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of(removed));
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of());
        IncrementalReviewService service = new IncrementalReviewService(
                flowMapper, edgeMapper, changeMapper, fileChangeMapper);
        CodeChunk changed = chunk(taskId, 10L, "OrderService#load", "return repository.findById(id);");
        changed.setFilePath("OrderService.java");
        changed.setStartLine(10);
        changed.setEndLine(12);
        changed.setAnalysisScope(AnalysisScope.CHANGED);

        IncrementalReviewUnit unit = service.build(
                taskId, List.of(changed), Map.of(), Map.of()).get(0);

        assertThat(unit.facts()).contains("GUARD_REMOVED", "HAS_DATA_ACCESS");
        assertThat(unit.mandatoryTypes()).containsExactlyInAnyOrder(
                VulnerabilityType.AUTHORIZATION, VulnerabilityType.VALIDATION_BYPASS);
        assertThat(unit.changeSummary()).contains("GUARD_REMOVED", "删除对象归属校验");
    }

    @Test
    void centersTriageExcerptOnChangedLinesNearEndOfLongMethod() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper changeMapper = mock(SemanticMethodChangeMapper.class);
        GitFileChangeMapper fileChangeMapper = mock(GitFileChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of());
        GitFileChange fileChange = new GitFileChange(taskId, "Demo.java", "Demo.java",
                "MODIFY", 1, 1, "120:120", "120:120", "tail diff", false);
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of(fileChange));
        IncrementalReviewService service = new IncrementalReviewService(
                flowMapper, edgeMapper, changeMapper, fileChangeMapper);
        String content = java.util.stream.IntStream.rangeClosed(1, 150)
                .mapToObj(line -> line == 120 ? "dangerousSink(input);" : "safeLine" + line + "();")
                .collect(java.util.stream.Collectors.joining("\n"));
        CodeChunk changed = new CodeChunk(taskId, "Demo.java", "Demo#longMethod", null,
                1, 150, content, "JAVA_METHOD", "String input", "", "dangerousSink");
        changed.setId(99L);
        changed.setAnalysisScope(AnalysisScope.CHANGED);

        IncrementalReviewUnit unit = service.build(taskId, List.of(changed), Map.of(), Map.of()).get(0);

        assertThat(unit.targetCodeExcerpt()).contains("120 | dangerousSink(input);")
                .doesNotContain("1 | safeLine1();");
    }

    private CodeChunk chunk(UUID taskId, long id, String symbol, String content) {
        CodeChunk chunk = new CodeChunk(taskId, "Demo.java", symbol, null, 1, 3, content,
                "JAVA_METHOD", "Long id", "", "findById");
        chunk.setId(id);
        return chunk;
    }
}
