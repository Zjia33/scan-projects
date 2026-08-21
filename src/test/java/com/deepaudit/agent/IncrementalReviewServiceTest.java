package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IncrementalReviewServiceTest {

    @Test
    void sendsOnlyUnifiedChangeContextCenteredOnChangedLines() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper changeMapper = mock(SemanticMethodChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of());
        IncrementalReviewService service = new IncrementalReviewService(flowMapper, edgeMapper, changeMapper);
        String base = IntStream.rangeClosed(1, 60).mapToObj(line -> "line-" + line)
                .collect(java.util.stream.Collectors.joining("\n"));
        String target = base.replace("line-45", "checkAuthorization();");
        CodeChunk changed = chunk(taskId, 4L, "OrderService#load", target);
        changed.setStartLine(100);
        changed.setEndLine(159);
        changed.setBaseContent(base);
        changed.setAnalysisScope(AnalysisScope.CHANGED);

        IncrementalReviewUnit unit = service.build(
                taskId, List.of(changed), Map.of(), Map.of()).get(0);

        assertThat(unit.baseCodeExcerpt()).isEmpty();
        assertThat(unit.targetCodeExcerpt())
                .contains("[CHANGE_CONTEXT]", "- B45 | line-45",
                        "+ T144 | checkAuthorization();", "T139 | line-40", "T149 | line-50")
                .doesNotContain("line-1\n", "line-20\n");
        LlmGateway.Target professionalTarget = AgentPromptSupport.target(changed, java.util.Set.of());
        assertThat(professionalTarget.baseCodeExcerpt()).isEmpty();
        assertThat(professionalTarget.codeExcerpt())
                .contains("[CHANGE_CONTEXT]", "+ T144 | checkAuthorization();")
                .doesNotContain("line-1\n");
    }

    @Test
    void buildsOnlyChangedUnitsAndAddsImpactedCodeOnDemand() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper changeMapper = mock(SemanticMethodChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        SemanticCallEdge impactEdge = new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                1L, 2L, 2, "detail", "service.detail(id)", "CODEGRAPH_CALL",
                Confidence.HIGH, "CodeGraph confirmed", "id -> id");
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(impactEdge));
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of());
        IncrementalReviewService service = new IncrementalReviewService(flowMapper, edgeMapper, changeMapper);
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
        assertThat(units.get(0).baseCodeExcerpt()).isEmpty();
        assertThat(units.get(0).targetCodeExcerpt())
                .contains("[CHANGE_CONTEXT]", "- B1 | return cache.get(id);",
                        "+ T1 | return repository.findById(id);");
        assertThat(units.get(0).relatedContext()).doesNotContain("return service.detail(id)");

        IncrementalReviewUnit enriched = service.enrichImpact(
                taskId, units, List.of(changed, impacted, context)).get(0);

        assertThat(enriched.relatedContext()).contains("[IMPACTED_CONTEXT]", "CHUNK_ID=2",
                "Controller#detail", "return service.detail(id)");
        assertThat(enriched.relatedContext()).doesNotContain("Dto#value");
    }

    @Test
    void exposesGuardRemovalAsMandatoryTypesWithoutClassifyingOrdinaryFacts() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper changeMapper = mock(SemanticMethodChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        SemanticMethodChange removed = new SemanticMethodChange(taskId, SemanticChangeKind.GUARD_REMOVED,
                "load", "OrderService.java", "OrderService.java", "demo.OrderService.load",
                "demo.OrderService.load", 10, 13, 10, 12, "checkOwner(id);", "return repository.findById(id);",
                "删除对象归属校验");
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of(removed));
        IncrementalReviewService service = new IncrementalReviewService(flowMapper, edgeMapper, changeMapper);
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
    void skipsChangedDataCarrierFilesEvenWhenMandatoryEvidenceMatchesButKeepsContextReadable() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper changeMapper = mock(SemanticMethodChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        SemanticCallEdge contextEdge = new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                23L, 26L, 2, "toResult", "toResult(order)", "CODEGRAPH_CALL",
                Confidence.HIGH, "CodeGraph confirmed", "order -> order");
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(contextEdge));
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of());
        IncrementalReviewService service = new IncrementalReviewService(flowMapper, edgeMapper, changeMapper);

        CodeChunk dto = chunk(taskId, 21L, "UserDTO#getName", "return name;");
        dto.setFilePath("src/main/java/demo/dto/UserDTO.java");
        dto.setAnalysisScope(AnalysisScope.CHANGED);
        CodeChunk entity = chunk(taskId, 22L, "OrderEntity#getId", "return id;");
        entity.setFilePath("src\\main\\java\\demo\\entity\\OrderEntity.java");
        entity.setAnalysisScope(AnalysisScope.CHANGED);
        CodeChunk regular = chunk(taskId, 23L, "OrderEntityService#load", "return repository.findById(id);");
        regular.setFilePath("src/main/java/demo/service/OrderEntityService.java");
        regular.setAnalysisScope(AnalysisScope.CHANGED);
        CodeChunk dtoPackageOnly = chunk(taskId, 24L, "UserRequest#getName", "return name;");
        dtoPackageOnly.setFilePath("src/main/java/demo/dto/UserRequest.java");
        dtoPackageOnly.setAnalysisScope(AnalysisScope.CHANGED);
        CodeChunk mandatoryDto = chunk(taskId, 25L, "CredentialDTO#getToken", "return token;");
        mandatoryDto.setFilePath("src/main/java/demo/dto/CredentialDTO.java");
        mandatoryDto.setAnalysisScope(AnalysisScope.CHANGED);
        CodeChunk contextDto = chunk(taskId, 26L, "OrderResultDTO#getId", "return orderId;");
        contextDto.setFilePath("src/main/java/demo/dto/OrderResultDTO.java");
        contextDto.setAnalysisScope(AnalysisScope.CONTEXT);

        List<IncrementalReviewUnit> units = service.build(taskId,
                List.of(dto, entity, regular, dtoPackageOnly, mandatoryDto, contextDto),
                Map.of(25L, java.util.Set.of(VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE)),
                Map.of(25L, "确定性敏感信息调查线索"));

        assertThat(units).extracting(IncrementalReviewUnit::primaryChunkId)
                .containsExactly(23L, 24L);
        IncrementalReviewUnit enriched = service.enrich(taskId, units,
                List.of(dto, entity, regular, dtoPackageOnly, mandatoryDto, contextDto)).stream()
                .filter(unit -> unit.primaryChunkId() == 23L)
                .findFirst().orElseThrow();
        assertThat(enriched.relatedContext()).contains(
                "[CONTEXT CHUNK_ID=26]", "OrderResultDTO#getId", "return orderId;");
    }

    private CodeChunk chunk(UUID taskId, long id, String symbol, String content) {
        CodeChunk chunk = new CodeChunk(taskId, "Demo.java", symbol, null, 1, 3, content,
                "JAVA_METHOD", "Long id", "", "findById");
        chunk.setId(id);
        return chunk;
    }
}
