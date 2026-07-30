package com.deepaudit.agent;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditUnitServiceTest {

    @Test
    void skipsIsolatedBoilerplateButKeepsExternalEntryAndRuleHint() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper semanticChangeMapper = mock(SemanticMethodChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(semanticChangeMapper.findByTaskId(taskId)).thenReturn(List.of());
        AuditUnitService service = new AuditUnitService(flowMapper, edgeMapper, semanticChangeMapper);

        CodeChunk getter = chunk(1L, "src/main/java/demo/UserDto.java", "UserDto#getName",
                null, "return name;");
        CodeChunk endpoint = chunk(2L, "src/main/java/demo/UserController.java", "UserController#detail",
                "/users/{id}", "return userService.findById(id);");
        CodeChunk hinted = chunk(3L, "src/main/java/demo/QueryService.java", "QueryService#lookup",
                null, "return helper.lookup(input);");

        List<AuditUnit> units = service.build(taskId, List.of(getter, endpoint, hinted), ScanMode.FULL,
                Map.of(3L, Set.of(VulnerabilityType.SQL_INJECTION)),
                Map.of(3L, "动态查询线索"));

        assertThat(units).extracting(AuditUnit::primaryChunkId).containsExactly(2L, 3L);
        assertThat(units.get(0).reasonCodes()).contains("EXTERNAL_ENTRY", "DANGEROUS_DATA_ACCESS");
        assertThat(units.get(1).reasonCodes()).contains("RULE_HINT");

        System.out.println(units);
    }

    @Test
    void doesNotGuessEveryVulnerabilityTypeForUnclassifiedChangedCode() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper semanticChangeMapper = mock(SemanticMethodChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(semanticChangeMapper.findByTaskId(taskId)).thenReturn(List.of());
        AuditUnitService service = new AuditUnitService(flowMapper, edgeMapper, semanticChangeMapper);
        CodeChunk changed = chunk(8L, "src/main/java/demo/Formatter.java", "Formatter#format",
                null, "return value.strip();");
        changed.setAnalysisScope(AnalysisScope.CHANGED);

        List<AuditUnit> units = service.build(taskId, List.of(changed), ScanMode.INCREMENTAL,
                Map.of(), Map.of());

        assertThat(units).isEmpty();
    }

    @Test
    void exposesRemovedGuardAsDeterministicAuditFact() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper semanticChangeMapper = mock(SemanticMethodChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        SemanticMethodChange removed = new SemanticMethodChange(taskId,
                SemanticChangeKind.GUARD_REMOVED, "load", "OrderService.java", "OrderService.java",
                "demo.OrderService.load(Long)", "demo.OrderService.load(Long)",
                1, 4, 1, 3, "checkOwner(id);", "return repository.findById(id);",
                "删除安全 Guard：checkOwner(id)");
        when(semanticChangeMapper.findByTaskId(taskId)).thenReturn(List.of(removed));
        AuditUnitService service = new AuditUnitService(flowMapper, edgeMapper, semanticChangeMapper);
        CodeChunk changed = chunk(9L, "OrderService.java", "OrderService#load",
                null, "return repository.findById(id);");
        changed.setAnalysisScope(AnalysisScope.CHANGED);

        List<AuditUnit> units = service.build(taskId, List.of(changed), ScanMode.INCREMENTAL,
                Map.of(), Map.of());

        assertThat(units).singleElement().satisfies(unit -> {
            assertThat(unit.reasonCodes()).contains("SEMANTIC_CHANGE", "GUARD_REMOVED");
            assertThat(unit.candidateTypes()).contains(VulnerabilityType.AUTHORIZATION,
                    VulnerabilityType.VALIDATION_BYPASS);
            assertThat(unit.contextSummary()).contains("删除安全 Guard", "checkOwner");
        });
    }

    @Test
    void ignoresLegacyFinancialRiskHintsWhenBuildingNewAuditUnits() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticMethodChangeMapper semanticChangeMapper = mock(SemanticMethodChangeMapper.class);
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(semanticChangeMapper.findByTaskId(taskId)).thenReturn(List.of());
        AuditUnitService service = new AuditUnitService(flowMapper, edgeMapper, semanticChangeMapper);
        CodeChunk payment = chunk(10L, "src/main/java/demo/PaymentService.java",
                "PaymentService#settle", null, "return completed;");

        List<AuditUnit> units = service.build(taskId, List.of(payment), ScanMode.FULL,
                Map.of(10L, Set.of(VulnerabilityType.FINANCIAL_RISK)),
                Map.of(10L, "旧版资金风险提示"));

        assertThat(units).isEmpty();
    }

    private CodeChunk chunk(long id, String path, String symbol, String endpoint, String content) {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), path, symbol, endpoint,
                1, 3, content, "JAVA_METHOD", "String input", "", "helper");
        chunk.setId(id);
        return chunk;
    }
}
