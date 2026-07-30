package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchestratorAgentServiceTest {

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void logsThreeStateAuditUnitCounts(CapturedOutput output) {
        UUID taskId = UUID.randomUUID();
        AuditUnit investigate = unit(1, List.of("DANGEROUS_DATA_ACCESS"));
        AuditUnit needContext = unit(2, List.of("UNRESOLVED_CALL"));
        AuditUnit skip = unit(3, List.of("EXTERNAL_ENTRY"));
        AuditUnitService unitService = mock(AuditUnitService.class);
        when(unitService.build(any(), anyList(), any(), any(), any()))
                .thenReturn(List.of(investigate, needContext, skip));
        when(unitService.enrich(any(), anyList(), anyList())).thenReturn(List.of(needContext));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triage(any(), any(), anyList()))
                .thenReturn(new LlmGateway.TriagePlan("初次分流", List.of(
                        decision(investigate, TriageDisposition.INVESTIGATE,
                                List.of(VulnerabilityType.SQL_INJECTION)),
                        decision(needContext, TriageDisposition.NEED_CONTEXT, List.of()),
                        decision(skip, TriageDisposition.SKIP, List.of()))))
                .thenReturn(new LlmGateway.TriagePlan("复判", List.of(
                        decision(needContext, TriageDisposition.SKIP, List.of()))));
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, new AiProperties(), traceService(taskId), unitService,
                mock(IncrementalReviewService.class));

        service.plan(taskId, recon(), List.of(), ScanMode.FULL, Map.of(), Map.of());

        assertThat(output).contains("审计单元三态统计（初次轻量分流）：总数=3，"
                + "INVESTIGATE=1，NEED_CONTEXT=1，SKIP=1");
        assertThat(output).contains("审计单元三态统计（补充上下文后复判）：总数=1，"
                + "INVESTIGATE=0，NEED_CONTEXT=0，SKIP=1");
    }

    @Test
    void doesNotTruncateSecurityRelevantUnitsAtThreeHundred() {
        UUID taskId = UUID.randomUUID();
        AuditUnitService unitService = mock(AuditUnitService.class);
        AgentTraceService traceService = traceService(taskId);
        LlmGateway gateway = mock(LlmGateway.class);
        AiProperties properties = new AiProperties();
        properties.setTriageBatchSize(100);
        List<AuditUnit> units = new ArrayList<>();
        for (int index = 1; index <= 305; index++) {
            units.add(unit(index, List.of("DANGEROUS_DATA_ACCESS")));
        }
        when(unitService.build(any(), anyList(), any(), any(), any())).thenReturn(units);
        when(gateway.triage(any(), any(), anyList())).thenAnswer(invocation -> {
            List<AuditUnit> batch = invocation.getArgument(2);
            List<LlmGateway.TriageDecision> decisions = batch.stream().map(unit ->
                    new LlmGateway.TriageDecision(unit.unitId(), unit.primaryChunkId(),
                            TriageDisposition.INVESTIGATE, List.of(VulnerabilityType.SQL_INJECTION),
                            unit.reasonCodes(), List.of(), "存在数据访问事实")).toList();
            return new LlmGateway.TriagePlan("已完成批次分流", decisions);
        });
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, properties, traceService, unitService,
                mock(IncrementalReviewService.class));

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), ScanMode.FULL,
                Map.of(), Map.of());

        assertThat(tasks).hasSize(305);
    }

    @Test
    void enrichesNeedContextOnceBeforeCreatingProfessionalTask() {
        UUID taskId = UUID.randomUUID();
        AuditUnit original = unit(9, List.of("UNRESOLVED_CALL"));
        AuditUnit enriched = original.withContext("CHUNK 10 OrderMapper#findById");
        AuditUnitService unitService = mock(AuditUnitService.class);
        when(unitService.build(any(), anyList(), any(), any(), any())).thenReturn(List.of(original));
        when(unitService.enrich(any(), anyList(), anyList())).thenReturn(List.of(enriched));
        AgentTraceService traceService = traceService(taskId);
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triage(any(), any(), anyList()))
                .thenReturn(new LlmGateway.TriagePlan("需要调用链", List.of(
                        new LlmGateway.TriageDecision(original.unitId(), original.primaryChunkId(),
                                TriageDisposition.NEED_CONTEXT, List.of(), original.reasonCodes(),
                                List.of("CALL_CHAIN"), "调用目标尚未解析"))))
                .thenReturn(new LlmGateway.TriagePlan("上下文已充分", List.of(
                        new LlmGateway.TriageDecision(enriched.unitId(), enriched.primaryChunkId(),
                                TriageDisposition.INVESTIGATE,
                                List.of(VulnerabilityType.SQL_INJECTION), enriched.reasonCodes(),
                                List.of(), "补充调用链后确认需要调查"))));
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, new AiProperties(), traceService, unitService,
                mock(IncrementalReviewService.class));

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), ScanMode.FULL,
                Map.of(), Map.of());

        assertThat(tasks).singleElement().satisfies(task -> {
            assertThat(task.chunkId()).isEqualTo(9L);
            assertThat(task.agentType()).isEqualTo(AgentType.SQL_INJECTION);
        });
        verify(unitService).enrich(any(), anyList(), anyList());
    }

    @Test
    void guardRemovalCannotBeSkippedByTriage() {
        UUID taskId = UUID.randomUUID();
        AuditUnitService unitService = mock(AuditUnitService.class);
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        IncrementalReviewUnit unit = incrementalUnit(20L, "CHANGED",
                List.of(VulnerabilityType.AUTHORIZATION, VulnerabilityType.VALIDATION_BYPASS));
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, new AiProperties(), traceService(taskId), unitService, reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), ScanMode.INCREMENTAL,
                Map.of(), Map.of());

        assertThat(tasks).extracting(AgentTask::vulnerabilityType)
                .containsExactlyInAnyOrder(VulnerabilityType.AUTHORIZATION,
                        VulnerabilityType.VALIDATION_BYPASS);
        verify(gateway, never()).triageIncremental(any(), any(), anyList());
        verify(unitService, never()).build(any(), anyList(), any(), any(), any());
    }

    @Test
    void incrementalReviewCoversChangedAndImpactedWithoutAuditUnitCandidateTypes() {
        UUID taskId = UUID.randomUUID();
        AuditUnitService auditUnitService = mock(AuditUnitService.class);
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        IncrementalReviewUnit changed = incrementalUnit(31L, "CHANGED", List.of());
        IncrementalReviewUnit impacted = incrementalUnit(32L, "IMPACTED", List.of());
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(changed, impacted));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList())).thenReturn(new LlmGateway.TriagePlan(
                "已比较全部真实差异", List.of(
                incrementalDecision(changed, TriageDisposition.INVESTIGATE,
                        List.of(VulnerabilityType.SQL_INJECTION)),
                incrementalDecision(impacted, TriageDisposition.SKIP, List.of()))));
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, new AiProperties(), traceService(taskId), auditUnitService, reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), ScanMode.INCREMENTAL,
                Map.of(), Map.of());

        assertThat(tasks).singleElement().satisfies(task -> {
            assertThat(task.chunkId()).isEqualTo(31L);
            assertThat(task.vulnerabilityType()).isEqualTo(VulnerabilityType.SQL_INJECTION);
        });
        verify(gateway).triageIncremental(any(), any(), anyList());
        verify(auditUnitService, never()).build(any(), anyList(), any(), any(), any());
    }

    @Test
    void incrementalReviewEnrichesContextExactlyOnceBeforeClassification() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        IncrementalReviewUnit original = incrementalUnit(41L, "IMPACTED", List.of());
        IncrementalReviewUnit enriched = original.withRelatedContext("CHUNK 42 Repository#query");
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(original));
        when(reviewService.enrich(any(), anyList(), anyList())).thenReturn(List.of(enriched));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList()))
                .thenReturn(new LlmGateway.TriagePlan("需要调用上下文", List.of(
                        incrementalDecision(original, TriageDisposition.NEED_CONTEXT, List.of()))))
                .thenReturn(new LlmGateway.TriagePlan("已确认调查类型", List.of(
                        incrementalDecision(enriched, TriageDisposition.INVESTIGATE,
                                List.of(VulnerabilityType.AUTHORIZATION)))));
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, new AiProperties(), traceService(taskId), mock(AuditUnitService.class), reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), ScanMode.INCREMENTAL,
                Map.of(), Map.of());

        assertThat(tasks).singleElement().extracting(AgentTask::vulnerabilityType)
                .isEqualTo(VulnerabilityType.AUTHORIZATION);
        verify(reviewService).enrich(any(), anyList(), anyList());
    }

    @Test
    void incrementalReviewFailsInsteadOfSilentlyDroppingUnclassifiedLocation() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        IncrementalReviewUnit unit = incrementalUnit(51L, "CHANGED", List.of());
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        when(reviewService.enrich(any(), anyList(), anyList())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList()))
                .thenReturn(new LlmGateway.TriagePlan("遗漏决定", List.of()));
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, new AiProperties(), traceService(taskId), mock(AuditUnitService.class), reviewService);

        assertThatThrownBy(() -> service.plan(taskId, recon(), List.of(), ScanMode.INCREMENTAL,
                Map.of(), Map.of()))
                .isInstanceOf(com.deepaudit.ai.AiResponseFormatException.class)
                .hasMessageContaining("change-51");
    }

    private AgentTraceService traceService(UUID taskId) {
        AgentTraceService traceService = mock(AgentTraceService.class);
        when(traceService.start(any(), any(), any(), any()))
                .thenReturn(new AgentRun(taskId, AgentType.ORCHESTRATOR, null, "triage"));
        return traceService;
    }

    private AuditUnit unit(long id, List<String> reasonCodes) {
        return new AuditUnit("chunk-" + id, id, "Demo.java", "Demo#query", "/query",
                "EXTERNAL_ENTRY", "UNCHANGED", "FULL",
                List.of(VulnerabilityType.SQL_INJECTION), reasonCodes,
                "String input", "@GetMapping", "execute -> database", "", "execute(input)");
    }

    private LlmGateway.TriageDecision decision(AuditUnit unit, TriageDisposition disposition,
                                               List<VulnerabilityType> types) {
        return new LlmGateway.TriageDecision(unit.unitId(), unit.primaryChunkId(), disposition,
                types, unit.reasonCodes(), List.of(), "测试分流决定");
    }

    private IncrementalReviewUnit incrementalUnit(long id, String scope,
                                                   List<VulnerabilityType> mandatoryTypes) {
        return new IncrementalReviewUnit("change-" + id, id, "Demo.java", "Demo#change", "/demo",
                "JAVA_METHOD", "MODIFIED", scope, VulnerabilityType.detectableValues().stream().toList(),
                mandatoryTypes, List.of(scope.equals("CHANGED") ? "DIRECT_CHANGE" : "IMPACTED_BY_CHANGE"),
                "String input", "", "repository.query", "return oldValue;", "return newValue;",
                "METHOD_MODIFIED", "", "");
    }

    private LlmGateway.TriageDecision incrementalDecision(
            IncrementalReviewUnit unit, TriageDisposition disposition, List<VulnerabilityType> types) {
        return new LlmGateway.TriageDecision(unit.unitId(), unit.primaryChunkId(), disposition,
                types, unit.facts(), List.of(), "测试增量分流决定");
    }

    private LlmGateway.ReconInsight recon() {
        return new LlmGateway.ReconInsight("测试项目", List.of(), List.of(), List.of());
    }
}
