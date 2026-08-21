package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchestratorAgentServiceTest {

    @Test
    void routesSensitiveInformationToDedicatedProfessionalAgent() {
        assertThat(OrchestratorAgentService.agentFor(VulnerabilityType.AUTHORIZATION))
                .isEqualTo(AgentType.AUTHORIZATION);
        assertThat(OrchestratorAgentService.agentFor(VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE))
                .isEqualTo(AgentType.SENSITIVE_INFORMATION);
    }

    @Test
    void guardRemovalCannotBeSkippedByTriage() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit unit = unit(41,
                List.of(VulnerabilityType.AUTHORIZATION, VulnerabilityType.VALIDATION_BYPASS));
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        OrchestratorAgentService service = service(taskId, gateway, new AiProperties(), reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).extracting(AgentTask::agentType)
                .containsExactlyInAnyOrder(AgentType.AUTHORIZATION, AgentType.VALIDATION_BYPASS);
        verify(gateway, never()).triageIncremental(any(), any(), anyList());
    }

    @Test
    void doesNotTruncateIncrementalUnitsAtProjectLevel() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        List<IncrementalReviewUnit> units = new ArrayList<>();
        for (int index = 1; index <= 305; index++) units.add(unit(index, List.of()));
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(units);
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList())).thenAnswer(invocation -> {
            List<IncrementalReviewUnit> batch = invocation.getArgument(2);
            return new LlmGateway.TriagePlan("批次完成", batch.stream()
                    .map(unit -> decision(unit, TriageDisposition.INVESTIGATE,
                            List.of(VulnerabilityType.SQL_INJECTION))).toList());
        });
        AiProperties properties = new AiProperties();
        properties.setTriageBatchSize(100);
        OrchestratorAgentService service = service(taskId, gateway, properties, reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).hasSize(305);
    }

    @Test
    void enrichesNeedContextExactlyOnceBeforeFinalDecision() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit original = unit(9, List.of());
        IncrementalReviewUnit enriched = original.withRelatedContext("CHUNK 10 OrderMapper#findById");
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(original));
        when(reviewService.enrich(any(), anyList(), anyList())).thenReturn(List.of(enriched));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList())).thenReturn(new LlmGateway.TriagePlan(
                "需要上下文", List.of(decision(original, TriageDisposition.NEED_CONTEXT, List.of()))));
        when(gateway.triageIncrementalFinal(any(), any(), any())).thenReturn(new LlmGateway.TriagePlan(
                "复判完成", List.of(decision(enriched, TriageDisposition.INVESTIGATE,
                List.of(VulnerabilityType.AUTHORIZATION)))));
        OrchestratorAgentService service = service(taskId, gateway, new AiProperties(), reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).singleElement().satisfies(task -> {
            assertThat(task.chunkId()).isEqualTo(9L);
            assertThat(task.agentType()).isEqualTo(AgentType.AUTHORIZATION);
            assertThat(task.ruleHint()).contains("CHUNK 10 OrderMapper#findById");
        });
        verify(reviewService).enrich(any(), anyList(), anyList());
    }

    @Test
    void doesNotLoadImpactedCodeForSkippedChange() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit unit = unit(10, List.of());
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList())).thenReturn(new LlmGateway.TriagePlan(
                "无需调查", List.of(decision(unit, TriageDisposition.SKIP, List.of()))));
        OrchestratorAgentService service = service(taskId, gateway, new AiProperties(), reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).isEmpty();
        verify(reviewService, never()).enrich(any(), anyList(), anyList());
        verify(reviewService, never()).enrichImpact(any(), anyList(), anyList());
    }

    @Test
    void addsImpactedCodeAfterInvestigateDecision() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit original = unit(11, List.of());
        IncrementalReviewUnit enriched = original.withRelatedContext(
                "[IMPACTED_CONTEXT] [IMPACTED CHUNK_ID=20] Service#load");
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(original));
        when(reviewService.enrichImpact(any(), anyList(), anyList())).thenReturn(List.of(enriched));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList())).thenReturn(new LlmGateway.TriagePlan(
                "进入调查", List.of(decision(original, TriageDisposition.INVESTIGATE,
                List.of(VulnerabilityType.AUTHORIZATION)))));
        OrchestratorAgentService service = service(taskId, gateway, new AiProperties(), reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).singleElement().satisfies(task ->
                assertThat(task.ruleHint()).contains("[IMPACTED_CONTEXT]", "CHUNK_ID=20"));
        verify(reviewService).enrichImpact(any(), anyList(), anyList());
        verify(reviewService, never()).enrich(any(), anyList(), anyList());
    }

    @Test
    void conservativelyInvestigatesMissingFinalDecisionInsteadOfFailingOrSkippingChange() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit unit = unit(12, List.of());
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        when(reviewService.enrich(any(), anyList(), anyList())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList()))
                .thenReturn(new LlmGateway.TriagePlan("缺少决定", List.of()));
        when(gateway.triageIncrementalFinal(any(), any(), any()))
                .thenReturn(new LlmGateway.TriagePlan("仍缺少决定", List.of()));
        OrchestratorAgentService service = service(taskId, gateway, new AiProperties(), reviewService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).hasSize(VulnerabilityType.values().length);
        assertThat(tasks).extracting(AgentTask::chunkId).containsOnly(12L);
        assertThat(tasks).extracting(AgentTask::vulnerabilityType)
                .containsExactlyInAnyOrder(VulnerabilityType.values());
    }

    private OrchestratorAgentService service(UUID taskId, LlmGateway gateway,
                                             AiProperties properties,
                                             IncrementalReviewService reviewService) {
        AgentTraceService traceService = mock(AgentTraceService.class);
        when(traceService.start(any(), any(), any(), any()))
                .thenReturn(new AgentRun(taskId, AgentType.ORCHESTRATOR, null, "triage"));
        return new OrchestratorAgentService(gateway, properties, traceService, reviewService);
    }

    private IncrementalReviewUnit unit(long id, List<VulnerabilityType> mandatoryTypes) {
        return new IncrementalReviewUnit("change-" + id, id, "Demo.java", "Demo#change", "/demo",
                "JAVA_METHOD", "MODIFIED", List.of(VulnerabilityType.values()),
                mandatoryTypes, List.of("DIRECT_CHANGE"),
                "String input", "", "repository.query", "return oldValue;", "return newValue;",
                "METHOD_MODIFIED", "", "");
    }

    private LlmGateway.TriageDecision decision(IncrementalReviewUnit unit,
                                               TriageDisposition disposition,
                                               List<VulnerabilityType> types) {
        return new LlmGateway.TriageDecision(unit.unitId(), unit.primaryChunkId(), disposition,
                types, "测试增量分流决定");
    }

    private LlmGateway.ReconInsight recon() {
        return new LlmGateway.ReconInsight("测试项目", com.deepaudit.recon.TechnologyProfile.empty());
    }
}
