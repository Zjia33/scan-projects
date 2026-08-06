package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.orchestrator.AuditCancellationService;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
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
    void mandatoryGuardRemovalStillRunsTriageForOtherVulnerabilityTypes() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit unit = unit(41,
                List.of(VulnerabilityType.AUTHORIZATION, VulnerabilityType.VALIDATION_BYPASS));
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList())).thenReturn(new LlmGateway.TriagePlan(
                "没有发现额外类型", List.of(decision(unit, TriageDisposition.SKIP,
                List.of(), List.of(), List.of()))));

        List<AgentTask> tasks = service(taskId, gateway, new AiProperties(), reviewService)
                .plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).extracting(AgentTask::agentType)
                .containsExactlyInAnyOrder(AgentType.AUTHORIZATION, AgentType.VALIDATION_BYPASS);
        verify(gateway).triageIncremental(any(), any(), anyList());
    }

    @Test
    void batchesWithoutProjectLevelTruncation() {
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
                            List.of(VulnerabilityType.SQL_INJECTION), List.of(), List.of())).toList());
        });
        AiProperties properties = new AiProperties();
        properties.setTriageBatchSize(100);

        List<AgentTask> tasks = service(taskId, gateway, properties, reviewService)
                .plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).hasSize(305);
    }

    @Test
    void triageBatchesRunWithConfiguredConcurrency() throws Exception {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit first = unit(1, List.of());
        IncrementalReviewUnit second = unit(2, List.of());
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(first, second));
        LlmGateway gateway = mock(LlmGateway.class);
        CountDownLatch twoBatchesStarted = new CountDownLatch(2);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximumActive = new AtomicInteger();
        when(gateway.triageIncremental(any(), any(), anyList())).thenAnswer(invocation -> {
            int current = active.incrementAndGet();
            maximumActive.accumulateAndGet(current, Math::max);
            twoBatchesStarted.countDown();
            try {
                if (!twoBatchesStarted.await(2, TimeUnit.SECONDS)) {
                    throw new AssertionError("Triage 批次没有并行启动");
                }
                List<IncrementalReviewUnit> batch = invocation.getArgument(2);
                return new LlmGateway.TriagePlan("批次完成", batch.stream()
                        .map(unit -> decision(unit, TriageDisposition.INVESTIGATE,
                                List.of(VulnerabilityType.SQL_INJECTION), List.of(), List.of()))
                        .toList());
            } finally {
                active.decrementAndGet();
            }
        });
        AiProperties properties = new AiProperties();
        properties.setTriageBatchSize(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        AgentTraceService traceService = mock(AgentTraceService.class);
        when(traceService.start(any(), any(), any(), any()))
                .thenReturn(new AgentRun(taskId, AgentType.ORCHESTRATOR, null, "triage"));
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, properties, traceService, reviewService, executor,
                mock(AuditCancellationService.class));

        try {
            List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), Map.of(), Map.of());

            assertThat(tasks).hasSize(2);
            assertThat(maximumActive).hasValueGreaterThan(1);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void skipCreatesNoProfessionalTaskAndNeverLoadsContext() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit unit = unit(10, List.of());
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList())).thenReturn(new LlmGateway.TriagePlan(
                "无安全相关变化", List.of(decision(unit, TriageDisposition.SKIP,
                List.of(), List.of(), List.of()))));

        List<AgentTask> tasks = service(taskId, gateway, new AiProperties(), reviewService)
                .plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).isEmpty();
        verify(reviewService).build(any(), anyList(), any(), any());
    }

    @Test
    void investigateCarriesFocusLinesAndQuestionsWithoutImpactedSource() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit unit = unit(11, List.of());
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        List<LlmGateway.LineRange> ranges = List.of(new LlmGateway.LineRange(10, 11));
        List<String> questions = List.of("调用方是否传入外部可控参数");
        when(gateway.triageIncremental(any(), any(), anyList())).thenReturn(new LlmGateway.TriagePlan(
                "存在查询变化", List.of(decision(unit, TriageDisposition.INVESTIGATE,
                List.of(VulnerabilityType.SQL_INJECTION), ranges, questions))));

        List<AgentTask> tasks = service(taskId, gateway, new AiProperties(), reviewService)
                .plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).singleElement().satisfies(task -> {
            assertThat(task.ruleHint()).contains("Triage 可疑行：10-11", "调用方是否传入外部可控参数")
                    .doesNotContain("IMPACTED_CONTEXT", unit.baseCodeExcerpt(), unit.targetCodeExcerpt());
            assertThat(task.baseChangeExcerpt()).isEqualTo(unit.baseCodeExcerpt());
            assertThat(task.targetChangeExcerpt()).isEqualTo(unit.targetCodeExcerpt());
        });
    }

    @Test
    void missingDecisionGetsOneFocusedRetryBeforeConservativeFallback() {
        UUID taskId = UUID.randomUUID();
        IncrementalReviewUnit unit = unit(12, List.of());
        IncrementalReviewService reviewService = mock(IncrementalReviewService.class);
        when(reviewService.build(any(), anyList(), any(), any())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triageIncremental(any(), any(), anyList()))
                .thenReturn(new LlmGateway.TriagePlan("缺少决定", List.of()),
                        new LlmGateway.TriagePlan("补判完成", List.of(decision(unit,
                                TriageDisposition.INVESTIGATE,
                                List.of(VulnerabilityType.SQL_INJECTION), List.of(), List.of()))));

        List<AgentTask> tasks = service(taskId, gateway, new AiProperties(), reviewService)
                .plan(taskId, recon(), List.of(), Map.of(), Map.of());

        assertThat(tasks).singleElement().extracting(AgentTask::vulnerabilityType)
                .isEqualTo(VulnerabilityType.SQL_INJECTION);
        verify(gateway, times(2)).triageIncremental(any(), any(), anyList());
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
                mandatoryTypes, List.of("DIRECT_CHANGE"), "String input", "", "repository.query",
                "return oldValue;", "return repository.query(input);", "METHOD_MODIFIED", "", 10, 15);
    }

    private LlmGateway.TriageDecision decision(IncrementalReviewUnit unit,
                                               TriageDisposition disposition,
                                               List<VulnerabilityType> types,
                                               List<LlmGateway.LineRange> ranges,
                                               List<String> questions) {
        return new LlmGateway.TriageDecision(unit.unitId(), unit.primaryChunkId(), disposition,
                types, "测试增量分流决定", ranges, questions);
    }

    private LlmGateway.ReconInsight recon() {
        return new LlmGateway.ReconInsight("测试项目", com.deepaudit.recon.TechnologyProfile.empty());
    }
}
