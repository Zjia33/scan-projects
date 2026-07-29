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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
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
                gateway, new AiProperties(), traceService(taskId), unitService);

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
                gateway, properties, traceService, unitService);

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
                gateway, new AiProperties(), traceService, unitService);

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
        AuditUnit unit = new AuditUnit("chunk-20", 20L, "OrderService.java", "OrderService#load",
                "/orders/{id}", "CHANGED_CODE", "MODIFIED", "CHANGED",
                List.of(VulnerabilityType.AUTHORIZATION, VulnerabilityType.VALIDATION_BYPASS),
                List.of("DIRECT_CHANGE", "SEMANTIC_CHANGE", "GUARD_REMOVED"),
                "Long id", "", "findById -> repository", "删除安全 Guard：checkOwner(id)",
                "return repository.findById(id);");
        AuditUnitService unitService = mock(AuditUnitService.class);
        when(unitService.build(any(), anyList(), any(), any(), any())).thenReturn(List.of(unit));
        LlmGateway gateway = mock(LlmGateway.class);
        when(gateway.triage(any(), any(), anyList())).thenReturn(new LlmGateway.TriagePlan("模型尝试跳过",
                List.of(new LlmGateway.TriageDecision(unit.unitId(), unit.primaryChunkId(),
                        TriageDisposition.SKIP, List.of(), unit.reasonCodes(), List.of(), "无需调查"))));
        OrchestratorAgentService service = new OrchestratorAgentService(
                gateway, new AiProperties(), traceService(taskId), unitService);

        List<AgentTask> tasks = service.plan(taskId, recon(), List.of(), ScanMode.INCREMENTAL,
                Map.of(), Map.of());

        assertThat(tasks).extracting(AgentTask::vulnerabilityType)
                .containsExactlyInAnyOrder(VulnerabilityType.AUTHORIZATION,
                        VulnerabilityType.VALIDATION_BYPASS);
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

    private LlmGateway.ReconInsight recon() {
        return new LlmGateway.ReconInsight("测试项目", List.of(), List.of(), List.of());
    }
}
