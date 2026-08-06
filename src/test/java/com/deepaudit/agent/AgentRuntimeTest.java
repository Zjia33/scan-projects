package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.orchestrator.AuditCancellationService;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentRuntimeTest {

    @Test
    void executesEachToolCallAndCompactsOlderObservations() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AiProperties properties = new AiProperties();
        properties.setMaxIterationsPerAgent(5);
        properties.setMaxToolCallsPerAgent(5);
        AuditToolService toolService = mock(AuditToolService.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        AuditCancellationService cancellationService = mock(AuditCancellationService.class);
        AgentRuntime runtime = new AgentRuntime(gateway, properties, toolService, traceService,
                hypothesisMapper, semanticEvidenceService, cancellationService);
        CodeChunk target = chunk(taskId, 1L, "Controller#entry", "service.load(input);");
        CodeChunk candidate = chunk(taskId, 2L, "OrderService#load", "return repository.find(input);");
        List<CodeChunk> chunks = List.of(target, candidate);
        AgentTask task = new AgentTask(1L, AgentType.AUTHORIZATION,
                VulnerabilityType.AUTHORIZATION, "检查授权；规则线索");

        when(traceService.start(eq(taskId), eq(AgentType.AUTHORIZATION), eq(1L), any()))
                .thenReturn(new AgentRun(taskId, AgentType.AUTHORIZATION, 1L, "entry"));
        when(semanticEvidenceService.query(taskId, 1L, 10,
                VulnerabilityType.AUTHORIZATION))
                .thenReturn(new SemanticEvidenceService.EvidenceResult("", Set.of()));
        when(gateway.decide(any())).thenReturn(
                tool("search_code", Map.of("query", "load"), "搜索调用"),
                tool("read_source", Map.of("chunkId", 2L, "startLine", 1, "endLine", 2),
                        "读取候选"),
                tool("read_source", Map.of("chunkId", 2L, "startLine", 1, "endLine", 2),
                        "重复读取"),
                new LlmGateway.AgentDecision("REJECT", null, Map.of(), "证据不足", null));
        when(toolService.execute(anyString(), anyMap(), eq(target), eq(chunks),
                eq(VulnerabilityType.AUTHORIZATION),
                any(ToolSessionContext.class))).thenReturn(
                new ToolResult("search result\n" + "x".repeat(5_000),
                        Set.of(1L), Set.of(2L)),
                new ToolResult("source range", Set.of(), Set.of(2L)),
                new ToolResult("source range repeated", Set.of(), Set.of(2L)));

        runtime.investigate(taskId, task, null, chunks);

        verify(toolService, times(3)).execute(anyString(), anyMap(), eq(target), eq(chunks),
                eq(VulnerabilityType.AUTHORIZATION),
                any(ToolSessionContext.class));
        ArgumentCaptor<LlmGateway.AgentTurn> turns = ArgumentCaptor.forClass(LlmGateway.AgentTurn.class);
        verify(gateway, times(4)).decide(turns.capture());
        LlmGateway.AgentTurn finalTurn = turns.getAllValues().get(3);
        assertThat(turns.getAllValues().get(0).budget()).satisfies(budget -> {
            assertThat(budget.currentRound()).isEqualTo(1);
            assertThat(budget.totalDecisionRounds()).isEqualTo(6);
            assertThat(budget.toolCallsRemaining()).isEqualTo(5);
            assertThat(budget.finalDecisionOnly()).isFalse();
        });
        assertThat(finalTurn.budget().toolCallsRemaining()).isEqualTo(2);
        assertThat(finalTurn.observations()).hasSize(3);
        assertThat(finalTurn.observations().get(0).tool()).isEqualTo("earlier_observations");
        assertThat(finalTurn.observations().get(0).result())
                .contains("EARLIER_OBSERVATIONS", "count=1", "search_code", "evidenceChunkIds=[1]")
                .doesNotContain("search result");
        assertThat(finalTurn.observations().get(2).result())
                .doesNotContain("TOOL_BUDGET", "CACHE_HIT");
        ArgumentCaptor<String> eventMessages = ArgumentCaptor.forClass(String.class);
        verify(traceService, atLeastOnce()).event(eq(taskId), any(), eq(AgentType.AUTHORIZATION),
                any(com.deepaudit.domain.AgentEventType.class), eventMessages.capture());
        assertThat(eventMessages.getAllValues()).allSatisfy(message -> assertThat(message)
                .doesNotContain("剩余工具", "TOOL_BUDGET", "第 1/", "第 2/", "第 3/"));
    }

    @Test
    void rejectsToolAfterBudgetExhaustionAndStillAllowsFinalFinding() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AiProperties properties = new AiProperties();
        properties.setMaxIterationsPerAgent(3);
        properties.setMaxToolCallsPerAgent(1);
        AuditToolService toolService = mock(AuditToolService.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        AuditCancellationService cancellationService = mock(AuditCancellationService.class);
        AgentRuntime runtime = new AgentRuntime(gateway, properties, toolService, traceService,
                hypothesisMapper, semanticEvidenceService, cancellationService);
        CodeChunk target = chunk(taskId, 1L, "Controller#entry", "return repository.query(input);");
        AgentTask task = new AgentTask(1L, AgentType.SQL_INJECTION,
                VulnerabilityType.SQL_INJECTION, "检查动态查询");
        when(traceService.start(eq(taskId), eq(AgentType.SQL_INJECTION), eq(1L), any()))
                .thenReturn(new AgentRun(taskId, AgentType.SQL_INJECTION, 1L, "entry"));
        when(semanticEvidenceService.query(taskId, 1L, 10, VulnerabilityType.SQL_INJECTION))
                .thenReturn(new SemanticEvidenceService.EvidenceResult("", Set.of()));
        when(semanticEvidenceService.callSiteLines(eq(taskId), eq(1L), any()))
                .thenReturn(Map.of());
        LlmGateway.FindingProposal finding = new LlmGateway.FindingProposal(
                VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "外部输入直接进入动态查询", "使用参数化查询",
                1L, List.of(1L), 1, 1);
        when(gateway.decide(any())).thenReturn(
                tool("search_code", Map.of("query", "query"), "查找查询实现"),
                tool("explore_call_graph", Map.of("direction", "CALLEES"), "继续扩展调用链"),
                new LlmGateway.AgentDecision("FINDING", null, Map.of(),
                        "现有证据足以确认动态 SQL 注入", finding));
        when(toolService.execute(anyString(), anyMap(), eq(target), any(),
                eq(VulnerabilityType.SQL_INJECTION), any(ToolSessionContext.class)))
                .thenReturn(new ToolResult("已读取动态查询实现", Set.of(1L), Set.of()));

        assertThat(runtime.investigate(taskId, task, null, List.of(target))).isPresent();

        verify(toolService, times(1)).execute(anyString(), anyMap(), eq(target), any(),
                eq(VulnerabilityType.SQL_INJECTION), any(ToolSessionContext.class));
        ArgumentCaptor<LlmGateway.AgentTurn> turns = ArgumentCaptor.forClass(LlmGateway.AgentTurn.class);
        verify(gateway, times(3)).decide(turns.capture());
        assertThat(turns.getAllValues().get(1).budget().finalDecisionOnly()).isTrue();
        assertThat(turns.getAllValues().get(1).budget().toolCallsRemaining()).isZero();
        assertThat(turns.getAllValues().get(2).observations()).anySatisfy(observation ->
                assertThat(observation.result()).contains("FINAL_DECISION_REQUIRED"));
    }

    @Test
    void suppliesConcreteReasonWhenModelRejectSummaryIsBlank() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AiProperties properties = new AiProperties();
        AuditToolService toolService = mock(AuditToolService.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        AuditCancellationService cancellationService = mock(AuditCancellationService.class);
        AgentRuntime runtime = new AgentRuntime(gateway, properties, toolService, traceService,
                hypothesisMapper, semanticEvidenceService, cancellationService);
        CodeChunk target = chunk(taskId, 1L, "Controller#entry", "return service.load(input);");
        AgentTask task = new AgentTask(1L, AgentType.AUTHORIZATION,
                VulnerabilityType.AUTHORIZATION, "检查授权");
        when(traceService.start(eq(taskId), eq(AgentType.AUTHORIZATION), eq(1L), any()))
                .thenReturn(new AgentRun(taskId, AgentType.AUTHORIZATION, 1L, "entry"));
        when(semanticEvidenceService.query(taskId, 1L, 10, VulnerabilityType.AUTHORIZATION))
                .thenReturn(new SemanticEvidenceService.EvidenceResult("", Set.of()));
        when(gateway.decide(any())).thenReturn(
                new LlmGateway.AgentDecision("REJECT", null, Map.of(), "", null));

        runtime.investigate(taskId, task, null, List.of(target));

        verify(traceService).event(eq(taskId), any(), eq(AgentType.AUTHORIZATION),
                eq(com.deepaudit.domain.AgentEventType.REJECTED),
                org.mockito.ArgumentMatchers.argThat(message -> message != null
                        && message.contains("未发现能够支持")));
    }

    @Test
    void treatsToolFailureFollowedByRejectAsIncompleteInvestigation() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AiProperties properties = new AiProperties();
        properties.setMaxIterationsPerAgent(2);
        properties.setMaxToolCallsPerAgent(2);
        AuditToolService toolService = mock(AuditToolService.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        AuditCancellationService cancellationService = mock(AuditCancellationService.class);
        AgentRuntime runtime = new AgentRuntime(gateway, properties, toolService, traceService,
                hypothesisMapper, semanticEvidenceService, cancellationService);
        CodeChunk target = chunk(taskId, 1L, "Controller#entry", "return service.load(input);");
        AgentTask task = new AgentTask(1L, AgentType.AUTHORIZATION,
                VulnerabilityType.AUTHORIZATION, "检查授权");
        when(traceService.start(eq(taskId), eq(AgentType.AUTHORIZATION), eq(1L), any()))
                .thenReturn(new AgentRun(taskId, AgentType.AUTHORIZATION, 1L, "entry"));
        when(semanticEvidenceService.query(taskId, 1L, 10, VulnerabilityType.AUTHORIZATION))
                .thenReturn(new SemanticEvidenceService.EvidenceResult("", Set.of()));
        when(gateway.decide(any())).thenReturn(
                tool("explore_call_graph", Map.of(), "查询调用关系"),
                new LlmGateway.AgentDecision("REJECT", null, Map.of(), "没有更多上下文", null));
        when(toolService.execute(anyString(), anyMap(), eq(target), any(),
                eq(VulnerabilityType.AUTHORIZATION), any(ToolSessionContext.class)))
                .thenReturn(new ToolResult(ToolResult.Status.ERROR, "CODEGRAPH_QUERY_FAILED",
                        "查询失败", Set.of(), Set.of(), false));

        assertThatThrownBy(() -> runtime.investigate(taskId, task, null, List.of(target)))
                .isInstanceOf(IncompleteInvestigationException.class)
                .hasMessageContaining("不完整");
    }

    private LlmGateway.AgentDecision tool(String tool, Map<String, Object> arguments, String summary) {
        return new LlmGateway.AgentDecision("TOOL", tool, arguments, summary, null);
    }

    private CodeChunk chunk(UUID taskId, long id, String symbol, String content) {
        CodeChunk chunk = new CodeChunk(taskId, "demo/Source.java", symbol, "/orders",
                1, 5, content, "JAVA_METHOD", "String input", "", "load,find");
        chunk.setId(id);
        chunk.setAnalysisScope(com.deepaudit.domain.AnalysisScope.CHANGED);
        return chunk;
    }
}
