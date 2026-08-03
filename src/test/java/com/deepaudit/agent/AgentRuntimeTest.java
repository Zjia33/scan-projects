package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
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
        AgentRuntime runtime = new AgentRuntime(gateway, properties, toolService, traceService,
                hypothesisMapper, semanticEvidenceService);
        CodeChunk target = chunk(taskId, 1L, "Controller#entry", "service.load(input);");
        CodeChunk candidate = chunk(taskId, 2L, "OrderService#load", "return repository.find(input);");
        List<CodeChunk> chunks = List.of(target, candidate);
        AgentTask task = new AgentTask(1L, AgentType.AUTHORIZATION,
                VulnerabilityType.AUTHORIZATION, "检查授权", "规则线索");

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
        assertThat(finalTurn.observations()).hasSize(3);
        assertThat(finalTurn.observations().get(0).result()).contains("COMPACT_OBSERVATION");
        assertThat(finalTurn.observations().get(2).result()).contains("TOOL_BUDGET")
                .doesNotContain("CACHE_HIT");
    }

    private LlmGateway.AgentDecision tool(String tool, Map<String, Object> arguments, String summary) {
        return new LlmGateway.AgentDecision("TOOL", tool, arguments, summary, null);
    }

    private CodeChunk chunk(UUID taskId, long id, String symbol, String content) {
        CodeChunk chunk = new CodeChunk(taskId, "demo/Source.java", symbol, "/orders",
                1, 5, content, "JAVA_METHOD", "String input", "", "load,find");
        chunk.setId(id);
        return chunk;
    }
}
