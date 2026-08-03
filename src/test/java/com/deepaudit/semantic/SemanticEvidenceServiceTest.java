package com.deepaudit.semantic;

import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SemanticEvidenceServiceTest {

    @Test
    void tracesRealCallSiteLinesBackFromFinalVulnerabilityChunk() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticEvidenceService service = new SemanticEvidenceService(flowMapper, edgeMapper);
        SemanticCallEdge controllerToFacade = edge(taskId, 1400L, 1497L, 60);
        SemanticCallEdge facadeToService = edge(taskId, 1497L, 1549L, 84);
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(controllerToFacade, facadeToService));

        Map<Long, Integer> callSites = service.callSiteLines(
                taskId, 1549L, Set.of(1400L, 1497L, 1549L));

        assertThat(callSites).containsEntry(1497L, 84).containsEntry(1400L, 60);
    }

    @Test
    void returnsStructuredChunkIdsForIndependentCriticEvidence() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticEvidenceService service = new SemanticEvidenceService(
                flowMapper, mock(SemanticCallEdgeMapper.class));
        SecurityFlow flow = new SecurityFlow(taskId, VulnerabilityType.SQL_INJECTION,
                UUID.randomUUID(), UUID.randomUUID(), 10L, "HTTP 参数", "动态查询", "无 Guard",
                "CHUNK 10 -> CHUNK 20", "10,20", Confidence.HIGH, 1, 0);
        when(flowMapper.findByTaskAndChunk(taskId, 10L)).thenReturn(List.of(flow));

        SemanticEvidenceService.EvidenceResult result = service.independentCriticEvidenceResult(
                taskId, 10L, VulnerabilityType.SQL_INJECTION);

        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(10L, 20L);
        assertThat(result.text()).contains("独立语义证据", "CHUNK 10 -> CHUNK 20");
    }

    @Test
    void returnsPathAndGuardSummaryTogether() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticEvidenceService service = new SemanticEvidenceService(
                flowMapper, mock(SemanticCallEdgeMapper.class));
        SecurityFlow flow = new SecurityFlow(taskId, VulnerabilityType.SQL_INJECTION,
                UUID.randomUUID(), UUID.randomUUID(), 10L, "HTTP 参数", "动态查询", "缺少参数化绑定",
                "input -> execute", "10,20", Confidence.HIGH, 2, 1);
        when(flowMapper.findByTaskAndChunk(taskId, 10L)).thenReturn(List.of(flow));

        SemanticEvidenceService.EvidenceResult result = service.query(
                taskId, 10L, 5, VulnerabilityType.SQL_INJECTION);

        assertThat(result.text()).contains("input -> execute", "缺少参数化绑定", "已解析边=2", "未解析边=1");
        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(10L, 20L);
    }

    private SemanticCallEdge edge(UUID taskId, long callerChunkId, long calleeChunkId, int line) {
        return new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                callerChunkId, calleeChunkId, line, "purchase", "purchase(request)",
                "JAVA_CALL", Confidence.HIGH, "方法签名唯一匹配", "request -> request");
    }
}
