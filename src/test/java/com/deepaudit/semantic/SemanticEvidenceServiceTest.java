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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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

        assertThat(result.text()).contains("input -> execute", "缺少参数化绑定", "已确认关系边=2", "局部语义缺口=1");
        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(10L, 20L);
    }

    @Test
    void doesNotPromoteALowConfidenceRelation() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticCallEdge candidate = new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                10L, 20L, 0, "load", "framework hint", "FRAMEWORK_HINT",
                Confidence.LOW, "只命中局部启发式", "");
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(candidate));
        SemanticEvidenceService service = new SemanticEvidenceService(flowMapper, edgeMapper);

        SemanticEvidenceService.RelationVerification result = service.verifyRelation(taskId, 10L, 20L);

        assertThat(result.verified()).isFalse();
    }

    @Test
    void doesNotPromoteHistoricalPlainJavaCallEdges() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        SemanticCallEdge historical = new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                10L, 20L, 7, "load", "service.load(id)", "JAVA_CALL",
                Confidence.HIGH, "历史普通 Java 调用边", "id -> id");
        when(flowMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(historical));
        SemanticEvidenceService service = new SemanticEvidenceService(flowMapper, edgeMapper);

        SemanticEvidenceService.RelationVerification result = service.verifyRelation(taskId, 10L, 20L);

        assertThat(result.verified()).isFalse();
    }

    @Test
    void reusesImmutableTaskEdgesUntilTaskCacheIsCleared() {
        UUID taskId = UUID.randomUUID();
        SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(edge(taskId, 10L, 20L, 7)));
        SemanticEvidenceService service = new SemanticEvidenceService(flowMapper, edgeMapper);

        service.callSiteLines(taskId, 20L, Set.of(10L, 20L));
        service.callSiteLines(taskId, 20L, Set.of(10L, 20L));
        verify(edgeMapper).findByTaskId(taskId);

        service.clearTaskCache(taskId);
        service.callSiteLines(taskId, 20L, Set.of(10L, 20L));
        verify(edgeMapper, times(2)).findByTaskId(taskId);
    }

    private SemanticCallEdge edge(UUID taskId, long callerChunkId, long calleeChunkId, int line) {
        return new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                callerChunkId, calleeChunkId, line, "purchase", "purchase(request)",
                "SPRING_EVENT", Confidence.HIGH, "事件类型与监听器参数匹配", "request -> request");
    }
}
