package com.deepaudit.semantic;

import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticSymbolMapper;
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
        SemanticSymbolMapper symbolMapper = mock(SemanticSymbolMapper.class);
        SemanticEvidenceService service = new SemanticEvidenceService(flowMapper, edgeMapper, symbolMapper);
        SemanticCallEdge controllerToFacade = edge(taskId, 1400L, 1497L, 60);
        SemanticCallEdge facadeToService = edge(taskId, 1497L, 1549L, 84);
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(controllerToFacade, facadeToService));

        Map<Long, Integer> callSites = service.callSiteLines(
                taskId, 1549L, Set.of(1400L, 1497L, 1549L));

        assertThat(callSites).containsEntry(1497L, 84).containsEntry(1400L, 60);
    }

    private SemanticCallEdge edge(UUID taskId, long callerChunkId, long calleeChunkId, int line) {
        return new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                callerChunkId, calleeChunkId, line, "purchase", "purchase(request)",
                "JAVA_CALL", Confidence.HIGH, "方法签名唯一匹配", "request -> request");
    }
}
