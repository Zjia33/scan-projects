package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphClient;
import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.codegraph.CodeGraphProperties;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CallGraphCandidatePrefetchServiceTest {

    @Test
    void addsDirectCallerAndCalleeMetadataWithoutMaterializingSource() {
        UUID taskId = UUID.randomUUID();
        CodeChunk changed = new CodeChunk(taskId, "demo/OrderService.java", "OrderService#load", null,
                10, 20, "Order load(Long id) { return repository.find(id); }",
                "JAVA_METHOD", "Long id", "", "find");
        changed.setId(7L);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        CodeGraphProperties properties = new CodeGraphProperties();
        properties.setAgentContextLimit(6);
        var caller = candidate("caller-1", 7L, CodeGraphIntegrationService.Direction.CALLERS,
                "OrderController.load", "demo/OrderController.java", 31);
        var callee = candidate("callee-1", 7L, CodeGraphIntegrationService.Direction.CALLEES,
                "OrderRepository.find", "demo/OrderRepository.java", 12);
        when(codeGraph.relatedCandidates(taskId, changed,
                CodeGraphIntegrationService.Direction.CALLERS, 6))
                .thenReturn(new CodeGraphIntegrationService.CandidatePage(List.of(caller), 1, false, null));
        when(codeGraph.relatedCandidates(taskId, changed,
                CodeGraphIntegrationService.Direction.CALLEES, 6))
                .thenReturn(new CodeGraphIntegrationService.CandidatePage(List.of(callee), 1, false, null));
        CallGraphCandidatePrefetchService service = new CallGraphCandidatePrefetchService(codeGraph, properties);

        AgentTask enriched = service.enrich(new AgentTask(7L, AgentType.AUTHORIZATION,
                VulnerabilityType.AUTHORIZATION, "检查资源归属"), List.of(changed));

        assertThat(enriched.ruleHint())
                .contains("检查资源归属", "candidateId=caller-1", "direction=CALLERS",
                        "candidateId=callee-1", "direction=CALLEES", "read_verified_relations")
                .doesNotContain(changed.getContent());
        verify(codeGraph).relatedCandidates(taskId, changed,
                CodeGraphIntegrationService.Direction.CALLERS, 6);
        verify(codeGraph).relatedCandidates(taskId, changed,
                CodeGraphIntegrationService.Direction.CALLEES, 6);
    }

    private CodeGraphIntegrationService.ImpactCandidate candidate(
            String id, long anchor, CodeGraphIntegrationService.Direction direction,
            String symbol, String file, int line) {
        return new CodeGraphIntegrationService.ImpactCandidate(id, anchor, direction,
                new CodeGraphClient.CodeGraphLocation(symbol, "method", file, line));
    }
}
