package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditToolServiceTest {

    @Test
    void verifyRelationPromotesCandidateToEvidence() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        AuditToolService tools = new AuditToolService(semantic);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders/{id}", "service.load(id)", "load");
        CodeChunk candidate = chunk(2L, "OrderService#load", null, "return repository.findById(id)", "findById");
        when(semantic.verifyRelation(current.getTaskId(), 1L, 2L))
                .thenReturn(new SemanticEvidenceService.RelationVerification(true, "调用图存在直接连接"));

        AuditToolService.ToolResult result = tools.execute("verify_relation", "CHUNK_ID=2", 1,
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION);

        assertThat(result.evidenceChunkIds()).containsExactly(2L);
        assertThat(result.candidateChunkIds()).isEmpty();
        assertThat(result.text()).contains("VERIFIED_EVIDENCE", "调用图存在直接连接");
    }

    @Test
    void dataAccessReturnsTypedSemanticEvidence() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        AuditToolService tools = new AuditToolService(semantic);
        CodeChunk current = chunk(1L, "Controller#entry", "/search", "statement.execute(sql)", "execute");
        when(semantic.query(current.getTaskId(), 1L, "trace_data_flow", 5, VulnerabilityType.SQL_INJECTION))
                .thenReturn(new SemanticEvidenceService.EvidenceResult("已验证 SQL 数据流", Set.of(1L, 3L)));

        AuditToolService.ToolResult result = tools.execute("data_access", "SQL", 5,
                current, List.of(current), VulnerabilityType.SQL_INJECTION);

        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 3L);
        assertThat(result.text()).contains("SEMANTIC_EVIDENCE", "已验证 SQL 数据流");
    }

    @Test
    void codeGraphContextRemainsCandidateEvidence() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders/{id}", "service.load(id)", "load");
        CodeChunk candidate = chunk(2L, "OrderService#inspect", null, "return repository.findById(id)", "findById");
        candidate.setFilePath("demo/OrderService.java");
        when(codeGraph.candidateContext(current.getTaskId(), current, List.of(current, candidate), 5))
                .thenReturn(new CodeGraphIntegrationService.CandidateContext(
                        "[CODEGRAPH_CANDIDATE] CHUNK_ID=2", Set.of(2L), 0));

        AuditToolService.ToolResult result = tools.execute("call_context", "", 5,
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION);

        assertThat(result.evidenceChunkIds()).isEmpty();
        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("CODEGRAPH_CANDIDATE");
    }

    private CodeChunk chunk(long id, String symbol, String endpoint, String content, String calls) {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "demo/Source.java", symbol, endpoint,
                1, 5, content, "JAVA_METHOD", "Long id", "", calls);
        chunk.setId(id);
        return chunk;
    }
}
