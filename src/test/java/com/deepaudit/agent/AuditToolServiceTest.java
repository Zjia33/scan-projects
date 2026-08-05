package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.recon.ReconService;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

class AuditToolServiceTest {

    @Test
    void catalogDefinesOnlyCurrentToolSet() {
        assertThat(AgentToolCatalog.specs()).extracting(AgentToolCatalog.ToolSpec::name)
                .containsExactly("read_source", "verify_relation", "search_symbols", "search_code",
                        "explore_call_graph", "read_impact_source", "get_change_context", "resolve_data_access",
                        "inspect_security_policy", "trace_value");
    }

    @Test
    void verifyRelationPromotesDiscoveredCandidateToEvidence() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        AuditToolService tools = tools(semantic);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders/{id}", "service.load(id)", "load");
        CodeChunk candidate = chunk(2L, "OrderService#load", null, "return repository.findById(id)", "findById");
        when(semantic.verifyRelation(current.getTaskId(), 1L, 2L))
                .thenReturn(new SemanticEvidenceService.RelationVerification(true, "调用图存在直接连接"));

        ToolResult result = tools.execute("verify_relation", Map.of("candidateChunkId", 2L),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(result.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(result.evidenceChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("VERIFIED_EVIDENCE", "调用图存在直接连接");
    }

    @Test
    void verifyRelationAcceptsDirectCodeGraphProofWhenLocalSemanticGraphMissesEdge() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ProfessionalToolService professional = mock(ProfessionalToolService.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph, professional, null, null);
        UUID taskId = UUID.randomUUID();
        CodeChunk current = chunk(taskId, 1L, "Controller#entry", "/orders/{id}",
                "service.load(id)", "load");
        CodeChunk candidate = chunk(taskId, 2L, "OrderService#load", null,
                "return repository.findById(id)", "findById");
        when(semantic.verifyRelation(taskId, 1L, 2L))
                .thenReturn(new SemanticEvidenceService.RelationVerification(false, "本地语义边未解析"));
        when(codeGraph.verifyDirectRelation(taskId, current, candidate, List.of(current, candidate)))
                .thenReturn(new CodeGraphIntegrationService.RelationCheck(
                        true, "CodeGraph Target 索引确认直接调用"));

        ToolResult result = tools.execute("verify_relation", Map.of("candidateChunkId", 2L),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(result.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(result.evidenceChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("CODEGRAPH_RELATION", "CodeGraph Target 索引确认直接调用");
    }

    @Test
    void relationRejectsUndiscoveredAndAmbiguousCandidates() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        AuditToolService tools = tools(semantic);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "service.load(id)", "load");
        CodeChunk first = chunk(2L, "FirstService#load", null, "return one();", "");
        CodeChunk second = chunk(3L, "SecondService#load", null, "return two();", "");

        ToolResult undiscovered = tools.execute("verify_relation", Map.of("candidateChunkId", 2L),
                current, List.of(current, first, second), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of()));
        when(semantic.verifyRelation(current.getTaskId(), 1L, 2L))
                .thenReturn(new SemanticEvidenceService.RelationVerification(false, "无法唯一解析"));
        ToolResult ambiguous = tools.execute("verify_relation", Map.of("candidateChunkId", 2L),
                current, List.of(current, first, second), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(undiscovered.status()).isEqualTo(ToolResult.Status.DENIED);
        assertThat(undiscovered.code()).isEqualTo("ACCESS_DENIED");
        assertThat(ambiguous.status()).isEqualTo(ToolResult.Status.DENIED);
        assertThat(ambiguous.code()).isEqualTo("RELATION_REJECTED");
        assertThat(ambiguous.text()).contains("NAME_MATCH_ONLY");
    }

    @Test
    void readSourceSupportsWholeChunkAndSmallRangeWithoutPromotingCandidate() {
        AuditToolService tools = tools(mock(SemanticEvidenceService.class));
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "service.load(id)", "load");
        CodeChunk candidate = new CodeChunk(current.getTaskId(), "demo/OrderService.java",
                "OrderService#load", null, 10, 14, """
                public Order load(Long id) {
                    validate(id);
                    return repository.find(id);
                }
                """, "JAVA_METHOD", "Long id", "", "validate,find");
        candidate.setId(2L);

        ToolResult whole = tools.execute("read_source", Map.of("chunkId", 2L),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));
        ToolResult range = tools.execute("read_source",
                Map.of("chunkId", 2L, "startLine", 12, "endLine", 12, "contextLines", 1),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(whole.text()).contains("10 |", "13 |");
        assertThat(range.text()).contains("11 |", ">>>    12 |", "13 |").doesNotContain("14 |");
        assertThat(range.candidateChunkIds()).containsExactly(2L);
        assertThat(range.evidenceChunkIds()).isEmpty();
    }

    @Test
    void dispatchesCallGraphAsUnverifiedSymbolCandidatesWithoutPreloadingSource() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ProfessionalToolService professional = mock(ProfessionalToolService.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph, professional, null, null);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "service.load(id)", "load");
        CodeChunk candidate = chunk(2L, "OrderService#load", null, "return row;", "");
        when(professional.exploreCallGraph(eq(current.getTaskId()), eq(current), eq(List.of(current, candidate)),
                any(ToolArguments.class), eq(5)))
                .thenReturn(new ToolResult("[CALL_GRAPH]", Set.of(1L), Set.of()));
        var location = new com.deepaudit.codegraph.CodeGraphClient.CodeGraphLocation(
                "OrderService.load", "method", "demo/OrderService.java", 10);
        var impactCandidate = new CodeGraphIntegrationService.ImpactCandidate(
                "candidate-1", 1L, CodeGraphIntegrationService.Direction.CALLEES, location);
        when(codeGraph.relatedCandidates(current.getTaskId(), current,
                CodeGraphIntegrationService.Direction.BOTH, 0, 5))
                .thenReturn(new CodeGraphIntegrationService.CandidatePage(
                        List.of(impactCandidate), 1, false, null));

        ToolResult result = tools.execute("explore_call_graph", Map.of("limit", 5),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of()));

        assertThat(result.evidenceChunkIds()).containsExactly(1L);
        assertThat(result.candidateChunkIds()).isEmpty();
        assertThat(result.text()).contains("CALL_GRAPH", "UNVERIFIED_SYMBOL_CANDIDATES",
                "candidateId=candidate-1").doesNotContain("CHUNK_ID=2");
    }

    @Test
    void materializesOnlyExplicitlySelectedImpactCandidate() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ProfessionalToolService professional = mock(ProfessionalToolService.class);
        ReconService recon = mock(ReconService.class);
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph, professional, recon, mapper);
        UUID taskId = UUID.randomUUID();
        CodeChunk current = chunk(taskId, 1L, "Controller#entry", "/orders", "service.load(id)", "load");
        CodeChunk selected = chunk(taskId, 2L, "OrderService#load", null,
                "return repository.find(id);", "find");
        var location = new com.deepaudit.codegraph.CodeGraphClient.CodeGraphLocation(
                "OrderService.load", "method", "demo/OrderService.java", 10);
        var candidate = new CodeGraphIntegrationService.ImpactCandidate(
                "candidate-1", 1L, CodeGraphIntegrationService.Direction.CALLEES, location);
        var chunks = new ArrayList<>(List.of(current));
        var root = java.nio.file.Path.of("target-worktree");
        when(codeGraph.candidate(taskId, "candidate-1")).thenReturn(candidate);
        when(codeGraph.targetRoot(taskId)).thenReturn(root);
        when(mapper.findByTaskId(taskId)).thenReturn(List.of(current, selected));
        when(codeGraph.mapCandidate(chunks, candidate)).thenReturn(selected);

        ToolResult result = tools.execute("read_impact_source", Map.of("candidateId", "candidate-1"),
                current, chunks, VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));

        assertThat(result.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.evidenceChunkIds()).isEmpty();
        assertThat(result.text()).contains("UNVERIFIED_CANDIDATE", "IMPACT_SOURCE");
        verify(recon).materializeCodeGraphLocations(taskId, root, List.of(location));
        verify(recon).promoteImpactScope(taskId, Set.of(2L));
    }

    @Test
    void rejectsRemovedToolsUnknownArgumentsAndCandidateAnchors() {
        AuditToolService tools = tools(mock(SemanticEvidenceService.class));
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "return ok();", "");
        CodeChunk candidate = chunk(2L, "Service#load", null, "return row;", "");

        ToolResult removed = tools.execute("get_chunk", Map.of("chunkId", 1L), current,
                List.of(current), VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult unknown = tools.execute("search_code", Map.of("query", "load", "mode", "REGEX"),
                current, List.of(current), VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult anchor = tools.execute("explore_call_graph", Map.of("anchorChunkId", 2L),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(removed.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(unknown.text()).contains("未知参数", "mode");
        assertThat(anchor.status()).isEqualTo(ToolResult.Status.DENIED);
        assertThat(anchor.text()).contains("先调用 verify_relation");
    }

    private AuditToolService tools(SemanticEvidenceService semantic) {
        return new AuditToolService(semantic, mock(CodeGraphIntegrationService.class),
                mock(ProfessionalToolService.class), null, null);
    }

    private ToolSessionContext session(Set<Long> evidence, Set<Long> candidates) {
        return new ToolSessionContext(1L, evidence, candidates);
    }

    private CodeChunk chunk(long id, String symbol, String endpoint, String content, String calls) {
        return chunk(UUID.randomUUID(), id, symbol, endpoint, content, calls);
    }

    private CodeChunk chunk(UUID taskId, long id, String symbol, String endpoint, String content, String calls) {
        CodeChunk chunk = new CodeChunk(taskId, "demo/Source.java", symbol, endpoint,
                1, 5, content, "JAVA_METHOD", "Long id", "", calls);
        chunk.setId(id);
        return chunk;
    }
}
