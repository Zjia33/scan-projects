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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

class AuditToolServiceTest {

    @Test
    void catalogDefinesOnlyCurrentToolSet() {
        assertThat(AgentToolCatalog.specs()).extracting(AgentToolCatalog.ToolSpec::name)
                .containsExactly("read_source", "search_symbols", "search_code",
                        "explore_call_graph", "read_verified_relations",
                        "get_change_context", "resolve_data_access",
                        "inspect_security_policy", "trace_value");
    }

    @Test
    void catalogPromptExplainsRequiredArgumentsAndToolIdentifiers() {
        String prompt = AgentToolCatalog.prompt();

        assertThat(prompt)
                .contains("必填=chunkId")
                .contains("startLine/endLine=文件绝对行号")
                .contains("scope=CURRENT_FILE、RELATED 或 PROJECT")
                .contains("candidateIds=explore_call_graph 或首次预取结果中的位置标识数组")
                .contains("不是数字 chunkId")
                .contains("服务端自动确认候选来源和 Target 唯一映射")
                .contains("PARTIAL_SCOPE 或 ERROR")
                .doesNotContain("nextCursor", "cursor=上一页");
        assertThat(AgentToolCatalog.specs()).anySatisfy(spec ->
                assertThat(spec.requiredArguments()).containsExactly("chunkId"));
        assertThat(AgentToolCatalog.specs()).anySatisfy(spec ->
                assertThat(spec.requiredArguments()).containsExactly("candidateIds"));
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
    void readSourceDoesNotAcceptPaginationCursor() {
        AuditToolService tools = tools(mock(SemanticEvidenceService.class));
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "service.load(id)", "load");
        String content = java.util.stream.IntStream.rangeClosed(1, 100)
                .mapToObj(line -> "line" + line + "();")
                .collect(java.util.stream.Collectors.joining("\n"));
        CodeChunk candidate = new CodeChunk(current.getTaskId(), "demo/LargeService.java",
                "LargeService#load", null, 1, 100, content,
                "JAVA_METHOD", "Long id", "", "");
        candidate.setId(2L);
        ToolSessionContext session = session(Set.of(1L), Set.of(2L));
        ToolResult result = tools.execute("read_source",
                Map.of("chunkId", 2L, "cursor", "rs1:2:81:0:100:1:100"),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION, session);

        assertThat(result.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(result.text()).contains("未知参数", "cursor");
    }

    @Test
    void dispatchesCallGraphAsUnverifiedSymbolCandidatesWithoutPreloadingSource() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ProfessionalToolService professional = mock(ProfessionalToolService.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph, professional, null, null);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "service.load(id)", "load");
        CodeChunk candidate = chunk(2L, "OrderService#load", null, "return row;", "");
        when(professional.exploreFrameworkRelations(eq(current.getTaskId()), eq(current), eq(List.of(current, candidate)),
                any(ToolArguments.class), eq(5)))
                .thenReturn(new ToolResult("[FRAMEWORK_SEMANTIC_RELATIONS]", Set.of(1L), Set.of()));
        var location = new com.deepaudit.codegraph.CodeGraphClient.CodeGraphLocation(
                "OrderService.load", "method", "demo/OrderService.java", 10);
        var impactCandidate = new CodeGraphIntegrationService.ImpactCandidate(
                "candidate-1", 1L, CodeGraphIntegrationService.Direction.CALLEES, location);
        when(codeGraph.relatedCandidates(current.getTaskId(), current,
                CodeGraphIntegrationService.Direction.BOTH, 5))
                .thenReturn(new CodeGraphIntegrationService.CandidatePage(
                        List.of(impactCandidate), 1, false, null));

        ToolResult result = tools.execute("explore_call_graph", Map.of("limit", 5),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of()));

        assertThat(result.evidenceChunkIds()).containsExactly(1L);
        assertThat(result.candidateChunkIds()).isEmpty();
        assertThat(result.text()).contains("CODEGRAPH_RELATION_CANDIDATES", "UNVERIFIED_SYMBOL_CANDIDATES",
                "FRAMEWORK_SEMANTIC_RELATIONS",
                "candidateId=candidate-1").doesNotContain("CHUNK_ID=2");
    }

    @Test
    void materializesSingleExplicitlySelectedImpactCandidateThroughBatchTool() {
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
        when(codeGraph.materializedChunkId(taskId, candidate)).thenReturn(null, 2L);
        when(mapper.findByTaskId(taskId)).thenReturn(List.of(current, selected));
        when(codeGraph.mapCandidate(chunks, candidate)).thenReturn(selected);

        ToolResult first = tools.execute("read_verified_relations", Map.of("candidateIds", List.of("candidate-1")),
                current, chunks, VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult second = tools.execute("read_verified_relations", Map.of("candidateIds", List.of("candidate-1")),
                current, chunks, VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));

        assertThat(first.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(first.candidateChunkIds()).isEmpty();
        assertThat(first.evidenceChunkIds()).containsExactly(2L);
        assertThat(first.text()).contains("VERIFIED_EVIDENCE", "IMPACT_SOURCE", "CodeGraph");
        assertThat(second.status()).isEqualTo(ToolResult.Status.OK);
        verify(recon, times(1)).materializeCodeGraphLocations(taskId, root, List.of(location));
        verify(recon, times(1)).promoteImpactScope(taskId, Set.of(2L));
    }

    @Test
    void batchToolMaterializesAndAutoConfirmsSelectedPrefetchedRelation() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ProfessionalToolService professional = mock(ProfessionalToolService.class);
        ReconService recon = mock(ReconService.class);
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph, professional, recon, mapper);
        UUID taskId = UUID.randomUUID();
        CodeChunk current = chunk(taskId, 1L, "Controller#entry", "/orders",
                "return service.load(id);", "unresolved");
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

        ToolResult result = tools.execute("read_verified_relations",
                Map.of("candidateIds", List.of("candidate-1")),
                current, chunks, VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of()));

        assertThat(result.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(result.evidenceChunkIds()).containsExactly(2L);
        assertThat(result.candidateChunkIds()).isEmpty();
        assertThat(result.text()).contains("BATCH_IMPACT_SOURCES", "VERIFIED_EVIDENCE",
                "CodeGraph", "本地调用点未能复验");
        verify(recon).materializeCodeGraphLocations(taskId, root, List.of(location));
        verify(recon).promoteImpactScope(taskId, Set.of(2L));
    }

    @Test
    void rejectsRemovedToolsUnknownArgumentsAndCandidateAnchors() {
        AuditToolService tools = tools(mock(SemanticEvidenceService.class));
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "return ok();", "");
        CodeChunk candidate = chunk(2L, "Service#load", null, "return row;", "");

        ToolResult removed = tools.execute("read_impact_source", Map.of("candidateId", "candidate-1"), current,
                List.of(current), VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult unknown = tools.execute("search_code", Map.of("query", "load", "mode", "REGEX"),
                current, List.of(current), VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult anchor = tools.execute("explore_call_graph", Map.of("anchorChunkId", 2L),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(removed.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(unknown.text()).contains("未知参数", "mode");
        assertThat(anchor.status()).isEqualTo(ToolResult.Status.DENIED);
        assertThat(anchor.text()).contains("read_verified_relations", "服务端确认");
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
