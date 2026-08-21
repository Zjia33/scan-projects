package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditToolServiceTest {

    @Test
    void catalogDefinesOnlyCurrentToolSet() {
        assertThat(AgentToolCatalog.specs()).extracting(AgentToolCatalog.ToolSpec::name)
                .containsExactly("read_source", "verify_relation", "search_symbols", "search_code",
                        "explore_call_graph", "get_change_context", "resolve_data_access",
                        "inspect_security_policy", "trace_value");
        assertThat(AgentToolCatalog.find("search_symbols").allowedArguments()).doesNotContain("text");
        assertThat(AgentToolCatalog.find("explore_call_graph").allowedArguments()).doesNotContain("targetSymbol");
    }

    @Test
    void catalogPromptExplainsToolArgumentsDefaultsAndEvidenceSemantics() {
        String prompt = AgentToolCatalog.prompt();

        assertThat(prompt)
                .contains("chunkId(long，必填)")
                .contains("candidateChunkId(long，必填")
                .contains("CURRENT_FILE|RELATED|PROJECT")
                .contains("CALLERS|CALLEES|BOTH")
                .contains("depth(int，1..5，默认3")
                .contains("contextLines(int，0..20，默认2)")
                .contains("limit 为1..20、默认10", "1..500字符", "最多160行")
                .contains("includeConfiguration(boolean，默认false", "文件最多返回3个相关 hunk")
                .contains("INVALID_ARGUMENT", "不会自动转换、裁剪或回退")
                .contains("evidenceChunkIds", "candidateChunkIds", "TOOL_RESULT_TRUNCATED")
                .contains("游标只越过本次实际返回的结果")
                .contains("相交或相邻的上下文窗口会合并")
                .contains("先检查全部策略", "再应用 limit")
                .contains("UNVERIFIED_CANDIDATE/candidateChunkIds 只能作为线索")
                .contains("VERIFIED_EVIDENCE", "SEMANTIC_EVIDENCE", "CODEGRAPH_RELATIONS")
                .contains("没有结果只表示当前分析未解析到满足条件的数据流")
                .doesNotContain("targetSymbol");
    }

    @Test
    void searchSymbolsExpandsCodeGraphBeforeRunningLocalStructuredFilters() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ProfessionalToolService professional = mock(ProfessionalToolService.class);
        CodeGraphSymbolSearchService symbolSearch = mock(CodeGraphSymbolSearchService.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph, professional, symbolSearch);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "return ok();", "");
        CodeChunk discovered = chunk(2L, "OrderService#load", null, "return row;", "");
        List<CodeChunk> chunks = new java.util.ArrayList<>(List.of(current));
        when(symbolSearch.expand(eq(current.getTaskId()), any(ToolArguments.class), eq(chunks)))
                .thenAnswer(invocation -> {
                    chunks.add(discovered);
                    return new CodeGraphSymbolSearchService.Expansion(
                            true, false, "[CODEGRAPH_QUERY status=OK] locations=1 mappedChunkIds=1");
                });
        when(professional.searchSymbols(eq(current.getTaskId()), eq(current), eq(chunks),
                any(ToolArguments.class), eq(5)))
                .thenReturn(new ToolResult("[SEARCH_RESULT] CHUNK_ID=2", Set.of(1L), Set.of(2L)));

        ToolResult result = tools.execute("search_symbols",
                Map.of("symbol", "OrderService#load", "limit", 5), current, chunks,
                VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));

        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("SEARCH_RESULT", "CODEGRAPH_QUERY status=OK");
        assertThat(chunks).extracting(CodeChunk::getId).containsExactly(1L, 2L);
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
    void verifyRelationReturnsMetadataWithoutSource() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        AuditToolService tools = tools(semantic);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders/{id}", "service.load(id)", "load");
        CodeChunk candidate = chunk(2L, "OrderService#load", null,
                "return repository.findById(id);", "findById");
        when(semantic.verifyRelation(current.getTaskId(), 1L, 2L))
                .thenReturn(new SemanticEvidenceService.RelationVerification(true, "调用图存在直接连接"));

        ToolResult result = tools.execute("verify_relation", Map.of("candidateChunkId", 2L),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(result.text()).contains("SOURCE_NOT_INCLUDED", "read_source", "OrderService#load")
                .doesNotContain("return repository.findById(id);", "UNTRUSTED_CODE");
    }

    @Test
    void verifyRelationAcceptsDirectCodeGraphProofWhenLocalSemanticGraphMissesEdge() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ProfessionalToolService professional = mock(ProfessionalToolService.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph, professional);
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
    void readSourceAllowsTwentyContextLinesAndReturnsUpToOneHundredSixtyLines() {
        AuditToolService tools = tools(mock(SemanticEvidenceService.class));
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "service.load(id)", "load");
        String content = IntStream.rangeClosed(1, 200)
                .mapToObj(line -> "line-" + line).collect(Collectors.joining("\n"));
        CodeChunk candidate = new CodeChunk(current.getTaskId(), "demo/LargeService.java",
                "LargeService#load", null, 1, 200, content,
                "JAVA_METHOD", "", "", "");
        candidate.setId(2L);

        ToolResult contextual = tools.execute("read_source",
                Map.of("chunkId", 2L, "startLine", 100, "endLine", 100, "contextLines", 20),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));
        ToolResult expanded = tools.execute("read_source",
                Map.of("chunkId", 2L, "startLine", 1, "endLine", 200, "contextLines", 0),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(contextual.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(contextual.text()).contains("80 |", ">>>   100 |", "120 |");
        assertThat(expanded.truncated()).isTrue();
        assertThat(expanded.text()).contains("160 | line-160").doesNotContain("161 | line-161");
    }

    @Test
    void legacyCallGraphDispatchKeepsRawCodeGraphRelationsAsCandidates() {
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ProfessionalToolService professional = mock(ProfessionalToolService.class);
        AuditToolService tools = new AuditToolService(semantic, codeGraph, professional);
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "service.load(id)", "load");
        CodeChunk candidate = chunk(2L, "OrderService#load", null, "return row;", "");
        when(professional.exploreCallGraph(eq(current.getTaskId()), eq(current), eq(List.of(current, candidate)),
                any(ToolArguments.class), eq(5)))
                .thenReturn(new ToolResult("[CALL_GRAPH]", Set.of(1L), Set.of()));
        when(codeGraph.relationContext(current.getTaskId(), current, List.of(current, candidate), 5))
                .thenReturn(new CodeGraphIntegrationService.RelationContext(
                        "[VERIFIED_EVIDENCE][CODEGRAPH_RELATIONS] CHUNK_ID=2", Set.of(2L), 0));

        ToolResult result = tools.execute("explore_call_graph", Map.of("limit", 5),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of()));

        assertThat(result.evidenceChunkIds()).containsExactly(1L);
        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("CALL_GRAPH", "CODEGRAPH_RELATIONS");
    }

    @Test
    void rejectsUnknownToolsArgumentsAndCandidateAnchors() {
        AuditToolService tools = tools(mock(SemanticEvidenceService.class));
        CodeChunk current = chunk(1L, "Controller#entry", "/orders", "return ok();", "");
        CodeChunk candidate = chunk(2L, "Service#load", null, "return row;", "");

        ToolResult unsupported = tools.execute("unknown_tool", Map.of(), current,
                List.of(current), VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult unknown = tools.execute("search_code", Map.of("query", "load", "mode", "REGEX"),
                current, List.of(current), VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult stringLimit = tools.execute("search_code", Map.of("query", "load", "limit", "6"),
                current, List.of(current), VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult excessiveLimit = tools.execute("search_code", Map.of("query", "load", "limit", 21),
                current, List.of(current), VulnerabilityType.AUTHORIZATION, session(Set.of(1L), Set.of()));
        ToolResult malformedAnchor = tools.execute("explore_call_graph", Map.of("anchorChunkId", "chunk-2"),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));
        ToolResult anchor = tools.execute("explore_call_graph", Map.of("anchorChunkId", 2L),
                current, List.of(current, candidate), VulnerabilityType.AUTHORIZATION,
                session(Set.of(1L), Set.of(2L)));

        assertThat(unsupported.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(unknown.text()).contains("未知参数", "mode");
        assertThat(stringLimit.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(stringLimit.text()).contains("参数 limit", "JSON 整数");
        assertThat(excessiveLimit.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(excessiveLimit.text()).contains("参数 limit", "1..20");
        assertThat(malformedAnchor.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(malformedAnchor.text()).contains("参数 anchorChunkId", "JSON 整数");
        assertThat(anchor.status()).isEqualTo(ToolResult.Status.DENIED);
        assertThat(anchor.text()).contains("先调用 verify_relation");
    }

    private AuditToolService tools(SemanticEvidenceService semantic) {
        return new AuditToolService(semantic, mock(CodeGraphIntegrationService.class),
                mock(ProfessionalToolService.class));
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
