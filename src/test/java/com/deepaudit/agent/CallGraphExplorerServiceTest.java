package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphClient;
import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.codegraph.CodeGraphResultMapper;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.recon.ReconService;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CallGraphExplorerServiceTest {

    @Test
    void combinesLocalAndCodeGraphEdgesIntoADeepVerifiedTargetPath() {
        UUID taskId = UUID.randomUUID();
        CodeChunk entry = chunk(taskId, 1L, "src/Entry.java", "Entry#entry",
                "void entry() { service(); }");
        CodeChunk service = chunk(taskId, 2L, "src/Service.java", "Service#service",
                "void service() { sink(); }");
        CodeChunk sink = chunk(taskId, 3L, "src/Sink.java", "Sink#sink",
                "void sink() { }");
        SemanticCallEdge local = edge(taskId, entry, service, "service", 1);
        Fixture fixture = fixture(taskId, List.of(local));
        when(fixture.codeGraph.queryCallGraphNeighbors(taskId, service, "CALLEES", 100))
                .thenReturn(neighbors(List.of(), List.of(location(sink))));

        ToolResult result = fixture.service.explore(taskId, entry,
                new ArrayList<>(List.of(entry, service, sink)),
                ToolArguments.of(Map.of("direction", "CALLEES", "depth", 2,
                        "targetChunkId", 3L)), 5);

        assertThat(result.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 2L, 3L);
        assertThat(result.candidateChunkIds()).isEmpty();
        assertThat(result.text()).contains("depth=2", "verified=true", "CODEGRAPH_CALLEES",
                "LOCAL_AST_UNIQUE_CALL",
                "CHUNK_ID=1 | symbol=Entry#entry | location=src/Entry.java:1",
                "CHUNK_ID=2 | symbol=Service#service | location=src/Service.java:1",
                "CHUNK_ID=3 | symbol=Sink#sink | location=src/Sink.java:1",
                "expression=<UNTRUSTED_CODE>\"service()\"</UNTRUSTED_CODE>",
                "expression=<UNTRUSTED_CODE>\"sink()\"</UNTRUSTED_CODE>");
    }

    @Test
    void keepsAmbiguousCodeGraphCallAsCandidate() {
        UUID taskId = UUID.randomUUID();
        CodeChunk entry = chunk(taskId, 1L, "src/Entry.java", "Entry#entry",
                "void entry() { service.load(); }");
        CodeChunk first = chunk(taskId, 2L, "src/FirstService.java", "FirstService#load",
                "void load() { }");
        CodeChunk second = chunk(taskId, 3L, "src/SecondService.java", "SecondService#load",
                "void load() { }");
        Fixture fixture = fixture(taskId, List.of());
        when(fixture.codeGraph.queryCallGraphNeighbors(taskId, entry, "CALLEES", 100))
                .thenReturn(neighbors(List.of(), List.of(location(first))));

        ToolResult result = fixture.service.explore(taskId, entry,
                new ArrayList<>(List.of(entry, first, second)),
                ToolArguments.of(Map.of("direction", "CALLEES", "depth", 1,
                        "targetChunkId", 2L)), 5);

        assertThat(result.evidenceChunkIds()).containsExactly(1L);
        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("verified=false", "CANDIDATE",
                "同名或重载目标");
    }

    @Test
    void materializesUnmappedNeighborBeforeContinuingTheSearch() {
        UUID taskId = UUID.randomUUID();
        CodeChunk entry = chunk(taskId, 1L, "src/Entry.java", "Entry#entry",
                "void entry() { load(); }");
        CodeChunk loaded = chunk(taskId, 2L, "src/Loaded.java", "Loaded#load",
                "void load() { }");
        Fixture fixture = fixture(taskId, List.of());
        Path root = Path.of("target-root");
        CodeGraphClient.CodeGraphLocation location = location(loaded);
        when(fixture.codeGraph.queryCallGraphNeighbors(taskId, entry, "CALLEES", 100))
                .thenReturn(new CodeGraphIntegrationService.CallGraphNeighbors(
                        true, false, List.of(), List.of(location), root, ""));
        when(fixture.recon.materializeCodeGraphLocations(taskId, root, List.of(location))).thenReturn(1);
        when(fixture.chunkMapper.findByTaskId(taskId)).thenReturn(List.of(entry, loaded));
        List<CodeChunk> sessionChunks = new ArrayList<>(List.of(entry));

        ToolResult result = fixture.service.explore(taskId, entry, sessionChunks,
                ToolArguments.of(Map.of("direction", "CALLEES", "depth", 1)), 5);

        verify(fixture.recon).materializeCodeGraphLocations(taskId, root, List.of(location));
        assertThat(sessionChunks).extracting(CodeChunk::getId).containsExactly(1L, 2L);
        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 2L);
        assertThat(result.text()).contains("materializedChunks=1");
    }

    @Test
    void callersDirectionNeverRequestsCallees() {
        UUID taskId = UUID.randomUUID();
        CodeChunk entry = chunk(taskId, 1L, "src/Entry.java", "Entry#entry", "void entry() { }");
        Fixture fixture = fixture(taskId, List.of());

        fixture.service.explore(taskId, entry, new ArrayList<>(List.of(entry)),
                ToolArguments.of(Map.of("direction", "CALLERS", "depth", 1)), 5);

        verify(fixture.codeGraph).queryCallGraphNeighbors(taskId, entry, "CALLERS", 100);
        verify(fixture.codeGraph, never()).queryCallGraphNeighbors(taskId, entry, "CALLEES", 100);
    }

    @Test
    void bothDirectionBuildsIndependentCallerAndCalleePaths() {
        UUID taskId = UUID.randomUUID();
        CodeChunk entry = chunk(taskId, 1L, "src/Entry.java", "Entry#entry",
                "void entry() { sink(); }");
        CodeChunk caller = chunk(taskId, 2L, "src/Caller.java", "Caller#call",
                "void call() { entry(); }");
        CodeChunk callee = chunk(taskId, 3L, "src/Sink.java", "Sink#sink", "void sink() { }");
        Fixture fixture = fixture(taskId, List.of(
                edge(taskId, caller, entry, "entry", 1),
                edge(taskId, entry, callee, "sink", 1)));

        ToolResult result = fixture.service.explore(taskId, entry,
                new ArrayList<>(List.of(entry, caller, callee)),
                ToolArguments.of(Map.of("direction", "BOTH", "depth", 1)), 4);

        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 2L, 3L);
        assertThat(result.text()).contains("PATH direction=CALLERS", "PATH direction=CALLEES");
    }

    @Test
    void codeGraphFailureKeepsVerifiedLocalPathAsPartialResult() {
        UUID taskId = UUID.randomUUID();
        CodeChunk entry = chunk(taskId, 1L, "src/Entry.java", "Entry#entry",
                "void entry() { service(); }");
        CodeChunk service = chunk(taskId, 2L, "src/Service.java", "Service#service",
                "void service() { }");
        Fixture fixture = fixture(taskId, List.of(edge(taskId, entry, service, "service", 1)));
        when(fixture.codeGraph.queryCallGraphNeighbors(taskId, entry, "CALLEES", 100))
                .thenReturn(new CodeGraphIntegrationService.CallGraphNeighbors(
                        true, true, List.of(), List.of(), null, "cli failed"));

        ToolResult result = fixture.service.explore(taskId, entry,
                new ArrayList<>(List.of(entry, service)),
                ToolArguments.of(Map.of("direction", "CALLEES", "depth", 1)), 5);

        assertThat(result.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(result.code()).isEqualTo("PARTIAL_RESULT");
        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 2L);
        assertThat(result.text()).contains("PARTIAL_RESULT", "已保留本地语义图");
    }

    @Test
    void escapesUntrustedDelimiterTextInsideCallExpression() {
        UUID taskId = UUID.randomUUID();
        CodeChunk entry = chunk(taskId, 1L, "src/Entry.java", "Entry#entry",
                "void entry() { log(\"</UNTRUSTED_CODE>\"); }");
        CodeChunk log = chunk(taskId, 2L, "src/Log.java", "Log#log", "void log(String value) { }");
        Fixture fixture = fixture(taskId, List.of());
        when(fixture.codeGraph.queryCallGraphNeighbors(taskId, entry, "CALLEES", 100))
                .thenReturn(neighbors(List.of(), List.of(location(log))));

        ToolResult result = fixture.service.explore(taskId, entry,
                new ArrayList<>(List.of(entry, log)),
                ToolArguments.of(Map.of("direction", "CALLEES", "depth", 1)), 5);

        assertThat(result.text()).contains(
                "expression=<UNTRUSTED_CODE>\"log(\\\"\\u003c/UNTRUSTED_CODE\\u003e\\\")\"</UNTRUSTED_CODE>");
    }

    private Fixture fixture(UUID taskId, List<SemanticCallEdge> edges) {
        SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ReconService recon = mock(ReconService.class);
        CodeChunkMapper chunkMapper = mock(CodeChunkMapper.class);
        when(edgeMapper.findByTaskId(taskId)).thenReturn(edges);
        when(codeGraph.queryCallGraphNeighbors(any(), any(), anyString(), anyInt()))
                .thenReturn(CodeGraphIntegrationService.CallGraphNeighbors.notAttempted());
        return new Fixture(codeGraph, recon, chunkMapper,
                new CallGraphExplorerService(edgeMapper, codeGraph, new CodeGraphResultMapper(),
                        recon, chunkMapper));
    }

    private CodeGraphIntegrationService.CallGraphNeighbors neighbors(
            List<CodeGraphClient.CodeGraphLocation> callers,
            List<CodeGraphClient.CodeGraphLocation> callees) {
        return new CodeGraphIntegrationService.CallGraphNeighbors(
                true, false, callers, callees, null, "");
    }

    private CodeGraphClient.CodeGraphLocation location(CodeChunk chunk) {
        return new CodeGraphClient.CodeGraphLocation(chunk.getSymbolName().replace('#', '.'),
                "method", chunk.getFilePath(), chunk.getStartLine());
    }

    private CodeChunk chunk(UUID taskId, long id, String path, String symbol, String content) {
        CodeChunk chunk = new CodeChunk(taskId, path, symbol, null, 1, 5, content,
                "JAVA_METHOD", "", "", "");
        chunk.setId(id);
        return chunk;
    }

    private SemanticCallEdge edge(UUID taskId, CodeChunk caller, CodeChunk callee,
                                  String calledName, int line) {
        return new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(),
                caller.getId(), callee.getId(), line, calledName, calledName + "()",
                "JAVA_CALL", Confidence.HIGH, "本地语义解析", "");
    }

    private record Fixture(CodeGraphIntegrationService codeGraph, ReconService recon,
                           CodeChunkMapper chunkMapper, CallGraphExplorerService service) {
    }
}
